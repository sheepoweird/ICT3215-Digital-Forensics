#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>
#include <esp_system.h>

#include "encryption.h"

#define SERVICE_UUID        "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define CHARACTERISTIC_UUID "beb5483f-36e1-4688-b7f5-ea07361b26a8"
#define FIRMWARE_VERSION    2

// --- ESP32-CAM FLASH LED CONFIGURATION ---
// Pin 4 is the bright white LED on the front. Uses standard logic (HIGH = ON).
#define LED_PIN 4

// --- BLE PROTOCOL (must match Python/token_comms.py) ---
// Host  -> Token  HELLO     : 0x10
// Token -> Host   CHALLENGE : 0x11 | token_nonce[16] | token_id[16]
// Host  -> Token  REQUEST   : 0x20 | host_nonce[16] | iv[12] | ct[33] | tag[16]
// Token -> Host   RESPONSE  : 0x21 | iv[12] | ct[33] | tag[16]
// Token -> Host   ERROR     : 0x7F | code
//
// session_key = HMAC(auth_key, "3T-SK-v1" | token_nonce | host_nonce)
// REQUEST plaintext  = op | env_hash[32]      (AAD = "3T-REQ-v1" | token_id)
// RESPONSE plaintext = status | data[32]      (AAD = "3T-RSP-v1" | token_id)
// env_key (DERIVE)   = HMAC(master_secret, "3T-ENV-v1" | env_hash)
#define MSG_HELLO      0x10
#define MSG_CHALLENGE  0x11
#define MSG_REQUEST    0x20
#define MSG_RESPONSE   0x21
#define MSG_ERROR      0x7F

#define OP_DERIVE      0x01
#define OP_PING        0x02

#define ERR_NOT_PAIRED   0x01
#define ERR_NO_CHALLENGE 0x02
#define ERR_AUTH_FAILED  0x03
#define ERR_BAD_FORMAT   0x04
#define ERR_LOCKED_OUT   0x05

#define REQ_PLAIN_LEN  (1 + SHA256_LEN)
#define REQUEST_LEN    (1 + NONCE_LEN + GCM_IV_LEN + REQ_PLAIN_LEN + GCM_TAG_LEN)

// Brute-force protection: too many bad requests locks the token for a while
#define MAX_AUTH_FAILURES 5
#define LOCKOUT_MS        30000

Preferences preferences;
BLECharacteristic *pCharacteristic;

bool devicePaired = false;
uint8_t masterSecret[MASTER_SECRET_LEN];
uint8_t authKey[AUTH_KEY_LEN];
uint8_t tokenId[TOKEN_ID_LEN];

// Single-use challenge for the current BLE session (prevents replay)
uint8_t tokenNonce[NONCE_LEN];
bool challengeActive = false;

int authFailures = 0;
unsigned long lockoutUntil = 0;

// Last USB pairing reply, re-sent if the host repeats the same request
String lastPairRequest = "";
String lastPairReply = "";

// --- LED STATUS PATTERNS ---
// Count tells you what happened, length tells you good (short) or bad (long):
//   Boot window (hold IO0 now)  short blink every 0.5 s for 3 s
//   Ready, paired               1 short
//   Ready, unpaired             2 short
//   Pairing success             3 short
//   Key served                  2 very fast
//   Auth failure                1 long
//   Pairing refused             2 long
//   Lockout engaged             3 long
//   Factory reset               10 rapid
#define PAT_SHORT_MS 150
#define PAT_LONG_MS  600

// Blocking flash, only used in setup() before BLE is running
void flashLED(int times, int delayMs) {
    for (int i = 0; i < times; i++) {
        digitalWrite(LED_PIN, HIGH); // HIGH = ON for Pin 4
        delay(delayMs);
        digitalWrite(LED_PIN, LOW);  // LOW = OFF
        if (i < times - 1) delay(delayMs);
    }
}

// Non-blocking patterns: queued from anywhere (including BLE callbacks) and
// played by updateLED() in loop(), so the BLE stack is never stalled by delay().
volatile uint8_t ledToggles = 0;
volatile uint16_t ledOnMs = 0, ledOffMs = 0;
bool ledIsOn = false;
unsigned long ledNextMs = 0;

void playPattern(uint8_t count, uint16_t onMs, uint16_t offMs) {
    ledOnMs = onMs;
    ledOffMs = offMs;
    ledIsOn = false;
    ledNextMs = millis();
    ledToggles = count * 2;
}

void updateLED() {
    if (!ledToggles || (long)(millis() - ledNextMs) < 0) return;
    ledIsOn = !ledIsOn;
    digitalWrite(LED_PIN, ledIsOn ? HIGH : LOW);
    ledNextMs = millis() + (ledIsOn ? ledOnMs : ledOffMs);
    ledToggles--;
}

bool loadSecrets() {
    if (!preferences.getBool("paired", false)) return false;
    return preferences.getBytes("master", masterSecret, MASTER_SECRET_LEN) == MASTER_SECRET_LEN &&
           preferences.getBytes("auth_key", authKey, AUTH_KEY_LEN) == AUTH_KEY_LEN &&
           preferences.getBytes("token_id", tokenId, TOKEN_ID_LEN) == TOKEN_ID_LEN;
}

void sendError(uint8_t code) {
    uint8_t msg[2] = { MSG_ERROR, code };
    pCharacteristic->setValue(msg, sizeof(msg));
    pCharacteristic->notify();
    pCharacteristic->setValue((uint8_t *)"", 0);
}

void handleHello() {
    secureRandom(tokenNonce, NONCE_LEN);
    challengeActive = true;

    uint8_t msg[1 + NONCE_LEN + TOKEN_ID_LEN];
    msg[0] = MSG_CHALLENGE;
    memcpy(msg + 1, tokenNonce, NONCE_LEN);
    memcpy(msg + 1 + NONCE_LEN, tokenId, TOKEN_ID_LEN);
    pCharacteristic->setValue(msg, sizeof(msg));
    pCharacteristic->notify();
    pCharacteristic->setValue((uint8_t *)"", 0);
}

void recordAuthFailure() {
    authFailures++;
    Serial.printf("[SEC] Rejected BLE request (%d/%d failures)\n", authFailures, MAX_AUTH_FAILURES);
    if (authFailures >= MAX_AUTH_FAILURES) {
        lockoutUntil = millis() + LOCKOUT_MS;
        authFailures = 0;
        Serial.println("[SEC] Too many failures. Token locked for 30 s.");
        playPattern(3, PAT_LONG_MS, 300);
    } else {
        playPattern(1, PAT_LONG_MS, 0);
    }
}

void handleRequest(const uint8_t *data, size_t len) {
    if (!challengeActive) {
        sendError(ERR_NO_CHALLENGE);
        return;
    }
    // The challenge is consumed by this attempt whether it succeeds or not
    challengeActive = false;

    if (len != REQUEST_LEN) {
        sendError(ERR_BAD_FORMAT);
        return;
    }

    const uint8_t *hostNonce = data + 1;
    const uint8_t *reqIv     = hostNonce + NONCE_LEN;
    const uint8_t *reqCt     = reqIv + GCM_IV_LEN;
    const uint8_t *reqTag    = reqCt + REQ_PLAIN_LEN;

    uint8_t sessionKey[SHA256_LEN];
    hmacSha256(authKey, AUTH_KEY_LEN, "3T-SK-v1",
               tokenNonce, NONCE_LEN, hostNonce, NONCE_LEN, sessionKey);

    uint8_t aad[9 + TOKEN_ID_LEN];
    memcpy(aad, "3T-REQ-v1", 9);
    memcpy(aad + 9, tokenId, TOKEN_ID_LEN);

    uint8_t plain[REQ_PLAIN_LEN];
    if (!gcmDecrypt(sessionKey, reqIv, aad, sizeof(aad), reqCt, REQ_PLAIN_LEN, reqTag, plain)) {
        // Host does not hold the auth key paired over USB: impostor or stale pairing
        secureWipe(sessionKey, sizeof(sessionKey));
        recordAuthFailure();
        sendError(ERR_AUTH_FAILED);
        return;
    }
    authFailures = 0;

    uint8_t op = plain[0];
    const uint8_t *envHash = plain + 1;

    uint8_t respPlain[1 + SHA256_LEN];
    respPlain[0] = 0x00; // status OK
    if (op == OP_DERIVE) {
        hmacSha256(masterSecret, MASTER_SECRET_LEN, "3T-ENV-v1",
                   envHash, SHA256_LEN, NULL, 0, respPlain + 1);
    } else if (op == OP_PING) {
        memset(respPlain + 1, 0, SHA256_LEN);
    } else {
        secureWipe(sessionKey, sizeof(sessionKey));
        secureWipe(plain, sizeof(plain));
        sendError(ERR_BAD_FORMAT);
        return;
    }

    uint8_t msg[1 + GCM_IV_LEN + sizeof(respPlain) + GCM_TAG_LEN];
    msg[0] = MSG_RESPONSE;
    uint8_t *respIv  = msg + 1;
    uint8_t *respCt  = respIv + GCM_IV_LEN;
    uint8_t *respTag = respCt + sizeof(respPlain);
    secureRandom(respIv, GCM_IV_LEN);

    memcpy(aad, "3T-RSP-v1", 9);
    gcmEncrypt(sessionKey, respIv, aad, sizeof(aad), respPlain, sizeof(respPlain), respCt, respTag);

    pCharacteristic->setValue(msg, sizeof(msg));
    pCharacteristic->notify();
    pCharacteristic->setValue((uint8_t *)"", 0);

    secureWipe(sessionKey, sizeof(sessionKey));
    secureWipe(plain, sizeof(plain));
    secureWipe(respPlain, sizeof(respPlain));

    if (op == OP_DERIVE) {
        Serial.println("[BLE] Authenticated key request served.");
        playPattern(2, 50, 80);
    } else {
        Serial.println("[BLE] Authenticated ping served.");
    }
}

class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
        Serial.println("[BLE] Host connected wirelessly.");
    }
    void onDisconnect(BLEServer* pServer) {
        challengeActive = false;
        secureWipe(tokenNonce, NONCE_LEN);
        Serial.println("[BLE] Host disconnected. Restarting advertising...");
        pServer->getAdvertising()->start();
    }
};

class MyCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pCharacteristic) {
        std::string value = pCharacteristic->getValue();
        if (value.empty()) return;
        const uint8_t *data = (const uint8_t *)value.data();
        size_t len = value.length();

        if (!devicePaired) {
            sendError(ERR_NOT_PAIRED);
            return;
        }
        if (lockoutUntil && (long)(lockoutUntil - millis()) > 0) {
            sendError(ERR_LOCKED_OUT);
            return;
        }
        lockoutUntil = 0;

        if (data[0] == MSG_HELLO && len == 1) {
            handleHello();
        } else if (data[0] == MSG_REQUEST) {
            handleRequest(data, len);
        } else {
            sendError(ERR_BAD_FORMAT);
        }
    }
};

bool isValidField(const String &s, unsigned int maxLen) {
    if (s.length() == 0 || s.length() > maxLen) return false;
    for (unsigned int i = 0; i < s.length(); i++) {
        if (!isalnum((unsigned char)s[i])) return false;
    }
    return true;
}

// PAIR_DEVICE:<host_id>:<request_id>
// The host repeats the command until the token answers, so a repeated
// request_id gets the same reply instead of rotating the auth key again.
void handlePairCommand(const String &args) {
    int sep = args.indexOf(':');
    String hostID = sep >= 0 ? args.substring(0, sep) : args;
    String reqID  = sep >= 0 ? args.substring(sep + 1) : "";

    if (!isValidField(hostID, 32) || !isValidField(reqID, 32)) {
        Serial.println("PAIRING_REFUSED;REASON=BAD_FORMAT");
        return;
    }
    if (reqID == lastPairRequest && lastPairReply.length() > 0) {
        Serial.println(lastPairReply);
        return;
    }

    // A token bound to another host must be factory reset (destroying its
    // master secret) before it can be bound again.
    if (devicePaired && preferences.getString("host_id", "") != hostID) {
        lastPairRequest = reqID;
        lastPairReply = "PAIRING_REFUSED;REQ=" + reqID + ";REASON=BOUND_TO_OTHER_HOST";
        Serial.println(lastPairReply);
        playPattern(2, PAT_LONG_MS, 300);
        return;
    }

    // The master secret is created once and survives re-pairing with the same
    // host, so files encrypted earlier stay recoverable.
    if (preferences.getBytes("master", masterSecret, MASTER_SECRET_LEN) != MASTER_SECRET_LEN) {
        secureRandom(masterSecret, MASTER_SECRET_LEN);
        secureRandom(tokenId, TOKEN_ID_LEN);
        preferences.putBytes("master", masterSecret, MASTER_SECRET_LEN);
        preferences.putBytes("token_id", tokenId, TOKEN_ID_LEN);
        Serial.println("[HW] Generated new master secret from hardware RNG.");
    } else {
        preferences.getBytes("token_id", tokenId, TOKEN_ID_LEN);
    }

    // A fresh auth key on every pairing invalidates any older host config
    secureRandom(authKey, AUTH_KEY_LEN);
    preferences.putBytes("auth_key", authKey, AUTH_KEY_LEN);
    preferences.putString("host_id", hostID);
    preferences.putBool("paired", true);
    devicePaired = true;
    challengeActive = false;
    authFailures = 0;

    std::string mac = BLEDevice::getAddress().toString();

    lastPairRequest = reqID;
    lastPairReply = "PAIRING_SUCCESS;REQ=" + reqID +
                    ";TOKEN_ID=" + toHex(tokenId, TOKEN_ID_LEN) +
                    ";AUTH_KEY=" + toHex(authKey, AUTH_KEY_LEN) +
                    ";BLE_MAC=" + String(mac.c_str()) +
                    ";CHAR_UUID=" + String(CHARACTERISTIC_UUID) +
                    ";FW=" + String(FIRMWARE_VERSION);
    Serial.println(lastPairReply);

    playPattern(3, PAT_SHORT_MS, PAT_SHORT_MS);
}

void setup() {
    Serial.begin(115200);

    // Initialize LED Pin and turn it OFF to start
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    pinMode(0, INPUT_PULLUP);

    Serial.println("\n--- 3T Token Booting ---");

    bool factoryResetTriggered = false;

    // Grace period: 3 seconds scanning for the IO0 button, with a short blink
    // every 0.5 s to show the factory-reset window is open
    for (int i = 0; i < 30; i++) {
        digitalWrite(LED_PIN, (i % 5 == 0) ? HIGH : LOW);
        if (digitalRead(0) == LOW) {
            factoryResetTriggered = true;
            break;
        }
        delay(100);
    }
    digitalWrite(LED_PIN, LOW);

    preferences.begin("3t_storage", false);

    if (factoryResetTriggered) {
        // Destroys the master secret: every file encrypted with this token
        // becomes permanently unrecoverable.
        Serial.println("[HW] Factory Reset triggered! Wiping all secrets...");
        preferences.clear();
        devicePaired = false;
        flashLED(10, 40);
    } else {
        devicePaired = loadSecrets();
        if (devicePaired) {
            Serial.println("[HW] Restored state: Token is ALREADY bound to host from NVS flash.");
        } else {
            Serial.println("[HW] Token is UNPAIRED. Waiting for USB handshake...");
        }
    }

    // Initialize BLE with V4 name to bypass Windows cache
    BLEDevice::init("3T-Token-v4");
    // Protocol messages are up to 78 bytes, above the 20-byte default payload
    BLEDevice::setMTU(185);
    BLEServer *pServer = BLEDevice::createServer();
    pServer->setCallbacks(new MyServerCallbacks());

    BLEService *pService = pServer->createService(SERVICE_UUID);
    // No READ property: responses are only delivered by notification and
    // cleared straight after, so nothing lingers on the characteristic.
    pCharacteristic = pService->createCharacteristic(
                        CHARACTERISTIC_UUID,
                        BLECharacteristic::PROPERTY_WRITE  |
                        BLECharacteristic::PROPERTY_NOTIFY
                      );

    pCharacteristic->addDescriptor(new BLE2902());
    pCharacteristic->setCallbacks(new MyCallbacks());
    pService->start();

    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);
    pAdvertising->setMinPreferred(0x12);
    pAdvertising->start();

    Serial.println("BLE Server is running. Waiting for connections...");

    // Ready: 1 short flash if paired, 2 if waiting for USB pairing
    playPattern(devicePaired ? 1 : 2, PAT_SHORT_MS, PAT_SHORT_MS);
}

void loop() {
    updateLED();

    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();

        if (command.startsWith("PAIR_DEVICE:")) {
            handlePairCommand(command.substring(12));
        }
    }
}
