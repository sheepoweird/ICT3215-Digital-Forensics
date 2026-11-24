#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>
#include <atomic>
#include <map>
#include <mutex>
#include <esp_system.h>
#include <mbedtls/sha256.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

#include "encryption.h"

#define SERVICE_UUID        "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define CHARACTERISTIC_UUID "beb5483f-36e1-4688-b7f5-ea07361b26a8"
#define FIRMWARE_VERSION    8

// Pairing must be confirmed by pressing IO0 within this long, so nothing can re-pair
// the token silently while it is plugged in.
#define PAIR_CONFIRM_MS     60000
// Factory reset needs IO0 held this long during the boot window (a quick tap is ignored,
// so pressing IO0 to confirm pairing can never wipe the token by accident).
#define FACTORY_HOLD_MS     2000

// --- ESP32-CAM FLASH LED CONFIGURATION ---
// Pin 4 is the bright white LED on the front. Uses standard logic (HIGH = ON).
#define LED_PIN 4

// --- BLE PROTOCOL (must match Python/token_comms.py) ---
// Host  -> Token  HELLO     : 0x10
// Token -> Host   CHALLENGE : 0x11 | token_nonce[16] | token_id[16]
// Host  -> Token  REQUEST   : 0x20 | host_nonce[16] | iv[12] | ct | tag[16]
// Token -> Host   RESPONSE  : 0x21 | iv[12] | ct | tag[16]
// Token -> Host   ERROR     : 0x7F | code
//
// session_key = HMAC(auth_key, "3T-SK-v1" | token_nonce | host_nonce)
// REQUEST plaintext  = op | context (32, 48, 64 or 96 bytes)      (AAD = "3T-REQ-v1" | token_id)
// RESPONSE plaintext = status | data (32 bytes, or 48 for mint/import batch) (AAD = "3T-RSP-v1" | token_id)
// env_key (DERIVE)   = HMAC(master_secret, "3T-ENV-v1" | env_hash)
#define MSG_HELLO      0x10
#define MSG_CHALLENGE  0x11
#define MSG_REQUEST    0x20
#define MSG_RESPONSE   0x21
#define MSG_ERROR      0x7F

#define OP_DERIVE      0x01
#define OP_PING        0x02
// New opcodes make older firmware fail closed on vault requests.
#define OP_VAULT_OPEN   0x13
#define OP_VAULT_MINT   0x14
#define OP_EXPORT_BEGIN 0x15
#define OP_EXPORT_NEXT  0x16

#define OP_IMPORT_BATCH 0x17
#define OP_EXPORT_CHILD 0x18

// These domains are independent of v7's single-file derivation.
void deriveBatchSecret(const uint8_t *master, const uint8_t *vaultContext,
                       const uint8_t *batchId, uint8_t *out) {
    hmacSha256(master, MASTER_SECRET_LEN, "3T-VAULT-BATCH-v1",
               vaultContext, SHA256_LEN, batchId, 16, out);
}

#define ERR_NOT_PAIRED   0x01
#define ERR_NO_CHALLENGE 0x02
#define ERR_AUTH_FAILED  0x03
#define ERR_BAD_FORMAT   0x04
#define ERR_INTERNAL     0x06
#define ERR_FILE_TIMEOUT 0x07

#define REQ_PLAIN_LEN  (1 + SHA256_LEN)
#define REQUEST_LEN    (1 + NONCE_LEN + GCM_IV_LEN + REQ_PLAIN_LEN + GCM_TAG_LEN)

// Close only the connection responsible for repeated authentication failures.
#define MAX_AUTH_FAILURES 5

Preferences preferences;
BLECharacteristic *pCharacteristic;
BLEServer *bleServer;
esp_gatt_if_t gattInterface = ESP_GATT_IF_NONE;

std::atomic<bool> devicePaired{false};
bool storageHealthy = false;
uint8_t masterSecret[MASTER_SECRET_LEN];
uint8_t authKey[AUTH_KEY_LEN];
uint8_t tokenId[TOKEN_ID_LEN];

struct BleSession {
    uint8_t nonce[NONCE_LEN] = {};
    bool challengeActive = false;
    unsigned int failures = 0;
    uint8_t exportCursor[SHA256_LEN] = {};  // Zero denotes no remaining selection.

};
std::map<uint16_t, BleSession> bleSessions;
std::mutex bleMutex;

struct FileApproval {
    bool active = false;
    bool released = false;
    uint16_t connection = 0;
    uint8_t operation = 0;
    unsigned long deadline = 0;
    uint8_t sessionKey[SHA256_LEN] = {};
    uint8_t context[SHA256_LEN] = {};
};
FileApproval fileApproval;

void clearFileApproval() {
    secureWipe(fileApproval.sessionKey, sizeof(fileApproval.sessionKey));
    secureWipe(fileApproval.context, sizeof(fileApproval.context));
    fileApproval.active = false;
}

// Last USB pairing reply, re-sent if the host repeats the same request
String lastPairRequest = "";
String lastPairReply = "";
uint8_t lastPairPcPub[X25519_LEN];

// A pairing request waiting for the user to press IO0
enum class PairState { Idle, Proving, Confirming };
PairState pairState = PairState::Idle;
String pendingReq = "";
uint8_t pendingPcPub[X25519_LEN];
uint8_t pendingPairNonce[NONCE_LEN];
unsigned long pairDeadline = 0;
bool pairButtonReleased = false;

// --- LED STATUS PATTERNS ---
// Count tells you what happened, length tells you good (short) or bad (long):
//   Boot window (hold IO0 2 s)  short blink every 0.5 s for 3 s
//   Confirm pairing/file action solid ON until IO0 is pressed (up to 60 s)
//   Ready, paired               1 short
//   Ready, unpaired             2 short
//   Pairing success             3 short
//   Key served                  2 very fast
//   Auth failure                1 long
//   Pairing refused             2 long
//   Failing BLE link closed     3 long
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
    if (pairState == PairState::Confirming) {
        digitalWrite(LED_PIN, HIGH);
        return;
    }
    if (!ledToggles || (long)(millis() - ledNextMs) < 0) return;
    ledIsOn = !ledIsOn;
    digitalWrite(LED_PIN, ledIsOn ? HIGH : LOW);
    ledNextMs = millis() + (ledIsOn ? ledOnMs : ledOffMs);
    ledToggles--;
}

bool loadSecrets() {
    if (preferences.isKey("credentials_v5")) {
        uint8_t stored[MASTER_SECRET_LEN + AUTH_KEY_LEN + TOKEN_ID_LEN];
        storageHealthy = preferences.getBytes("credentials_v5", stored, sizeof(stored)) == sizeof(stored);
        if (storageHealthy) {
            memcpy(masterSecret, stored, MASTER_SECRET_LEN);
            memcpy(authKey, stored + MASTER_SECRET_LEN, AUTH_KEY_LEN);
            memcpy(tokenId, stored + MASTER_SECRET_LEN + AUTH_KEY_LEN, TOKEN_ID_LEN);
        }
        secureWipe(stored, sizeof(stored));
        return storageHealthy;
    }
    // Preserve already enrolled v3/v4 tokens and the files derived from their master key.
    if (!preferences.getBool("paired", false)) {
        storageHealthy = !preferences.isKey("master") && !preferences.isKey("auth_key") &&
                         !preferences.isKey("token_id");
        return false;
    }
    storageHealthy = preferences.getBytes("master", masterSecret, MASTER_SECRET_LEN) == MASTER_SECRET_LEN &&
                     preferences.getBytes("auth_key", authKey, AUTH_KEY_LEN) == AUTH_KEY_LEN &&
                     preferences.getBytes("token_id", tokenId, TOKEN_ID_LEN) == TOKEN_ID_LEN;
    return storageHealthy;
}

void sendToLink(uint16_t connId, uint8_t *data, size_t len) {
    esp_ble_gatts_send_indicate(gattInterface, connId, pCharacteristic->getHandle(), len, data, false);
}

void sendError(uint16_t connId, uint8_t code) {
    uint8_t msg[2] = { MSG_ERROR, code };
    sendToLink(connId, msg, sizeof(msg));
}

void handleHello(uint16_t connId, BleSession &session) {
    if (fileApproval.active && fileApproval.connection == connId) clearFileApproval();
    secureRandom(session.nonce, NONCE_LEN);
    session.challengeActive = true;

    uint8_t msg[1 + NONCE_LEN + TOKEN_ID_LEN];
    msg[0] = MSG_CHALLENGE;
    memcpy(msg + 1, session.nonce, NONCE_LEN);
    memcpy(msg + 1 + NONCE_LEN, tokenId, TOKEN_ID_LEN);
    sendToLink(connId, msg, sizeof(msg));
}

void recordAuthFailure(uint16_t connId, BleSession &session) {
    session.failures++;
    Serial.printf("[SEC] Rejected BLE request (%u/%d failures on this link)\n", session.failures, MAX_AUTH_FAILURES);
    sendError(connId, ERR_AUTH_FAILED);
    if (session.failures >= MAX_AUTH_FAILURES) {
        bleServer->disconnect(connId);
        playPattern(3, PAT_LONG_MS, 300);
    } else {
        playPattern(1, PAT_LONG_MS, 0);
    }
}

void handleRequest(uint16_t connId, BleSession &session, const uint8_t *data, size_t len) {
    if (!session.challengeActive) {
        sendError(connId, ERR_NO_CHALLENGE);
        return;
    }
    // The challenge is consumed by this attempt whether it succeeds or not
    session.challengeActive = false;

    if (len != REQUEST_LEN && len != REQUEST_LEN + 16 && len != REQUEST_LEN + SHA256_LEN &&
            len != REQUEST_LEN + 2 * SHA256_LEN) {
        sendError(connId, ERR_BAD_FORMAT);
        return;
    }

    const uint8_t *hostNonce = data + 1;
    const uint8_t *reqIv     = hostNonce + NONCE_LEN;
    const uint8_t *reqCt     = reqIv + GCM_IV_LEN;
    const size_t plainLen = len - REQUEST_LEN + REQ_PLAIN_LEN;
    const uint8_t *reqTag = reqCt + plainLen;

    uint8_t sessionKey[SHA256_LEN];
    hmacSha256(authKey, AUTH_KEY_LEN, "3T-SK-v1",
               session.nonce, NONCE_LEN, hostNonce, NONCE_LEN, sessionKey);

    uint8_t aad[9 + TOKEN_ID_LEN];
    memcpy(aad, "3T-REQ-v1", 9);
    memcpy(aad + 9, tokenId, TOKEN_ID_LEN);

    uint8_t plain[REQ_PLAIN_LEN + 2 * SHA256_LEN];
    if (!gcmDecrypt(sessionKey, reqIv, aad, sizeof(aad), reqCt, plainLen, reqTag, plain)) {
        // Host does not hold the auth key paired over USB: impostor or stale pairing
        secureWipe(sessionKey, sizeof(sessionKey));
        recordAuthFailure(connId, session);
        return;
    }
    session.failures = 0;

    uint8_t op = plain[0];
    const uint8_t *envHash = plain + 1;

    size_t expected = REQ_PLAIN_LEN;
    if (op == OP_VAULT_MINT) expected += 16;
    if (op == OP_EXPORT_NEXT) expected += SHA256_LEN;
    if (op == OP_EXPORT_CHILD) expected += 2 * SHA256_LEN;
    if (plainLen != expected) {
        secureWipe(sessionKey, sizeof(sessionKey));
        secureWipe(plain, sizeof(plain));
        sendError(connId, ERR_BAD_FORMAT);
        return;
    }

    uint8_t respPlain[1 + 16 + SHA256_LEN] = {};
    size_t responseLen = 1 + SHA256_LEN;
    respPlain[0] = 0x00; // status OK
    if (op == OP_DERIVE) {
        hmacSha256(masterSecret, MASTER_SECRET_LEN, "3T-ENV-v1",
                   envHash, SHA256_LEN, NULL, 0, respPlain + 1);
    } else if (op == OP_PING) {
        memset(respPlain + 1, 0, SHA256_LEN);
    } else if (op == OP_VAULT_MINT) {
        // A caller may choose the vault, but only the token chooses the new blob ID.
        constexpr char domain[] = "EnvVault-v2";
        constexpr size_t prefixLen = sizeof(domain) - 1;
        constexpr size_t vaultContextLen = 16 + SHA256_LEN;
        uint8_t material[prefixLen + vaultContextLen + 16];
        memcpy(material, domain, prefixLen);
        memcpy(material + prefixLen, envHash, vaultContextLen);
        secureRandom(respPlain + 1, 16);
        memcpy(material + prefixLen + vaultContextLen, respPlain + 1, 16);
        uint8_t context[SHA256_LEN];
        if (mbedtls_sha256_ret(material, sizeof(material), context, 0) != 0) {
            secureWipe(sessionKey, sizeof(sessionKey));
            secureWipe(plain, sizeof(plain));
            sendError(connId, ERR_INTERNAL);
            return;
        }
        hmacSha256(masterSecret, MASTER_SECRET_LEN, "3T-VAULT-FILE-v2",
                   context, sizeof(context), nullptr, 0, respPlain + 17);
        responseLen += 16;
    } else if (op == OP_IMPORT_BATCH) {
        // The token chooses the batch ID. The host cannot ask to remint an existing batch.
        secureRandom(respPlain + 1, 16);
        deriveBatchSecret(masterSecret, envHash, respPlain + 1, respPlain + 17);
        responseLen += 16;
    } else if (op == OP_EXPORT_NEXT || op == OP_EXPORT_CHILD) {
        // Each approved link commits to this file context and the remaining suffix.
        const uint8_t empty[SHA256_LEN] = {};
        uint8_t digest[SHA256_LEN];
        if (!memcmp(session.exportCursor, empty, SHA256_LEN) ||
                mbedtls_sha256_ret(envHash, plainLen - 1, digest, 0) != 0 ||
                memcmp(session.exportCursor, digest, SHA256_LEN)) {
            secureWipe(session.exportCursor, SHA256_LEN);
            secureWipe(sessionKey, sizeof(sessionKey));
            secureWipe(plain, sizeof(plain));
            sendError(connId, ERR_BAD_FORMAT);
            return;
        }
        memcpy(session.exportCursor, plain + plainLen - SHA256_LEN, SHA256_LEN);
        if (op == OP_EXPORT_CHILD) {
            // context = vault context (32) | batch ID (16) | selected file ID (16).
            uint8_t batch[SHA256_LEN];
            deriveBatchSecret(masterSecret, envHash, envHash + SHA256_LEN, batch);
            hmacSha256(batch, sizeof(batch), "3T-VAULT-CHILD-v1",
                       envHash + SHA256_LEN + 16, 16, nullptr, 0, respPlain + 1);
            secureWipe(batch, sizeof(batch));
        } else {
            hmacSha256(masterSecret, MASTER_SECRET_LEN, "3T-VAULT-FILE-v2",
                       envHash, SHA256_LEN, nullptr, 0, respPlain + 1);
        }
    } else if (op == OP_VAULT_OPEN || op == OP_EXPORT_BEGIN) {
        secureWipe(session.exportCursor, SHA256_LEN);
        if (fileApproval.active || pairState != PairState::Idle) {
            secureWipe(sessionKey, sizeof(sessionKey));
            secureWipe(plain, sizeof(plain));
            sendError(connId, ERR_INTERNAL);
            return;
        }
        fileApproval.operation = op;
        fileApproval.connection = connId;
        fileApproval.deadline = millis() + 60000;
        fileApproval.released = digitalRead(0) != LOW;
        memcpy(fileApproval.sessionKey, sessionKey, SHA256_LEN);
        memcpy(fileApproval.context, envHash, SHA256_LEN);
        fileApproval.active = true;
        // Signal that this connection must now wait for a fresh physical press.
        respPlain[0] = 0x01;
        memset(respPlain + 1, 0, SHA256_LEN);
        Serial.println(op == OP_VAULT_OPEN ? "[VAULT] Confirm opening the list with IO0." :
                                           "[VAULT] Confirm selected export with IO0.");
    } else {
        secureWipe(sessionKey, sizeof(sessionKey));
        secureWipe(plain, sizeof(plain));
        sendError(connId, ERR_BAD_FORMAT);
        return;
    }

    uint8_t msg[1 + GCM_IV_LEN + sizeof(respPlain) + GCM_TAG_LEN];
    msg[0] = MSG_RESPONSE;
    uint8_t *respIv  = msg + 1;
    uint8_t *respCt  = respIv + GCM_IV_LEN;
    uint8_t *respTag = respCt + responseLen;
    secureRandom(respIv, GCM_IV_LEN);

    memcpy(aad, "3T-RSP-v1", 9);
    bool encrypted = gcmEncrypt(sessionKey, respIv, aad, sizeof(aad), respPlain, responseLen, respCt, respTag);

    secureWipe(sessionKey, sizeof(sessionKey));
    secureWipe(plain, sizeof(plain));
    secureWipe(respPlain, sizeof(respPlain));
    if (!encrypted) {
        sendError(connId, ERR_INTERNAL);
        return;
    }
    sendToLink(connId, msg, 1 + GCM_IV_LEN + responseLen + GCM_TAG_LEN);

    if (op == OP_DERIVE) {
        Serial.println("[BLE] Authenticated key request served.");
        playPattern(2, 50, 80);
    } else if (op == OP_PING) {
        Serial.println("[BLE] Authenticated ping served.");
    }
}

class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer*, esp_ble_gatts_cb_param_t *param) override {
        std::lock_guard<std::mutex> guard(bleMutex);
        bleSessions[param->connect.conn_id] = BleSession{};
        Serial.println("[BLE] Host connected wirelessly.");
    }
    void onDisconnect(BLEServer* pServer, esp_ble_gatts_cb_param_t *param) override {
        std::lock_guard<std::mutex> guard(bleMutex);
        if (fileApproval.active && fileApproval.connection == param->disconnect.conn_id) clearFileApproval();
        bleSessions.erase(param->disconnect.conn_id);
        Serial.println("[BLE] Host disconnected. Restarting advertising...");
        pServer->getAdvertising()->start();
    }
};

class MyCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *characteristic, esp_ble_gatts_cb_param_t *param) override {
        std::lock_guard<std::mutex> guard(bleMutex);
        // conn_id is the first field for both normal and committed long writes.
        uint16_t connId = param->write.conn_id;
        auto session = bleSessions.find(connId);
        if (session == bleSessions.end()) return;
        std::string value = characteristic->getValue();
        if (value.empty()) return;
        const uint8_t *data = (const uint8_t *)value.data();
        size_t len = value.length();

        if (!devicePaired) {
            sendError(connId, ERR_NOT_PAIRED);
            return;
        }
        if (session->second.failures >= MAX_AUTH_FAILURES) return;

        if (data[0] == MSG_HELLO && len == 1) {
            handleHello(connId, session->second);
        } else if (data[0] == MSG_REQUEST) {
            handleRequest(connId, session->second, data, len);
        } else {
            sendError(connId, ERR_BAD_FORMAT);
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

void refusePairing(const String &req, const char *reason) {
    Serial.println("PAIRING_REFUSED;REQ=" + req + ";REASON=" + reason);
}

void clearPendingPairing() {
    pairState = PairState::Idle;
    pendingReq = "";
    secureWipe(pendingPcPub, sizeof(pendingPcPub));
    secureWipe(pendingPairNonce, sizeof(pendingPairNonce));
    digitalWrite(LED_PIN, LOW);
}

void sendPairingState() {
    if (pairState == PairState::Proving) {
        Serial.println("PAIRING_PROOF;REQ=" + pendingReq +
                       ";NONCE=" + toHex(pendingPairNonce, NONCE_LEN) +
                       ";TOKEN_ID=" + toHex(tokenId, TOKEN_ID_LEN));
    } else {
        Serial.println("PAIRING_PENDING;REQ=" + pendingReq + ";REASON=PRESS_BUTTON");
    }
}

void waitForButton() {
    pairState = PairState::Confirming;
    pairButtonReleased = digitalRead(0) != LOW;
    pairDeadline = millis() + PAIR_CONFIRM_MS;
    sendPairingState();
}

// PAIR_V5:<request_id>:<pc_pub>:<ENROLL|REPAIR>
void handlePairStart(const String &args) {
    if (fileApproval.active) {
        Serial.println("PAIRING_REFUSED;REASON=BUSY");
        return;
    }
    int separator = args.indexOf(':');
    int modeSeparator = (separator >= 0) ? args.indexOf(':', separator + 1) : -1;
    if (modeSeparator < 0) return;
    String req = args.substring(0, separator);
    String mode = args.substring(modeSeparator + 1);
    uint8_t pcPub[X25519_LEN];
    if (req.length() != 16 || !isValidField(req, 16) ||
        !fromHex(args.substring(separator + 1, modeSeparator), pcPub, X25519_LEN) ||
        (mode != "ENROLL" && mode != "REPAIR")) {
        refusePairing(req, "BAD_FORMAT");
        return;
    }
    if (req == lastPairRequest && memcmp(lastPairPcPub, pcPub, X25519_LEN) == 0) {
        Serial.println(lastPairReply);
        return;
    }
    if (!storageHealthy) {
        refusePairing(req, "STORAGE_ERROR");
        return;
    }
    const bool paired = devicePaired.load();
    if (paired != (mode == "REPAIR")) {
        refusePairing(req, paired ? "PROOF_REQUIRED" : "TOKEN_UNPAIRED");
        return;
    }
    if (pairState != PairState::Idle) {
        if (req == pendingReq && memcmp(pendingPcPub, pcPub, X25519_LEN) == 0) {
            sendPairingState();
        } else {
            refusePairing(req, "BUSY");
        }
        return;
    }

    pendingReq = req;
    memcpy(pendingPcPub, pcPub, X25519_LEN);
    if (paired) {
        pairState = PairState::Proving;
        pairDeadline = millis() + 10000;
        secureRandom(pendingPairNonce, NONCE_LEN);
        sendPairingState();
    } else {
        waitForButton();
    }
}

// PAIR_PROVE:<request_id>:<HMAC>. The transcript binds proof to this token,
// its one-time challenge, and the host's exact ephemeral public key.
void handlePairProof(const String &args) {
    int separator = args.indexOf(':');
    if (separator < 0) return;
    String req = args.substring(0, separator);
    if (!devicePaired || pairState == PairState::Idle || req != pendingReq) {
        refusePairing(req, "NO_PENDING");
        return;
    }
    uint8_t proof[SHA256_LEN];
    if (!fromHex(args.substring(separator + 1), proof, SHA256_LEN)) {
        refusePairing(req, "BAD_FORMAT");
        return;
    }
    uint8_t transcript[TOKEN_ID_LEN + NONCE_LEN + 16 + X25519_LEN];
    memcpy(transcript, tokenId, TOKEN_ID_LEN);
    memcpy(transcript + TOKEN_ID_LEN, pendingPairNonce, NONCE_LEN);
    memcpy(transcript + TOKEN_ID_LEN + NONCE_LEN, req.c_str(), 16);
    memcpy(transcript + TOKEN_ID_LEN + NONCE_LEN + 16, pendingPcPub, X25519_LEN);
    uint8_t expected[SHA256_LEN];
    hmacSha256(authKey, AUTH_KEY_LEN, "3T-PAIR-PROOF-v1",
               transcript, sizeof(transcript), nullptr, 0, expected);
    volatile uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(proof); ++i) difference |= proof[i] ^ expected[i];
    secureWipe(expected, sizeof(expected));
    secureWipe(proof, sizeof(proof));
    if (difference != 0) {
        refusePairing(req, "AUTH_FAILED");
        return;
    }
    if (pairState == PairState::Proving) {
        waitForButton();
    } else {
        sendPairingState();
    }
}

bool confirmButtonPressed() {
    if (digitalRead(0) != LOW) {
        pairButtonReleased = true;
        return false;
    }
    if (!pairButtonReleased) return false;
    delay(50);
    return digitalRead(0) == LOW;
}

void completePairing() {
    String req = pendingReq;
    uint8_t pcPub[X25519_LEN];
    memcpy(pcPub, pendingPcPub, X25519_LEN);
    clearPendingPairing();

    uint8_t tokPriv[X25519_LEN], tokPub[X25519_LEN], shared[X25519_LEN];
    bool exchanged = x25519Keypair(tokPriv, tokPub) && x25519Shared(tokPriv, pcPub, shared);
    secureWipe(tokPriv, sizeof(tokPriv));
    if (!exchanged) {
        secureWipe(shared, sizeof(shared));
        refusePairing(req, "CRYPTO_ERROR");
        return;
    }

    // Re-pairing refreshes the PC's config without rotating working credentials.
    const bool enrolling = !devicePaired.load();
    if (enrolling) {
        secureRandom(masterSecret, MASTER_SECRET_LEN);
        secureRandom(authKey, AUTH_KEY_LEN);
        secureRandom(tokenId, TOKEN_ID_LEN);
    }

    uint8_t aad[X25519_LEN + X25519_LEN + TOKEN_ID_LEN];
    memcpy(aad, pcPub, X25519_LEN);
    memcpy(aad + X25519_LEN, tokPub, X25519_LEN);
    memcpy(aad + 2 * X25519_LEN, tokenId, TOKEN_ID_LEN);
    uint8_t info[16 + sizeof(aad)];
    memcpy(info, "EnvStego-pair-v1", 16);
    memcpy(info + 16, aad, sizeof(aad));
    uint8_t wrapKey[AUTH_KEY_LEN];
    hkdfSha256(nullptr, 0, shared, sizeof(shared), info, sizeof(info), wrapKey, sizeof(wrapKey));
    secureWipe(shared, sizeof(shared));

    uint8_t enc[GCM_IV_LEN + AUTH_KEY_LEN + GCM_TAG_LEN];
    secureRandom(enc, GCM_IV_LEN);
    bool wrapped = gcmEncrypt(wrapKey, enc, aad, sizeof(aad), authKey, AUTH_KEY_LEN,
                              enc + GCM_IV_LEN, enc + GCM_IV_LEN + AUTH_KEY_LEN);
    secureWipe(wrapKey, sizeof(wrapKey));
    if (!wrapped) {
        refusePairing(req, "CRYPTO_ERROR");
        return;
    }

    // Commit new credentials as one NVS value only after the exchange and wrap succeed.
    if (enrolling) {
        uint8_t stored[MASTER_SECRET_LEN + AUTH_KEY_LEN + TOKEN_ID_LEN];
        memcpy(stored, masterSecret, MASTER_SECRET_LEN);
        memcpy(stored + MASTER_SECRET_LEN, authKey, AUTH_KEY_LEN);
        memcpy(stored + MASTER_SECRET_LEN + AUTH_KEY_LEN, tokenId, TOKEN_ID_LEN);
        storageHealthy = preferences.putBytes("credentials_v5", stored, sizeof(stored)) == sizeof(stored);
        secureWipe(stored, sizeof(stored));
        if (!storageHealthy) {
            refusePairing(req, "STORAGE_ERROR");
            return;
        }
        devicePaired = true;
    }

    std::string mac = BLEDevice::getAddress().toString();
    lastPairRequest = req;
    memcpy(lastPairPcPub, pcPub, X25519_LEN);
    lastPairReply = "PAIRING_SUCCESS;REQ=" + req + ";MODE=ECDH" +
                    ";TOKEN_ID=" + toHex(tokenId, TOKEN_ID_LEN) +
                    ";TOK_PUB=" + toHex(tokPub, X25519_LEN) +
                    ";ENC=" + toHex(enc, sizeof(enc)) +
                    ";BLE_MAC=" + String(mac.c_str()) +
                    ";CHAR_UUID=" + String(CHARACTERISTIC_UUID) +
                    ";FW=" + String(FIRMWARE_VERSION);
    Serial.println(lastPairReply);
    playPattern(3, PAT_SHORT_MS, PAT_SHORT_MS);
}

void setup() {
    // --- Brownout mitigation for the ESP32-CAM on weak USB power ---
    // The current spike when BLE starts can dip the supply below the brownout
    // threshold and reset the board in a loop. The detector is paused only for
    // start-up and switched back on at the end of setup(), once the lower CPU clock
    // and BLE TX power are in place. It must be on afterwards: pairing writes the
    // secrets to flash, and a dip mid-write with no detector could corrupt them.
    uint32_t brownoutReg = READ_PERI_REG(RTC_CNTL_BROWN_OUT_REG);
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);   // pause the detector for start-up
    setCpuFrequencyMhz(80);                       // ~half the current of 240 MHz

    Serial.begin(115200);

    // Initialize LED Pin and turn it OFF to start
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    pinMode(0, INPUT_PULLUP);

    Serial.println("\n--- 3T Token Booting ---");

    bool factoryResetTriggered = false;

    // Grace period: 3 seconds watching the IO0 button, with a short blink every 0.5 s
    // to show the factory-reset window is open. IO0 must be HELD for FACTORY_HOLD_MS:
    // a quick tap (e.g. someone pressing it early to confirm pairing) does nothing.
    int heldMs = 0;
    for (int i = 0; i < 30; i++) {
        digitalWrite(LED_PIN, (i % 5 == 0) ? HIGH : LOW);
        heldMs = (digitalRead(0) == LOW) ? heldMs + 100 : 0;
        if (heldMs >= FACTORY_HOLD_MS) {
            factoryResetTriggered = true;
            break;
        }
        delay(100);
    }
    digitalWrite(LED_PIN, LOW);

    storageHealthy = preferences.begin("3t_storage", false);

    if (factoryResetTriggered) {
        // Destroys the master secret: every file encrypted with this token
        // becomes permanently unrecoverable.
        Serial.println("[HW] Factory Reset triggered! Wiping all secrets...");
        storageHealthy = storageHealthy && preferences.clear();
        if (storageHealthy) flashLED(10, 40);
    } else if (storageHealthy) {
        devicePaired = loadSecrets();
        if (devicePaired) {
            Serial.println("[HW] Restored pairing credentials from NVS flash.");
        } else if (storageHealthy) {
            Serial.println("[HW] Token is UNPAIRED. Waiting for USB handshake...");
        }
    }
    if (!storageHealthy) Serial.println("[HW] Pairing storage could not be read or reset.");

    BLEDevice::init("3T-Token-v8");
    // Lower the radio TX power to cut the current spike that causes brownouts.
    // The PC pairs over USB first, so a shorter BLE range is an acceptable trade.
    BLEDevice::setPower(ESP_PWR_LVL_N9);
    // Protocol messages are up to 78 bytes, above the 20-byte default payload
    BLEDevice::setMTU(185);
    BLEDevice::setCustomGattsHandler([](esp_gatts_cb_event_t event, esp_gatt_if_t interface,
                                      esp_ble_gatts_cb_param_t *param) {
        if (event == ESP_GATTS_REG_EVT && param->reg.status == ESP_GATT_OK) gattInterface = interface;
    });
    bleServer = BLEDevice::createServer();
    bleServer->setCallbacks(new MyServerCallbacks());

    BLEService *pService = bleServer->createService(SERVICE_UUID);
    // No READ property. Replies are notifications addressed to the requesting link.
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

    // Start-up is over: switch the brownout detector back on (see the top of setup()).
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, brownoutReg);

    // Ready: 1 short flash if paired, 2 if waiting for USB pairing
    playPattern(devicePaired ? 1 : 2, PAT_SHORT_MS, PAT_SHORT_MS);
}

void loop() {
    std::lock_guard<std::mutex> guard(bleMutex);
    updateLED();

    if (fileApproval.active) {
        digitalWrite(LED_PIN, HIGH);
        if ((long)(millis() - fileApproval.deadline) >= 0) {
            sendError(fileApproval.connection, ERR_FILE_TIMEOUT);
            clearFileApproval();
            digitalWrite(LED_PIN, LOW);
        } else if (digitalRead(0) != LOW) {
            fileApproval.released = true;
        } else if (fileApproval.released) {
            delay(50);
            if (digitalRead(0) == LOW) {
                uint8_t response[1 + GCM_IV_LEN + 33 + GCM_TAG_LEN];
                uint8_t plain[33] = {};
                uint8_t aad[9 + TOKEN_ID_LEN];
                response[0] = MSG_RESPONSE;
                secureRandom(response + 1, GCM_IV_LEN);
                memcpy(aad, "3T-RSP-v1", 9);
                memcpy(aad + 9, tokenId, TOKEN_ID_LEN);
                if (fileApproval.operation == OP_VAULT_OPEN) {
                    hmacSha256(masterSecret, MASTER_SECRET_LEN, "3T-VAULT-META-v2",
                               fileApproval.context, SHA256_LEN, nullptr, 0, plain + 1);
                }
                bool encrypted = gcmEncrypt(fileApproval.sessionKey, response + 1, aad, sizeof(aad),
                                            plain, sizeof(plain), response + 1 + GCM_IV_LEN,
                                            response + 1 + GCM_IV_LEN + sizeof(plain));
                if (encrypted) {
                    if (fileApproval.operation == OP_EXPORT_BEGIN) {
                        memcpy(bleSessions[fileApproval.connection].exportCursor, fileApproval.context, SHA256_LEN);
                    }
                    sendToLink(fileApproval.connection, response, sizeof(response));
                } else {
                    sendError(fileApproval.connection, ERR_INTERNAL);
                }
                secureWipe(plain, sizeof(plain));
                clearFileApproval();
                digitalWrite(LED_PIN, LOW);
                playPattern(2, PAT_SHORT_MS, PAT_SHORT_MS);
            }
        }
    }

    if (pairState != PairState::Idle && (long)(millis() - pairDeadline) >= 0) {
        const char *reason = pairState == PairState::Proving ? "NO_PENDING" : "NOT_CONFIRMED";
        refusePairing(pendingReq, reason);
        clearPendingPairing();
        playPattern(2, PAT_LONG_MS, 300);
    }

    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();

        if (command.startsWith("PAIR_V5:")) {
            handlePairStart(command.substring(8));
        } else if (command.startsWith("PAIR_PROVE:")) {
            handlePairProof(command.substring(11));
        } else if (command.startsWith("PAIR_CANCEL:") && command.substring(12) == pendingReq) {
            clearPendingPairing();
        }
    }
    if (pairState == PairState::Confirming && confirmButtonPressed()) completePairing();
}
