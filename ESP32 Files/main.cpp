#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>
#include <esp_system.h>

#define SERVICE_UUID        "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

// --- LED CONFIGURATION ---
// Pin 4 is the bright Flash LED next to the SD Card slot
#define LED_PIN 4  

Preferences preferences;
bool devicePaired = false;
BLECharacteristic *pCharacteristic;

// Helper function to blink the LED
void flashLED(int times, int delayMs) {
    for (int i = 0; i < times; i++) {
        digitalWrite(LED_PIN, HIGH);
        delay(delayMs);
        digitalWrite(LED_PIN, LOW);
        if (i < times - 1) delay(delayMs);
    }
}

class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
        Serial.println("[BLE] Host connected wirelessly.");
    }
    void onDisconnect(BLEServer* pServer) {
        Serial.println("[BLE] Host disconnected. Restarting advertising...");
        pServer->getAdvertising()->start();
    }
};

class MyCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pCharacteristic) {
        std::string value = pCharacteristic->getValue();
        if (value.length() > 0) {
            String envData = String(value.c_str());
            Serial.print("[BLE] Received Environment Data: ");
            Serial.println(envData);

            if (!devicePaired) {
                pCharacteristic->setValue("ERROR: NOT_PAIRED");
                pCharacteristic->notify();
                return;
            }

            // Visual feedback: 2 fast flashes to prove BLE communication!
            flashLED(2, 50);

            // Generate deterministic key anchored by hardware secret + environment
            String finalKey = "3T_HARDWARE_ANCHOR_SECRET_778899-" + envData;
            
            pCharacteristic->setValue(finalKey.c_str());
            pCharacteristic->notify();
            Serial.println("[BLE] Secure key generated and sent back.");
        }
    }
};

void setup() {
    Serial.begin(115200);
    
    // Initialize LED Pin and BOOT button
    pinMode(LED_PIN, OUTPUT);
    pinMode(0, INPUT_PULLUP);

    // 1. Boot Indicator: Turn LED ON solid
    digitalWrite(LED_PIN, HIGH);
    Serial.println("\n--- 3T Token Booting ---");
    Serial.println("You have 3 seconds to press and hold the BOOT (IO0) button for a Factory Reset...");
    
    bool factoryResetTriggered = false;
    
    // 2. The Grace Period: Wait 3 seconds, scanning for the BOOT button
    for (int i = 0; i < 30; i++) {
        if (digitalRead(0) == LOW) {
            factoryResetTriggered = true;
            break;
        }
        delay(100);
    }
    
    digitalWrite(LED_PIN, LOW); // Turn off the boot indicator LED

    // 3. Process the Result
    preferences.begin("3t_storage", false);

    if (factoryResetTriggered) {
        Serial.println("[HW] Factory Reset triggered! Wiping pairing state...");
        preferences.clear(); 
        devicePaired = false;
        
        // Visual feedback: 10 rapid flashes
        flashLED(10, 40); 
    } else {
        devicePaired = preferences.getBool("paired", false);
        if (devicePaired) {
            Serial.println("[HW] Restored state: Token is ALREADY bound to host from NVS flash.");
            // Single short blink to show it's alive and paired
            flashLED(1, 100);
        } else {
            Serial.println("[HW] Token is UNPAIRED. Waiting for USB handshake...");
        }
    }

    // Initialize BLE
    BLEDevice::init("3T-Hardware-Token");
    BLEServer *pServer = BLEDevice::createServer();
    pServer->setCallbacks(new MyServerCallbacks());

    BLEService *pService = pServer->createService(SERVICE_UUID);
    pCharacteristic = pService->createCharacteristic(
                        CHARACTERISTIC_UUID,
                        BLECharacteristic::PROPERTY_READ   |
                        BLECharacteristic::PROPERTY_WRITE  |
                        BLECharacteristic::PROPERTY_NOTIFY
                      );

    pCharacteristic->addDescriptor(new BLE2902());
    pCharacteristic->setCallbacks(new MyCallbacks());
    pService->start();

    Serial.println("BLE Server is running. Waiting for connections...");
}

void loop() {
    // Handle Serial (USB) Pairing Command
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();

        if (command == "PAIR_DEVICE") {
            devicePaired = true;
            preferences.putBool("paired", true); // Save permanently to flash
            Serial.println("PAIRING_SUCCESS: 3T-Hardware-Token is now bound to this host.");
            
            // Visual feedback: 3 flashes for successful wired pairing
            flashLED(3, 150);
        } 
        else if (command == "CHECK_STATUS") {
            if (devicePaired) {
                Serial.println("STATUS: PAIRED");
            } else {
                Serial.println("STATUS: UNPAIRED");
            }
        }
    }
}