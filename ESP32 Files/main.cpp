#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>
#include <esp_system.h>

#define SERVICE_UUID        "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

// --- ESP32-CAM FLASH LED CONFIGURATION ---
// Pin 4 is the bright white LED on the front. Uses standard logic (HIGH = ON).
#define LED_PIN 4  

Preferences preferences;
bool devicePaired = false;
BLECharacteristic *pCharacteristic;

void flashLED(int times, int delayMs) {
    for (int i = 0; i < times; i++) {
        digitalWrite(LED_PIN, HIGH); // HIGH = ON for Pin 4
        delay(delayMs);
        digitalWrite(LED_PIN, LOW);  // LOW = OFF
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

            // Visual feedback: 2 fast white flashes
            flashLED(2, 50);

            String finalKey = "3T_HARDWARE_ANCHOR_SECRET_778899-" + envData;
            pCharacteristic->setValue(finalKey.c_str());
            pCharacteristic->notify();
            Serial.println("[BLE] Secure key generated and sent back.");
        }
    }
};

void setup() {
    Serial.begin(115200);
    
    // Initialize LED Pin and turn it OFF to start
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    pinMode(0, INPUT_PULLUP);

    // 1. Boot Indicator: Turn white LED ON solid
    digitalWrite(LED_PIN, HIGH);
    Serial.println("\n--- 3T Token Booting ---");
    
    bool factoryResetTriggered = false;
    
    // 2. The Grace Period: Wait 3 seconds, scanning for the IO0 button
    for (int i = 0; i < 30; i++) {
        if (digitalRead(0) == LOW) {
            factoryResetTriggered = true;
            break;
        }
        delay(100);
    }
    
    // Turn off the boot indicator LED
    digitalWrite(LED_PIN, LOW); 

    preferences.begin("3t_storage", false);

    if (factoryResetTriggered) {
        Serial.println("[HW] Factory Reset triggered! Wiping pairing state...");
        preferences.clear(); 
        devicePaired = false;
        flashLED(10, 40); 
    } else {
        devicePaired = preferences.getBool("paired", false);
        if (devicePaired) {
            Serial.println("[HW] Restored state: Token is ALREADY bound to host from NVS flash.");
            flashLED(1, 100);
        } else {
            Serial.println("[HW] Token is UNPAIRED. Waiting for USB handshake...");
        }
    }

    // Initialize BLE with V3 name to bypass Windows cache
    BLEDevice::init("3T-Token-v3");
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

    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);  
    pAdvertising->setMinPreferred(0x12);
    pAdvertising->start();
    
    Serial.println("BLE Server is running. Waiting for connections...");
}

void loop() {
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();

        // New Host Binding Logic
        if (command.startsWith("PAIR_DEVICE:")) {
            // Extract the unique Host ID sent by Python
            String hostID = command.substring(12); 
            
            devicePaired = true;
            preferences.putBool("paired", true);
            preferences.putString("host_id", hostID); // Save specific PC identity
            
            Serial.print("PAIRING_SUCCESS: Token bound to Host ID: ");
            Serial.println(hostID);
            
            // Visual feedback: 3 flashes for successful binding
            flashLED(3, 150);
        } 
        else if (command == "CHECK_STATUS") {
            if (devicePaired) {
                String savedHost = preferences.getString("host_id", "UNKNOWN");
                Serial.print("STATUS: PAIRED to ");
                Serial.println(savedHost);
            } else {
                Serial.println("STATUS: UNPAIRED");
            }
        }
    }
}