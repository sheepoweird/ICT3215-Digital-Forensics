#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <Preferences.h>
#include <esp_system.h>

#define SERVICE_UUID        "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

Preferences preferences;
bool devicePaired = false;
BLECharacteristic *pCharacteristic;

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
    delay(1000);

    // Check why the ESP32 restarted
    esp_reset_reason_t reason = esp_reset_reason();
    
    // Open NVS storage space named "3t_storage"
    preferences.begin("3t_storage", false);

    // FACTORY RESET CONDITION: If user pressed the physical RST button (EXT_RESET), wipe memory!
    if (reason == ESP_RST_EXT || reason == ESP_RST_SW) {
        Serial.println("[HW] Physical RST button detected! Wiping pairing state (Factory Reset)...");
        preferences.clear(); // Clear NVS storage
        devicePaired = false;
    } else {
        // Normal power on — check if it was previously paired
        devicePaired = preferences.getBool("paired", false);
        if (devicePaired) {
            Serial.println("[HW] Restored state: Token is ALREADY bound to host from NVS flash.");
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

    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);  
    pAdvertising->setMinPreferred(0x12);
    pAdvertising->start();
    
    Serial.println("Token secret initialized and stored safely off-disk.");
    Serial.println("BLE Server is running. Waiting for connections...");
}

void loop() {
    // Handle Serial (USB) Pairing Command
    if (Serial.available() > 0) {
        String command = Serial.readStringUntil('\n');
        command.trim();

        if (command == "PAIR_DEVICE") {
            devicePaired = true;
            preferences.putBool("paired", true); // Save permanently to flash!
            Serial.println("PAIRING_SUCCESS: 3T-Hardware-Token is now bound to this host.");
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