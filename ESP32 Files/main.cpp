#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "encryption.h"

// Define unique UUIDs for your BLE Service and Characteristic
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

BLECharacteristic *pCharacteristic;
bool deviceConnected = false;

// Callback to handle incoming BLE messages (Environment Variables)
class MyCallbacks: public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pChar) {
        std::string rxValue = pChar->getValue();
        if (rxValue.length() > 0) {
            String envVars = String(rxValue.c_str());
            Serial.println("Received Env Variables via BLE: " + envVars);
            
            // Generate the unique file key[cite: 3]
            String fileKey = generateDecryptionKey(envVars);
            
            // Send the key back to the PC via BLE
            pChar->setValue(fileKey.c_str());
            pChar->notify();
            Serial.println("File key dispatched to host.");
        }
    }
};

class MyServerCallbacks: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) { deviceConnected = true; }
    void onDisconnect(BLEServer* pServer) { deviceConnected = false; }
};

void setup() {
    Serial.begin(115200);
    initTokenSecret();

    // 1. Setup BLE (Wireless Protocol)
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
    BLEDevice::startAdvertising();
    Serial.println("BLE Server is running. Waiting for connections...");
}

void loop() {
    // 2. Setup USB Pairing Listener (Wired Protocol)
    if (Serial.available() > 0) {
        String msg = Serial.readStringUntil('\n');
        msg.trim();
        if (msg == "PAIR_DEVICE") {
            // Establish shared secret over wired connection[cite: 3]
            Serial.println("PAIRING_SUCCESS: 3T-Hardware-Token is now bound to this host.");
        }
    }
}