#include "encryption.h"

// The high-entropy master secret held ONLY on the token
String masterSecret = "";

void initTokenSecret() {
    // In a production build, generate a secure random byte array here
    masterSecret = "3T_HARDWARE_ANCHOR_SECRET_778899"; 
    Serial.println("Token secret initialized and stored safely off-disk.");
}

String generateDecryptionKey(String envVariables) {
    // Combine the hardware secret with the user-selected environment variables
    // Note: For the final submission, run this through a SHA-256 or HMAC hashing function.
    String finalKey = masterSecret + "-" + envVariables;
    return finalKey;
}