#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <Arduino.h>

// Initializes the high-entropy master secret on the token
void initTokenSecret();

// Combines the master secret with the host's environment variables
String generateDecryptionKey(String envVariables);

#endif