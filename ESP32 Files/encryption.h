#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <Arduino.h>

// Sizes used by the 3T token protocol (must match Python/token_comms.py)
#define MASTER_SECRET_LEN 32   // never leaves the token
#define AUTH_KEY_LEN      32   // shared with the paired host over USB
#define TOKEN_ID_LEN      16   // public identifier of this token
#define NONCE_LEN         16   // per-session challenge nonces
#define GCM_IV_LEN        12
#define GCM_TAG_LEN       16
#define SHA256_LEN        32

// Fills buf with bytes from the ESP32 hardware RNG.
// True random only while the RF subsystem (BLE) is running, so call after BLEDevice::init().
void secureRandom(uint8_t *buf, size_t len);

// HMAC-SHA256(key, label || data1 || data2). Any data pointer may be NULL with len 0.
void hmacSha256(const uint8_t *key, size_t keyLen,
                const char *label,
                const uint8_t *data1, size_t len1,
                const uint8_t *data2, size_t len2,
                uint8_t out[SHA256_LEN]);

// AES-256-GCM. Output ciphertext is the same length as the input; the tag is separate.
// Decrypt returns false if the tag does not verify (wrong key or tampered message).
bool gcmEncrypt(const uint8_t key[32], const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad, size_t aadLen,
                const uint8_t *in, size_t len,
                uint8_t *out, uint8_t tag[GCM_TAG_LEN]);
bool gcmDecrypt(const uint8_t key[32], const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad, size_t aadLen,
                const uint8_t *in, size_t len,
                const uint8_t tag[GCM_TAG_LEN], uint8_t *out);

// Overwrites sensitive memory in a way the compiler cannot optimise away.
void secureWipe(void *buf, size_t len);

String toHex(const uint8_t *buf, size_t len);

#endif
