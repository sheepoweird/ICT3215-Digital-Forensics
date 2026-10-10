#include "encryption.h"

#include <esp_system.h>
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"

void secureRandom(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

void hmacSha256(const uint8_t *key, size_t keyLen,
                const char *label,
                const uint8_t *data1, size_t len1,
                const uint8_t *data2, size_t len2,
                uint8_t out[SHA256_LEN]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    if (label) mbedtls_md_hmac_update(&ctx, (const uint8_t *)label, strlen(label));
    if (data1 && len1) mbedtls_md_hmac_update(&ctx, data1, len1);
    if (data2 && len2) mbedtls_md_hmac_update(&ctx, data2, len2);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

bool gcmEncrypt(const uint8_t key[32], const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad, size_t aadLen,
                const uint8_t *in, size_t len,
                uint8_t *out, uint8_t tag[GCM_TAG_LEN]) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, iv, GCM_IV_LEN,
                                       aad, aadLen, in, out, GCM_TAG_LEN, tag);
    }
    mbedtls_gcm_free(&ctx);
    return rc == 0;
}

bool gcmDecrypt(const uint8_t key[32], const uint8_t iv[GCM_IV_LEN],
                const uint8_t *aad, size_t aadLen,
                const uint8_t *in, size_t len,
                const uint8_t tag[GCM_TAG_LEN], uint8_t *out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        // Verifies the tag in constant time before releasing any plaintext
        rc = mbedtls_gcm_auth_decrypt(&ctx, len, iv, GCM_IV_LEN, aad, aadLen,
                                      tag, GCM_TAG_LEN, in, out);
    }
    mbedtls_gcm_free(&ctx);
    if (rc != 0) secureWipe(out, len);
    return rc == 0;
}

void secureWipe(void *buf, size_t len) {
    mbedtls_platform_zeroize(buf, len);
}

String toHex(const uint8_t *buf, size_t len) {
    static const char *digits = "0123456789abcdef";
    String s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s += digits[buf[i] >> 4];
        s += digits[buf[i] & 0x0F];
    }
    return s;
}
