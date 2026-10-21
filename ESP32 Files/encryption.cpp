#include "encryption.h"

#include <esp_system.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"

// RNG callback for mbedTLS, backed by the ESP32 hardware RNG
static int esp_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

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

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool fromHex(const String &hex, uint8_t *buf, size_t len) {
    if (hex.length() != len * 2) return false;
    for (size_t i = 0; i < len; i++) {
        int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// HKDF-SHA256 built from HMAC (the ESP32 mbedTLS build omits mbedtls_hkdf).
// Only one output block (<= 32 bytes) is needed here, so Expand is a single HMAC.
void hkdfSha256(const uint8_t *salt, size_t saltLen,
                const uint8_t *ikm, size_t ikmLen,
                const uint8_t *info, size_t infoLen,
                uint8_t *out, size_t outLen) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t zeros[SHA256_LEN] = {0};
    if (salt == NULL || saltLen == 0) { salt = zeros; saltLen = SHA256_LEN; }

    // Extract: PRK = HMAC(salt, IKM)
    uint8_t prk[SHA256_LEN];
    mbedtls_md_hmac(md, salt, saltLen, ikm, ikmLen, prk);

    // Expand: T(1) = HMAC(PRK, info | 0x01); OKM = first outLen bytes of T(1)
    uint8_t t[SHA256_LEN];
    uint8_t counter = 1;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md, 1);
    mbedtls_md_hmac_starts(&ctx, prk, SHA256_LEN);
    if (info && infoLen) mbedtls_md_hmac_update(&ctx, info, infoLen);
    mbedtls_md_hmac_update(&ctx, &counter, 1);
    mbedtls_md_hmac_finish(&ctx, t);
    mbedtls_md_free(&ctx);

    if (outLen > SHA256_LEN) outLen = SHA256_LEN;
    memcpy(out, t, outLen);
    secureWipe(prk, sizeof(prk));
    secureWipe(t, sizeof(t));
}

// ── X25519 (RFC 7748), wire-compatible with Python cryptography's x25519 ──

bool x25519Keypair(uint8_t priv[X25519_LEN], uint8_t pub[X25519_LEN]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
              mbedtls_ecdh_gen_public(&grp, &d, &Q, esp_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary_le(&d, priv, X25519_LEN) == 0 &&
              mbedtls_mpi_write_binary_le(&Q.X, pub, X25519_LEN) == 0;

    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return ok;
}

bool x25519Shared(const uint8_t priv[X25519_LEN], const uint8_t peerPub[X25519_LEN],
                  uint8_t out[X25519_LEN]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Qp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Qp);

    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
              mbedtls_mpi_read_binary_le(&d, priv, X25519_LEN) == 0 &&
              mbedtls_mpi_read_binary_le(&Qp.X, peerPub, X25519_LEN) == 0 &&
              mbedtls_mpi_lset(&Qp.Z, 1) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, esp_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary_le(&z, out, X25519_LEN) == 0;

    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Qp);
    return ok;
}
