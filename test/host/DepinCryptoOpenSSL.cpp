/*
 * Host-only backend for DepinCrypto.h (tests): AES-256-GCM via OpenSSL EVP,
 * randomness from RAND_bytes or, when the test sets it, a deterministic
 * counter stream so envelopes are reproducible. Never shipped to devices.
 */
#include "DepinCrypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

static bool g_deterministic = false;
static uint64_t g_counter = 0;

void depinTestSetDeterministicRng(bool on, uint64_t seed) {
    g_deterministic = on;
    g_counter = seed;
}

namespace {

bool gcmEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t * plaintext, size_t len, uint8_t * ciphertext, uint8_t tag[16]) {
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int outl = 0, fl = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) break;
        if (len && EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, (int)len) != 1) break;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + outl, &fl) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) break;
        ok = ((size_t)(outl + fl) == len);
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool gcmDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t * ciphertext, size_t len, const uint8_t tag[16], uint8_t * plaintext) {
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int outl = 0, fl = 0;
    uint8_t tagCopy[16];
    memcpy(tagCopy, tag, 16);
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) break;
        if (len && EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext, (int)len) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagCopy) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, plaintext ? plaintext + outl : NULL, &fl) != 1) break;   /* tag check */
        ok = ((size_t)(outl + fl) == len);
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok && plaintext && len) memset(plaintext, 0, len);
    return ok;
}

bool randomBytes(uint8_t * out, size_t len) {
    if (!out) return false;
    if (g_deterministic) {
        /* SHA-free counter stream: good enough to make test envelopes stable */
        for (size_t i = 0; i < len; i++) {
            g_counter = g_counter * 6364136223846793005ULL + 1442695040888963407ULL;
            out[i] = (uint8_t)(g_counter >> 56);
        }
        return true;
    }
    return RAND_bytes(out, (int)len) == 1;
}

struct Register {
    Register() {
        depin::CryptoBackend b = { gcmEncrypt, gcmDecrypt, randomBytes };
        depin::setCryptoBackend(b);
    }
} registerBackend;

} // namespace
