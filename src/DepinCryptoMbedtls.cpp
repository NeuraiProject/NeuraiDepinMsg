/*
 * ESP32 / Arduino backend for DepinCrypto.h: AES-256-GCM via the mbedTLS that
 * ships with the Arduino-ESP32 core, randomness via esp_fill_random().
 *
 * esp_fill_random() is only cryptographically strong while an RF subsystem
 * (Wi-Fi / Bluetooth) is running, or after the bootloader/ESP-IDF has seeded
 * the RNG; the DePIN client requires the network anyway, so this holds in
 * practice. See docs.espressif.com → System → Random Number Generation.
 *
 * Compiled only on ESP32 targets; host builds supply their own backend.
 */
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)

#include "DepinCrypto.h"
#include <mbedtls/gcm.h>
#include <esp_random.h>

namespace {

bool gcmEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t * plaintext, size_t len, uint8_t * ciphertext, uint8_t tag[16]) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, 12,
                                        NULL, 0, plaintext, ciphertext, 16, tag);
    }
    mbedtls_gcm_free(&gcm);
    return ret == 0;
}

bool gcmDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t * ciphertext, size_t len, const uint8_t tag[16], uint8_t * plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, len, nonce, 12, NULL, 0, tag, 16, ciphertext, plaintext);
    }
    mbedtls_gcm_free(&gcm);
    return ret == 0;
}

bool randomBytes(uint8_t * out, size_t len) {
    if (!out) return false;
    esp_fill_random(out, len);
    return true;
}

} // namespace

namespace depin {
const CryptoBackend * mbedtlsCryptoBackend() {
    static const CryptoBackend backend = { gcmEncrypt, gcmDecrypt, randomBytes };
    return &backend;
}
} // namespace depin

#endif /* ESP32 */
