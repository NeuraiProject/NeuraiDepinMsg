#ifndef __NEURAI_DEPIN_CRYPTO_H__
#define __NEURAI_DEPIN_CRYPTO_H__

#include <stdint.h>
#include <stddef.h>

/*
 * Symmetric-crypto and randomness backend for the DePIN codec.
 *
 * The codec (DepinCodec.h) only needs AES-256-GCM with 12-byte nonces and
 * 16-byte tags, no AAD, plus a cryptographic random source. Both are
 * platform-specific, so they are supplied through this small table:
 *
 *   - ESP32 / Arduino: DepinCryptoMbedtls.cpp supplies mbedTLS + esp_fill_random
 *     automatically through an explicit linker reference. Wi-Fi/BT must be started, or a DRBG
 *     seeded, for esp_fill_random() to be cryptographically strong — see the
 *     Espressif random-number documentation.
 *   - Host tests: test/host/DepinCryptoOpenSSL.cpp registers OpenSSL EVP and a
 *     deterministic or /dev/urandom source.
 *
 * Every function returns true on success. The codec fails the whole operation
 * on the first false and never emits partially encrypted material.
 */
namespace depin {

struct CryptoBackend {
    /* ciphertext has the same length as the plaintext; tag is 16 bytes */
    bool (*aesGcmEncrypt)(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t * plaintext, size_t len,
                          uint8_t * ciphertext, uint8_t tag[16]);
    /* returns false (and writes nothing usable) if the tag does not verify */
    bool (*aesGcmDecrypt)(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t * ciphertext, size_t len, const uint8_t tag[16],
                          uint8_t * plaintext);
    /* cryptographically secure random bytes */
    bool (*randomBytes)(uint8_t * out, size_t len);
};

/* Install / query the backend. A codec call without a backend fails with
 * Err::NoCryptoBackend instead of silently using weak primitives. */
void setCryptoBackend(const CryptoBackend & backend);
const CryptoBackend * cryptoBackend();

/* Best-effort secure wipe (volatile write loop; never optimised away). */
void secureWipe(void * p, size_t n);

} // namespace depin

#endif /* __NEURAI_DEPIN_CRYPTO_H__ */
