#ifndef __NEURAI_DEPIN_MSG_H__
#define __NEURAI_DEPIN_MSG_H__

#include <Arduino.h>
#include <Neurai.h>
#include <Hash.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <vector>
#include <map>
#include <string>

struct EciesMessage {
    std::vector<uint8_t> ephemeralPubKey; // 33 bytes
    std::vector<uint8_t> encryptedPayload; // Nonce(12) + Cipher + Tag(16)
    std::map<std::string, std::vector<uint8_t>> recipientKeys; // KeyID (20 bytes hex) -> Nonce(12) + EncKey(32) + Tag(16)
};

struct DepinMessageResult {
    String hex;
    String messageHash;
    std::vector<uint8_t> messageHashBytes;
    String encryptedPayloadHex;
};

struct DepinParams {
    String token;
    String senderAddress;
    String senderPubKey; // 66 hex chars
    String privateKey;   // WIF or 64 hex chars
    uint64_t timestamp;
    String message;
    std::vector<String> recipientPubKeys; // 66 hex chars each
    String messageType; // "private" or "group"
};

class NeuraiDepinMsg {
public:
    static DepinMessageResult buildDepinMessage(const DepinParams& params);
    static String decryptPayload(const char* encryptedPayloadHex, const String& recipientPrivateKey);
    static String wrapMessageForServer(const String& messageHex, const String& serverPubKeyHex);

private:
    // Serialization
    static std::vector<uint8_t> serializeCompactSize(uint64_t value);
    static std::vector<uint8_t> serializeString(const String& str);
    static std::vector<uint8_t> serializeVector(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> serializeInt64(uint64_t value);
    
    // Deserialization
    static uint64_t parseCompactSize(const std::vector<uint8_t>& data, size_t& offset);
    static std::vector<uint8_t> parseVector(const std::vector<uint8_t>& data, size_t& offset);

    // Crypto
    static std::vector<uint8_t> kdfSha256(const uint8_t* sharedSecret, size_t sharedSecretLen, size_t outputLen);
    static bool aesGcmEncrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, std::vector<uint8_t>& iv, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& tag);
    static bool aesGcmDecrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag, std::vector<uint8_t>& plaintext);
    
    // ECIES
    static EciesMessage eciesEncrypt(const std::vector<uint8_t>& plaintext, const std::vector<std::vector<uint8_t>>& recipientPubKeys);
    static std::vector<uint8_t> serializeEciesMessage(const EciesMessage& msg);
    
    // Utilities
    static std::vector<uint8_t> hexToBytes(const String& hex);
    static std::vector<uint8_t> hexToBytes(const char* hex);
    static String bytesToHex(const uint8_t* bytes, size_t len);
    static std::vector<uint8_t> doubleSha256(const std::vector<uint8_t>& data);
};

#endif // __NEURAI_DEPIN_MSG_H__
