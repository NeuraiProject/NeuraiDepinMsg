#include "NeuraiDepinMsg.h"
#include <map>
#include <algorithm>

// ============================================
// SERIALIZATION UTILITIES
// ============================================

std::vector<uint8_t> NeuraiDepinMsg::serializeCompactSize(uint64_t value) {
    if (value < 253) {
        return {(uint8_t)value};
    } else if (value <= 0xffff) {
        return {253, (uint8_t)(value & 0xff), (uint8_t)((value >> 8) & 0xff)};
    } else if (value <= 0xffffffff) {
        return {254, (uint8_t)(value & 0xff), (uint8_t)((value >> 8) & 0xff), (uint8_t)((value >> 16) & 0xff), (uint8_t)((value >> 24) & 0xff)};
    } else {
        std::vector<uint8_t> buf = {255};
        for (int i = 0; i < 8; i++) {
            buf.push_back((uint8_t)((value >> (8 * i)) & 0xff));
        }
        return buf;
    }
}

std::vector<uint8_t> NeuraiDepinMsg::serializeString(const String& str) {
    std::vector<uint8_t> res = serializeCompactSize(str.length());
    const char* c_str = str.c_str();
    res.insert(res.end(), c_str, c_str + str.length());
    return res;
}

std::vector<uint8_t> NeuraiDepinMsg::serializeVector(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> res = serializeCompactSize(data.size());
    res.insert(res.end(), data.begin(), data.end());
    return res;
}

std::vector<uint8_t> NeuraiDepinMsg::serializeInt64(uint64_t value) {
    std::vector<uint8_t> buf(8);
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)((value >> (8 * i)) & 0xff);
    }
    return buf;
}

// ============================================
// DESERIALIZATION UTILITIES
// ============================================

uint64_t NeuraiDepinMsg::parseCompactSize(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset >= data.size()) return 0;
    
    uint8_t first = data[offset++];
    if (first < 253) {
        return first;
    } else if (first == 253) {
        if (offset + 2 > data.size()) return 0;
        uint16_t val = data[offset] | (data[offset+1] << 8);
        offset += 2;
        return val;
    } else if (first == 254) {
        if (offset + 4 > data.size()) return 0;
        uint32_t val = data[offset] | (data[offset+1] << 8) | (data[offset+2] << 16) | (data[offset+3] << 24);
        offset += 4;
        return val;
    } else {
        if (offset + 8 > data.size()) return 0;
        uint64_t val = 0;
        for (int i=0; i<8; i++) val |= ((uint64_t)data[offset+i] << (8*i));
        offset += 8;
        return val;
    }
}

std::vector<uint8_t> NeuraiDepinMsg::parseVector(const std::vector<uint8_t>& data, size_t& offset) {
    uint64_t len = parseCompactSize(data, offset);
    if (offset + len > data.size()) return {};
    
    std::vector<uint8_t> res;
    res.insert(res.end(), data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return res;
}

// ============================================
// CRYPTOGRAPHIC FUNCTIONS
// ============================================

std::vector<uint8_t> NeuraiDepinMsg::kdfSha256(const uint8_t* sharedSecret, size_t sharedSecretLen, size_t outputLen) {
    std::vector<uint8_t> output;
    uint32_t counter = 1;
    
    while (output.size() < outputLen) {
        uint8_t counterBytes[4];
        counterBytes[0] = (counter >> 24) & 0xff;
        counterBytes[1] = (counter >> 16) & 0xff;
        counterBytes[2] = (counter >> 8) & 0xff;
        counterBytes[3] = counter & 0xff;
        
        SHA256 hasher;
        hasher.write(sharedSecret, sharedSecretLen);
        hasher.write(counterBytes, 4);
        
        uint8_t hash[32];
        hasher.end(hash);
        
        size_t remaining = outputLen - output.size();
        size_t toCopy = std::min((size_t)32, remaining);
        output.insert(output.end(), hash, hash + toCopy);
        counter++;
    }
    return output;
}

bool NeuraiDepinMsg::aesGcmEncrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, std::vector<uint8_t>& iv, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& tag) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    
    ciphertext.resize(plaintext.size());
    tag.resize(16);
    
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), iv.data(), iv.size(), NULL, 0, plaintext.data(), ciphertext.data(), 16, tag.data());
    
    mbedtls_gcm_free(&gcm);
    return ret == 0;
}

bool NeuraiDepinMsg::aesGcmDecrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag, std::vector<uint8_t>& plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    
    plaintext.resize(ciphertext.size());
    
    ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext.size(), iv.data(), iv.size(), NULL, 0, tag.data(), 16, ciphertext.data(), plaintext.data());
    
    mbedtls_gcm_free(&gcm);
    return ret == 0;
}

// ============================================
// ECIES ENCRYPTION
// ============================================

EciesMessage NeuraiDepinMsg::eciesEncrypt(const std::vector<uint8_t>& plaintext, const std::vector<std::vector<uint8_t>>& recipientPubKeys) {
    // 1. Generate ephemeral key pair
    uint8_t ephemPriv[32];
    for(int i=0; i<32; i++) ephemPriv[i] = random(256); // FIXME: Use better RNG in production?
    
    PrivateKey ephemKey(ephemPriv);
    PublicKey ephemPubKey = ephemKey.publicKey();
    
    EciesMessage msg;
    uint8_t ephemPubKeySerialized[33];
    ephemPubKey.sec(ephemPubKeySerialized, 33);
    msg.ephemeralPubKey.assign(ephemPubKeySerialized, ephemPubKeySerialized + 33);
    
    // 2. Derive master AES key from ephemeral private key
    // Neurai Core compatible: KDF_SHA256(ephemeral_privkey, 32)
    std::vector<uint8_t> aesKey = kdfSha256(ephemPriv, 32, 32);
    
    // 3. Encrypt payload with AES-256-GCM
    std::vector<uint8_t> payloadIv(12);
    for(int i=0; i<12; i++) payloadIv[i] = random(256);
    
    std::vector<uint8_t> ciphertext, tag;
    aesGcmEncrypt(plaintext, aesKey, payloadIv, ciphertext, tag);
    
    // payload = Nonce(12) + Ciphertext + Tag(16)
    msg.encryptedPayload.insert(msg.encryptedPayload.end(), payloadIv.begin(), payloadIv.end());
    msg.encryptedPayload.insert(msg.encryptedPayload.end(), ciphertext.begin(), ciphertext.end());
    msg.encryptedPayload.insert(msg.encryptedPayload.end(), tag.begin(), tag.end());
    
    // 4. Wrap AES key for each recipient
    for (const auto& pubKeyBytes : recipientPubKeys) {
        PublicKey recipientPubKey(pubKeyBytes.data());
        
        // ECDH: SHA256(Compressed(SharedPoint))
        ECPoint sharedPoint = ephemKey * recipientPubKey;
        sharedPoint.compressed = true; // Force compressed serialization (33 bytes)
        
        uint8_t sharedPointBytes[33];
        sharedPoint.sec(sharedPointBytes, 33);
        
        uint8_t sharedSecret[32];
        sha256(sharedPointBytes, 33, sharedSecret);
        
        // Derive per-recipient KDF key
        std::vector<uint8_t> encKey = kdfSha256(sharedSecret, 32, 32);
        
        // Encrypt the master AES key
        std::vector<uint8_t> recipientIv(12);
        for(int i=0; i<12; i++) recipientIv[i] = random(256);
        
        std::vector<uint8_t> encAesKey, recipientTag;
        aesGcmEncrypt(aesKey, encKey, recipientIv, encAesKey, recipientTag);
        
        // package = Nonce(12) + encryptedAESKey(32) + Tag(16)
        std::vector<uint8_t> package;
        package.insert(package.end(), recipientIv.begin(), recipientIv.end());
        package.insert(package.end(), encAesKey.begin(), encAesKey.end());
        package.insert(package.end(), recipientTag.begin(), recipientTag.end());
        
        // KeyID is Hash160(recipient_pubkey)
        uint8_t keyId[20];
        hash160(pubKeyBytes.data(), 33, keyId);
        msg.recipientKeys[std::string(bytesToHex(keyId, 20).c_str())] = package;
    }
    
    return msg;
}

std::vector<uint8_t> NeuraiDepinMsg::serializeEciesMessage(const EciesMessage& msg) {
    std::vector<uint8_t> res;
    // Ephemeral PubKey as vector
    std::vector<uint8_t> ephemVec = serializeVector(msg.ephemeralPubKey);
    res.insert(res.end(), ephemVec.begin(), ephemVec.end());
    
    // Encrypted Payload as vector
    std::vector<uint8_t> payloadVec = serializeVector(msg.encryptedPayload);
    res.insert(res.end(), payloadVec.begin(), payloadVec.end());
    
    // Recipient counts
    std::vector<uint8_t> countVec = serializeCompactSize(msg.recipientKeys.size());
    res.insert(res.end(), countVec.begin(), countVec.end());
    
    // Recipient keys (sorted by KeyID hex for determinism)
    // std::map is already sorted by key
    for (auto const& [keyIdHex, package] : msg.recipientKeys) {
        std::vector<uint8_t> keyIdBytes = hexToBytes(String(keyIdHex.c_str()));
        res.insert(res.end(), keyIdBytes.begin(), keyIdBytes.end());
        
        std::vector<uint8_t> packageVec = serializeVector(package);
        res.insert(res.end(), packageVec.begin(), packageVec.end());
    }
    
    return res;
}

// ============================================
// MAIN API
// ============================================

String NeuraiDepinMsg::decryptPayload(const char* encryptedPayloadHex, const String& recipientPrivateKey) {
    std::vector<uint8_t> data = hexToBytes(encryptedPayloadHex);
    size_t offset = 0;
    
    // 1. Parse Encrypted Message Structure
    // Ephemeral PubKey
    std::vector<uint8_t> ephemVec = parseVector(data, offset);
    if (ephemVec.empty()) return "";
    
    // Encrypted Payload (Ciphertext)
    std::vector<uint8_t> payloadVec = parseVector(data, offset);
    if (payloadVec.empty()) return ""; // This payload includes nonce(12) + cipher + tag(16)
    
    // Recipient Count
    uint64_t count = parseCompactSize(data, offset);
    
    // 2. Prepare Recipient Private Key
    PrivateKey privKey;
    if (recipientPrivateKey.length() == 64) {
        std::vector<uint8_t> pkBytes = hexToBytes(recipientPrivateKey);
        privKey.setSecret(pkBytes.data());
    } else {
        privKey.fromWIF(recipientPrivateKey.c_str());
    }
    
    // Calculate our own KeyID (Hash160 of our PubKey)
    PublicKey myPubKey = privKey.publicKey();
    uint8_t myPubKeyBytes[33];
    myPubKey.sec(myPubKeyBytes, 33);
    uint8_t myKeyId[20];
    hash160(myPubKeyBytes, 33, myKeyId);
    
    // 3. Find our package
    std::vector<uint8_t> myPackage;
    bool found = false;
    
    for (uint64_t i = 0; i < count; i++) {
        if (offset + 20 > data.size()) return "";
        
        bool match = true;
        for (int j = 0; j < 20; j++) {
            if (data[offset + j] != myKeyId[j]) {
                match = false;
                // Don't break here, we need to consume the KeyID bytes
            }
        }
        offset += 20;
        
        std::vector<uint8_t> package = parseVector(data, offset);
        
        if (match) {
            myPackage = package;
            found = true;
            // We can break if we don't care about parsing the rest
            break; 
        }
    }
    
    if (!found || myPackage.empty()) return "";
    
    // 4. Decrypt the Master AES Key
    // Package = Nonce(12) + EncKey(32) + Tag(16) -> Total 60 bytes typically
    if (myPackage.size() < 12 + 16) return "";
    
    std::vector<uint8_t> pkgIv(myPackage.begin(), myPackage.begin() + 12);
    std::vector<uint8_t> pkgTag(myPackage.end() - 16, myPackage.end());
    std::vector<uint8_t> pkgCipher(myPackage.begin() + 12, myPackage.end() - 16);
    
    // Derive KDF Key
    // Shared Secret = ECDH(EphemeralPubKey, MyPrivateKey)
    // IMPORTANT: JS library uses SHA256(COMPRESSED_POINT). uNeurai ecdh() uses UNCOMPRESSED if use_hash=true.
    // So we manually calculate: Point * Scaler -> Compressed -> SHA256
    
    PublicKey ephemKey(ephemVec.data()); 
    ECPoint sharedPoint = privKey * ephemKey;
    sharedPoint.compressed = true; // Force compressed serialization (33 bytes)

    uint8_t sharedPointBytes[33];
    sharedPoint.sec(sharedPointBytes, 33);

    uint8_t sharedSecret[32];
    sha256(sharedPointBytes, 33, sharedSecret);
    
    // KDF(SharedSecret)
    std::vector<uint8_t> encKey = kdfSha256(sharedSecret, 32, 32);
    
    std::vector<uint8_t> masterAesKey;
    // Decrypt AES Key
    if (!aesGcmDecrypt(pkgCipher, encKey, pkgIv, pkgTag, masterAesKey)) {
        return ""; // Failed to decrypt master key
    }
    
    // 5. Decrypt the Payload
    // Payload = Nonce(12) + Ciphertext + Tag(16)
    if (payloadVec.size() < 12 + 16) return "";
    
    std::vector<uint8_t> payloadIv(payloadVec.begin(), payloadVec.begin() + 12);
    std::vector<uint8_t> payloadTag(payloadVec.end() - 16, payloadVec.end());
    std::vector<uint8_t> payloadCipher(payloadVec.begin() + 12, payloadVec.end() - 16); // Missing bytes?
    
    std::vector<uint8_t> plaintextBytes;
    if (!aesGcmDecrypt(payloadCipher, masterAesKey, payloadIv, payloadTag, plaintextBytes)) {
        return ""; // Failed to decrypt payload
    }
    
    // Convert to String
    String result = "";
    for (uint8_t b : plaintextBytes) {
        result += (char)b;
    }
    
    return result;
}

DepinMessageResult NeuraiDepinMsg::buildDepinMessage(const DepinParams& params) {
    DepinMessageResult result;
    
    // 1. Prepare private key
    PrivateKey privKey;
    if (params.privateKey.length() == 64) {
        std::vector<uint8_t> pkBytes = hexToBytes(params.privateKey);
        privKey.setSecret(pkBytes.data());
    } else {
        privKey.fromWIF(params.privateKey.c_str());
    }
    
    // 2. Prepare recipients
    std::vector<std::vector<uint8_t>> recipientPubKeys;
    for (const auto& pkHex : params.recipientPubKeys) {
        recipientPubKeys.push_back(hexToBytes(pkHex));
    }
    
    // Auto-add sender to recipients
    std::vector<uint8_t> senderPubKeyBytes = hexToBytes(params.senderPubKey);
    bool senderIncluded = false;
    for (const auto& pk : recipientPubKeys) {
        if (pk == senderPubKeyBytes) {
            senderIncluded = true;
            break;
        }
    }
    if (!senderIncluded) {
        recipientPubKeys.push_back(senderPubKeyBytes);
    }
    
    // 3. Encrypt message
    std::vector<uint8_t> plaintextBytes;
    plaintextBytes.insert(plaintextBytes.end(), params.message.c_str(), params.message.c_str() + params.message.length());
    
    EciesMessage eciesMsg = eciesEncrypt(plaintextBytes, recipientPubKeys);
    std::vector<uint8_t> encryptedPayload = serializeEciesMessage(eciesMsg);
    
    // 4. Build hash data for signing
    // byte(0x01 = private, 0x02 = group)
    uint8_t messageTypeByte = (params.messageType == "private") ? 0x01 : 0x02;
    
    std::vector<uint8_t> hashData;
    std::vector<uint8_t> tokenSer = serializeString(params.token);
    hashData.insert(hashData.end(), tokenSer.begin(), tokenSer.end());
    
    std::vector<uint8_t> senderSer = serializeString(params.senderAddress);
    hashData.insert(hashData.end(), senderSer.begin(), senderSer.end());
    
    std::vector<uint8_t> timeSer = serializeInt64(params.timestamp);
    hashData.insert(hashData.end(), timeSer.begin(), timeSer.end());
    
    hashData.push_back(messageTypeByte);
    
    std::vector<uint8_t> payloadSer = serializeVector(encryptedPayload);
    hashData.insert(hashData.end(), payloadSer.begin(), payloadSer.end());
    
    // 5. Sign message
    uint8_t messageHash[32];
    doubleSha(hashData.data(), hashData.size(), messageHash);
    
    result.messageHashBytes.assign(messageHash, messageHash + 32);
    
    // Reverse hash for display (Neurai Core style)
    uint8_t displayHash[32];
    for(int i=0; i<32; i++) displayHash[i] = messageHash[31-i];
    result.messageHash = bytesToHex(displayHash, 32);
    
    Signature sig = privKey.sign(messageHash);
    uint8_t derSig[80];
    size_t sigLen = sig.der(derSig, 80);
    std::vector<uint8_t> sigBytes(derSig, derSig + sigLen);
    
    // 6. Final serialization
    std::vector<uint8_t> finalBytes;
    finalBytes.insert(finalBytes.end(), tokenSer.begin(), tokenSer.end());
    finalBytes.insert(finalBytes.end(), senderSer.begin(), senderSer.end());
    finalBytes.insert(finalBytes.end(), timeSer.begin(), timeSer.end());
    finalBytes.push_back(messageTypeByte);
    finalBytes.insert(finalBytes.end(), payloadSer.begin(), payloadSer.end());
    
    std::vector<uint8_t> sigSer = serializeVector(sigBytes);
    finalBytes.insert(finalBytes.end(), sigSer.begin(), sigSer.end());
    
    result.hex = bytesToHex(finalBytes.data(), finalBytes.size());
    result.encryptedPayloadHex = bytesToHex(encryptedPayload.data(), encryptedPayload.size());
    
    return result;
}

String NeuraiDepinMsg::wrapMessageForServer(const String& messageHex, const String& serverPubKeyHex) {
    // 1. Convert hex message to bytes (as UTF-8 string of the hex chars, NOT decoding the hex)
    // The server expects the payload to be the hex string itself.
    std::vector<uint8_t> messageBytes;
    const char* hexCStr = messageHex.c_str();
    messageBytes.insert(messageBytes.end(), hexCStr, hexCStr + messageHex.length());

    // 2. Prepare server pubkey
    std::vector<uint8_t> serverPubKeyBytes = hexToBytes(serverPubKeyHex);
    std::vector<std::vector<uint8_t>> recipientPubKeys = { serverPubKeyBytes };

    // 3. Encrypt
    EciesMessage eciesMsg = eciesEncrypt(messageBytes, recipientPubKeys);
    std::vector<uint8_t> encryptedPayload = serializeEciesMessage(eciesMsg);

    // 4. Return hex
    return bytesToHex(encryptedPayload.data(), encryptedPayload.size());
}

// ============================================
// UTILITIES
// ============================================

std::vector<uint8_t> NeuraiDepinMsg::hexToBytes(const String& hex) {
    return hexToBytes(hex.c_str());
}

std::vector<uint8_t> NeuraiDepinMsg::hexToBytes(const char* hex) {
    std::vector<uint8_t> bytes;
    if (!hex) return bytes;
    size_t len = strlen(hex);
    for (size_t i = 0; i < len; i += 2) {
        String byteString = "";
        byteString += hex[i];
        byteString += hex[i+1];
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

String NeuraiDepinMsg::bytesToHex(const uint8_t* bytes, size_t len) {
    String res = "";
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] < 0x10) res += "0";
        res += String(bytes[i], HEX);
    }
    return res;
}
