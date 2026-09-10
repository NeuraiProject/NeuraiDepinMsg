#include "DepinAuth.h"
#include "Message.h"
#include "Hash.h"
#include "Conversion.h"
#include <string.h>

namespace depin {

/* ── pin ─────────────────────────────────────────────────────────────────── */

Err pinPublicKey(const Pin & pin, PublicKey & out) {
    if (!pin.hasKey()) return Err::PinRequired;
    return loadPublicKey(pin.poolPubKeyHex, out);
}

/* ── fields ──────────────────────────────────────────────────────────────── */

bool validPreimageField(const std::string & s, size_t max) {
    if (s.empty() || s.size() > max) return false;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e || c == '|') return false;
    }
    return true;
}

bool validToken(const std::string & token, const Limits & lim) {
    return validPreimageField(token, lim.maxToken) && token.size() >= 2 && token[0] == '&';
}

bool validChallenge(const std::string & challenge) {
    if (challenge.size() != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        char c = challenge[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

static bool validAddress(const std::string & a) { return validPreimageField(a, 64); }

/* ── preimages ───────────────────────────────────────────────────────────── */

Err requestPreimage(const std::string & type, const std::string & token,
                    const std::string & address, uint64_t unixMs, std::string & out) {
    out.clear();
    if (type != "receive" && type != "admin") return Err::BadPreimageField;
    if (!validToken(token) || !validAddress(address)) return Err::BadPreimageField;
    if (unixMs < 1000000000000ULL) return Err::BadPreimageField;    /* not a real ms clock */
    char ms[24];
    snprintf(ms, sizeof(ms), "%llu", (unsigned long long)unixMs);
    out.reserve(16 + type.size() + token.size() + address.size() + 24);
    out = "DEPIN-REQ|"; out += type; out += '|'; out += token; out += '|'; out += address; out += '|'; out += ms;
    return Err::Ok;
}

Err usePreimage(bool clear, const std::string & token, const std::string & address,
                const std::string & challenge, std::string & out) {
    out.clear();
    if (!validToken(token) || !validAddress(address) || !validChallenge(challenge)) return Err::BadPreimageField;
    out = clear ? "DEPIN-CLEAR|" : "DEPIN-GET|";
    out += token; out += '|'; out += address; out += '|'; out += challenge;
    return Err::Ok;
}

Err replyPreimage(const std::string & method, const std::string & token,
                  const std::string & address, const std::string & challenge,
                  const std::string & bodyStr, std::string & out) {
    out.clear();
    if (!validPreimageField(method, 40)) return Err::BadPreimageField;
    if (!token.empty() && !validToken(token)) return Err::BadPreimageField;
    if (!address.empty() && !validAddress(address)) return Err::BadPreimageField;
    if (!challenge.empty() && !validChallenge(challenge)) return Err::BadPreimageField;
    if (bodyStr.empty()) return Err::BadPreimageField;
    out.reserve(16 + method.size() + token.size() + address.size() + challenge.size() + 64);
    out = "DEPIN-RESP|"; out += method; out += '|'; out += token; out += '|'; out += address; out += '|';
    out += challenge; out += '|'; out += sha256Hex(bodyStr);
    return Err::Ok;
}

std::string sha256Hex(const std::string & s) {
    uint8_t h[32];
    sha256((const uint8_t *)s.data(), s.size(), h);
    return hexEncode(h, 32);
}

/* ── signatures ──────────────────────────────────────────────────────────── */

/* canonical base64 + header 31..34 */
static Err checkProfile(const std::string & sigB64) {
    if (sigB64.size() != NEURAI_MESSAGE_SIG_B64_LEN) return Err::BadSignature;
    uint8_t raw[NEURAI_MESSAGE_SIG_LEN];
    if (fromBase64(sigB64.c_str(), sigB64.size(), raw, sizeof(raw)) != NEURAI_MESSAGE_SIG_LEN) return Err::BadSignature;
    char canon[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    size_t n = toBase64(raw, sizeof(raw), canon, sizeof(canon));
    if (n != NEURAI_MESSAGE_SIG_B64_LEN) return Err::BadSignature;
    canon[n] = '\0';
    if (sigB64 != canon) return Err::BadSignature;
    if (raw[0] < 31 || raw[0] > 34) return Err::BadSignature;   /* compressed keys only */
    return Err::Ok;
}

Err signPreimage(const PrivateKey & key, const std::string & preimage, std::string & sigB64) {
    sigB64.clear();
    if (preimage.empty()) return Err::BadArg;
    PublicKey pub = key.publicKey();
    if (!pub.isValid() || !pub.compressed) return Err::BadPrivKey;
    char buf[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    if (signMessageBase64(key, (const uint8_t *)preimage.data(), preimage.size(), buf, sizeof(buf)) != NEURAI_MESSAGE_SIG_B64_LEN)
        return Err::Crypto;
    sigB64 = buf;
    return checkProfile(sigB64);
}

Err recoverSigner(const std::string & preimage, const std::string & sigB64, std::string & pubKeyHex) {
    pubKeyHex.clear();
    if (preimage.empty()) return Err::BadArg;
    Err e = checkProfile(sigB64);
    if (e != Err::Ok) return e;
    uint8_t pub[33];
    if (!recoverMessageSigner(sigB64.c_str(), (const uint8_t *)preimage.data(), preimage.size(), pub)) return Err::PoolSigInvalid;
    PublicKey p;
    if (loadPublicKey(pub, 33, p) != Err::Ok) return Err::PoolSigInvalid;
    pubKeyHex = hexEncode(pub, 33);
    return Err::Ok;
}

Err verifyPoolSig(const PublicKey & poolKey, const std::string & preimage, const std::string & sigB64) {
    if (!poolKey.isValid()) return Err::BadPubKey;
    std::string got;
    Err e = recoverSigner(preimage, sigB64, got);
    if (e != Err::Ok) return e;
    PublicKey want = poolKey;
    want.compressed = true;
    uint8_t sec[33];
    if (want.sec(sec, 33) != 33) return Err::BadPubKey;
    return (got == hexEncode(sec, 33)) ? Err::Ok : Err::PoolSigInvalid;
}

std::string addressForKey(const PublicKey & key, const ChainNetwork * net) {
    PublicKey k = key;
    k.compressed = true;
    char buf[64];
    int n = k.address(buf, sizeof(buf), net ? net : &DEFAULT_NETWORK);
    if (n <= 0) return std::string();
    return std::string(buf);
}

} // namespace depin
