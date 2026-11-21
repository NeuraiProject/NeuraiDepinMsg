#include "DepinAuth.h"
#include "Message.h"
#include "NeuraiPQ.h"
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
    if (token.empty() || token[0] != '&' || token.size() > 120 || token.size() > lim.maxToken) return false;
    size_t start = 0;
    for (size_t i = 1; i < token.size(); ++i) {
        char c = token[i];
        if (c == '/') {
            if (i - start < 3) return false;
            start = i + 1;
        } else if (!(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '.' && c != '_') return false;
    }
    return token.size() - start >= (start ? 3u : 4u);
}

bool tokenInScope(const std::string & messageToken, const std::string & scope) {
    if (!validToken(scope) || !validToken(messageToken)) return false;
    if (messageToken == scope) return true;
    return messageToken.size() > scope.size() + 1 &&
           messageToken.compare(0, scope.size(), scope) == 0 && messageToken[scope.size()] == '/';
}

bool validChallenge(const std::string & challenge) {
    if (challenge.size() != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        char c = challenge[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
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

Err signPreimage(const PrivateKey & key, const std::string & preimage, std::string & sigB64, const std::string & address) {
    sigB64.clear();
    if (preimage.empty()) return Err::BadArg;
    PublicKey pub = key.publicKey();
    if (!pub.isValid() || (address.empty() && !pub.compressed)) return Err::BadPrivKey;
    char buf[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    if (!address.empty() && !pubKeyMatchesAddress(pub, address)) return Err::BadPubKey;
    uint8_t version, program[32];
    if (!address.empty() && authScriptAddressDecode(address.c_str(), &version, NULL, program)) {
        const char domain[] = "Neurai Strict AuthScript Message";
        uint8_t original[32], digest[32], compact[65], bin[65];
        messageMagicHash((const uint8_t *)preimage.data(), preimage.size(), original);
        DoubleSha h;
        h.begin(); h.write(sizeof(domain)-1); h.write((const uint8_t *)domain, sizeof(domain)-1);
        h.write(version); h.write(program, 32); h.write(original, 32); h.end(digest);
        Signature sig = key.sign(digest);
        if (!sig.isValid()) return Err::Crypto;
        sig.bin(bin, sizeof(bin));
        compact[0] = 31 + (bin[64] & 3);
        memcpy(compact+1, bin, 64);
        if (toBase64(compact, sizeof(compact), buf, sizeof(buf)) != 88) return Err::Crypto;
        buf[88] = 0;
    } else if (signMessageBase64(key, (const uint8_t *)preimage.data(), preimage.size(), buf, sizeof(buf)) != NEURAI_MESSAGE_SIG_B64_LEN)
        return Err::Crypto;
    sigB64 = buf;
    return pub.compressed ? checkProfile(sigB64) : Err::Ok;
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
    char buf[64];
    int n = k.address(buf, sizeof(buf), net ? net : &DEFAULT_NETWORK);
    if (n <= 0) return std::string();
    return std::string(buf);
}

} // namespace depin
