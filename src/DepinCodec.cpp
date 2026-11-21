#include "DepinCodec.h"
#include "Hash.h"
#include "DepinAuth.h"
#include "NeuraiPQ.h"
#include "Conversion.h"
#include "Networks.h"
#include "utility/trezor/bignum.h"
#include "utility/trezor/ecdsa.h"
#include "utility/trezor/secp256k1.h"
#include "utility/trezor/memzero.h"
#include <string.h>
#include <algorithm>

namespace depin {

/* ── errors / limits ─────────────────────────────────────────────────────── */

const char * errName(Err e) {
    switch (e) {
        case Err::Ok:                 return "ok";
        case Err::BadArg:             return "bad-arg";
        case Err::NoCryptoBackend:    return "no-crypto-backend";
        case Err::Rng:                return "rng";
        case Err::Crypto:             return "crypto";
        case Err::BadHex:             return "bad-hex";
        case Err::BadCompactSize:     return "bad-compactsize";
        case Err::Truncated:          return "truncated";
        case Err::TrailingBytes:      return "trailing-bytes";
        case Err::TooLarge:           return "too-large";
        case Err::BadPrivKey:         return "bad-privkey";
        case Err::BadPubKey:          return "bad-pubkey";
        case Err::BadEphemeral:       return "bad-ephemeral";
        case Err::BadPayload:         return "bad-payload";
        case Err::BadRecipientEntry:  return "bad-recipient-entry";
        case Err::RecipientOrder:     return "recipient-order";
        case Err::DuplicateRecipient: return "duplicate-recipient";
        case Err::TooManyRecipients:  return "too-many-recipients";
        case Err::NotForRecipient:    return "not-for-recipient";
        case Err::KeyUnwrapFailed:    return "key-unwrap-failed";
        case Err::PayloadAuthFailed:  return "payload-auth-failed";
        case Err::BadMessageType:     return "bad-message-type";
        case Err::BadTimestamp:       return "bad-timestamp";
        case Err::BadField:           return "bad-field";
        case Err::BadSignature:       return "bad-signature";
        case Err::SignatureInvalid:   return "signature-invalid";
        case Err::HashMismatch:       return "hash-mismatch";
        case Err::BadPreimageField:   return "bad-preimage-field";
        case Err::RpcError:           return "rpc-error";
        case Err::BadJson:            return "bad-json";
        case Err::BadReply:           return "bad-reply";
        case Err::ReplyKindMismatch:  return "reply-kind-mismatch";
        case Err::PoolSigInvalid:     return "poolsig-invalid";
        case Err::PinRequired:        return "pin-required";
        case Err::PinMismatch:        return "pin-mismatch";
        case Err::ProtocolMismatch:   return "protocol-mismatch";
        case Err::ServiceDisabled:    return "service-disabled";
        case Err::NotBootstrapped:    return "not-bootstrapped";
        case Err::PinNotAccepted:     return "pin-not-accepted";
        case Err::ClockInvalid:       return "clock-invalid";
        case Err::Transport:          return "transport";
        case Err::RateLimited:        return "rate-limited";
        case Err::RecipientsTruncated:return "recipients-truncated";
        case Err::KeyNotRevealed:     return "key-not-revealed";
        case Err::SubmitMismatch:     return "submit-mismatch";
        case Err::ScopeMismatch:      return "scope-mismatch";
        case Err::ChallengeInvalid:   return "challenge-invalid";
        case Err::BadPage:            return "bad-page";
    }
    return "unknown";
}

const Limits & defaultLimits() {
    static const Limits lim;
    return lim;
}

/* ── crypto backend registry (DepinCrypto.h) ─────────────────────────────── */

static CryptoBackend g_backend = { NULL, NULL, NULL };

void setCryptoBackend(const CryptoBackend & backend) { g_backend = backend; }

#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
const CryptoBackend * mbedtlsCryptoBackend();
#endif

const CryptoBackend * cryptoBackend() {
#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)
    // An explicit reference retains the backend when linked from an archive.
    if (!g_backend.aesGcmEncrypt && !g_backend.aesGcmDecrypt && !g_backend.randomBytes)
        return mbedtlsCryptoBackend();
#endif
    if (!g_backend.aesGcmEncrypt || !g_backend.aesGcmDecrypt || !g_backend.randomBytes) return NULL;
    return &g_backend;
}

void secureWipe(void * p, size_t n) {
    if (p && n) memzero(p, n);
}

/* ── hex ─────────────────────────────────────────────────────────────────── */

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t hexDecode(const char * hex, size_t hexLen, uint8_t * out, size_t cap, Err * err) {
    Err local; if (!err) err = &local;
    if (!hex || !out) { *err = Err::BadArg; return 0; }
    if (hexLen == 0) hexLen = strlen(hex);
    if (hexLen & 1) { *err = Err::BadHex; return 0; }
    size_t n = hexLen / 2;
    if (n > cap) { *err = Err::TooLarge; return 0; }
    for (size_t i = 0; i < n; i++) {
        int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { *err = Err::BadHex; return 0; }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *err = Err::Ok;
    return n;
}

std::string hexEncode(const uint8_t * data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    if (!data) return s;
    s.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        s[2 * i]     = digits[data[i] >> 4];
        s[2 * i + 1] = digits[data[i] & 0x0f];
    }
    return s;
}

/* ── CompactSize ─────────────────────────────────────────────────────────── */

size_t writeCompactSize(uint64_t v, uint8_t * out, size_t cap) {
    if (!out) return 0;
    if (v < 253) {
        if (cap < 1) return 0;
        out[0] = (uint8_t)v; return 1;
    }
    if (v <= 0xffff) {
        if (cap < 3) return 0;
        out[0] = 253; out[1] = (uint8_t)v; out[2] = (uint8_t)(v >> 8); return 3;
    }
    if (v <= 0xffffffffULL) {
        if (cap < 5) return 0;
        out[0] = 254;
        for (int i = 0; i < 4; i++) out[1 + i] = (uint8_t)(v >> (8 * i));
        return 5;
    }
    if (cap < 9) return 0;
    out[0] = 255;
    for (int i = 0; i < 8; i++) out[1 + i] = (uint8_t)(v >> (8 * i));
    return 9;
}

Err readCompactSize(const uint8_t * d, size_t len, size_t & off, uint64_t & v) {
    if (!d) return Err::BadArg;
    if (off >= len) return Err::Truncated;
    uint8_t first = d[off];
    if (first < 253) { v = first; off += 1; return Err::Ok; }
    size_t need = (first == 253) ? 2 : (first == 254) ? 4 : 8;
    if (len - off - 1 < need) return Err::Truncated;
    uint64_t x = 0;
    for (size_t i = 0; i < need; i++) x |= (uint64_t)d[off + 1 + i] << (8 * i);
    /* minimal encoding: each prefix must be needed */
    if (first == 253 && x < 253)          return Err::BadCompactSize;
    if (first == 254 && x <= 0xffff)      return Err::BadCompactSize;
    if (first == 255 && x <= 0xffffffffULL) return Err::BadCompactSize;
    v = x;
    off += 1 + need;
    return Err::Ok;
}

/* read ser_vector / ser_string: returns a view into d */
static Err readSpan(const uint8_t * d, size_t len, size_t & off,
                    const uint8_t ** data, size_t * n, size_t maxLen) {
    uint64_t l;
    Err e = readCompactSize(d, len, off, l);
    if (e != Err::Ok) return e;
    if (l > maxLen) return Err::TooLarge;
    if (l > len - off) return Err::Truncated;
    *data = d + off;
    *n = (size_t)l;
    off += (size_t)l;
    return Err::Ok;
}

static void appendCompactSize(std::vector<uint8_t> & out, uint64_t v) {
    uint8_t b[9];
    size_t n = writeCompactSize(v, b, sizeof(b));
    out.insert(out.end(), b, b + n);
}
static void appendSpan(std::vector<uint8_t> & out, const uint8_t * d, size_t n) {
    appendCompactSize(out, n);
    if (n) out.insert(out.end(), d, d + n);
}
static void appendString(std::vector<uint8_t> & out, const std::string & s) {
    appendSpan(out, (const uint8_t *)s.data(), s.size());
}

/* ── KDF ─────────────────────────────────────────────────────────────────── */

const char * networkGenesis(const ChainNetwork * net) {
    return chainNetworkIsTestnet(net) ? "000000c710413a4265a996d30c86043aedef6a563900f1bc43fea61d5b2dc77d"
                                      : "00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806";
}

static Err contextPrefix(const char * domain, const std::string & genesis, std::vector<uint8_t> & bytes) {
    if (!validChallenge(genesis)) return Err::BadField;
    uint8_t network[32];
    hexDecode(genesis.c_str(), genesis.size(), network, sizeof(network), NULL);
    appendString(bytes, domain);
    bytes.insert(bytes.end(), network, network + 32);
    return Err::Ok;
}

Err transportContext(TransportUse use, const std::string & genesis, EnvelopeContext & out) {
    std::vector<uint8_t> bytes;
    Err e = contextPrefix(use == TransportUse::Reply ? "Neurai/DePIN/reply/v3" : "Neurai/DePIN/submit/v3", genesis, bytes);
    if (e == Err::Ok) sha256(bytes.data(), bytes.size(), out.data());
    return e;
}

static void commitment(const EnvelopeContext & context, const uint8_t key[32], uint8_t out[32]) {
    SHA256 hash;
    hash.begin();
    const char domain[] = "Neurai/DePIN/commit/v3";
    hash.write(sizeof(domain) - 1);
    hash.write((const uint8_t *)domain, sizeof(domain) - 1);
    hash.write(context.data(), context.size());
    hash.write(key, 32);
    hash.end(out);
}

static void deriveWrapKey(const EnvelopeContext & context, const uint8_t secret[32], const uint8_t eph[33],
                          const std::vector<uint8_t> & id, uint8_t out[32]) {
    uint8_t prk[32];
    sha256Hmac(context.data(), 32, secret, 32, prk);
    std::vector<uint8_t> info;
    appendString(info, "Neurai/DePIN/wrap/v3");
    appendSpan(info, eph, 33);
    appendSpan(info, id.data(), id.size());
    info.push_back(1);  // First HKDF-Expand block
    sha256Hmac(prk, 32, info.data(), info.size(), out);
    secureWipe(prk, sizeof(prk));
}

/* ── keys ────────────────────────────────────────────────────────────────── */

static bool scalarInRange(const uint8_t secret[32]) {
    bignum256 d;
    bn_read_be(secret, &d);
    bool ok = !bn_is_zero(&d) && bn_is_less(&d, &secp256k1.order);
    secureWipe(&d, sizeof(d));
    return ok;
}

Err loadPrivateKey(const std::string & wifOrHex, PrivateKey & out, bool * compressed) {
    if (wifOrHex.empty()) return Err::BadArg;
    if (wifOrHex.size() == 64) {
        uint8_t secret[32];
        Err e;
        if (hexDecode(wifOrHex.c_str(), 64, secret, sizeof(secret), &e) != 32) return Err::BadPrivKey;
        if (!scalarInRange(secret)) { secureWipe(secret, sizeof(secret)); return Err::BadPrivKey; }
        out = PrivateKey(secret, true, &DEFAULT_NETWORK);
        secureWipe(secret, sizeof(secret));
        if (compressed) *compressed = true;
        return Err::Ok;
    }
    /* WIF: base58check → version || 32 bytes || [0x01]. Validate the scalar
     * before PrivateKey::fromWIF() multiplies by G. */
    uint8_t raw[40];
    size_t l = fromBase58Check(wifOrHex.c_str(), wifOrHex.size(), raw, sizeof(raw));
    if (l != 33 && l != 34) { secureWipe(raw, sizeof(raw)); return Err::BadPrivKey; }
    if (l == 34 && raw[33] != 0x01) { secureWipe(raw, sizeof(raw)); return Err::BadPrivKey; }
    bool known = false;
    for (uint8_t i = 0; i < networks_len; i++) if (raw[0] == networks[i]->wif) known = true;
    if (!known || !scalarInRange(raw + 1)) { secureWipe(raw, sizeof(raw)); return Err::BadPrivKey; }
    secureWipe(raw, sizeof(raw));
    if (!out.fromWIF(wifOrHex.c_str(), wifOrHex.size())) return Err::BadPrivKey;
    if (compressed) *compressed = (l == 34);
    return Err::Ok;
}

/* Independent on-curve check of a compressed SEC key, straight on the 33
 * bytes with trezor's reader (x < p, y² == x³ + 7, not infinity), plus a
 * serialisation round trip so the PublicKey object really holds that point. */
Err loadPublicKey(const uint8_t * sec, size_t len, PublicKey & out) {
    if (!sec || !((len == 33 && (sec[0] == 2 || sec[0] == 3)) || (len == 65 && sec[0] == 4)))
        return Err::BadPubKey;
    curve_point cp;
    if (!ecdsa_read_pubkey(&secp256k1, sec, &cp)) return Err::BadPubKey;
    PublicKey parsed(sec);
    parsed.compressed = len == 33;
    uint8_t back[65];
    if (!parsed.isValid() || parsed.sec(back, sizeof(back)) != len || memcmp(back, sec, len)) return Err::BadPubKey;
    out = parsed;
    return Err::Ok;
}

Err loadPublicKey(const std::string & hex, PublicKey & out) {
    uint8_t sec[65];
    if (hex.size() != 66 && hex.size() != 130) return Err::BadPubKey;
    size_t n = hexDecode(hex.c_str(), hex.size(), sec, sizeof(sec), NULL);
    return loadPublicKey(sec, n, out);
}

static Err recipientId(const PublicKey & pub, const std::string & address, const ChainNetwork * net,
                       std::vector<uint8_t> & id) {
    uint8_t sec[65];
    size_t n = pub.sec(sec, sizeof(sec));
    if (n != 33 && n != 65) return Err::BadPubKey;
    if (!address.empty()) {
        if (address.size() > 64 || address.find(char(0)) != std::string::npos) return Err::BadField;
        uint8_t version, program[32];
        bool testnet;
        if (authScriptAddressDecode(address.c_str(), &version, &testnet, program)) {
            id.resize(33);
            id[0] = 3;
            if (address.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos || version != 3 || n != 33 || (net && testnet != chainNetworkIsTestnet(net)) ||
                !ecdsaCommitmentFromPubKey(sec, id.data()+1) || memcmp(program, id.data()+1, 32)) return Err::BadPubKey;
            return Err::Ok;
        }
    }
    id.resize(21);
    id[0] = 0;
    hash160(sec, n, id.data()+1);
    if (address.empty()) return Err::Ok;
    if (address.find_first_not_of("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") != std::string::npos) return Err::BadPubKey;
    uint8_t payload[21];
    if (fromBase58Check(address.c_str(), address.size(), payload, sizeof(payload)) != 21 ||
        (net ? payload[0] != net->p2pkh : payload[0] != Neurai.p2pkh && payload[0] != NeuraiTest.p2pkh) ||
        memcmp(payload+1, id.data()+1, 20)) return Err::BadPubKey;
    return Err::Ok;
}

bool pubKeyMatchesAddress(const PublicKey & pub, const std::string & address, const ChainNetwork * net) {
    std::vector<uint8_t> id;
    return !address.empty() && recipientId(pub, address, net, id) == Err::Ok;
}

/* ECDH: SHA256(compressed(d·Q)) — libsecp256k1's default hash function. */
static Err ecdhSecret(const PrivateKey & d, const PublicKey & Q, uint8_t out[32]) {
    ECPoint shared = d * Q;
    shared.compressed = true;
    if (!shared.isValid()) return Err::Crypto;
    uint8_t sec[33];
    if (shared.sec(sec, 33) != 33) return Err::Crypto;
    sha256(sec, 33, out);
    secureWipe(sec, sizeof(sec));
    return Err::Ok;
}

/* ── ECIES parse ─────────────────────────────────────────────────────────── */

Err eciesParse(const uint8_t * data, size_t len, EciesView & view, const Limits & lim) {
    view = EciesView();
    if (!data || len == 0) return Err::BadArg;
    if (len > lim.maxPayload) return Err::TooLarge;
    if (len < 2 || data[0] != 0 || data[1] != 3) return Err::ProtocolMismatch;
    size_t off = 2;
    Err e;
    const uint8_t * eph; size_t ephLen;
    if ((e = readSpan(data, len, off, &eph, &ephLen, 65)) != Err::Ok) return e;
    if (ephLen != 33) return Err::BadEphemeral;
    {
        PublicKey p;
        if (loadPublicKey(eph, 33, p) != Err::Ok) return Err::BadEphemeral;
    }
    if (len - off < 32) return Err::Truncated;
    const uint8_t * committed = data + off;
    off += 32;
    const uint8_t * pl; size_t plLen;
    if ((e = readSpan(data, len, off, &pl, &plLen, lim.maxPayload)) != Err::Ok) return e;
    if (plLen <= DEPIN_ECIES_NONCE_LEN + DEPIN_ECIES_TAG_LEN) return Err::BadPayload;
    if (plLen - 28 > std::min<size_t>(lim.maxContent, 4 * 1024 * 1024)) return Err::TooLarge;

    uint64_t count;
    if ((e = readCompactSize(data, len, off, count)) != Err::Ok) return e;
    if (count == 0) return Err::BadRecipientEntry;
    if (count > 50 || count > lim.maxRecipients) return Err::TooManyRecipients;

    const uint8_t * entries = data + off;
    const uint8_t * prevKey = NULL;
    for (uint64_t i = 0; i < count; ++i) {
        if (off >= len) return Err::Truncated;
        const uint8_t * key = data + off;
        if (*key != 0 && *key != 3) return Err::BadRecipientEntry;
        const size_t n = *key == 0 ? 21 : 33;
        if (len - off < n) return Err::Truncated;
        if (prevKey) {
            int order = *prevKey == *key ? memcmp(prevKey, key, n) : int(*prevKey) - int(*key);
            if (order == 0) return Err::DuplicateRecipient;
            if (order > 0) return Err::RecipientOrder;
        }
        prevKey = key;
        off += n;
        const uint8_t * pkg; size_t pkgLen;
        if ((e = readSpan(data, len, off, &pkg, &pkgLen, 60)) != Err::Ok) return e;
        if (pkgLen != 60) return Err::BadRecipientEntry;
    }
    if (off != len) return Err::TrailingBytes;

    view.commitment = committed;
    view.ephemeral = eph;
    view.payload = pl;
    view.payloadLen = plLen;
    view.recipientCount = (size_t)count;
    view.entries = entries;
    view.entriesLen = (size_t)(data + len - entries);
    return Err::Ok;
}

const uint8_t * eciesFindEntry(const EciesView & view, const uint8_t * wireId, size_t idLen) {
    const uint8_t * p = view.entries;
    for (size_t i = 0; i < view.recipientCount; ++i) {
        size_t n = *p == 3 ? 33 : 21;
        if (n == idLen && memcmp(p, wireId, n) == 0) return p+n+1;
        p += n+1+DEPIN_ECIES_ENTRY_LEN;
    }
    return NULL;
}

/* ── ECIES decrypt ───────────────────────────────────────────────────────── */

namespace {
class PrivateIdentity : public IdentityProvider {
public:
    explicit PrivateIdentity(const PrivateKey & key) : key_(key) {}
    Err publicKey(uint8_t out[33]) const override {
        PublicKey pub = key_.publicKey(); pub.compressed = true;
        if (!pub.isValid()) return Err::BadPrivKey;
        return pub.sec(out, 33) == 33 ? Err::Ok : Err::Crypto;
    }
    Err signDigest(const uint8_t digest[32], uint8_t der[72], size_t & length) const override {
        length = 0;
        Signature sig = key_.sign(digest);
        if (!sig.isValid()) return Err::Crypto;
        length = sig.der(der, 72);
        return length ? Err::Ok : Err::Crypto;
    }
    Err ecdh(const uint8_t peer[33], uint8_t secret[32]) const override {
        PublicKey pub;
        Err e = loadPublicKey(peer, 33, pub);
        return e == Err::Ok ? ecdhSecret(key_, pub, secret) : e;
    }
private:
    const PrivateKey & key_;
};
} // namespace

Err eciesDecrypt(const uint8_t * data, size_t len, const IdentityProvider & identity,
                 const EnvelopeContext & context, const std::string & address,
                 uint8_t * plaintext, size_t capacity, size_t & written, const Limits & lim) {
    written = 0;
    const CryptoBackend * cb = cryptoBackend();
    if (!cb) return Err::NoCryptoBackend;
    EciesView v;
    Err e = eciesParse(data, len, v, lim);
    if (e != Err::Ok) return e;
    const size_t ctLen = v.payloadLen - DEPIN_ECIES_NONCE_LEN - DEPIN_ECIES_TAG_LEN;
    if (ctLen > lim.maxContent || ctLen > capacity) return Err::TooLarge;
    if (ctLen && !plaintext) return Err::BadArg;
    uint8_t sec[33];
    if ((e = identity.publicKey(sec)) != Err::Ok) return e;
    PublicKey mine;
    if (loadPublicKey(sec, 33, mine) != Err::Ok) return Err::BadPubKey;
    std::vector<uint8_t> id;
    if (address.empty()) return Err::BadField;
    if (recipientId(mine, address, NULL, id) != Err::Ok) {
        mine.compressed = false;
        if (recipientId(mine, address, NULL, id) != Err::Ok) return Err::BadPubKey;
    }
    const uint8_t * entry = eciesFindEntry(v, id.data(), id.size());
    if (!entry) return Err::NotForRecipient;

    uint8_t secret[32] = {}, wrapKey[32], contentKey[32];
    e = identity.ecdh(v.ephemeral, secret);
    if (e != Err::Ok) { secureWipe(secret, sizeof(secret)); return e; }
    deriveWrapKey(context, secret, v.ephemeral, id, wrapKey);
    secureWipe(secret, sizeof(secret));
    bool ok = cb->aesGcmDecrypt(wrapKey, entry, NULL, 0, entry + 12, 32, entry + 44, contentKey);
    secureWipe(wrapKey, sizeof(wrapKey));
    if (!ok) { secureWipe(contentKey, sizeof(contentKey)); return Err::KeyUnwrapFailed; }
    uint8_t expected[32];
    commitment(context, contentKey, expected);
    unsigned difference = 0;
    for (size_t i = 0; i < 32; ++i) difference |= expected[i] ^ v.commitment[i];
    if (difference) { secureWipe(contentKey, sizeof(contentKey)); return Err::PayloadAuthFailed; }
    ok = cb->aesGcmDecrypt(contentKey, v.payload, context.data(), 32, v.payload + 12, ctLen,
                          v.payload + 12 + ctLen, plaintext);
    secureWipe(contentKey, sizeof(contentKey));
    if (!ok) { secureWipe(plaintext, ctLen); return Err::PayloadAuthFailed; }
    written = ctLen;
    return Err::Ok;
}

Err eciesDecrypt(const uint8_t * data, size_t len, const IdentityProvider & identity,
                 const EnvelopeContext & context, const std::string & address,
                 std::vector<uint8_t> & plaintext, const Limits & lim) {
    plaintext.clear();
    if (!cryptoBackend()) return Err::NoCryptoBackend;
    EciesView v;
    Err e = eciesParse(data, len, v, lim);
    if (e != Err::Ok) return e;
    const size_t count = v.payloadLen - DEPIN_ECIES_NONCE_LEN - DEPIN_ECIES_TAG_LEN;
    if (count > lim.maxContent) return Err::TooLarge;
    plaintext.resize(count);
    size_t written;
    e = eciesDecrypt(data, len, identity, context, address, plaintext.data(), plaintext.size(), written, lim);
    if (e != Err::Ok) { secureWipe(plaintext.data(), plaintext.size()); plaintext.clear(); }
    return e;
}

Err eciesDecrypt(const uint8_t * data, size_t len, const PrivateKey & key,
                 const EnvelopeContext & context, const std::string & address,
                 std::vector<uint8_t> & plaintext, const Limits & lim) {
    return eciesDecrypt(data, len, PrivateIdentity(key), context, address, plaintext, lim);
}

/* ── ECIES encrypt ───────────────────────────────────────────────────────── */

struct Recipient {
    std::vector<uint8_t> id;
    PublicKey key;
};
static bool recipientLess(const Recipient & a, const Recipient & b) { return a.id < b.id; }

Err eciesEncrypt(const uint8_t * plaintext, size_t len,
                 const RecipientKeys & recipientPubKeys, const EnvelopeContext & context,
                 std::vector<uint8_t> & envelope, const Limits & lim) {
    envelope.clear();
    const CryptoBackend * cb = cryptoBackend();
    if (!cb) return Err::NoCryptoBackend;
    if (!plaintext && len) return Err::BadArg;
    if (len == 0) return Err::BadField;
    if (len > std::min<size_t>(lim.maxContent, 4 * 1024 * 1024)) return Err::TooLarge;
    if (recipientPubKeys.empty()) return Err::BadArg;

    /* validate + canonicalise recipients */
    std::vector<Recipient> rs;
    rs.reserve(recipientPubKeys.size());
    for (size_t i = 0; i < recipientPubKeys.size(); i++) {
        PublicKey p;
        Err e = loadPublicKey(recipientPubKeys[i].sec.data(), recipientPubKeys[i].sec.size(), p);
        if (e != Err::Ok) return e;
        Recipient r;
        r.key = p;
        if ((e = recipientId(p, recipientPubKeys[i].address, NULL, r.id)) != Err::Ok) return e;
        rs.push_back(r);
    }
    std::sort(rs.begin(), rs.end(), recipientLess);
    for (size_t i = 1; i < rs.size(); ) {
        if (rs[i-1].id == rs[i].id) rs.erase(rs.begin() + i); else i++;
    }
    if (rs.size() > 50 || rs.size() > lim.maxRecipients) return Err::TooManyRecipients;

    /* ephemeral key, content key and payload nonce from the CSPRNG */
    uint8_t ephSecret[32], contentKey[32], nonce[12];
    Err result = Err::Ok;
    std::vector<uint8_t> ct;
    std::vector<uint8_t> out;
    do {
        int tries = 0;
        do {
            if (!cb->randomBytes(ephSecret, 32)) { result = Err::Rng; break; }
        } while (!scalarInRange(ephSecret) && ++tries < 8);
        if (result != Err::Ok) break;
        if (!scalarInRange(ephSecret)) { result = Err::Rng; break; }
        if (!cb->randomBytes(contentKey, 32) || !cb->randomBytes(nonce, 12)) { result = Err::Rng; break; }

        PrivateKey eph(ephSecret, true, &DEFAULT_NETWORK);
        PublicKey ephPub = eph.publicKey();
        ephPub.compressed = true;
        uint8_t ephSec[33];
        if (!ephPub.isValid() || ephPub.sec(ephSec, 33) != 33) { result = Err::Crypto; break; }

        /* payload */
        ct.resize(len);
        uint8_t tag[16];
        if (!cb->aesGcmEncrypt(contentKey, nonce, context.data(), 32, plaintext, len, ct.data(), tag)) { result = Err::Crypto; break; }

        out.reserve(114 + len + rs.size() * 94);
        out.push_back(0);
        out.push_back(3);
        appendSpan(out, ephSec, 33);
        uint8_t committed[32];
        commitment(context, contentKey, committed);
        out.insert(out.end(), committed, committed + 32);
        appendCompactSize(out, 12 + len + 16);
        out.insert(out.end(), nonce, nonce + 12);
        out.insert(out.end(), ct.begin(), ct.end());
        out.insert(out.end(), tag, tag + 16);
        appendCompactSize(out, rs.size());

        /* one wrapped copy of the content key per recipient */
        for (size_t i = 0; i < rs.size() && result == Err::Ok; i++) {
            uint8_t secret[32], wrapKey[32], eNonce[12], wrapped[32], wTag[16];
            Err e = ecdhSecret(eph, rs[i].key, secret);
            if (e != Err::Ok) { result = e; break; }
            deriveWrapKey(context, secret, ephSec, rs[i].id, wrapKey);
            secureWipe(secret, sizeof(secret));
            if (!cb->randomBytes(eNonce, 12)) { secureWipe(wrapKey, 32); result = Err::Rng; break; }
            bool ok = cb->aesGcmEncrypt(wrapKey, eNonce, NULL, 0, contentKey, 32, wrapped, wTag);
            secureWipe(wrapKey, sizeof(wrapKey));
            if (!ok) { result = Err::Crypto; break; }
            out.insert(out.end(), rs[i].id.begin(), rs[i].id.end());
            appendCompactSize(out, DEPIN_ECIES_ENTRY_LEN);
            out.insert(out.end(), eNonce, eNonce + 12);
            out.insert(out.end(), wrapped, wrapped + 32);
            out.insert(out.end(), wTag, wTag + 16);
        }
    } while (0);

    secureWipe(ephSecret, sizeof(ephSecret));
    secureWipe(contentKey, sizeof(contentKey));
    if (result != Err::Ok) { if (!out.empty()) secureWipe(out.data(), out.size()); return result; }
    if (out.size() > lim.maxPayload) { secureWipe(out.data(), out.size()); return Err::TooLarge; }
    envelope.swap(out);
    return Err::Ok;
}

/* ── CDepinMessage ───────────────────────────────────────────────────────── */

std::string DepinMessage::hash() const {
    uint8_t rev[32];
    for (int i = 0; i < 32; i++) rev[i] = digest[31 - i];
    return hexEncode(rev, 32);
}

static Err checkFields(const DepinMessage & m, const Limits & lim) {
    if (m.token.empty() || m.token.size() > std::min<size_t>(120, lim.maxToken)) return Err::BadField;
    if (m.sender.empty() || m.sender.size() > std::min<size_t>(64, lim.maxAddress)) return Err::BadField;
    if (m.timestamp <= 0) return Err::BadTimestamp;
    if (m.type != DEPIN_TYPE_PRIVATE && m.type != DEPIN_TYPE_GROUP) return Err::BadMessageType;
    if (m.payload.empty() || m.payload.size() > std::min<size_t>(16384, lim.maxPayload)) return Err::BadPayload;
    return Err::Ok;
}

static Err checkMessageEnvelope(const DepinMessage & m, const Limits & lim) {
    Limits bounds = lim;
    bounds.maxContent = std::min<size_t>(10240, bounds.maxContent);
    EciesView view;
    return eciesParse(m.payload.data(), m.payload.size(), view, bounds);
}

/* The message header shared by the wire encoding and the envelope context. */
static void serializeHeader(const DepinMessage & m, std::vector<uint8_t> & out) {
    appendString(out, m.token);
    appendString(out, m.sender);
    uint64_t ts = (uint64_t)m.timestamp;
    for (int i = 0; i < 8; i++) out.push_back((uint8_t)(ts >> (8 * i)));
    out.push_back(m.type);
}

Err messageContext(const DepinMessage & m, EnvelopeContext & out) {
    std::vector<uint8_t> bytes;
    Err e = contextPrefix("Neurai/DePIN/message/v3", m.genesis, bytes);
    if (e != Err::Ok) return e;
    serializeHeader(m, bytes);
    sha256(bytes.data(), bytes.size(), out.data());
    return Err::Ok;
}

static Err computeDigest(const DepinMessage & m, uint8_t digest[32]) {
    EnvelopeContext context;
    Err e = messageContext(m, context);
    if (e != Err::Ok) return e;
    uint8_t size[9];
    size_t n = writeCompactSize(m.payload.size(), size, sizeof(size));
    DoubleSha hash;
    hash.begin();
    hash.write(context.data(), context.size());
    hash.write(size, n);
    hash.write(m.payload.data(), m.payload.size());
    hash.end(digest);
    return Err::Ok;
}

Err messageDigest(DepinMessage & m, const Limits & lim) {
    Err e = checkFields(m, lim);
    return e == Err::Ok ? computeDigest(m, m.digest) : e;
}

Err messageSerialize(const DepinMessage & m, std::vector<uint8_t> & out, const Limits & lim) {
    out.clear();
    Err e = checkFields(m, lim);
    if (e != Err::Ok) return e;
    if (m.signature.empty() || m.signature.size() > std::min<size_t>(80, lim.maxSignature)) return Err::BadSignature;
    if ((e = checkMessageEnvelope(m, lim)) != Err::Ok) return e;
    out.reserve(m.token.size() + m.sender.size() + m.payload.size() + m.signature.size() + 32);
    serializeHeader(m, out);
    appendSpan(out, m.payload.data(), m.payload.size());
    appendSpan(out, m.signature.data(), m.signature.size());
    if (out.size() > 16384) { out.clear(); return Err::TooLarge; }
    return Err::Ok;
}

Err messageParse(const uint8_t * data, size_t len, const std::string & genesis, DepinMessage & out, const Limits & lim) {
    if (!data || len == 0) return Err::BadArg;
    if (len > 16384) return Err::TooLarge;
    size_t off = 0;
    Err e;
    const uint8_t * p; size_t n;
    if ((e = readSpan(data, len, off, &p, &n, lim.maxToken)) != Err::Ok) return e;
    out.genesis = genesis;
    out.token.assign((const char *)p, n);
    if ((e = readSpan(data, len, off, &p, &n, lim.maxAddress)) != Err::Ok) return e;
    out.sender.assign((const char *)p, n);
    if (len - off < 8) return Err::Truncated;
    uint64_t ts = 0;
    for (int i = 0; i < 8; i++) ts |= (uint64_t)data[off + i] << (8 * i);
    off += 8;
    if (ts > (uint64_t)INT64_MAX) return Err::BadTimestamp;
    out.timestamp = (int64_t)ts;
    if (len - off < 1) return Err::Truncated;
    out.type = data[off++];
    if ((e = readSpan(data, len, off, &p, &n, lim.maxPayload)) != Err::Ok) return e;
    out.payload.assign(p, p + n);
    if ((e = readSpan(data, len, off, &p, &n, lim.maxSignature)) != Err::Ok) return e;
    out.signature.assign(p, p + n);
    if (off != len) return Err::TrailingBytes;
    if (out.signature.empty()) return Err::BadSignature;
    if ((e = checkMessageEnvelope(out, lim)) != Err::Ok) return e;
    return messageDigest(out, lim);
}

/* Strict DER (r, s) parse: SEQUENCE { INTEGER r, INTEGER s }, minimal
 * lengths, no negative values, r and s < n. Fills r/s as 32-byte big-endian. */
static bool derToRS(const uint8_t * der, size_t len, uint8_t r[32], uint8_t s[32]) {
    if (!der || len < 8 || len > 72) return false;
    if (der[0] != 0x30 || der[1] != len - 2) return false;
    size_t off = 2;
    uint8_t * outs[2] = { r, s };
    for (int k = 0; k < 2; k++) {
        if (off + 2 > len || der[off] != 0x02) return false;
        size_t l = der[off + 1];
        off += 2;
        if (l == 0 || l > 33 || off + l > len) return false;
        const uint8_t * v = der + off;
        if (v[0] & 0x80) return false;                        /* negative */
        if (l > 1 && v[0] == 0x00 && !(v[1] & 0x80)) return false; /* non-minimal */
        if (l == 33 && v[0] != 0x00) return false;
        size_t start = (l == 33) ? 1 : 0;
        size_t vl = l - start;
        memset(outs[k], 0, 32);
        memcpy(outs[k] + 32 - vl, v + start, vl);
        off += l;
    }
    if (off != len) return false;
    bignum256 x;
    for (int k = 0; k < 2; k++) {
        bn_read_be(outs[k], &x);
        if (bn_is_zero(&x) || !bn_is_less(&x, &secp256k1.order)) return false;
    }
    return true;
}

Err messageVerify(const DepinMessage & m, const PublicKey & senderPub, const char * expectedHashHex) {
    if (!pubKeyMatchesAddress(senderPub, m.sender)) return Err::BadPubKey;
    Limits wireLimits;
    wireLimits.maxContent = 10240;
    Err e = checkFields(m, wireLimits);
    if (e != Err::Ok) return e;
    if ((e = checkMessageEnvelope(m, wireLimits)) != Err::Ok) return e;
    uint8_t digest[32];
    e = computeDigest(m, digest);
    if (e != Err::Ok) return e;
    if (memcmp(digest, m.digest, 32)) return Err::HashMismatch;
    if (expectedHashHex) {
        std::string h = m.hash();
        if (strlen(expectedHashHex) != 64) return Err::HashMismatch;
        for (size_t i = 0; i < 64; i++) {
            char c = expectedHashHex[i];
            if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
            if (c != h[i]) return Err::HashMismatch;
        }
    }
    uint8_t r[32], s[32];
    if (!derToRS(m.signature.data(), m.signature.size(), r, s)) return Err::BadSignature;
    /* node normalises high-S before verifying; producers emit low-S */
    bignum256 sn;
    bn_read_be(s, &sn);
    if (bn_is_less(&secp256k1.order_half, &sn)) {
        bn_subtract(&secp256k1.order, &sn, &sn);
        bn_write_be(&sn, s);
    }
    Signature sig(r, s);
    return senderPub.verify(sig, m.digest) ? Err::Ok : Err::SignatureInvalid;
}

Err messageSign(DepinMessage & m, const PrivateKey & senderKey, const Limits & lim) {
    return messageSign(m, PrivateIdentity(senderKey), lim);
}

Err messageBuild(const std::string & genesis, const std::string & token, const std::string & senderAddress,
                 int64_t timestamp, uint8_t type, const uint8_t * content, size_t contentLen,
                 const RecipientKeys & recipients, const PrivateKey & senderKey, DepinMessage & out, const Limits & lim) {
    return messageBuild(genesis, token, senderAddress, timestamp, type, content, contentLen,
                        recipients, PrivateIdentity(senderKey), out, lim);
}

Err messageSign(DepinMessage & m, const IdentityProvider & identity, const Limits & lim) {
    m.signature.clear();
    if (!validToken(m.token, lim)) return Err::BadField;
    Err e = checkMessageEnvelope(m, lim);
    if (e != Err::Ok) return e;
    e = messageDigest(m, lim);
    if (e != Err::Ok) return e;
    uint8_t sec[33];
    if ((e = identity.publicKey(sec)) != Err::Ok) return e;
    PublicKey pub;
    if (loadPublicKey(sec, 33, pub) != Err::Ok) return Err::BadPubKey;
    if (!pubKeyMatchesAddress(pub, m.sender)) {
        pub.compressed = false;
        if (!pubKeyMatchesAddress(pub, m.sender)) return Err::BadPubKey;
    }
    uint8_t der[72] = {};
    size_t length = 0;
    if ((e = identity.signDigest(m.digest, der, length)) != Err::Ok) return e;
    if (!length || length > sizeof(der) || length > lim.maxSignature) return Err::BadSignature;
    m.signature.assign(der, der + length);
    e = messageVerify(m, pub);
    if (e != Err::Ok) m.signature.clear();
    return e;
}

Err messageBuild(const std::string & genesis, const std::string & token, const std::string & senderAddress,
                 int64_t timestamp, uint8_t type, const uint8_t * content, size_t contentLen,
                 const RecipientKeys & recipients,
                 const IdentityProvider & identity, DepinMessage & out, const Limits & lim) {
    out = DepinMessage();
    if (!validToken(token, lim)) return Err::BadField;
    DepinMessage message;
    message.genesis = genesis;
    message.token = token;
    message.sender = senderAddress;
    message.timestamp = timestamp;
    message.type = type;
    if (timestamp <= 0) return Err::BadTimestamp;
    if (type != DEPIN_TYPE_PRIVATE && type != DEPIN_TYPE_GROUP) return Err::BadMessageType;
    if (senderAddress.empty() || senderAddress.size() > std::min<size_t>(64, lim.maxAddress)) return Err::BadField;
    EnvelopeContext context;
    Err e = messageContext(message, context);
    if (e != Err::Ok) return e;
    Limits bounds = lim;
    if (type == DEPIN_TYPE_PRIVATE) bounds.maxRecipients = std::min(size_t(2), bounds.maxRecipients);
    bounds.maxContent = std::min(size_t(10240), bounds.maxContent);
    e = eciesEncrypt(content, contentLen, recipients, context, message.payload, bounds);
    if (e != Err::Ok) return e;
    e = messageSign(message, identity, lim);
    if (e == Err::Ok) out = std::move(message);
    return e;
}

Err wrapForPool(const std::string & genesis, const std::string & messageHex, const uint8_t poolPubKey33[33],
                std::vector<uint8_t> & envelope, const Limits & lim) {
    envelope.clear();
    if (messageHex.empty() || !poolPubKey33) return Err::BadArg;
    /* the pool decrypts to the ASCII hex string and hex-decodes it itself */
    Limits l = lim;
    l.maxContent = std::max(lim.maxContent, messageHex.size());
    l.maxPayload = std::max(lim.maxPayload, messageHex.size() + 256);
    if (messageHex.size() > 32768 || messageHex.size() % 2 || messageHex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        return Err::BadField;
    EnvelopeContext context;
    Err e = transportContext(TransportUse::Submit, genesis, context);
    if (e != Err::Ok) return e;
    RecipientKeys rcpt = {{std::vector<uint8_t>(poolPubKey33, poolPubKey33 + 33), ""}};
    return eciesEncrypt((const uint8_t *)messageHex.data(), messageHex.size(), rcpt, context, envelope, l);
}

} // namespace depin
