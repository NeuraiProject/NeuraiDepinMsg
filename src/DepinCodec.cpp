#include "DepinCodec.h"
#include "Hash.h"
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

const CryptoBackend * cryptoBackend() {
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

void kdfSha256(const uint8_t * secret, size_t secretLen, uint8_t * out, size_t outLen) {
    uint32_t counter = 1;
    size_t done = 0;
    while (done < outLen) {
        uint8_t c[4] = { (uint8_t)(counter >> 24), (uint8_t)(counter >> 16), (uint8_t)(counter >> 8), (uint8_t)counter };
        SHA256 h;
        h.begin();
        h.write(secret, secretLen);
        h.write(c, 4);
        uint8_t block[32];
        h.end(block);
        size_t take = std::min((size_t)32, outLen - done);
        memcpy(out + done, block, take);
        secureWipe(block, sizeof(block));
        done += take;
        counter++;
    }
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
static bool compressedPointValid(const uint8_t * sec33) {
    if (sec33[0] != 0x02 && sec33[0] != 0x03) return false;
    curve_point cp;
    return ecdsa_read_pubkey(&secp256k1, sec33, &cp) == 1;
}

Err loadPublicKey(const uint8_t * sec33, size_t len, PublicKey & out) {
    if (!sec33) return Err::BadArg;
    if (len != 33 || !compressedPointValid(sec33)) return Err::BadPubKey;
    PublicKey p(sec33);
    p.compressed = true;
    if (!p.isValid()) return Err::BadPubKey;
    uint8_t back[33];
    if (p.sec(back, 33) != 33 || memcmp(back, sec33, 33) != 0) return Err::BadPubKey;
    out = p;
    return Err::Ok;
}

Err loadPublicKey(const std::string & hex, PublicKey & out) {
    uint8_t sec[33];
    Err e;
    size_t n = hexDecode(hex.c_str(), hex.size(), sec, sizeof(sec), &e);
    if (e != Err::Ok) return (e == Err::TooLarge) ? Err::BadPubKey : e;
    return loadPublicKey(sec, n, out);
}

bool pubKeyMatchesAddress(const PublicKey & pub, const std::string & address, const ChainNetwork * net) {
    if (address.empty() || address.size() > 64 || !pub.isValid()) return false;
    uint8_t payload[25];
    size_t l = fromBase58Check(address.c_str(), address.size(), payload, sizeof(payload));
    if (l != 21) return false;
    bool prefixOk = false;
    if (net) prefixOk = (payload[0] == net->p2pkh);
    else for (uint8_t i = 0; i < networks_len; i++) if (payload[0] == networks[i]->p2pkh) prefixOk = true;
    if (!prefixOk) return false;
    PublicKey p = pub;
    p.compressed = true;
    uint8_t sec[33], h[20];
    if (p.sec(sec, 33) != 33) return false;
    hash160(sec, 33, h);
    return memcmp(payload + 1, h, 20) == 0;
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
    if (!data || len == 0) return Err::BadArg;
    if (len > lim.maxPayload) return Err::TooLarge;
    size_t off = 0;
    Err e;
    const uint8_t * eph; size_t ephLen;
    if ((e = readSpan(data, len, off, &eph, &ephLen, 65)) != Err::Ok) return e;
    if (ephLen != 33) return Err::BadEphemeral;
    {
        PublicKey p;
        if (loadPublicKey(eph, 33, p) != Err::Ok) return Err::BadEphemeral;
    }
    const uint8_t * pl; size_t plLen;
    if ((e = readSpan(data, len, off, &pl, &plLen, lim.maxPayload)) != Err::Ok) return e;
    if (plLen < DEPIN_ECIES_NONCE_LEN + DEPIN_ECIES_TAG_LEN) return Err::BadPayload;
    /* content = plLen - 28; the sender's plaintext cap applies on decrypt */

    uint64_t count;
    if ((e = readCompactSize(data, len, off, count)) != Err::Ok) return e;
    if (count == 0) return Err::BadRecipientEntry;
    if (count > lim.maxRecipients) return Err::TooManyRecipients;

    const uint8_t * entries = data + off;
    const uint8_t * prevKey = NULL;
    for (uint64_t i = 0; i < count; i++) {
        if (len - off < 20) return Err::Truncated;
        const uint8_t * key = data + off;
        off += 20;
        const uint8_t * pkg; size_t pkgLen;
        if ((e = readSpan(data, len, off, &pkg, &pkgLen, 255)) != Err::Ok) return e;
        if (pkgLen != DEPIN_ECIES_ENTRY_LEN) return Err::BadRecipientEntry;
        if (prevKey) {
            int c = memcmp(prevKey, key, 20);
            if (c == 0) return Err::DuplicateRecipient;
            if (c > 0)  return Err::RecipientOrder;      /* node: std::map<uint160> bytewise */
        }
        prevKey = key;
    }
    if (off != len) return Err::TrailingBytes;

    view.ephemeral = eph;
    view.payload = pl;
    view.payloadLen = plLen;
    view.recipientCount = (size_t)count;
    view.entries = entries;
    view.entriesLen = (size_t)(data + len - entries);
    return Err::Ok;
}

const uint8_t * eciesFindEntry(const EciesView & view, const uint8_t keyId[20]) {
    const uint8_t * p = view.entries;
    for (size_t i = 0; i < view.recipientCount; i++) {
        /* validated layout: key(20) || 0x3c || 60 */
        if (memcmp(p, keyId, 20) == 0) return p + 21;
        p += 21 + DEPIN_ECIES_ENTRY_LEN;
    }
    return NULL;
}

/* ── ECIES decrypt ───────────────────────────────────────────────────────── */

Err eciesDecrypt(const uint8_t * data, size_t len, const PrivateKey & key,
                 std::vector<uint8_t> & plaintext, const Limits & lim) {
    plaintext.clear();
    const CryptoBackend * cb = cryptoBackend();
    if (!cb) return Err::NoCryptoBackend;

    EciesView v;
    Err e = eciesParse(data, len, v, lim);
    if (e != Err::Ok) return e;

    /* our key id */
    PublicKey mine = key.publicKey();
    mine.compressed = true;
    if (!mine.isValid()) return Err::BadPrivKey;
    uint8_t sec[33];
    if (mine.sec(sec, 33) != 33) return Err::Crypto;
    uint8_t keyId[20];
    hash160(sec, 33, keyId);

    const uint8_t * entry = eciesFindEntry(v, keyId);
    if (!entry) return Err::NotForRecipient;

    /* unwrap the content key */
    PublicKey eph;
    if (loadPublicKey(v.ephemeral, 33, eph) != Err::Ok) return Err::BadEphemeral;
    uint8_t secret[32], wrapKey[32], contentKey[32];
    if ((e = ecdhSecret(key, eph, secret)) != Err::Ok) return e;
    kdfSha256(secret, 32, wrapKey, 32);
    secureWipe(secret, sizeof(secret));
    bool ok = cb->aesGcmDecrypt(wrapKey, entry, entry + 12, 32, entry + 12 + 32, contentKey);
    secureWipe(wrapKey, sizeof(wrapKey));
    if (!ok) { secureWipe(contentKey, sizeof(contentKey)); return Err::KeyUnwrapFailed; }

    /* decrypt the payload: nonce(12) || ct || tag(16) */
    size_t ctLen = v.payloadLen - DEPIN_ECIES_NONCE_LEN - DEPIN_ECIES_TAG_LEN;
    if (ctLen > lim.maxContent) { secureWipe(contentKey, sizeof(contentKey)); return Err::TooLarge; }
    plaintext.resize(ctLen);
    ok = cb->aesGcmDecrypt(contentKey, v.payload, v.payload + 12, ctLen,
                           v.payload + 12 + ctLen, ctLen ? plaintext.data() : NULL);
    secureWipe(contentKey, sizeof(contentKey));
    if (!ok) {
        if (ctLen) secureWipe(plaintext.data(), ctLen);
        plaintext.clear();
        return Err::PayloadAuthFailed;
    }
    return Err::Ok;
}

/* ── ECIES encrypt ───────────────────────────────────────────────────────── */

struct Recipient {
    uint8_t keyId[20];
    uint8_t sec[33];
};
static bool recipientLess(const Recipient & a, const Recipient & b) { return memcmp(a.keyId, b.keyId, 20) < 0; }

Err eciesEncrypt(const uint8_t * plaintext, size_t len,
                 const std::vector<std::vector<uint8_t> > & recipientPubKeys,
                 std::vector<uint8_t> & envelope, const Limits & lim) {
    envelope.clear();
    const CryptoBackend * cb = cryptoBackend();
    if (!cb) return Err::NoCryptoBackend;
    if (!plaintext && len) return Err::BadArg;
    if (len == 0) return Err::BadField;
    if (len > lim.maxContent) return Err::TooLarge;
    if (recipientPubKeys.empty()) return Err::BadArg;

    /* validate + canonicalise recipients */
    std::vector<Recipient> rs;
    rs.reserve(recipientPubKeys.size());
    for (size_t i = 0; i < recipientPubKeys.size(); i++) {
        PublicKey p;
        Err e = loadPublicKey(recipientPubKeys[i].data(), recipientPubKeys[i].size(), p);
        if (e != Err::Ok) return e;
        Recipient r;
        memcpy(r.sec, recipientPubKeys[i].data(), 33);
        hash160(r.sec, 33, r.keyId);
        rs.push_back(r);
    }
    std::sort(rs.begin(), rs.end(), recipientLess);
    for (size_t i = 1; i < rs.size(); ) {
        if (memcmp(rs[i - 1].keyId, rs[i].keyId, 20) == 0) rs.erase(rs.begin() + i); else i++;
    }
    if (rs.size() > lim.maxRecipients) return Err::TooManyRecipients;

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
        if (!cb->aesGcmEncrypt(contentKey, nonce, plaintext, len, ct.data(), tag)) { result = Err::Crypto; break; }

        out.reserve(34 + 3 + 12 + len + 16 + 9 + rs.size() * 81);
        appendSpan(out, ephSec, 33);
        appendCompactSize(out, 12 + len + 16);
        out.insert(out.end(), nonce, nonce + 12);
        out.insert(out.end(), ct.begin(), ct.end());
        out.insert(out.end(), tag, tag + 16);
        appendCompactSize(out, rs.size());

        /* one wrapped copy of the content key per recipient */
        for (size_t i = 0; i < rs.size() && result == Err::Ok; i++) {
            PublicKey rp;
            if (loadPublicKey(rs[i].sec, 33, rp) != Err::Ok) { result = Err::BadPubKey; break; }
            uint8_t secret[32], wrapKey[32], eNonce[12], wrapped[32], wTag[16];
            Err e = ecdhSecret(eph, rp, secret);
            if (e != Err::Ok) { result = e; break; }
            kdfSha256(secret, 32, wrapKey, 32);
            secureWipe(secret, sizeof(secret));
            if (!cb->randomBytes(eNonce, 12)) { secureWipe(wrapKey, 32); result = Err::Rng; break; }
            bool ok = cb->aesGcmEncrypt(wrapKey, eNonce, contentKey, 32, wrapped, wTag);
            secureWipe(wrapKey, sizeof(wrapKey));
            if (!ok) { result = Err::Crypto; break; }
            out.insert(out.end(), rs[i].keyId, rs[i].keyId + 20);
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
    if (m.token.empty() || m.token.size() > lim.maxToken) return Err::BadField;
    if (m.sender.empty() || m.sender.size() > lim.maxAddress) return Err::BadField;
    if (m.timestamp < 0) return Err::BadTimestamp;
    if (m.type != DEPIN_TYPE_PRIVATE && m.type != DEPIN_TYPE_GROUP) return Err::BadMessageType;
    if (m.payload.empty() || m.payload.size() > lim.maxPayload) return Err::BadPayload;
    return Err::Ok;
}

/* the five signed fields (§5.2) */
static void serializeBody(const DepinMessage & m, std::vector<uint8_t> & out) {
    appendString(out, m.token);
    appendString(out, m.sender);
    uint64_t ts = (uint64_t)m.timestamp;
    for (int i = 0; i < 8; i++) out.push_back((uint8_t)(ts >> (8 * i)));
    out.push_back(m.type);
    appendSpan(out, m.payload.data(), m.payload.size());
}

Err messageDigest(DepinMessage & m, const Limits & lim) {
    Err e = checkFields(m, lim);
    if (e != Err::Ok) return e;
    std::vector<uint8_t> body;
    body.reserve(m.token.size() + m.sender.size() + m.payload.size() + 32);
    serializeBody(m, body);
    doubleSha(body.data(), body.size(), m.digest);
    return Err::Ok;
}

Err messageSerialize(const DepinMessage & m, std::vector<uint8_t> & out, const Limits & lim) {
    out.clear();
    Err e = checkFields(m, lim);
    if (e != Err::Ok) return e;
    if (m.signature.empty() || m.signature.size() > lim.maxSignature) return Err::BadSignature;
    out.reserve(m.token.size() + m.sender.size() + m.payload.size() + m.signature.size() + 32);
    serializeBody(m, out);
    appendSpan(out, m.signature.data(), m.signature.size());
    return Err::Ok;
}

Err messageParse(const uint8_t * data, size_t len, DepinMessage & out, const Limits & lim) {
    if (!data || len == 0) return Err::BadArg;
    size_t off = 0;
    Err e;
    const uint8_t * p; size_t n;
    if ((e = readSpan(data, len, off, &p, &n, lim.maxToken)) != Err::Ok) return e;
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
    if (!senderPub.isValid()) return Err::BadPubKey;
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
    Err e = messageDigest(m, lim);
    if (e != Err::Ok) return e;
    Signature sig = senderKey.sign(m.digest);   /* trezor: deterministic, low-S */
    if (!sig.isValid()) return Err::Crypto;
    uint8_t der[80];
    size_t n = sig.der(der, sizeof(der));
    if (n == 0 || n > lim.maxSignature) return Err::Crypto;
    m.signature.assign(der, der + n);
    /* self-check with the derived public key */
    PublicKey pub = senderKey.publicKey();
    pub.compressed = true;
    return messageVerify(m, pub, NULL);
}

Err messageBuild(const std::string & token, const std::string & senderAddress,
                 int64_t timestamp, uint8_t type,
                 const uint8_t * content, size_t contentLen,
                 const std::vector<std::vector<uint8_t> > & recipientPubKeys,
                 const PrivateKey & senderKey, DepinMessage & out,
                 const Limits & lim) {
    out = DepinMessage();
    out.token = token;
    out.sender = senderAddress;
    out.timestamp = timestamp;
    out.type = type;
    Err e = eciesEncrypt(content, contentLen, recipientPubKeys, out.payload, lim);
    if (e != Err::Ok) return e;
    return messageSign(out, senderKey, lim);
}

Err wrapForPool(const std::string & messageHex, const uint8_t poolPubKey33[33],
                std::vector<uint8_t> & envelope, const Limits & lim) {
    if (messageHex.empty() || !poolPubKey33) return Err::BadArg;
    /* the pool decrypts to the ASCII hex string and hex-decodes it itself */
    Limits l = lim;
    l.maxContent = std::max(lim.maxContent, messageHex.size());
    l.maxPayload = std::max(lim.maxPayload, messageHex.size() + 256);
    std::vector<std::vector<uint8_t> > rcpt(1, std::vector<uint8_t>(poolPubKey33, poolPubKey33 + 33));
    return eciesEncrypt((const uint8_t *)messageHex.data(), messageHex.size(), rcpt, envelope, l);
}

} // namespace depin
