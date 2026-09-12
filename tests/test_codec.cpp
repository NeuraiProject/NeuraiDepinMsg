/*
 * Host tests for DepinCodec against the protocol vectors
 * (tests/fixtures/vectors.txt = Neurai/contrib/depin/vectors.txt, §13 of
 * depin-messaging-protocol.md). Usage: test_codec <vectors.txt>
 */
#include <stdio.h>
#include <string.h>
#include <string>
#include <map>
#include <fstream>
#include <vector>
#include "DepinCodec.h"
#include "Hash.h"
#include "Conversion.h"

using namespace depin;
using std::string;
using std::vector;

void depinTestSetDeterministicRng(bool on, uint64_t seed);   /* DepinCryptoOpenSSL.cpp */

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { g_pass++; } else { g_fail++; printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } } while (0)
#define CHECK_ERR(expr, want, msg) do { Err _e = (expr); if (_e == (want)) { g_pass++; } else { g_fail++; printf("  FAIL %s:%d: %s (got %s, want %s)\n", __FILE__, __LINE__, msg, errName(_e), errName(want)); } } while (0)

static std::map<string, string> V;

static vector<uint8_t> H(const string & hex) {
    vector<uint8_t> out(hex.size() / 2 + 1);
    Err e;
    size_t n = hexDecode(hex.c_str(), hex.size(), out.data(), out.size(), &e);
    if (e != Err::Ok) { printf("  bad fixture hex\n"); g_fail++; }
    out.resize(n);
    return out;
}
static string S(const vector<uint8_t> & v) { return string((const char *)v.data(), v.size()); }

/* tiny JSON field extractor for the fixture plaintexts ("key":"value" / number) */
static string jsonField(const string & json, const string & key) {
    string k = "\"" + key + "\":";
    size_t p = json.find(k);
    if (p == string::npos) return "";
    p += k.size();
    if (json[p] == '"') { size_t q = json.find('"', p + 1); return json.substr(p + 1, q - p - 1); }
    size_t q = json.find_first_of(",}", p);
    return json.substr(p, q - p);
}

/* ── primitives ──────────────────────────────────────────────────────────── */

static void test_hex() {
    printf("hex\n");
    uint8_t b[4]; Err e;
    CHECK(hexDecode("00ff7Aa1", 0, b, 4, &e) == 4 && e == Err::Ok && b[2] == 0x7a, "mixed case decode");
    CHECK(hexDecode("abc", 0, b, 4, &e) == 0 && e == Err::BadHex, "odd length");
    CHECK(hexDecode("zz", 0, b, 4, &e) == 0 && e == Err::BadHex, "non-hex char");
    CHECK(hexDecode("0102030405", 0, b, 4, &e) == 0 && e == Err::TooLarge, "over capacity");
    CHECK(hexDecode("", 0, b, 4, &e) == 0 && e == Err::Ok, "empty is zero bytes, ok");
    CHECK(hexEncode(b, 0) == "" && hexEncode((const uint8_t *)"\x01\xab", 2) == "01ab", "encode lowercase");
}

static void test_compactsize() {
    printf("compactsize\n");
    uint8_t b[9]; size_t off; uint64_t v;
    CHECK(writeCompactSize(252, b, 9) == 1 && b[0] == 252, "1-byte");
    CHECK(writeCompactSize(253, b, 9) == 3 && b[0] == 253 && b[1] == 253 && b[2] == 0, "3-byte");
    CHECK(writeCompactSize(0x10000, b, 9) == 5 && b[0] == 254, "5-byte");
    CHECK(writeCompactSize(0x100000000ULL, b, 9) == 9 && b[0] == 255, "9-byte");
    CHECK(writeCompactSize(300, b, 2) == 0, "no room");
    off = 0; CHECK_ERR(readCompactSize(b, 9, off, v), Err::Ok, "read 9-byte"); CHECK(v == 0x100000000ULL && off == 9, "value 2^32");
    uint8_t nonmin[3] = { 253, 5, 0 };  off = 0; CHECK_ERR(readCompactSize(nonmin, 3, off, v), Err::BadCompactSize, "253 with value < 253");
    uint8_t nonmin2[5] = { 254, 0xff, 0xff, 0, 0 }; off = 0; CHECK_ERR(readCompactSize(nonmin2, 5, off, v), Err::BadCompactSize, "254 with value <= 0xffff");
    uint8_t trunc[2] = { 253, 5 }; off = 0; CHECK_ERR(readCompactSize(trunc, 2, off, v), Err::Truncated, "truncated 253");
    off = 0; CHECK_ERR(readCompactSize(b, 0, off, v), Err::Truncated, "empty");
    uint8_t big[9] = { 255, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff }; off = 0; CHECK_ERR(readCompactSize(big, 9, off, v), Err::Ok, "2^64-1 readable"); CHECK(v == UINT64_MAX, "max value");
}

static void test_kdf() {
    printf("kdf\n");
    /* KDF(secret) first block == SHA256(secret || 00000001) */
    uint8_t secret[3] = { 1, 2, 3 }, in[7] = { 1, 2, 3, 0, 0, 0, 1 }, want[32], got[40];
    sha256(in, 7, want);
    kdfSha256(secret, 3, got, 32);
    CHECK(memcmp(want, got, 32) == 0, "block 1 = sha256(secret||BE32(1))");
    kdfSha256(secret, 3, got, 40);
    in[6] = 2; sha256(in, 7, want);
    CHECK(memcmp(got + 32, want, 8) == 0, "block 2 continues with counter 2");
}

static void test_keys() {
    printf("keys\n");
    PrivateKey k; bool comp = false;
    CHECK_ERR(loadPrivateKey(V["holder_wif"], k, &comp), Err::Ok, "holder WIF (regtest, 0xef)");
    CHECK(comp, "holder WIF is compressed");
    uint8_t sec[33]; PublicKey p = k.publicKey(); p.compressed = true; p.sec(sec, 33);
    CHECK(hexEncode(sec, 33) == V["holder_pubkey"], "WIF -> pubkey (§13.1)");
    CHECK(k.address() == V["holder_address"], "pubkey -> address (§13.1)");
    CHECK_ERR(loadPrivateKey("", k), Err::BadArg, "empty");
    CHECK_ERR(loadPrivateKey(string(64, '0'), k), Err::BadPrivKey, "hex zero scalar");
    CHECK_ERR(loadPrivateKey("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", k), Err::BadPrivKey, "hex scalar == n");
    CHECK_ERR(loadPrivateKey("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", k), Err::Ok, "hex scalar n-1");
    CHECK_ERR(loadPrivateKey(string(63, '1') + "g", k), Err::BadPrivKey, "hex with bad char");
    CHECK_ERR(loadPrivateKey("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", k, &comp), Err::Ok, "uncompressed WIF, prefix 0x80 (= Neurai mainnet) loads");
    CHECK(!comp, "uncompressed WIF reported as such");
    string wif = V["holder_wif"]; wif[10] = (wif[10] == 'a') ? 'b' : 'a';
    CHECK_ERR(loadPrivateKey(wif, k), Err::BadPrivKey, "WIF with broken checksum");

    PublicKey pub;
    CHECK_ERR(loadPublicKey(V["holder_pubkey"], pub), Err::Ok, "load holder pubkey hex");
    CHECK_ERR(loadPublicKey("02" + string(64, '0'), pub), Err::BadPubKey, "x = 0 is not on the curve");
    CHECK_ERR(loadPublicKey("04" + string(128, '1'), pub), Err::BadPubKey, "uncompressed rejected");
    CHECK_ERR(loadPublicKey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", pub), Err::Ok, "generator point");
    CHECK_ERR(loadPublicKey("zz", pub), Err::BadHex, "bad hex");

    /* address binding */
    PublicKey hp; loadPublicKey(V["holder_pubkey"], hp);
    CHECK(pubKeyMatchesAddress(hp, V["holder_address"]), "holder key <-> holder address (any network)");
    CHECK(pubKeyMatchesAddress(hp, V["holder_address"], &NeuraiTest), "holder key <-> address on testnet/regtest");
    CHECK(!pubKeyMatchesAddress(hp, V["holder_address"], &Neurai), "testnet address rejected for mainnet");
    CHECK(!pubKeyMatchesAddress(hp, V["pool_address"]), "holder key != pool address");
    PublicKey pp; loadPublicKey(V["pool_pubkey"], pp);
    CHECK(pubKeyMatchesAddress(pp, V["pool_address"]), "pool key <-> pool address (§13.1)");
    uint8_t payload[25]; fromBase58Check(V["holder_address"].c_str(), V["holder_address"].size(), payload, 25);
    payload[0] = NeuraiTest.p2sh;
    CHECK(!pubKeyMatchesAddress(hp, toBase58Check(payload, 21)), "P2SH version rejected");
    CHECK(!pubKeyMatchesAddress(hp, "not-base58-0OIl"), "garbage address");
    CHECK(!pubKeyMatchesAddress(PublicKey(), V["holder_address"]), "invalid pubkey never matches");
}

/* ── ECIES vectors ───────────────────────────────────────────────────────── */

static void test_ecies_vectors() {
    printf("ecies vectors (§13.4, §13.5)\n");
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    vector<uint8_t> env = H(V["challenge_encrypted"]);
    EciesView view;
    CHECK_ERR(eciesParse(env.data(), env.size(), view), Err::Ok, "parse challenge envelope");
    CHECK(view.recipientCount == 1, "challenge: single recipient");
    vector<uint8_t> pt;
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), holder, pt), Err::Ok, "decrypt challenge reply");
    CHECK(S(pt) == V["challenge_plain"], "challenge plaintext");

    vector<uint8_t> env2 = H(V["receive_encrypted"]);
    CHECK_ERR(eciesDecrypt(env2.data(), env2.size(), holder, pt), Err::Ok, "decrypt receive reply (empty pool)");
    CHECK(S(pt) == V["receive_plain"], "receive plaintext");

    vector<uint8_t> env3 = H(V["receive2_encrypted"]);
    Limits big; big.maxContent = 8192;
    CHECK_ERR(eciesDecrypt(env3.data(), env3.size(), holder, pt, big), Err::Ok, "decrypt receive reply (one message)");
    CHECK(S(pt) == V["receive2_plain"], "receive2 plaintext");
    Limits small; small.maxContent = 512;
    CHECK_ERR(eciesDecrypt(env3.data(), env3.size(), holder, pt, small), Err::TooLarge, "receive2 (1001 bytes) exceeds maxContent 512");
    CHECK(pt.empty(), "no plaintext when over the limit");
}

static void test_ecies_map_order() {
    printf("ecies Core / JS 3.1.0 recipient ordering\n");
    auto seed = H(V["challenge_encrypted"]);
    EciesView view;
    CHECK_ERR(eciesParse(seed.data(), seed.size(), view), Err::Ok, "order test seed");
    size_t countOffset = view.entries - seed.data() - 1;
    auto envelope = [&](std::initializer_list<int> order) {
        vector<uint8_t> result(seed.begin(), seed.begin() + countOffset);
        result.push_back(static_cast<uint8_t>(order.size()));
        for (int key : order) {
            // Opposite rankings: bytewise A < B < C, numeric C < B < A.
            uint8_t id[20] = {}; id[0] = key; id[19] = 4 - key;
            result.insert(result.end(), id, id + 20);
            result.push_back(60);
            result.insert(result.end(), view.entries + 21, view.entries + 81);
        }
        return result;
    };
    EciesView parsed;
    auto canonical = envelope({1, 2, 3});
    CHECK_ERR(eciesParse(canonical.data(), canonical.size(), parsed), Err::Ok, "Core bytewise order");
    auto legacy = envelope({3, 2, 1});
    auto unchanged = legacy;
    CHECK_ERR(eciesParse(legacy.data(), legacy.size(), parsed), Err::Ok, "JS numeric order");
    CHECK(legacy == unchanged, "signed envelope bytes are never normalized");
    auto mixed = envelope({2, 1, 3});
    CHECK_ERR(eciesParse(mixed.data(), mixed.size(), parsed), Err::RecipientOrder, "mixed order rejected");
    auto duplicate = envelope({1, 1, 2});
    CHECK_ERR(eciesParse(duplicate.data(), duplicate.size(), parsed), Err::DuplicateRecipient, "adjacent duplicate rejected");
    duplicate = envelope({1, 2, 1});
    CHECK_ERR(eciesParse(duplicate.data(), duplicate.size(), parsed), Err::DuplicateRecipient, "non-adjacent duplicate rejected");
}

static void test_ecies_negative() {
    printf("ecies negative (N3, N4, N5) and structure\n");
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    vector<uint8_t> env = H(V["challenge_encrypted"]);
    vector<uint8_t> pt;

    /* N3 as written in verify_vectors.py: flip the LAST byte of the envelope.
     * With one recipient that byte is the holder's entry tag (entries follow
     * the payload on the wire), so the failure surfaces at key unwrap. */
    vector<uint8_t> n3 = env; n3.back() ^= 0x01;
    CHECK_ERR(eciesDecrypt(n3.data(), n3.size(), holder, pt), Err::KeyUnwrapFailed, "N3 last byte (entry tag)");
    CHECK(pt.empty(), "N3 no plaintext");
    /* N3 proper: the payload's own GCM tag */
    {
        EciesView pv; eciesParse(env.data(), env.size(), pv);
        vector<uint8_t> n3b = env; n3b[(pv.payload - env.data()) + pv.payloadLen - 1] ^= 0x01;
        CHECK_ERR(eciesDecrypt(n3b.data(), n3b.size(), holder, pt), Err::PayloadAuthFailed, "N3 payload tag");
        CHECK(pt.empty(), "N3 payload: no plaintext");
    }

    /* N4: flip the last byte of the holder's entry (its tag) */
    EciesView v; eciesParse(env.data(), env.size(), v);
    uint8_t sec[33]; PublicKey hp = holder.publicKey(); hp.compressed = true; hp.sec(sec, 33);
    uint8_t keyId[20]; hash160(sec, 33, keyId);
    const uint8_t * entry = eciesFindEntry(v, keyId);
    CHECK(entry != NULL, "holder entry found");
    vector<uint8_t> n4 = env; n4[(entry - env.data()) + 59] ^= 0x01;
    CHECK_ERR(eciesDecrypt(n4.data(), n4.size(), holder, pt), Err::KeyUnwrapFailed, "N4 entry tag");

    /* N5: another key has no entry */
    uint8_t other[32]; memset(other, 0x42, 32);
    PrivateKey stranger(other, true, &NeuraiTest);
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), stranger, pt), Err::NotForRecipient, "N5 not for recipient");

    /* structural mutations */
    vector<uint8_t> trailing = env; trailing.push_back(0);
    CHECK_ERR(eciesDecrypt(trailing.data(), trailing.size(), holder, pt), Err::TrailingBytes, "trailing byte");
    vector<uint8_t> cut(env.begin(), env.end() - 1);
    CHECK_ERR(eciesDecrypt(cut.data(), cut.size(), holder, pt), Err::Truncated, "truncated envelope");
    vector<uint8_t> badEph = env; badEph[0] = 0x20;   /* ephemeral length 32 */
    CHECK_ERR(eciesParse(badEph.data(), badEph.size(), v), Err::BadEphemeral, "ephemeral not 33 bytes");
    vector<uint8_t> badEph2 = env; badEph2[1] = 0x04;
    CHECK_ERR(eciesParse(badEph2.data(), badEph2.size(), v), Err::BadEphemeral, "ephemeral prefix 0x04");
    vector<uint8_t> offCurve = env; memset(&offCurve[2], 0, 32);
    CHECK_ERR(eciesParse(offCurve.data(), offCurve.size(), v), Err::BadEphemeral, "ephemeral x=0 off curve");
    CHECK_ERR(eciesParse(env.data(), env.size(), v), Err::Ok, "good envelope still parses");
    CHECK_ERR(eciesParse(offCurve.data(), offCurve.size(), v), Err::BadEphemeral, "ephemeral x=0 off curve (after a good parse: no stale point)");
    vector<uint8_t> offCurve5 = env; memset(&offCurve5[2], 0x05, 32);
    CHECK_ERR(eciesParse(offCurve5.data(), offCurve5.size(), v), Err::BadEphemeral, "ephemeral x=0x05..05 off curve");
    /* entry length 59 / 61 */
    size_t entryLenPos = (entry - env.data()) - 1;
    vector<uint8_t> e59 = env; e59[entryLenPos] = 59; e59.erase(e59.begin() + entryLenPos + 1 + 59);
    CHECK_ERR(eciesParse(e59.data(), e59.size(), v), Err::BadRecipientEntry, "entry of 59 bytes");
    vector<uint8_t> e61 = env; e61[entryLenPos] = 61; e61.push_back(0);
    CHECK_ERR(eciesParse(e61.data(), e61.size(), v), Err::BadRecipientEntry, "entry of 61 bytes");
    /* zero recipients */
    vector<uint8_t> zero(env.begin(), env.begin() + (entry - env.data()) - 21);
    zero.back() = 0;
    CHECK_ERR(eciesParse(zero.data(), zero.size(), v), Err::BadRecipientEntry, "zero recipients");
    /* over limit */
    Limits one; one.maxPayload = 100;
    CHECK_ERR(eciesParse(env.data(), env.size(), v, one), Err::TooLarge, "over maxPayload");
    CHECK_ERR(eciesParse(NULL, 0, v), Err::BadArg, "null input");
}

static void test_ecies_roundtrip() {
    printf("ecies encrypt/decrypt round trip\n");
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    uint8_t s2[32]; memset(s2, 0x33, 32);
    PrivateKey second(s2, true, &NeuraiTest);
    uint8_t sec1[33], sec2[33];
    { PublicKey p = holder.publicKey(); p.compressed = true; p.sec(sec1, 33); }
    { PublicKey p = second.publicKey(); p.compressed = true; p.sec(sec2, 33); }
    vector<vector<uint8_t> > rcpt;
    rcpt.push_back(vector<uint8_t>(sec2, sec2 + 33));
    rcpt.push_back(vector<uint8_t>(sec1, sec1 + 33));
    rcpt.push_back(vector<uint8_t>(sec1, sec1 + 33));    /* duplicate: must collapse */

    const char msg[] = "Hello from the ESP32 codec";
    vector<uint8_t> env, pt;
    depinTestSetDeterministicRng(true, 7);
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, rcpt, env), Err::Ok, "encrypt for two recipients");
    EciesView v;
    CHECK_ERR(eciesParse(env.data(), env.size(), v), Err::Ok, "own envelope parses strictly");
    CHECK(v.recipientCount == 2, "duplicate recipient collapsed");
    CHECK(memcmp(v.entries, v.entries + 81, 20) < 0, "encryption still emits Core bytewise order");
    CHECK(env.size() == 34 + 1 + 12 + (sizeof(msg) - 1) + 16 + 1 + 2 * 81, "envelope size formula 1090-ish");
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), holder, pt), Err::Ok, "holder decrypts");
    CHECK(S(pt) == msg, "holder plaintext");
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), second, pt), Err::Ok, "second decrypts");
    CHECK(S(pt) == msg, "second plaintext");
    vector<uint8_t> env2;
    depinTestSetDeterministicRng(true, 7);
    eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, rcpt, env2);
    CHECK(env == env2, "deterministic RNG -> identical envelope");
    depinTestSetDeterministicRng(false, 0);
    eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, rcpt, env2);
    CHECK(env != env2, "real RNG -> different envelope");

    /* failures leave no output */
    vector<vector<uint8_t> > bad = rcpt;
    vector<uint8_t> offCurveKey(33, 0x05); offCurveKey[0] = 0x02;     /* x = 0x0505..05 is not on the curve */
    bad.push_back(offCurveKey);
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, bad, env2), Err::BadPubKey, "one off-curve recipient fails all");
    CHECK(env2.empty(), "no partial envelope");
    bad = rcpt; bad.push_back(vector<uint8_t>(32, 0x02));
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, bad, env2), Err::BadPubKey, "32-byte recipient key rejected");
    bad = rcpt; bad.push_back(vector<uint8_t>(sec1, sec1 + 33)); bad.back()[0] = 0x04;
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, bad, env2), Err::BadPubKey, "uncompressed prefix rejected");
    Limits lim; lim.maxRecipients = 1;
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, rcpt, env2, lim), Err::TooManyRecipients, "over maxRecipients");
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, 0, rcpt, env2), Err::BadField, "empty content");
    lim = Limits(); lim.maxContent = 4;
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, rcpt, env2, lim), Err::TooLarge, "content over maxContent");
    vector<vector<uint8_t> > none;
    CHECK_ERR(eciesEncrypt((const uint8_t *)msg, sizeof(msg) - 1, none, env2), Err::BadArg, "no recipients");
}

/* ── CDepinMessage vectors ───────────────────────────────────────────────── */

static void test_message_vector() {
    printf("message vector (§13.6)\n");
    string plain = V["receive2_plain"];
    string msgJson = plain.substr(plain.find("{", 1));
    DepinMessage m;
    m.token = jsonField(msgJson, "token");
    m.sender = jsonField(msgJson, "sender");
    m.timestamp = atoll(jsonField(msgJson, "timestamp").c_str());
    m.type = (jsonField(msgJson, "message_type") == "group") ? DEPIN_TYPE_GROUP : DEPIN_TYPE_PRIVATE;
    m.payload = H(jsonField(msgJson, "encrypted_payload_hex"));
    m.signature = H(jsonField(msgJson, "signature_hex"));
    string hash = jsonField(msgJson, "hash");
    CHECK(m.token == "&TEST/SEC" && m.type == DEPIN_TYPE_GROUP, "fixture fields");

    CHECK_ERR(messageDigest(m), Err::Ok, "digest");
    CHECK(m.hash() == hash, "hash = hex(reverse(sha256d))");
    PublicKey senderPub; loadPublicKey(V["sender_pubkey"], senderPub);
    CHECK_ERR(messageVerify(m, senderPub, hash.c_str()), Err::Ok, "DER verifies with sender key + hash matches");

    /* serialize -> parse round trip */
    vector<uint8_t> wire;
    CHECK_ERR(messageSerialize(m, wire), Err::Ok, "serialize");
    DepinMessage back;
    CHECK_ERR(messageParse(wire.data(), wire.size(), back), Err::Ok, "parse");
    CHECK(back.token == m.token && back.sender == m.sender && back.timestamp == m.timestamp &&
          back.type == m.type && back.payload == m.payload && back.signature == m.signature, "fields survive");
    CHECK(back.hash() == hash, "parsed hash");

    /* content decrypts for the holder */
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    vector<uint8_t> pt;
    CHECK_ERR(eciesDecrypt(m.payload.data(), m.payload.size(), holder, pt), Err::Ok, "decrypt content");
    CHECK(S(pt) == "Hello from the spec", "content");

    /* N6: flip last byte of DER */
    DepinMessage n6 = m; n6.signature.back() ^= 0x01;
    Err e6 = messageVerify(n6, senderPub, hash.c_str());
    CHECK(e6 == Err::SignatureInvalid || e6 == Err::BadSignature, "N6 tampered DER rejected");
    /* N7: timestamp + 1 with the old hash and signature */
    DepinMessage n7 = m; n7.timestamp += 1; messageDigest(n7);
    CHECK_ERR(messageVerify(n7, senderPub, hash.c_str()), Err::HashMismatch, "N7 hash mismatch");
    CHECK_ERR(messageVerify(n7, senderPub, NULL), Err::SignatureInvalid, "N7 signature fails even without hash");
    /* wrong key */
    PublicKey holderPub; loadPublicKey(V["holder_pubkey"], holderPub);
    CHECK_ERR(messageVerify(m, holderPub, hash.c_str()), Err::SignatureInvalid, "wrong sender key");
    CHECK_ERR(messageVerify(m, PublicKey(), hash.c_str()), Err::BadPubKey, "empty pubkey");
    /* high-S normalisation: encode s' = n - s, must still verify */
    {
        uint8_t r[32], s[32];
        /* rebuild from DER manually via a Signature */
        Signature sig; sig.fromDer(m.signature.data(), m.signature.size());
        uint8_t bin[65]; sig.bin(bin, 65);
        memcpy(r, bin, 32); memcpy(s, bin + 32, 32);
        /* n - s */
        static const uint8_t N[32] = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                                       0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41 };
        uint8_t hs[32]; int borrow = 0;
        for (int i = 31; i >= 0; i--) { int d = (int)N[i] - (int)s[i] - borrow; borrow = d < 0; hs[i] = (uint8_t)(d + (borrow ? 256 : 0)); }
        Signature high(r, hs);
        uint8_t der[80]; size_t n = high.der(der, 80);
        DepinMessage hm = m; hm.signature.assign(der, der + n);
        CHECK_ERR(messageVerify(hm, senderPub, hash.c_str()), Err::Ok, "high-S normalised like the node");
    }
    /* malformed DER shapes */
    DepinMessage bad = m; bad.signature[0] = 0x31;
    CHECK_ERR(messageVerify(bad, senderPub, NULL), Err::BadSignature, "not a SEQUENCE");
    bad = m; bad.signature.push_back(0x00);
    CHECK_ERR(messageVerify(bad, senderPub, NULL), Err::BadSignature, "trailing byte in DER");
    bad = m; bad.signature.clear();
    CHECK_ERR(messageVerify(bad, senderPub, NULL), Err::BadSignature, "empty DER");
    /* hash comparison is case-insensitive but length-strict */
    string upper = hash; for (char & c : upper) if (c >= 'a' && c <= 'f') c = (char)(c - 'a' + 'A');
    CHECK_ERR(messageVerify(m, senderPub, upper.c_str()), Err::Ok, "uppercase expected hash");
    CHECK_ERR(messageVerify(m, senderPub, "abcd"), Err::HashMismatch, "short expected hash");
}

static void test_message_parse_negative() {
    printf("message parse negative\n");
    string plain = V["receive2_plain"];
    string msgJson = plain.substr(plain.find("{", 1));
    DepinMessage m;
    m.token = jsonField(msgJson, "token"); m.sender = jsonField(msgJson, "sender");
    m.timestamp = atoll(jsonField(msgJson, "timestamp").c_str()); m.type = DEPIN_TYPE_GROUP;
    m.payload = H(jsonField(msgJson, "encrypted_payload_hex")); m.signature = H(jsonField(msgJson, "signature_hex"));
    vector<uint8_t> wire; messageSerialize(m, wire);
    DepinMessage out;
    vector<uint8_t> t = wire; t.push_back(0);
    CHECK_ERR(messageParse(t.data(), t.size(), out), Err::TrailingBytes, "trailing");
    t = wire; t.pop_back();
    CHECK_ERR(messageParse(t.data(), t.size(), out), Err::Truncated, "truncated");
    t = wire; t[1 + m.token.size() + 1 + m.sender.size() + 8] = 0x03;
    CHECK_ERR(messageParse(t.data(), t.size(), out), Err::BadMessageType, "type 0x03");
    t = wire; t[1 + m.token.size() + 1 + m.sender.size() + 7] = 0x80;   /* timestamp sign bit */
    CHECK_ERR(messageParse(t.data(), t.size(), out), Err::BadTimestamp, "negative timestamp");
    t = wire; t[0] = 0;                                                 /* empty token */
    t.erase(t.begin() + 1, t.begin() + 1 + m.token.size());
    CHECK_ERR(messageParse(t.data(), t.size(), out), Err::BadField, "empty token");
    Limits lim; lim.maxToken = 4;
    CHECK_ERR(messageParse(wire.data(), wire.size(), out, lim), Err::TooLarge, "token over maxToken");
    CHECK_ERR(messageParse(NULL, 0, out), Err::BadArg, "null");
    /* checkFields on the struct */
    DepinMessage f = m; f.type = 0; CHECK_ERR(messageDigest(f), Err::BadMessageType, "type 0");
    f = m; f.timestamp = -1; CHECK_ERR(messageDigest(f), Err::BadTimestamp, "timestamp -1");
    f = m; f.payload.clear(); CHECK_ERR(messageDigest(f), Err::BadPayload, "empty payload");
    f = m; f.sender.clear(); CHECK_ERR(messageDigest(f), Err::BadField, "empty sender");
    f = m; f.signature.clear(); CHECK_ERR(messageSerialize(f, wire), Err::BadSignature, "serialize without signature");
}

static void test_message_build_and_wrap() {
    printf("message build + pool wrap\n");
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    uint8_t sec[33]; { PublicKey p = holder.publicKey(); p.compressed = true; p.sec(sec, 33); }
    vector<vector<uint8_t> > rcpt(1, vector<uint8_t>(sec, sec + 33));
    const char content[] = "round trip";
    DepinMessage m;
    depinTestSetDeterministicRng(true, 99);
    CHECK_ERR(messageBuild("&TEST/SEC", V["holder_address"], 1787377444, DEPIN_TYPE_PRIVATE,
                           (const uint8_t *)content, sizeof(content) - 1, rcpt, holder, m), Err::Ok, "build");
    PublicKey holderPub; loadPublicKey(V["holder_pubkey"], holderPub);
    CHECK_ERR(messageVerify(m, holderPub, m.hash().c_str()), Err::Ok, "built message verifies");
    CHECK(m.signature.size() >= 70 && m.signature.size() <= 72 && m.signature[0] == 0x30, "DER 70..72 bytes");
    vector<uint8_t> wire; messageSerialize(m, wire);
    DepinMessage back; CHECK_ERR(messageParse(wire.data(), wire.size(), back), Err::Ok, "reparse built message");
    CHECK(back.hash() == m.hash(), "hash stable through the wire");
    vector<uint8_t> pt;
    CHECK_ERR(eciesDecrypt(back.payload.data(), back.payload.size(), holder, pt), Err::Ok, "content decrypts");
    CHECK(S(pt) == content, "content matches");
    /* type validation on build */
    CHECK_ERR(messageBuild("&TEST/SEC", V["holder_address"], 1, 0x07, (const uint8_t *)content, 10, rcpt, holder, m), Err::BadMessageType, "bad type");
    CHECK_ERR(messageBuild("", V["holder_address"], 1, DEPIN_TYPE_GROUP, (const uint8_t *)content, 10, rcpt, holder, m), Err::BadField, "empty token");

    /* pool wrap: envelope of the ASCII hex, decryptable by the pool key */
    uint8_t poolSecret[32]; memset(poolSecret, 0x55, 32);
    PrivateKey pool(poolSecret, true, &NeuraiTest);
    uint8_t poolSec[33]; { PublicKey p = pool.publicKey(); p.compressed = true; p.sec(poolSec, 33); }
    string hex = hexEncode(wire.data(), wire.size());
    vector<uint8_t> env;
    CHECK_ERR(wrapForPool(hex, poolSec, env), Err::Ok, "wrap for pool");
    Limits big; big.maxContent = 65536; big.maxPayload = 70000;
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), pool, pt, big), Err::Ok, "pool unwraps");
    CHECK(S(pt) == hex, "pool sees the ASCII hex of the signed message");
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), holder, pt, big), Err::NotForRecipient, "sender cannot open the pool envelope");
    depinTestSetDeterministicRng(false, 0);
}

struct TestIdentity : IdentityProvider {
    PrivateKey key;
    bool locked = false, badSignature = false, oversized = false, failEcdh = false;
    mutable int signs = 0, exchanges = 0;
    explicit TestIdentity(const PrivateKey &k) : key(k) {}
    Err publicKey(uint8_t out[33]) const override {
        if (locked) return Err::BadPrivKey;
        PublicKey pub = key.publicKey(); pub.compressed = true;
        return pub.sec(out, 33) == 33 ? Err::Ok : Err::Crypto;
    }
    Err signDigest(const uint8_t digest[32], uint8_t der[72], size_t &n) const override {
        ++signs; n = 0;
        if (locked) return Err::BadPrivKey;
        Signature sig = key.sign(digest); n = sig.der(der, 72);
        if (badSignature) der[n - 1] ^= 1;
        if (oversized) n = 73;
        return Err::Ok;
    }
    Err ecdh(const uint8_t peer[33], uint8_t secret[32]) const override {
        ++exchanges;
        if (locked || failEcdh) return Err::BadPrivKey;
        PublicKey p(peer); ECPoint shared = key * p; shared.compressed = true;
        uint8_t sec[33];
        if (!shared.isValid() || shared.sec(sec, 33) != 33) return Err::Crypto;
        sha256(sec, 33, secret); return Err::Ok;
    }
};

static void test_identity_provider() {
    PrivateKey holder; CHECK_ERR(loadPrivateKey(V["holder_wif"], holder), Err::Ok, "provider fixture key");
    TestIdentity identity(holder);
    uint8_t pub[33]; identity.publicKey(pub);
    vector<vector<uint8_t>> recipients(1, vector<uint8_t>(pub, pub + 33));
    const string content = "provider message";
    DepinMessage direct, external;
    depinTestSetDeterministicRng(true, 1234);
    CHECK_ERR(messageBuild("&TEST/SEC", V["holder_address"], 1787377444, DEPIN_TYPE_GROUP,
        (const uint8_t*)content.data(), content.size(), recipients, holder, direct), Err::Ok, "direct message");
    depinTestSetDeterministicRng(true, 1234);
    CHECK_ERR(messageBuild("&TEST/SEC", V["holder_address"], 1787377444, DEPIN_TYPE_GROUP,
        (const uint8_t*)content.data(), content.size(), recipients, identity, external), Err::Ok, "provider message");
    vector<uint8_t> a,b; messageSerialize(direct,a); messageSerialize(external,b);
    CHECK(a == b && identity.signs == 1, "provider produces identical signed wire bytes");
    vector<uint8_t> plain;
    CHECK_ERR(eciesDecrypt(external.payload.data(), external.payload.size(), identity, plain), Err::Ok, "provider decrypt");
    CHECK(string(plain.begin(),plain.end()) == content, "provider plaintext");
    uint8_t out[32]; memset(out,0xa5,sizeof(out)); size_t written = 99;
    int before = identity.exchanges;
    CHECK_ERR(eciesDecrypt(external.payload.data(), external.payload.size(), identity, out, 1, written), Err::TooLarge, "bounded output");
    CHECK(!written && out[0] == 0xa5 && identity.exchanges == before, "capacity checked before ECDH");
    vector<uint8_t> broken = external.payload; EciesView view;
    eciesParse(broken.data(),broken.size(),view);
    broken[(view.payload - broken.data()) + view.payloadLen - 1] ^= 1;
    CHECK_ERR(eciesDecrypt(broken.data(),broken.size(),identity,out,sizeof(out),written), Err::PayloadAuthFailed, "provider tampered payload");
    bool wiped = true; for (size_t i=0;i<content.size();++i) wiped &= out[i] == 0;
    CHECK(!written && wiped && out[content.size()] == 0xa5, "failed plaintext wiped within bounds");
    identity.locked = true;
    CHECK_ERR(messageSign(external,identity), Err::BadPrivKey, "locked provider cannot sign");
    CHECK(external.signature.empty(), "failed signing clears previous signature");
    CHECK_ERR(eciesDecrypt(direct.payload.data(),direct.payload.size(),identity,plain), Err::BadPrivKey, "locked provider cannot decrypt");
    CHECK(plain.empty(), "locked decrypt has no output");
    identity.locked = false; identity.failEcdh = true;
    CHECK_ERR(eciesDecrypt(direct.payload.data(),direct.payload.size(),identity,plain), Err::BadPrivKey, "ECDH refusal propagated");
    identity.failEcdh = false; identity.badSignature = true;
    CHECK(messageSign(external,identity) != Err::Ok && external.signature.empty(), "provider signature independently checked");
    identity.badSignature = false; identity.oversized = true;
    CHECK_ERR(messageSign(external,identity), Err::BadSignature, "oversized provider signature rejected");
    identity.oversized = false; external.sender = V["pool_address"];
    before = identity.signs;
    CHECK_ERR(messageSign(external,identity), Err::BadPubKey, "provider bound to sender address");
    CHECK(identity.signs == before, "wrong sender rejected before signing");
    external.sender = V["holder_address"];
    CHECK_ERR(messageSign(external,identity), Err::Ok, "provider recovers after refusal");
    depinTestSetDeterministicRng(false,0);
}

int main(int argc, char ** argv) {
    const char * path = (argc > 1) ? argv[1] : "fixtures/vectors.txt";
    std::ifstream f(path);
    if (!f) { printf("cannot open %s\n", path); return 2; }
    string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == string::npos) continue;
        V[line.substr(0, eq)] = line.substr(eq + 1);
    }
    if (V.count("challenge_encrypted") == 0) { printf("fixture incomplete\n"); return 2; }
    CHECK(cryptoBackend() != NULL, "crypto backend registered");

    test_identity_provider();
    test_hex();
    test_compactsize();
    test_kdf();
    test_keys();
    test_ecies_vectors();
    test_ecies_map_order();
    test_ecies_negative();
    test_ecies_roundtrip();
    test_message_vector();
    test_message_parse_negative();
    test_message_build_and_wrap();

    printf("\n%d checks, %d failures\n", g_pass + g_fail, g_fail);
    return g_fail ? 1 : 0;
}
