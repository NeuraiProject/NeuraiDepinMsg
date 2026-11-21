#include <stdio.h>
#include <string.h>
#include <string>
#include <map>
#include <fstream>
#include <vector>
#include "DepinCodec.h"
#include "Hash.h"
#include "DepinAuth.h"
#include <ArduinoJson.h>
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
    CHECK_ERR(loadPublicKey("zz", pub), Err::BadPubKey, "bad hex");

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

static string genesis;
static DynamicJsonDocument vectors(100000);
static EnvelopeContext replyContext;

static void test_format3() {
    for (JsonObjectConst entry : vectors["cases"].as<JsonArrayConst>()) {
        JsonObjectConst row = entry["message"];
        DepinMessage m;
        m.genesis = genesis; m.token = row["token"].as<string>(); m.sender = row["sender"].as<string>();
        m.timestamp = row["timestamp"]; m.type = row["type"]; m.payload = H(row["envelope"]); m.signature = H(row["signature"]);
        PublicKey pub;
        CHECK_ERR(loadPublicKey(row["sender_pubkey"].as<string>(), pub), Err::Ok, "sender key");
        EnvelopeContext context;
        CHECK_ERR(messageContext(m, context), Err::Ok, "header context");
        CHECK_ERR(messageDigest(m), Err::Ok, "message digest");
        if (entry["name"] == "valid") {
            CHECK(m.hash() == vectors["steps"]["message_hash_displayed"].as<string>(), "Core message hash");
            CHECK(hexEncode(context.data(),32) == vectors["steps"]["context"].as<string>(), "Core context");
            vector<uint8_t> wire;
            CHECK_ERR(messageSerialize(m, wire), Err::Ok, "wire serialization");
            DepinMessage back;
            CHECK_ERR(messageParse(wire.data(), wire.size(), genesis, back), Err::Ok, "wire parse");
            CHECK_ERR(messageVerify(back, pub, m.hash().c_str()), Err::Ok, "wire signature");
            ++back.timestamp;
            CHECK_ERR(messageVerify(back, pub), Err::HashMismatch, "edited header cannot use cached digest");
        }
        for (const char * person : {"ana", "luis"}) {
            const char * verdict = entry["stops_at"][person];
            if (!verdict) continue;
            JsonObjectConst user = vectors["people"][person];
            PrivateKey key; loadPrivateKey(user["secret"].as<string>(), key);
            vector<uint8_t> plain;
            Err e = messageVerify(m, pub);
            if (e == Err::Ok) e = eciesDecrypt(m.payload.data(), m.payload.size(), key, context, user["address"], plain);
            CHECK((e == Err::Ok) == (string(verdict) == "ok"), entry["name"].as<const char *>());
            if (e == Err::Ok) CHECK(S(plain) == vectors["inputs"]["plaintext_utf8"].as<string>(), "fixture plaintext");
            else CHECK(plain.empty(), "failure returns no plaintext");
        }
    }
    JsonObjectConst t = vectors["transport"];
    EnvelopeContext submit;
    transportContext(TransportUse::Reply, genesis, replyContext);
    transportContext(TransportUse::Submit, genesis, submit);
    CHECK(hexEncode(replyContext.data(),32) == t["reply_context"].as<string>(), "reply context");
    CHECK(hexEncode(submit.data(),32) == t["submit_context"].as<string>(), "submit context");
    auto env = H(t["reply"]["envelope"]);
    PrivateKey key;
    auto person = vectors["people"]["luis"];
    loadPrivateKey(person["secret"].as<string>(), key);
    vector<uint8_t> plain;
    CHECK_ERR(eciesDecrypt(env.data(),env.size(),key,replyContext,person["address"],plain), Err::Ok, "Core bound reply");
    CHECK(hexEncode(plain.data(),plain.size()) == t["reply"]["plaintext"].as<string>(), "reply bytes");
    CHECK_ERR(eciesDecrypt(env.data(),env.size(),key,submit,person["address"],plain), Err::KeyUnwrapFailed, "transport separation");
}

static void test_ecies_map_order() {
    printf("format 3 recipient ordering\n");
    auto seed = H(vectors["transport"]["reply"]["envelope"]);
    EciesView view;
    CHECK_ERR(eciesParse(seed.data(), seed.size(), view), Err::Ok, "order test seed");
    size_t countOffset = view.entries - seed.data() - 1;
    auto envelope = [&](std::initializer_list<int> order) {
        vector<uint8_t> result(seed.begin(), seed.begin() + countOffset);
        result.push_back(static_cast<uint8_t>(order.size()));
        for (int key : order) {
            // Opposite rankings: bytewise A < B < C, numeric C < B < A.
            uint8_t id[20] = {}; id[0] = key; id[19] = 4 - key;
            result.push_back(0);
            result.insert(result.end(), id, id + 20);
            result.push_back(60);
            result.insert(result.end(), view.entries + 22, view.entries + 82);
        }
        return result;
    };
    EciesView parsed;
    auto canonical = envelope({1, 2, 3});
    CHECK_ERR(eciesParse(canonical.data(), canonical.size(), parsed), Err::Ok, "Core bytewise order");
    auto legacy = envelope({3, 2, 1});
    auto unchanged = legacy;
    CHECK_ERR(eciesParse(legacy.data(), legacy.size(), parsed), Err::RecipientOrder, "old numeric order");
    CHECK(legacy == unchanged, "signed envelope bytes are never normalized");
    auto mixed = envelope({2, 1, 3});
    CHECK_ERR(eciesParse(mixed.data(), mixed.size(), parsed), Err::RecipientOrder, "mixed order rejected");
    auto duplicate = envelope({1, 1, 2});
    CHECK_ERR(eciesParse(duplicate.data(), duplicate.size(), parsed), Err::DuplicateRecipient, "adjacent duplicate rejected");
    duplicate = envelope({1, 2, 1});
    CHECK_ERR(eciesParse(duplicate.data(), duplicate.size(), parsed), Err::RecipientOrder, "non-adjacent duplicate rejected");
}

static void test_ecies_negative() {
    printf("ecies negative (N3, N4, N5) and structure\n");
    PrivateKey holder; loadPrivateKey(vectors["people"]["luis"]["secret"].as<string>(), holder);
    vector<uint8_t> env = H(vectors["transport"]["reply"]["envelope"]);
    vector<uint8_t> pt;

    /* N3 as written in verify_vectors.py: flip the LAST byte of the envelope.
     * With one recipient that byte is the holder's entry tag (entries follow
     * the payload on the wire), so the failure surfaces at key unwrap. */
    vector<uint8_t> n3 = env; n3.back() ^= 0x01;
    CHECK_ERR(eciesDecrypt(n3.data(), n3.size(), holder, replyContext, vectors["people"]["luis"]["address"], pt), Err::KeyUnwrapFailed, "N3 last byte (entry tag)");
    CHECK(pt.empty(), "N3 no plaintext");
    /* N3 proper: the payload's own GCM tag */
    {
        EciesView pv; eciesParse(env.data(), env.size(), pv);
        vector<uint8_t> n3b = env; n3b[(pv.payload - env.data()) + pv.payloadLen - 1] ^= 0x01;
        CHECK_ERR(eciesDecrypt(n3b.data(), n3b.size(), holder, replyContext, vectors["people"]["luis"]["address"], pt), Err::PayloadAuthFailed, "N3 payload tag");
        CHECK(pt.empty(), "N3 payload: no plaintext");
    }

    /* N4: flip the last byte of the holder's entry (its tag) */
    EciesView v; eciesParse(env.data(), env.size(), v);
    uint8_t sec[33]; PublicKey hp = holder.publicKey(); hp.compressed = true; hp.sec(sec, 33);
    uint8_t keyId[21] = {}; hash160(sec, 33, keyId+1);
    const uint8_t * entry = eciesFindEntry(v, keyId, 21);
    CHECK(entry != NULL, "holder entry found");
    vector<uint8_t> n4 = env; n4[(entry - env.data()) + 59] ^= 0x01;
    CHECK_ERR(eciesDecrypt(n4.data(), n4.size(), holder, replyContext, vectors["people"]["luis"]["address"], pt), Err::KeyUnwrapFailed, "N4 entry tag");

    /* N5: another key has no entry */
    uint8_t other[32]; memset(other, 0x42, 32);
    PrivateKey stranger(other, true, &NeuraiTest);
    CHECK_ERR(eciesDecrypt(env.data(), env.size(), stranger, replyContext, stranger.address(), pt), Err::NotForRecipient, "N5 not for recipient");

    /* structural mutations */
    vector<uint8_t> trailing = env; trailing.push_back(0);
    CHECK_ERR(eciesDecrypt(trailing.data(), trailing.size(), holder, replyContext, vectors["people"]["luis"]["address"], pt), Err::TrailingBytes, "trailing byte");
    vector<uint8_t> cut(env.begin(), env.end() - 1);
    CHECK_ERR(eciesDecrypt(cut.data(), cut.size(), holder, replyContext, vectors["people"]["luis"]["address"], pt), Err::Truncated, "truncated envelope");
    vector<uint8_t> badEph = env; badEph[2] = 0x20;   /* ephemeral length 32 */
    CHECK_ERR(eciesParse(badEph.data(), badEph.size(), v), Err::BadEphemeral, "ephemeral not 33 bytes");
    vector<uint8_t> badEph2 = env; badEph2[3] = 0x04;
    CHECK_ERR(eciesParse(badEph2.data(), badEph2.size(), v), Err::BadEphemeral, "ephemeral prefix 0x04");
    vector<uint8_t> offCurve = env; memset(&offCurve[4], 0, 32);
    CHECK_ERR(eciesParse(offCurve.data(), offCurve.size(), v), Err::BadEphemeral, "ephemeral x=0 off curve");
    CHECK_ERR(eciesParse(env.data(), env.size(), v), Err::Ok, "good envelope still parses");
    CHECK_ERR(eciesParse(offCurve.data(), offCurve.size(), v), Err::BadEphemeral, "ephemeral x=0 off curve (after a good parse: no stale point)");
    vector<uint8_t> offCurve5 = env; memset(&offCurve5[4], 0x05, 32);
    CHECK_ERR(eciesParse(offCurve5.data(), offCurve5.size(), v), Err::BadEphemeral, "ephemeral x=0x05..05 off curve");
    /* entry length 59 / 61 */
    size_t entryLenPos = (entry - env.data()) - 1;
    vector<uint8_t> e59 = env; e59[entryLenPos] = 59; e59.erase(e59.begin() + entryLenPos + 1 + 59);
    CHECK_ERR(eciesParse(e59.data(), e59.size(), v), Err::BadRecipientEntry, "entry of 59 bytes");
    vector<uint8_t> e61 = env; e61[entryLenPos] = 61; e61.push_back(0);
    CHECK_ERR(eciesParse(e61.data(), e61.size(), v), Err::TooLarge, "entry of 61 bytes");
    /* zero recipients */
    vector<uint8_t> zero(env.begin(), env.begin() + (entry - env.data()) - 22);
    zero.back() = 0;
    CHECK_ERR(eciesParse(zero.data(), zero.size(), v), Err::BadRecipientEntry, "zero recipients");
    /* over limit */
    Limits one; one.maxPayload = 100;
    CHECK_ERR(eciesParse(env.data(), env.size(), v, one), Err::TooLarge, "over maxPayload");
    CHECK_ERR(eciesParse(NULL, 0, v), Err::BadArg, "null input");
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
    RecipientKeys recipients = {{vector<uint8_t>(pub, pub + 33), V["holder_address"]}};
    const string content = "provider message";
    DepinMessage direct, external;
    depinTestSetDeterministicRng(true, 1234);
    CHECK_ERR(messageBuild(genesis, "&TEST/SEC", V["holder_address"], 1787377444, DEPIN_TYPE_GROUP,
        (const uint8_t*)content.data(), content.size(), recipients, holder, direct), Err::Ok, "direct message");
    depinTestSetDeterministicRng(true, 1234);
    CHECK_ERR(messageBuild(genesis, "&TEST/SEC", V["holder_address"], 1787377444, DEPIN_TYPE_GROUP,
        (const uint8_t*)content.data(), content.size(), recipients, identity, external), Err::Ok, "provider message");
    vector<uint8_t> a,b; messageSerialize(direct,a); messageSerialize(external,b);
    CHECK(a == b && identity.signs == 1, "provider produces identical signed wire bytes");
    EnvelopeContext ctx; messageContext(external, ctx);
    vector<uint8_t> plain;
    CHECK_ERR(eciesDecrypt(external.payload.data(), external.payload.size(), identity, ctx, V["holder_address"], plain), Err::Ok, "provider decrypt");
    CHECK(string(plain.begin(),plain.end()) == content, "provider plaintext");
    uint8_t out[32]; memset(out,0xa5,sizeof(out)); size_t written = 99;
    int before = identity.exchanges;
    CHECK_ERR(eciesDecrypt(external.payload.data(), external.payload.size(), identity, ctx, V["holder_address"], out, 1, written), Err::TooLarge, "bounded output");
    CHECK(!written && out[0] == 0xa5 && identity.exchanges == before, "capacity checked before ECDH");
    vector<uint8_t> broken = external.payload; EciesView view;
    eciesParse(broken.data(),broken.size(),view);
    broken[(view.payload - broken.data()) + view.payloadLen - 1] ^= 1;
    CHECK_ERR(eciesDecrypt(broken.data(),broken.size(),identity,ctx,V["holder_address"],out,sizeof(out),written), Err::PayloadAuthFailed, "provider tampered payload");
    bool wiped = true; for (size_t i=0;i<content.size();++i) wiped &= out[i] == 0;
    CHECK(!written && wiped && out[content.size()] == 0xa5, "failed plaintext wiped within bounds");
    identity.locked = true;
    CHECK_ERR(messageSign(external,identity), Err::BadPrivKey, "locked provider cannot sign");
    CHECK(external.signature.empty(), "failed signing clears previous signature");
    CHECK_ERR(eciesDecrypt(direct.payload.data(),direct.payload.size(),identity,ctx,V["holder_address"],plain), Err::BadPrivKey, "locked provider cannot decrypt");
    CHECK(plain.empty(), "locked decrypt has no output");
    identity.locked = false; identity.failEcdh = true;
    CHECK_ERR(eciesDecrypt(direct.payload.data(),direct.payload.size(),identity,ctx,V["holder_address"],plain), Err::BadPrivKey, "ECDH refusal propagated");
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
    std::ifstream format("fixtures/depin_format3.json");
    if (deserializeJson(vectors, format)) return 2;
    genesis = vectors["network"].as<string>();
    test_format3();
    test_identity_provider();
    test_hex();
    test_compactsize();
    test_keys();
    test_ecies_map_order();
    test_ecies_negative();

    printf("\n%d checks, %d failures\n", g_pass + g_fail, g_fail);
    return g_fail ? 1 : 0;
}
