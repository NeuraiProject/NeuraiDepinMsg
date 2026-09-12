/*
 * Host tests for DepinAuth / DepinReply against the protocol vectors
 * (§13.2 request signatures, §13.3 plain reply + N1/N2, §13.4 bound
 * challenge reply, §13.5 bound receive reply + N8, bootstrap trust modes).
 * Usage: test_auth <vectors.txt>
 */
#include <stdio.h>
#include <string.h>
#include <string>
#include <map>
#include <fstream>
#include "DepinAuth.h"
#include "DepinReply.h"
#include "Message.h"
#include "Conversion.h"

using namespace depin;
using std::string;

void depinTestSetDeterministicRng(bool on, uint64_t seed);

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { g_pass++; } else { g_fail++; printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } } while (0)
#define CHECK_ERR(expr, want, msg) do { Err _e = (expr); if (_e == (want)) { g_pass++; } else { g_fail++; printf("  FAIL %s:%d: %s (got %s, want %s)\n", __FILE__, __LINE__, msg, errName(_e), errName(want)); } } while (0)

static std::map<string, string> V;

/* JSON-RPC container around a wrapper, as the node / proxy sends it */
static string rpcPlain(const string & body, const string & sig, const string & id = "t1") {
    return "{\"result\":{\"body\":\"" + body + "\",\"poolsig\":\"" + sig + "\"},\"error\":null,\"id\":\"" + id + "\"}";
}
static string rpcBound(const string & enc, const string & sig, const string & id = "t1") {
    return "{\"result\":{\"encrypted\":\"" + enc + "\",\"poolsig\":\"" + sig + "\"},\"error\":null,\"id\":\"" + id + "\"}";
}
static string toHexStr(const string & s) { return hexEncode((const uint8_t *)s.data(), s.size()); }

static Pin fullPin() {
    Pin p; p.serviceId = "https://pool.example/rpc"; p.rootToken = "&TEST"; p.poolPubKeyHex = V["pool_pubkey"]; return p;
}

/* ── preimages ───────────────────────────────────────────────────────────── */

static void test_preimages() {
    printf("preimages\n");
    string pre;
    CHECK_ERR(requestPreimage("receive", "&TEST/SEC", V["holder_address"], 1730000000000ULL, pre), Err::Ok, "DEPIN-REQ build");
    CHECK(pre == V["req_preimage"], "DEPIN-REQ matches §13.2");
    CHECK_ERR(usePreimage(false, "&TEST/SEC", V["holder_address"], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", pre), Err::Ok, "DEPIN-GET build");
    CHECK(pre == V["get_preimage"], "DEPIN-GET matches §13.2");
    CHECK_ERR(usePreimage(true, "&TEST", V["holder_address"], V["receive_nonce"], pre), Err::Ok, "DEPIN-CLEAR build");
    CHECK(pre.rfind("DEPIN-CLEAR|&TEST|", 0) == 0, "DEPIN-CLEAR prefix");
    CHECK_ERR(replyPreimage("depingetmsginfo", "&TEST", "", "", V["info_body"], pre), Err::Ok, "DEPIN-RESP build");
    CHECK(pre == "DEPIN-RESP|depingetmsginfo|&TEST|||" + sha256Hex(V["info_body"]), "DEPIN-RESP layout with empty fields");

    /* field validation */
    CHECK_ERR(requestPreimage("read", "&TEST", V["holder_address"], 1730000000000ULL, pre), Err::BadPreimageField, "type must be receive|admin");
    CHECK_ERR(requestPreimage("receive", "TEST", V["holder_address"], 1730000000000ULL, pre), Err::BadPreimageField, "token must start with &");
    CHECK_ERR(requestPreimage("receive", "&TE|ST", V["holder_address"], 1730000000000ULL, pre), Err::BadPreimageField, "'|' in token");
    CHECK_ERR(requestPreimage("receive", "&TEST", "addr|x", 1730000000000ULL, pre), Err::BadPreimageField, "'|' in address");
    CHECK_ERR(requestPreimage("receive", "&TEST", V["holder_address"], 1730000000ULL, pre), Err::BadPreimageField, "seconds instead of milliseconds");
    CHECK_ERR(usePreimage(false, "&TEST", V["holder_address"], "abc", pre), Err::BadPreimageField, "challenge not 64 hex");
    CHECK_ERR(usePreimage(false, "&TEST", V["holder_address"], string(64, 'G'), pre), Err::BadPreimageField, "challenge with non-hex");
    string upper = V["receive_nonce"]; upper[0] = 'A';
    CHECK_ERR(usePreimage(false, "&TEST", V["holder_address"], upper, pre), Err::BadPreimageField, "challenge must be lowercase");
    CHECK_ERR(replyPreimage("", "&TEST", "", "", V["info_body"], pre), Err::BadPreimageField, "empty method");
    CHECK_ERR(replyPreimage("depingetmsginfo", "&TEST", "", "", "", pre), Err::BadPreimageField, "empty body string");
    CHECK(!validToken("&"), "bare & is not a token");
    CHECK(validChallenge(V["receive_nonce"]) && !validChallenge(""), "challenge validator");
}

/* ── holder signatures ───────────────────────────────────────────────────── */

static void test_signatures() {
    printf("holder signatures (§13.2) and DePIN profile\n");
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    string sig;
    CHECK_ERR(signPreimage(holder, V["req_preimage"], sig), Err::Ok, "sign DEPIN-REQ");
    CHECK(sig == V["req_signature"], "DEPIN-REQ signature byte for byte");
    CHECK_ERR(signPreimage(holder, V["get_preimage"], sig), Err::Ok, "sign DEPIN-GET");
    CHECK(sig == V["get_signature"], "DEPIN-GET signature byte for byte");
    string who;
    CHECK_ERR(recoverSigner(V["req_preimage"], V["req_signature"], who), Err::Ok, "recover holder");
    CHECK(who == V["holder_pubkey"], "recovered == holder pubkey");

    /* uncompressed key: uNeurai signs with header 27..30, the DePIN profile refuses it */
    uint8_t s[32]; memset(s, 0x11, 32);
    PrivateKey unc(s, false, &NeuraiTest);
    CHECK_ERR(signPreimage(unc, V["req_preimage"], sig), Err::BadPrivKey, "uncompressed holder key refused to sign");
    char raw[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    signMessageBase64(unc, V["req_preimage"].c_str(), raw, sizeof(raw));
    CHECK(raw[0] != 0 && verifyMessage(unc.address().c_str(), raw, V["req_preimage"].c_str(), &NeuraiTest), "uNeurai itself accepts the uncompressed signature");
    CHECK_ERR(recoverSigner(V["req_preimage"], raw, who), Err::BadSignature, "DePIN profile rejects header 27..30");
    /* non-canonical base64 */
    string nc = V["req_signature"]; nc[nc.size() - 2] = 't';
    CHECK_ERR(recoverSigner(V["req_preimage"], nc, who), Err::BadSignature, "non-canonical base64 rejected");
    CHECK_ERR(recoverSigner(V["req_preimage"], "", who), Err::BadSignature, "empty signature");
    CHECK_ERR(recoverSigner("", V["req_signature"], who), Err::BadArg, "empty preimage");
}

/* ── §13.3 plain reply ───────────────────────────────────────────────────── */

static void test_plain_reply() {
    printf("plain reply §13.3 + N1 + N2\n");
    PublicKey pool; loadPublicKey(V["pool_pubkey"], pool);
    string rpc = rpcPlain(V["info_body"], V["info_poolsig"]);
    ReplyEnvelope env;
    CHECK_ERR(parseReplyEnvelope(rpc, "t1", env), Err::Ok, "container parses");
    CHECK(env.kind == ReplyKind::Plain && env.bodyStr == V["info_body"] && env.poolSig == V["info_poolsig"], "wrapper fields verbatim");
    ReplyContext ctx; ctx.method = "depingetmsginfo"; ctx.token = "&TEST";
    CHECK_ERR(verifyReply(env, ctx, pool), Err::Ok, "poolsig verifies with pool root bound");
    string json;
    CHECK_ERR(openReply(rpc, "t1", ctx, ReplyKind::Plain, pool, NULL, json), Err::Ok, "openReply plain");
    CHECK(json.find("\"protocol\":2") != string::npos && json.find("\"token\":\"&TEST\"") != string::npos, "decoded body JSON");
    PoolInfo info;
    CHECK_ERR(parsePoolInfo(json, info), Err::Ok, "pool info parses");
    CHECK(info.enabled && info.protocolVersion == 2 && info.maxRecipients == 20 && info.maxMessageSize == 1024 &&
          info.messageExpiryHours == 168 && info.cipher == "AES-256-GCM" && info.poolPubKeyHex == V["pool_pubkey"] &&
          info.poolAddress == V["pool_address"] && info.token == "&TEST", "pool info fields");

    /* wrong context */
    ReplyContext other = ctx; other.token = "&TEST/SEC";
    CHECK_ERR(verifyReply(env, other, pool), Err::PoolSigInvalid, "different token in preimage -> invalid");
    other = ctx; other.method = "depinpoolstats";
    CHECK_ERR(verifyReply(env, other, pool), Err::PoolSigInvalid, "different method -> invalid");
    PublicKey holderPub; loadPublicKey(V["holder_pubkey"], holderPub);
    CHECK_ERR(verifyReply(env, ctx, holderPub), Err::PoolSigInvalid, "wrong pinned key -> invalid");

    /* N1: flipped poolsig */
    uint8_t raw[65]; fromBase64(V["info_poolsig"].c_str(), 88, raw, 65); raw[40] ^= 0x01;
    char b64[89]; size_t n = toBase64(raw, 65, b64, 89); b64[n] = 0;
    CHECK_ERR(openReply(rpcPlain(V["info_body"], b64), "t1", ctx, ReplyKind::Plain, pool, NULL, json), Err::PoolSigInvalid, "N1 tampered poolsig");
    CHECK(json.empty(), "N1: nothing decoded");
    /* N2: re-serialised body (same JSON, different bytes) */
    string reser = "{\"cipher\":\"AES-256-GCM\",\"depinpoolkeyaddress\":\"" + V["pool_address"] + "\",\"depinpoolpkey\":\"" + V["pool_pubkey"] +
                   "\",\"depinwallet\":\"wallet.dat\",\"enabled\":true,\"maxmessagesize\":1024,\"maxpoolsizemb\":100,\"maxrecipients\":20,"
                   "\"memoryusage\":0,\"memoryusagemb\":0,\"messageexpiryhours\":168,\"messages\":0,\"protocol\":2,\"token\":\"&TEST\"}";
    CHECK(toHexStr(reser) != V["info_body"], "N2 fixture: re-serialisation differs");
    CHECK_ERR(openReply(rpcPlain(toHexStr(reser), V["info_poolsig"]), "t1", ctx, ReplyKind::Plain, pool, NULL, json), Err::PoolSigInvalid, "N2 re-serialised body rejected");

    /* container shapes */
    RpcError re;
    CHECK_ERR(parseReplyEnvelope("{\"result\":null,\"error\":{\"code\":-8,\"message\":\"bad cursor\"},\"id\":\"t1\"}", "t1", env, &re), Err::RpcError, "JSON-RPC error");
    CHECK(re.code == -8 && re.message == "bad cursor", "error code/message captured");
    CHECK_ERR(parseReplyEnvelope(rpc, "t2", env), Err::BadJson, "id mismatch");
    CHECK_ERR(parseReplyEnvelope("{\"result\":{\"body\":\"7b7d\",\"encrypted\":\"7b7d\",\"poolsig\":\"" + V["info_poolsig"] + "\"},\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "both body and encrypted");
    CHECK_ERR(parseReplyEnvelope("{\"result\":{\"poolsig\":\"" + V["info_poolsig"] + "\"},\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "neither wrapper");
    CHECK_ERR(parseReplyEnvelope("{\"result\":{\"body\":\"7b7d\"},\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "missing poolsig");
    CHECK_ERR(parseReplyEnvelope("{\"result\":{\"body\":\"7b7\",\"poolsig\":\"" + V["info_poolsig"] + "\"},\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "odd hex body");
    CHECK_ERR(parseReplyEnvelope("{\"result\":{\"body\":123,\"poolsig\":\"" + V["info_poolsig"] + "\"},\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "body not a string");
    CHECK_ERR(parseReplyEnvelope("{\"result\":[],\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "old-style array result rejected");
    CHECK_ERR(parseReplyEnvelope("{\"result\":{\"messages\":[]},\"error\":null,\"id\":\"t1\"}", "t1", env), Err::BadReply, "plaintext protocol-1 reply rejected");
    CHECK_ERR(parseReplyEnvelope("not json", "t1", env), Err::BadJson, "not JSON");
    CHECK_ERR(parseReplyEnvelope("", "t1", env), Err::BadArg, "empty");
    CHECK_ERR(openReply(rpc, "t1", ctx, ReplyKind::Bound, pool, NULL, json), Err::ReplyKindMismatch, "expected bound, got plain");
    Limits small; small.maxReplyHex = 100;
    CHECK_ERR(parseReplyEnvelope(rpc, "t1", env, NULL, small), Err::BadReply, "body over maxReplyHex");
}

/* ── §13.4 / §13.5 bound replies ─────────────────────────────────────────── */

static void test_bound_replies() {
    printf("bound replies §13.4, §13.5 + N8\n");
    PublicKey pool; loadPublicKey(V["pool_pubkey"], pool);
    PrivateKey holder; loadPrivateKey(V["holder_wif"], holder);
    string json;

    ReplyContext ch; ch.method = "depinchallenge"; ch.token = "&TEST/SEC"; ch.address = V["holder_address"];
    CHECK_ERR(openReply(rpcBound(V["challenge_encrypted"], V["challenge_poolsig"]), "t1", ch, ReplyKind::Bound, pool, &holder, json), Err::Ok, "§13.4 challenge reply opens");
    CHECK(json == V["challenge_plain"], "§13.4 plaintext");
    CHECK_ERR(openReply(rpcBound(V["challenge_encrypted"], V["challenge_poolsig"]), "t1", ch, ReplyKind::Bound, pool, NULL, json), Err::BadArg, "bound reply needs the holder key");
    CHECK_ERR(openReply(rpcBound(V["challenge_encrypted"], V["challenge_poolsig"]), "t1", ch, ReplyKind::Plain, pool, &holder, json), Err::ReplyKindMismatch, "expected plain, got bound");

    ReplyContext rc; rc.method = "depinreceivemsg"; rc.token = "&TEST/SEC"; rc.address = V["holder_address"]; rc.challenge = V["receive_nonce"];
    CHECK_ERR(openReply(rpcBound(V["receive_encrypted"], V["receive_poolsig"]), "t1", rc, ReplyKind::Bound, pool, &holder, json), Err::Ok, "§13.5 receive reply opens (challenge bound)");
    CHECK(json == V["receive_plain"], "§13.5 plaintext");

    /* N8: §13.5 poolsig verified with the §13.4 preimage (empty challenge) */
    ReplyContext n8 = rc; n8.challenge = "";
    CHECK_ERR(openReply(rpcBound(V["receive_encrypted"], V["receive_poolsig"]), "t1", n8, ReplyKind::Bound, pool, &holder, json), Err::PoolSigInvalid, "N8 reply is bound to its challenge");
    CHECK(json.empty(), "N8: nothing decrypted");
    /* another holder cannot open it even with a valid poolsig */
    uint8_t s[32]; memset(s, 0x42, 32); PrivateKey stranger(s, true, &NeuraiTest);
    CHECK_ERR(openReply(rpcBound(V["receive_encrypted"], V["receive_poolsig"]), "t1", rc, ReplyKind::Bound, pool, &stranger, json), Err::NotForRecipient, "bound to the holder");
    /* second page vector, if present */
    if (V.count("receive2_encrypted")) {
        ReplyContext r2 = rc; r2.challenge = V["receive2_nonce"];
        Limits lim; lim.maxContent = 4096;
        CHECK_ERR(openReply(rpcBound(V["receive2_encrypted"], V["receive2_poolsig"]), "t1", r2, ReplyKind::Bound, pool, &holder, json, NULL, lim), Err::Ok, "§13.5 second page opens");
        CHECK(json == V["receive2_plain"], "second page plaintext");
        Limits small; small.maxContent = 512;   /* the page is 1001 bytes */
        CHECK_ERR(openReply(rpcBound(V["receive2_encrypted"], V["receive2_poolsig"]), "t1", r2, ReplyKind::Bound, pool, &holder, json, NULL, small), Err::TooLarge, "page over maxContent is refused after poolsig");
        CHECK(json.empty(), "nothing returned when over the limit");
    }
}

/* ── bootstrap trust modes ───────────────────────────────────────────────── */

static void test_bootstrap() {
    printf("bootstrap (§6.4)\n");
    string rpc = rpcPlain(V["info_body"], V["info_poolsig"]);
    BootstrapResult b;
    Pin pin = fullPin();

    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::RequirePin, pin, pin.serviceId, &NeuraiTest, b), Err::Ok, "RequirePin with the right pin");
    CHECK(b.pinConfirmed && b.candidate.rootToken == "&TEST" && b.info.maxRecipients == 20, "RequirePin confirmed");
    Pin wrongRoot = pin; wrongRoot.rootToken = "&OTHER";
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::RequirePin, wrongRoot, pin.serviceId, &NeuraiTest, b), Err::PoolSigInvalid, "RequirePin: wrong root -> preimage differs -> invalid");
    Pin wrongKey = pin; wrongKey.poolPubKeyHex = V["holder_pubkey"];
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::RequirePin, wrongKey, pin.serviceId, &NeuraiTest, b), Err::PoolSigInvalid, "RequirePin: wrong key -> invalid, body never decoded");
    Pin partial = pin; partial.rootToken = "";
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::RequirePin, partial, pin.serviceId, &NeuraiTest, b), Err::PinRequired, "RequirePin: incomplete pin is not degraded to TOFU");
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::RequirePin, Pin(), pin.serviceId, &NeuraiTest, b), Err::PinRequired, "RequirePin: no pin");

    Pin keyOnly; keyOnly.poolPubKeyHex = V["pool_pubkey"];
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::PinnedKeyDiscoverRoot, keyOnly, "svc", &NeuraiTest, b), Err::Ok, "PinnedKeyDiscoverRoot");
    CHECK(b.pinConfirmed && b.candidate.rootToken == "&TEST" && b.candidate.serviceId == "svc" && b.candidate.poolPubKeyHex == V["pool_pubkey"], "root learned from the signed body");
    Pin otherKey; otherKey.poolPubKeyHex = V["holder_pubkey"];
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::PinnedKeyDiscoverRoot, otherKey, "svc", &NeuraiTest, b), Err::PoolSigInvalid, "PinnedKeyDiscoverRoot: other key -> invalid");
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::PinnedKeyDiscoverRoot, Pin(), "svc", &NeuraiTest, b), Err::PinRequired, "PinnedKeyDiscoverRoot needs a key");

    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::ExplicitTofu, Pin(), "svc", &NeuraiTest, b), Err::Ok, "ExplicitTofu self-consistent reply");
    CHECK(!b.pinConfirmed && b.candidate.rootToken == "&TEST" && b.candidate.poolPubKeyHex == V["pool_pubkey"] && b.candidate.serviceId == "svc", "TOFU candidate, not confirmed");
    /* TOFU: body announcing a different key than the signer must fail */
    string body = V["info_body"];
    string swapped;
    { string json;
      std::vector<uint8_t> tmp(body.size() / 2); Err e; hexDecode(body.c_str(), body.size(), tmp.data(), tmp.size(), &e);
      json.assign((const char *)tmp.data(), tmp.size());
      size_t p = json.find(V["pool_pubkey"]); json.replace(p, 66, V["holder_pubkey"]);
      swapped = toHexStr(json); }
    CHECK_ERR(bootstrap(rpcPlain(swapped, V["info_poolsig"]), "t1", TrustMode::ExplicitTofu, Pin(), "svc", &NeuraiTest, b), Err::PoolSigInvalid, "TOFU: announced key != signer (body changed, sig stale)");
    /* address mismatch on any mode: announce another address with a re-signed body is impossible here (no pool key); check the address check path with the wrong network */
    CHECK_ERR(bootstrap(rpc, "t1", TrustMode::RequirePin, pin, pin.serviceId, &Neurai, b), Err::PinMismatch, "pool address is a testnet address: mainnet network rejects it");
    /* protocol / enabled checks on a hand-built body signed by nobody: parsePoolInfo + checkInfo via ExplicitTofu is not reachable without a signature, so test parsePoolInfo directly */
    PoolInfo info;
    CHECK_ERR(parsePoolInfo("{\"enabled\":true,\"token\":\"&T\",\"protocol\":2,\"depinpoolpkey\":\"" + V["pool_pubkey"] + "\",\"maxrecipients\":0,\"maxmessagesize\":1024}", info), Err::BadJson, "maxrecipients 0 rejected");
    CHECK_ERR(parsePoolInfo("{\"enabled\":true,\"token\":\"&T\",\"protocol\":2,\"depinpoolpkey\":\"" + V["pool_pubkey"] + "\",\"maxrecipients\":51,\"maxmessagesize\":1024}", info), Err::BadJson, "maxrecipients 51 rejected");
    CHECK_ERR(parsePoolInfo("{\"enabled\":true,\"token\":\"T\",\"protocol\":2,\"depinpoolpkey\":\"" + V["pool_pubkey"] + "\",\"maxrecipients\":20,\"maxmessagesize\":1024}", info), Err::BadJson, "token without & rejected");
    CHECK_ERR(parsePoolInfo("{\"enabled\":true,\"token\":\"&T\",\"protocol\":\"2\",\"depinpoolpkey\":\"" + V["pool_pubkey"] + "\",\"maxrecipients\":20,\"maxmessagesize\":1024}", info), Err::BadJson, "protocol as string rejected");
    CHECK_ERR(parsePoolInfo("{\"enabled\":true,\"token\":\"&T\",\"protocol\":2,\"depinpoolpkey\":\"" + V["pool_pubkey"] + "\",\"maxrecipients\":20,\"maxmessagesize\":1024,\"cipher\":\"AES-256-GCM\"}", info), Err::Ok, "minimal valid info");
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
    CHECK(cryptoBackend() != NULL, "crypto backend registered");
    test_preimages();
    test_signatures();
    test_plain_reply();
    test_bound_replies();
    test_bootstrap();
    printf("\n%d checks, %d failures\n", g_pass + g_fail, g_fail);
    return g_fail ? 1 : 0;
}
