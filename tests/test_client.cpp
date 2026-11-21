/*
 * Host tests for DepinClient: an in-process FakeNode implements the protocol
 * 6 RPC surface (depingetmsginfo, depingetancestorrecipients, getpubkey,
 * depinsubmitmsg, depinchallenge, depinreceivemsg) with its own pool key,
 * signing replies with poolsig and encrypting bound replies for the caller,
 * so the client's whole flow is exercised end to end without a network.
 * Usage: test_client <vectors.txt>
 */
#include <stdio.h>
#include <string.h>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <ArduinoJson.h>
#include "DepinClient.h"
#include "Message.h"
#include "Conversion.h"

using namespace depin;
using std::string;
using std::vector;

void depinTestSetDeterministicRng(bool on, uint64_t seed);

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { g_pass++; } else { g_fail++; printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } } while (0)
#define CHECK_ERR(expr, want, msg) do { Err _e = (expr); if (_e == (want)) { g_pass++; } else { g_fail++; printf("  FAIL %s:%d: %s (got %s, want %s)\n", __FILE__, __LINE__, msg, errName(_e), errName(want)); } } while (0)

static std::map<string, string> V;

/* ── clocks ──────────────────────────────────────────────────────────────── */

struct FakeClock : public Clock {
    uint64_t wall = 1787377444000ULL;
    uint32_t mono = 100000;
    uint64_t unixMs() override { wall += 7; return wall; }       /* always advances */
    uint32_t monotonicMs() override { mono += 5; return mono; }
};

/* ── fake node ───────────────────────────────────────────────────────────── */

struct Holder { string address, pubHex; vector<uint8_t> sec; };

struct StoredMsg { string hash, token, sender, type, payloadHex, sigHex; int64_t ts; };

struct FakeNode : public RpcTransport {
    PrivateKey poolKey; string poolPubHex, poolAddress;
    string root = "&TEST";
    vector<Holder> holders;                 /* holders of &TEST (root) */
    vector<StoredMsg> pool;
    std::map<string, PrivateKey> signingKeys;
    ServiceContext service;
    string requestHash;
    DepinMessage lastMessage;
    std::map<string, string> revealed;      /* address -> pubkey hex */
    string liveChallenge; string challengeAddr; bool challengeUsed = true;
    /* knobs */
    bool truncated = false, dropNextChallenge = false, tamperPoolSig = false;
    bool tamperSubmitHash = false, rateLimit = false, transportFail = false, wrongIdOnce = false;
    int maxRecipients = 20, maxMessageSize = 1024;
    int rowMutation = 0;
    string lastMethod; vector<string> calls;

    FakeNode() {
        uint8_t s[32]; memset(s, 0x77, 32);
        poolKey = PrivateKey(s, true, &NeuraiTest);
        uint8_t sec[33]; PublicKey p = poolKey.publicKey(); p.compressed = true; p.sec(sec, 33);
        poolPubHex = hexEncode(sec, 33);
        poolAddress = addressForKey(p, &NeuraiTest);
        service.network = networkGenesis(&NeuraiTest); service.poolKey = poolPubHex; service.root = root;
        service.instance = string(64,'1'); service.revision = string(64,'2'); service.block = string(64,'3');
        service.height = 42;
    }
    void addHolder(const PrivateKey & k) {
        Holder h; uint8_t sec[33]; PublicKey p = k.publicKey(); p.compressed = true; p.sec(sec, 33);
        h.sec.assign(sec, sec + 33); h.pubHex = hexEncode(sec, 33); h.address = addressForKey(p, &NeuraiTest);
        holders.push_back(h); revealed[h.address] = h.pubHex; signingKeys[h.address] = k;
    }
    RpcReply response(const string & id, const string & body, const string & method, bool bound) {
        string pre, sig;
        responsePreimage(service, method, requestHash, bound, body, pre);
        signPreimage(poolKey, pre, sig);
        if (tamperPoolSig) sig[10] = sig[10] == 'A' ? 'B' : 'A';
        DynamicJsonDocument doc(4096 + body.size());
        doc["id"] = id;
        JsonObject r = doc.createNestedObject("result");
        r["protocol"] = 6; r["body_kind"] = int(bound); r["request_hash"] = requestHash;
        r["network"] = service.network; r["pool_pubkey"] = poolPubHex; r["pool_root"] = root;
        r["instance_id"] = service.instance; r["membership_revision"] = service.revision;
        r["membership_blockhash"] = service.block; r["membership_height"] = service.height;
        r[bound ? "encrypted" : "body"] = body; r["poolsig"] = sig;
        RpcReply result; result.ok = true; serializeJson(doc,result.body); return result;
    }
    RpcReply plain(const string & id, const string & json, const string & method, const string &) {
        return response(id, hexEncode((const uint8_t *)json.data(), json.size()), method, false);
    }
    RpcReply bound(const string & id, const string & json, const string & method, const string &, const string & address, const string &) {
        vector<uint8_t> sec(33);
        if (hexDecode(revealed[address].c_str(), 0, sec.data(), sec.size(), NULL) != 33) return error(id,-5,"unrevealed");
        RecipientKeys recipients = {{sec,address}};
        EnvelopeContext ctx; transportContext(TransportUse::Reply,service.network,ctx);
        vector<uint8_t> env; Limits limits; limits.maxContent = 65536; limits.maxPayload = 70000;
        if (eciesEncrypt((const uint8_t *)json.data(),json.size(),recipients,ctx,env,limits) != Err::Ok) return error(id,-25,"encrypt");
        return response(id,hexEncode(env.data(),env.size()),method,true);
    }
    RpcReply error(const string & id, int code, const string & msg) {
        RpcReply r; r.ok = true; r.httpStatus = 200;
        r.body = "{\"result\":null,\"error\":{\"code\":" + std::to_string(code) + ",\"message\":\"" + msg + "\"},\"id\":\"" + id + "\"}";
        return r;
    }
    static string newNonce(int n) { char b[65]; for (int i = 0; i < 64; i++) b[i] = "0123456789abcdef"[(i * 7 + n * 13) % 16]; b[64] = 0; return b; }

    RpcReply call(const string & method, const string & paramsJson, const string & idIn) override {
        lastMethod = method; calls.push_back(method);
        string id = idIn;
        if (wrongIdOnce) { id = "zzz"; wrongIdOnce = false; }
        if (transportFail) { RpcReply r; r.ok = false; r.transportError = "connect"; return r; }
        if (rateLimit) { RpcReply r; r.ok = false; r.rateLimited = true; r.retryAfterSec = 17; r.httpStatus = 429; return r; }
        DynamicJsonDocument p(paramsJson.size() * 2 + 2048);
        deserializeJson(p, paramsJson);
        JsonArray a = p.as<JsonArray>();

        JsonObjectConst obj = a[0];
        JsonObjectConst args = obj["args"];
        string token = obj["token"] | "", address = obj["address"] | "", ch = obj["challenge"] | "";
        if (method != "getpubkey") {
            RpcRequest req; req.method = method; req.service = service;
            req.id = obj["request_id"] | ""; req.timestampMs = obj["timestamp_ms"];
            req.token = token; req.address = address; req.challenge = ch;
            req.limit = args["limit"] | (args["max_results"] | 0);
            req.encrypted = args["encrypted"] | ""; req.afterHash = args["after_hash"] | "";
            if (args["cursor"] && readCursor(args["cursor"], req, req.cursor) != Err::Ok) return error(id,-8,"cursor");
            string serialized;
            if (encodeRequest(req, address.empty() ? NULL : &signingKeys[address], serialized, requestHash) != Err::Ok)
                return error(id,-8,"request");
            if (!address.empty() && !verifyMessage(address.c_str(), obj["signature"].as<const char *>(),
                ("DEPIN-RPC-REQUEST-v6|" + requestHash).c_str(), &NeuraiTest)) return error(id,-8,"signature");
        }
        if (method == "depingetmsginfo") {
            string j = "{\"enabled\":true,\"token\":\"" + root + "\",\"cipher\":\"AES-256-GCM\",\"maxrecipients\":" + std::to_string(maxRecipients) +
                       ",\"maxmessagesize\":" + std::to_string(maxMessageSize) + ",\"messageexpiryhours\":168,\"protocol\":6,\"accepted_protocols\":[6],\"ecies_formats\":[3],\"server_time_ms\":1787377444000,\"network\":\"" + service.network + "\",\"instance_id\":\"" + service.instance + "\",\"membership_revision\":\"" + service.revision + "\",\"membership_height\":42,\"membership_blockhash\":\"" + service.block + "\",\"depinpoolpkey\":\"" +
                       poolPubHex + "\",\"depinpoolkeyaddress\":\"" + poolAddress + "\"}";
            return plain(id, j, method, root);
        }
        if (method == "getpubkey") {
            string addr = a[0] | "";
            RpcReply r; r.ok = true; r.httpStatus = 200;
            { uint8_t payload[25]; if (fromBase58Check(addr.c_str(), addr.size(), payload, 25) != 21) return error(id, -5, "Invalid address"); }
            std::map<string, string>::iterator it = revealed.find(addr);
            if (it == revealed.end())
                r.body = "{\"result\":{\"address\":\"" + addr + "\",\"pubkey\":\"\",\"revealed\":false},\"error\":null,\"id\":\"" + id + "\"}";
            else
                r.body = "{\"result\":{\"address\":\"" + addr + "\",\"pubkey\":\"" + it->second + "\",\"revealed\":true},\"error\":null,\"id\":\"" + id + "\"}";
            return r;
        }
        if (method == "depingetancestorrecipients") {
            int max = args["max_results"] | 0; string stop = args["stop_at"] | "";
            string j = "{\"token\":\"" + token + "\",\"stop_at\":\"" + stop + "\",\"ancestors\":[\"" + token + "\"";
            if (token != root) j += ",\"" + root + "\"";
            j += "],\"recipients\":[";
            for (size_t i = 0; i < holders.size(); i++) {
                if (i) j += ",";
                j += "{\"address\":\"" + holders[i].address + "\",\"pubkey\":\"" + holders[i].pubHex + "\"}";
            }
            j += "],\"returned\":" + std::to_string(holders.size()) + ",\"max_results\":" + std::to_string(max) +
                 ",\"truncated\":" + (truncated ? "true" : "false") + ",\"skipped_no_pubkey\":1,\"skipped_no_pubkey_complete\":true}";
            return plain(id, j, method, token);
        }
        if (method == "depinsubmitmsg") {
            EnvelopeContext ctx; transportContext(TransportUse::Submit, service.network, ctx);
            string sender = address; string enc = args["encrypted"] | "";
            vector<uint8_t> env(enc.size() / 2); hexDecode(enc.c_str(), enc.size(), env.data(), env.size(), NULL);
      vector<uint8_t> pt; Limits lim; lim.maxContent = 65536; lim.maxPayload = 70000;
            if (eciesDecrypt(env.data(), env.size(), poolKey, ctx, poolAddress, pt, lim) != Err::Ok) return error(id, -25, "Failed to decrypt outer privacy shell");
            string hex((const char *)pt.data(), pt.size());
            vector<uint8_t> wire(hex.size() / 2); hexDecode(hex.c_str(), hex.size(), wire.data(), wire.size(), NULL);
            DepinMessage m;
            if (messageParse(wire.data(), wire.size(), service.network, m) != Err::Ok) return error(id, -22, "deserialize");
            if (m.sender != sender) return error(id, -8, "sender mismatch");
            std::map<string, string>::iterator it = revealed.find(sender);
            if (it == revealed.end()) return error(id, -5, "no revealed key");
            PublicKey pub; loadPublicKey(it->second, pub);
            if (messageVerify(m, pub, NULL) != Err::Ok) return error(id, -25, "bad signature");
            StoredMsg s; s.hash = m.hash(); s.token = m.token; s.sender = m.sender; s.ts = m.timestamp;
            s.type = (m.type == DEPIN_TYPE_GROUP) ? "group" : "private";
            s.payloadHex = hexEncode(m.payload.data(), m.payload.size()); s.sigHex = hexEncode(m.signature.data(), m.signature.size());
            lastMessage = m; pool.push_back(s);
            string h = tamperSubmitHash ? string(64, 'a') : s.hash;
            return bound(id, "{\"result\":\"success\",\"hash\":\"" + h + "\",\"timestamp\":" + std::to_string(s.ts) + "}", method, m.token, sender, "");
        }
        if (method == "depinchallenge") {
            liveChallenge = newNonce((int)calls.size()); challengeAddr = address; challengeUsed = false;
            return bound(id, "{\"challenge\":\"" + liveChallenge + "\",\"expires_in\":30,\"type\":\"receive\"}", method, token, address, "");
        }
        if (method == "depinreceivemsg" || method == "depinreceiveseq") {
            string after = args["after_hash"] | ""; int limit = args["limit"] | 0;
            int64_t seq = args["cursor"]["after_seq"] | int64_t(0);
            if (challengeUsed || ch != liveChallenge || address != challengeAddr) return error(id,-32600,"challenge");
            challengeUsed = true;
            /* page: messages after `after`, oldest first, in scope */
            bool found = after.empty(); string j = "{\"messages\":["; int n = 0; bool more = false;
            for (size_t i = 0; i < pool.size(); i++) {
                if (int64_t(i+1) <= seq) continue;
                if (!found) { if (pool[i].hash == after) found = true; continue; }
                if (!tokenInScope(pool[i].token, token)) continue;
                if (limit > 0 && n >= limit) { more = true; break; }
                seq = i+1;
                if (n) j += ",";
                j += "{\"sequence\":" + std::to_string(seq) + ",\"sender_pubkey_hex\":\"" + revealed[pool[i].sender] + "\",\"hash\":\"" + pool[i].hash + "\",\"token\":\"" + pool[i].token + "\",\"sender\":\"" + pool[i].sender +
                     "\",\"timestamp\":" + std::to_string(pool[i].ts) + ",\"message_type\":\"" + pool[i].type +
                     "\",\"encrypted_payload_hex\":\"" + pool[i].payloadHex + "\",\"signature_hex\":\"" + pool[i].sigHex + "\"}";
                n++;
            }
            if (!found) return error(id, -8, "after_hash not found");
            j += "],\"has_more\":" + string(more ? "true" : "false");
            if (method == "depinreceiveseq") {
                j += ",\"cursor\":{\"version\":1,\"stream_id\":\"" + string(64,'a') + "\",\"after_seq\":" + std::to_string(seq) +
                     ",\"scope\":\"" + token + "\",\"address\":\"" + address + "\",\"from_timestamp\":0}";
            }
            if (!dropNextChallenge) {
                liveChallenge = newNonce((int)calls.size() + 100); challengeUsed = false;
                j += ",\"next_challenge\":\"" + liveChallenge + "\",\"next_expires_in\":300";
            }
            j += "}";
            if (rowMutation) {
                DynamicJsonDocument changed(j.size() * 2 + 1024);
                deserializeJson(changed, j);
                JsonArray rows = changed["messages"].as<JsonArray>();
                if (rowMutation == 1) rows[0]["timestamp"] = "123";
                if (rowMutation == 2) rows[0].as<JsonObject>().remove("sender");
                if (rowMutation == 3) rows[0]["encrypted_payload_hex"] = "zz";
                if (rowMutation == 4) rows[1].as<JsonObject>().remove("sender_pubkey_hex");
                if (rowMutation == 5) rows[1]["sequence"] = rows[0]["sequence"];
                if (rowMutation == 6) changed["cursor"]["address"] = poolAddress;
                j.clear(); serializeJson(changed, j);
            }
            return bound(id, j, method, token, address, ch);
        }
        return error(id, -32601, "Method not found");
    }
};

/* ── fixtures ────────────────────────────────────────────────────────────── */

static PrivateKey keyFrom(uint8_t fill) { uint8_t s[32]; memset(s, fill, 32); return PrivateKey(s, true, &NeuraiTest); }
static string wifOf(const PrivateKey & k) { char b[64]; k.wif(b, sizeof(b)); return b; }

static ClientConfig cfgFor(FakeNode & node, const string & token = "&TEST/SEC") {
    ClientConfig c; c.serviceId = "https://pool.test/rpc"; c.token = token; c.net = &NeuraiTest;
    c.pin.serviceId = c.serviceId; c.pin.rootToken = node.root; c.pin.poolPubKeyHex = node.poolPubHex;
    return c;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

static void test_begin_and_bootstrap() {
    printf("begin + bootstrap\n");
    FakeNode node; FakeClock clock;
    PrivateKey alice = keyFrom(0x21), bob = keyFrom(0x22);
    node.addHolder(alice); node.addHolder(bob);
    DepinClient c(node, clock);
    ClientConfig cfg = cfgFor(node);
    CHECK_ERR(c.begin(cfg, wifOf(alice)), Err::Ok, "begin");
    CHECK(c.address() == node.holders[0].address && c.pubKeyHex() == node.holders[0].pubHex, "identity derived");
    CHECK_ERR(c.bootstrap(), Err::Ok, "bootstrap RequirePin");
    CHECK(c.ready() && c.pinConfirmed() && c.info().maxRecipients == 20 && c.pin().rootToken == "&TEST", "ready with confirmed pin");

    /* wrong pin key -> refuses before decoding */
    ClientConfig bad = cfg; bad.pin.poolPubKeyHex = node.holders[1].pubHex;
    DepinClient c2(node, clock);
    CHECK_ERR(c2.begin(bad, wifOf(alice)), Err::Ok, "begin with wrong pin");
    CHECK_ERR(c2.bootstrap(), Err::PinMismatch, "bootstrap rejects wrong pool key");
    CHECK(!c2.ready(), "not ready");
    SendResult sr;
    CHECK_ERR(c2.sendGroup("x", sr), Err::NotBootstrapped, "operations refused before bootstrap");

    /* incomplete pin */
    ClientConfig inc = cfg; inc.pin.rootToken = "";
    CHECK_ERR(c2.begin(inc, wifOf(alice)), Err::PinRequired, "RequirePin needs a full pin");
    /* pin for another service */
    ClientConfig other = cfg; other.pin.serviceId = "https://other/rpc";
    CHECK_ERR(c2.begin(other, wifOf(alice)), Err::PinMismatch, "pin bound to another service");
    /* token outside the root */
    ClientConfig out = cfg; out.token = "&OTHER/XXX";
    CHECK_ERR(c2.begin(out, wifOf(alice)), Err::Ok, "begin outside root");
    CHECK_ERR(c2.bootstrap(), Err::ScopeMismatch, "token outside the pool root");
    /* Legacy also supports uncompressed identities. */
    uint8_t s[32]; memset(s, 0x21, 32); PrivateKey unc(s, false, &NeuraiTest);
    CHECK_ERR(c2.begin(cfg, wifOf(unc)), Err::Ok, "uncompressed Legacy WIF accepted");
    /* the spec vector holder WIF (regtest) also loads */
    CHECK_ERR(c2.begin(cfg, V["holder_wif"]), Err::Ok, "regtest vector WIF accepted");
    CHECK(c2.address() == V["holder_address"], "vector address");

    /* TOFU: candidate must be accepted explicitly */
    ClientConfig tofu = cfg; tofu.trust = TrustMode::ExplicitTofu; tofu.pin = Pin();
    DepinClient c3(node, clock);
    CHECK_ERR(c3.begin(tofu, wifOf(alice)), Err::Ok, "begin TOFU");
    CHECK_ERR(c3.bootstrap(), Err::PinNotAccepted, "TOFU bootstrap returns candidate, not accepted");
    CHECK(c3.ready() && !c3.pinConfirmed() && c3.candidatePin().poolPubKeyHex == node.poolPubHex, "candidate exposed");
    CHECK_ERR(c3.sendGroup("x", sr), Err::PinNotAccepted, "refuses to operate before acceptPin");
    CHECK_ERR(c3.acceptPin(), Err::Ok, "acceptPin");
    CHECK(c3.pinConfirmed() && c3.pin().rootToken == "&TEST", "pin accepted");

    /* transport failures */
    node.transportFail = true;
    CHECK_ERR(c.bootstrap(), Err::Transport, "transport failure surfaces");
    node.transportFail = false; node.rateLimit = true;
    CHECK_ERR(c.bootstrap(), Err::RateLimited, "429 surfaces");
    CHECK(c.lastError().retryAfterSec == 17, "Retry-After captured");
    node.rateLimit = false; node.tamperPoolSig = true;
    CHECK_ERR(c.bootstrap(), Err::PoolSigInvalid, "tampered poolsig");
    node.tamperPoolSig = false; node.wrongIdOnce = true;
    CHECK_ERR(c.bootstrap(), Err::BadJson, "reply with another id rejected");
    CHECK_ERR(c.bootstrap(), Err::Ok, "recovers");
}

static void test_publish() {
    printf("publish group / private\n");
    FakeNode node; FakeClock clock;
    PrivateKey alice = keyFrom(0x31), bob = keyFrom(0x32), carol = keyFrom(0x33);
    node.addHolder(alice); node.addHolder(bob);       /* carol: revealed but not a holder */
    { uint8_t sec[33]; PublicKey p = carol.publicKey(); p.compressed = true; p.sec(sec, 33);
      node.revealed[addressForKey(p, &NeuraiTest)] = hexEncode(sec, 33); }
    DepinClient c(node, clock);
    c.begin(cfgFor(node), wifOf(alice)); c.bootstrap();

    RecipientKeys keys; SendResult st;
    CHECK_ERR(c.resolveGroupRecipients(keys, st), Err::Ok, "resolve recipients");
    CHECK(keys.size() == 2 && st.skippedNoPubKey == 1, "alice + bob, skipped reported");
    node.holders.push_back(node.holders[1]);          /* duplicate holder entry */
    CHECK_ERR(c.resolveGroupRecipients(keys, st), Err::Ok, "resolve with duplicate");
    CHECK(keys.size() == 2, "duplicate collapsed");
    node.holders.pop_back();
    node.truncated = true;
    CHECK_ERR(c.resolveGroupRecipients(keys, st), Err::RecipientsTruncated, "truncated refused");
    node.truncated = false;
    node.maxRecipients = 1;
    c.bootstrap();
    CHECK_ERR(c.resolveGroupRecipients(keys, st), Err::TooManyRecipients, "final set above pool max");
    node.maxRecipients = 20; c.bootstrap();

    depinTestSetDeterministicRng(false, 0);
    SendResult r;
    CHECK_ERR(c.sendGroup("hello group", r), Err::Ok, "send group");
    CHECK(r.hash.size() == 64 && r.recipients == 2 && node.pool.size() == 1 && node.pool[0].hash == r.hash, "group stored with confirmed hash");
    CHECK(node.pool[0].type == "group" && node.pool[0].token == "&TEST/SEC", "group fields");
    CHECK(node.calls.back() == "depinsubmitmsg" && node.calls[node.calls.size() - 2] == "depingetancestorrecipients", "call sequence");

    /* private to carol: getpubkey + {carol, self} */
    string carolAddr; { uint8_t sec[33]; PublicKey p = carol.publicKey(); p.compressed = true; p.sec(sec, 33); carolAddr = addressForKey(p, &NeuraiTest); }
    CHECK_ERR(c.sendPrivate(carolAddr, "psst", r), Err::Ok, "send private");
    CHECK(node.pool.size() == 2 && node.pool[1].type == "private" && r.recipients == 2, "private stored with 2 readers");
    /* carol can decrypt it, bob cannot */
    { vector<uint8_t> env(node.pool[1].payloadHex.size() / 2); hexDecode(node.pool[1].payloadHex.c_str(), 0, env.data(), env.size(), NULL);
      EnvelopeContext ctx; messageContext(node.lastMessage, ctx);
      vector<uint8_t> pt;
      CHECK_ERR(eciesDecrypt(env.data(), env.size(), carol, ctx, carolAddr, pt), Err::Ok, "carol decrypts the private message");
      CHECK(string((const char *)pt.data(), pt.size()) == "psst", "private content");
      CHECK_ERR(eciesDecrypt(env.data(), env.size(), bob, ctx, node.holders[1].address, pt), Err::NotForRecipient, "bob cannot"); }
    /* cached pubkey: second private send makes no getpubkey call */
    size_t before = node.calls.size();
    CHECK_ERR(c.sendPrivate(carolAddr, "again", r), Err::Ok, "send private again");
    bool calledGetPubKey = false;
    for (size_t i = before; i < node.calls.size(); i++) if (node.calls[i] == "getpubkey") calledGetPubKey = true;
    CHECK(!calledGetPubKey, "pubkey served from cache");
    /* unknown address */
    string nobody; { PrivateKey n = keyFrom(0x44); PublicKey p = n.publicKey(); p.compressed = true; nobody = addressForKey(p, &NeuraiTest); }
    CHECK_ERR(c.sendPrivate(nobody, "x", r), Err::KeyNotRevealed, "private to an address without revealed key");
    CHECK_ERR(c.sendPrivate("not-an-address", "x", r), Err::RpcError, "invalid address -> node error");
    /* content limits */
    CHECK_ERR(c.sendGroup("", r), Err::BadField, "empty content");
    CHECK_ERR(c.sendGroup(string(1025, 'a'), r), Err::TooLarge, "content over maxmessagesize");
    CHECK_ERR(c.sendGroup(string(1024, 'a'), r), Err::Ok, "content at the limit");
    /* node confirms a different hash */
    node.tamperSubmitHash = true;
    CHECK_ERR(c.sendGroup("x", r), Err::SubmitMismatch, "hash mismatch on confirmation");
    CHECK(r.hash.size() == 64, "local hash kept for the caller");
    node.tamperSubmitHash = false;
    /* clock */
    clock.wall = 5;
    CHECK_ERR(c.sendGroup("x", r), Err::ClockInvalid, "unset clock refuses to send");
}

static void test_receive() {
    printf("receive pages, challenges, cursors\n");
    FakeNode node; FakeClock clock;
    PrivateKey alice = keyFrom(0x51), bob = keyFrom(0x52);
    node.addHolder(alice); node.addHolder(bob);
    DepinClient a(node, clock), b(node, clock);
    a.begin(cfgFor(node), wifOf(alice)); a.bootstrap();
    b.begin(cfgFor(node), wifOf(bob)); b.bootstrap();
    SendResult r;
    CHECK_ERR(a.sendGroup("m1", r), Err::Ok, "alice m1");
    CHECK_ERR(a.sendGroup("m2", r), Err::Ok, "alice m2");
    CHECK_ERR(b.sendGroup("m3", r), Err::Ok, "bob m3");
    { DepinClient rootc(node, clock); rootc.begin(cfgFor(node, "&TEST"), wifOf(alice)); rootc.bootstrap();
      CHECK_ERR(rootc.sendGroup("root-only", r), Err::Ok, "message on the root (outside &TEST/SEC)"); }

    ReceivePage p;
    size_t callsBefore = node.calls.size();
    CHECK_ERR(b.receivePage("", 2, p), Err::Ok, "page 1 (limit 2)");
    CHECK(node.calls[callsBefore] == "depinchallenge" && node.calls[callsBefore + 1] == "depinreceiveseq", "challenge requested once, then receive");
    CHECK(p.received == 2 && p.messages.size() == 2 && p.rejected == 0, "two verified messages");
    CHECK(string((const char *)p.messages[0].content.data(), p.messages[0].content.size()) == "m1" &&
          string((const char *)p.messages[1].content.data(), p.messages[1].content.size()) == "m2", "contents in order");
    CHECK(p.messages[0].verified && p.messages[0].decrypted && p.messages[0].msg.sender == a.address(), "verified + sender");
    CHECK(p.serverHasMore && p.shouldContinue, "another sequence page exists");
    CHECK(p.nextCursor.find("\"after_seq\":2") != string::npos, "sequence cursor");
    CHECK(b.hasChallenge(), "chained challenge kept");

    callsBefore = node.calls.size();
    ReceivePage p2;
    CHECK_ERR(b.receivePage(p.nextCursor, 2, p2), Err::Ok, "page 2 with the chained challenge");
    CHECK(node.calls[callsBefore] == "depinreceiveseq", "no new depinchallenge call");
    CHECK(p2.received == 1 && p2.messages.size() == 1 && string((const char *)p2.messages[0].content.data(), 2) == "m3", "bob's own message (sender sees it)");
    CHECK(!p2.shouldContinue, "last page not full -> stop");
    ReceivePage p3;
    CHECK_ERR(b.receivePage(p2.nextCursor, 2, p3), Err::Ok, "empty page");
    CHECK(p3.received == 0 && p3.nextCursor == p2.nextCursor && !p3.shouldContinue, "empty page keeps the cursor");

    ReceivePage corrected, correctedLast;
    CHECK_ERR(b.receivePage("", 2, corrected), Err::Ok, "corrected server first page");
    CHECK(corrected.serverHasMore && corrected.shouldContinue, "correct has_more=true still continues");
    CHECK_ERR(b.receivePage(corrected.nextCursor, 2, correctedLast), Err::Ok, "corrected server last page");
    CHECK(correctedLast.messages.size() == 1 && !correctedLast.serverHasMore && !correctedLast.shouldContinue,
          "corrected server stops on partial final page");

    /* Invalid rows must not prevent later valid rows from being delivered. */
    for (int mutation = 1; mutation <= 3; ++mutation) {
        node.rowMutation = mutation;
        ReceivePage mixed;
        CHECK_ERR(b.receivePage("", 3, mixed), Err::Ok, "mixed valid/invalid page opens");
        CHECK(mixed.received == 3 && mixed.rejected == 1 && mixed.messages.size() == 2,
              "invalid row rejected independently of later rows");
        CHECK(mixed.nextCursor == correctedLast.nextCursor && !mixed.shouldContinue,
              "cursor follows examined sequence on final page");
        for (const auto &item : mixed.messages)
            CHECK(item.verified && item.decrypted && !item.content.empty(), "later rows remain owned and verified");
    }
    for (int mutation = 4; mutation <= 6; ++mutation) {
        node.rowMutation = mutation;
        ReceivePage bad;
        CHECK_ERR(b.receivePage("", 3, bad), Err::BadPage, "invalid RPC 6 page");
        CHECK(bad.nextCursor.empty() && bad.messages.empty(), "page failure is atomic");
    }
    node.rowMutation = 0;

    /* the root-only message is never delivered on &TEST/SEC (scope) */
    bool sawRoot = false;
    for (size_t i = 0; i < p.messages.size(); i++) if (p.messages[i].msg.token == "&TEST") sawRoot = true;
    CHECK(!sawRoot, "root message outside scope not delivered");

    /* missing next_challenge -> a new depinchallenge on the next page */
    node.dropNextChallenge = true;
    ReceivePage p4;
    CHECK_ERR(b.receivePage("", 1, p4), Err::Ok, "page without next_challenge");
    CHECK(!b.hasChallenge(), "no chained challenge stored");
    node.dropNextChallenge = false;
    callsBefore = node.calls.size();
    CHECK_ERR(b.receivePage("", 1, p4), Err::Ok, "next page requests a fresh challenge");
    CHECK(node.calls[callsBefore] == "depinchallenge", "depinchallenge called again");

    /* expiry: monotonic clock jumps past the TTL */
    clock.mono += 400000;
    CHECK(!b.hasChallenge(), "chained challenge expired locally");
    /* transport error mid-page: challenge invalidated, cursor untouched */
    node.transportFail = true;
    ReceivePage p5;
    CHECK_ERR(b.receivePage("", 2, p5), Err::Transport, "transport error");
    CHECK(!b.hasChallenge() && p5.messages.empty() && p5.nextCursor.empty(), "nothing advanced");
    node.transportFail = false;
    /* Malformed cursors are rejected before issuing an authenticated RPC. */
    ReceivePage p6;
    const size_t callsBeforeInvalid = node.calls.size();
    CHECK_ERR(b.receivePage(string(64, 'f'), 2, p6), Err::BadArg, "a hash is not a sequence cursor");
    CHECK(node.calls.size() == callsBeforeInvalid, "invalid cursor never reaches the node");
    CHECK_ERR(b.receivePage("zz", 2, p6), Err::BadArg, "malformed cursor rejected locally");
    CHECK_ERR(b.receivePage("", 1001, p6), Err::BadArg, "limit over 1000");

    /* tampered stored message: signature rejected, row counted, cursor still advances */
    node.pool[0].sigHex[10] = (node.pool[0].sigHex[10] == 'a') ? 'b' : 'a';
    ReceivePage p7;
    CHECK_ERR(b.receivePage("", 1, p7), Err::Ok, "page with a tampered row");
    CHECK(p7.received == 1 && p7.rejected == 1 && p7.messages.empty() && p7.nextCursor.find("\"after_seq\":1") != string::npos, "row rejected, cursor advances past it");
    /* Operation IDs are independent of clock resolution. */
    struct StuckClock : public Clock { uint64_t unixMs() override { return 1787377444000ULL; } uint32_t monotonicMs() override { return 1; } } stuck;
    DepinClient s(node, stuck);
    s.begin(cfgFor(node), wifOf(alice)); s.bootstrap();
    ReceivePage p8;
    CHECK_ERR(s.receivePage("", 1, p8), Err::Ok, "first request with a fixed clock");
    s.invalidateChallenge();
    CHECK_ERR(s.receivePage("", 1, p8), Err::Ok, "fresh operation ID allows the same millisecond");
}

int main(int argc, char ** argv) {
    const char * path = (argc > 1) ? argv[1] : "fixtures/vectors.txt";
    std::ifstream f(path);
    if (!f) { printf("cannot open %s\n", path); return 2; }
    string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq != string::npos) V[line.substr(0, eq)] = line.substr(eq + 1);
    }
    CHECK(cryptoBackend() != NULL, "crypto backend registered");
    test_begin_and_bootstrap();
    test_publish();
    test_receive();
    printf("\n%d checks, %d failures\n", g_pass + g_fail, g_fail);
    return g_fail ? 1 : 0;
}
