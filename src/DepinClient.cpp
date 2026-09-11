#include "DepinClient.h"
#include <ArduinoJson.h>
#include <string.h>
#include <stdio.h>

namespace depin {

/* ── helpers ─────────────────────────────────────────────────────────────── */

bool tokenInScope(const std::string & messageToken, const std::string & scope) {
    if (scope.empty() || messageToken.empty()) return false;
    if (messageToken == scope) return true;
    return messageToken.size() > scope.size() + 1 &&
           messageToken.compare(0, scope.size(), scope) == 0 && messageToken[scope.size()] == '/';
}

std::string jsonEscape(const std::string & s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
                else o += c;
        }
    }
    return o;
}
static std::string q(const std::string & s) { return "\"" + jsonEscape(s) + "\""; }

static bool isHex64(const std::string & s) { return validChallenge(s); }

/* ── construction / identity ─────────────────────────────────────────────── */

DepinClient::DepinClient(RpcTransport & rpc, Clock & clock) : _rpc(rpc), _clock(clock) {
    memset(_pubKey, 0, sizeof(_pubKey));
}

Err DepinClient::fail(Err e, const std::string & detail) {
    _last.err = e;
    _last.detail = detail;
    if (e != Err::RpcError) _last.rpc = RpcError();
    if (e != Err::RateLimited) _last.retryAfterSec = 0;
    return e;
}

std::string DepinClient::nextId() {
    char b[24];
    snprintf(b, sizeof(b), "d%lu", (unsigned long)++_callSeq);
    return b;
}

Err DepinClient::begin(const ClientConfig & cfg, const std::string & wif) {
    _began = _ready = _pinConfirmed = false;
    _challengeValid = false;
    _pubCache.clear(); _pubOrder.clear();
    _cfg = cfg;
    if (_cfg.serviceId.empty() || !validToken(_cfg.token, _cfg.limits)) return fail(Err::BadArg, "serviceId/token");
    if (_cfg.pageLimit == 0 || _cfg.pageLimit > 1000) return fail(Err::BadArg, "pageLimit");
    bool compressed = false;
    Err e = loadPrivateKey(wif, _key, &compressed);
    if (e != Err::Ok) return fail(e, "wif");
    if (!compressed) return fail(Err::BadPrivKey, "uncompressed WIF");
    PublicKey pub = _key.publicKey();
    pub.compressed = true;
    if (!pub.isValid() || pub.sec(_pubKey, 33) != 33) return fail(Err::BadPrivKey, "pubkey");
    _pubKeyHex = hexEncode(_pubKey, 33);
    _address = addressForKey(pub, _cfg.net);
    if (_address.empty() || !pubKeyMatchesAddress(pub, _address, _cfg.net)) return fail(Err::BadPrivKey, "address");
    if (_cfg.trust == TrustMode::RequirePin) {
        if (_cfg.pin.serviceId.empty()) _cfg.pin.serviceId = _cfg.serviceId;
        if (!_cfg.pin.complete()) return fail(Err::PinRequired, "RequirePin needs a full pin");
        if (_cfg.pin.serviceId != _cfg.serviceId) return fail(Err::PinMismatch, "pin is for another service");
    } else if (_cfg.trust == TrustMode::PinnedKeyDiscoverRoot && !_cfg.pin.hasKey()) {
        return fail(Err::PinRequired, "PinnedKeyDiscoverRoot needs the pool key");
    }
    _began = true;
    return fail(Err::Ok);
}

/* ── transport wrapper ───────────────────────────────────────────────────── */

Err DepinClient::rpcCall(const std::string & method, const std::string & paramsJson, std::string & id, std::string & body) {
    id = nextId();
    RpcReply r = _rpc.call(method, paramsJson, id);
    if (r.rateLimited) {
        _last.retryAfterSec = r.retryAfterSec;
        Err e = fail(Err::RateLimited, method);
        _last.retryAfterSec = r.retryAfterSec;
        return e;
    }
    if (!r.ok) {
        /* a JSON-RPC error may still come with a non-200 status: surface it */
        if (!r.body.empty()) {
            ReplyEnvelope env; RpcError re;
            if (parseReplyEnvelope(r.body, id, env, &re, _cfg.limits) == Err::RpcError) {
                fail(Err::RpcError, method); _last.rpc = re; return Err::RpcError;
            }
        }
        return fail(Err::Transport, r.transportError.empty() ? method : r.transportError);
    }
    body.swap(r.body);
    return Err::Ok;
}

Err DepinClient::requireReady() {
    if (!_began) return fail(Err::NotBootstrapped, "begin");
    if (!_ready) return fail(Err::NotBootstrapped, "bootstrap");
    if (!_pinConfirmed) return fail(Err::PinNotAccepted);
    return Err::Ok;
}

/* ── bootstrap ───────────────────────────────────────────────────────────── */

Err DepinClient::bootstrap() {
    if (!_began) return fail(Err::NotBootstrapped, "begin");
    _ready = false;
    _challengeValid = false;
    std::string id, body;
    Err e = rpcCall("depingetmsginfo", "[]", id, body);
    if (e != Err::Ok) return e;
    BootstrapResult b;
    RpcError re;
    e = depin::bootstrap(body, id, _cfg.trust, _cfg.pin, _cfg.serviceId, _cfg.net, b, &re, _cfg.limits);
    if (e == Err::RpcError) { fail(e, "depingetmsginfo"); _last.rpc = re; return e; }
    if (e != Err::Ok) return fail(e, "depingetmsginfo");
    if (!tokenInScope(_cfg.token, b.info.token)) return fail(Err::ScopeMismatch, "token outside the pool root");
    /* the server can never raise our local ceilings */
    if (b.info.maxRecipients > _cfg.limits.maxRecipients) b.info.maxRecipients = (uint32_t)_cfg.limits.maxRecipients;
    if (b.info.maxMessageSize > _cfg.limits.maxContent) b.info.maxMessageSize = (uint32_t)_cfg.limits.maxContent;
    _info = b.info;
    if (loadPublicKey(b.candidate.poolPubKeyHex, _poolKey) != Err::Ok) return fail(Err::BadPubKey, "pool key");
    _candidate = b.candidate;
    _pinConfirmed = b.pinConfirmed;
    if (_pinConfirmed) _pin = b.candidate;
    _ready = true;
    return fail(_pinConfirmed ? Err::Ok : Err::PinNotAccepted);
}

Err DepinClient::acceptPin() {
    if (!_ready) return fail(Err::NotBootstrapped, "bootstrap");
    if (_pinConfirmed) return fail(Err::Ok);
    if (!_candidate.complete()) return fail(Err::PinRequired, "no candidate");
    _pin = _candidate;
    _pinConfirmed = true;
    return fail(Err::Ok);
}

/* ── public keys ─────────────────────────────────────────────────────────── */

void DepinClient::cachePut(const std::string & address, const std::string & hex) {
    if (_cfg.pubKeyCacheSize == 0) return;
    if (_pubCache.find(address) == _pubCache.end()) {
        if (_pubOrder.size() >= _cfg.pubKeyCacheSize) {
            _pubCache.erase(_pubOrder.front());
            _pubOrder.erase(_pubOrder.begin());
        }
        _pubOrder.push_back(address);
    }
    _pubCache[address] = hex;
}

Err DepinClient::getPubKey(const std::string & address, std::string & pubKeyHex) {
    pubKeyHex.clear();
    if (!_began) return fail(Err::NotBootstrapped, "begin");
    if (!validPreimageField(address, 64)) return fail(Err::BadField, "address");
    if (address == _address) { pubKeyHex = _pubKeyHex; return Err::Ok; }
    std::map<std::string, std::string>::const_iterator it = _pubCache.find(address);
    if (it != _pubCache.end()) { pubKeyHex = it->second; return Err::Ok; }

    std::string id, body;
    Err e = rpcCall("getpubkey", "[" + q(address) + "]", id, body);
    if (e != Err::Ok) return e;
    /* getpubkey is a plain chain query: {result:{address,pubkey,revealed,...}} or a bare string */
    DynamicJsonDocument doc(body.size() + 512);
    if (body.size() > 4096 || deserializeJson(doc, body) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::BadJson, "getpubkey");
    if (!doc["error"].isNull()) {
        fail(Err::RpcError, "getpubkey");
        _last.rpc.code = doc["error"]["code"] | 0;
        const char * m = doc["error"]["message"] | "";
        _last.rpc.message.assign(m, strnlen(m, 200));
        return Err::RpcError;
    }
    std::string gotId = doc["id"].is<const char *>() ? std::string(doc["id"].as<const char *>()) : std::string();
    if (gotId != id) return fail(Err::BadJson, "getpubkey id");
    JsonVariant res = doc["result"];
    std::string hex;
    if (res.is<const char *>()) hex = res.as<const char *>();
    else if (res.is<JsonObject>()) {
        if (res["revealed"].is<bool>() && !res["revealed"].as<bool>()) return fail(Err::KeyNotRevealed, address);
        const char * p = res["pubkey"] | "";
        hex = p;
        const char * a = res["address"] | "";
        if (*a && address != a) return fail(Err::BadJson, "getpubkey address");
    } else return fail(Err::BadJson, "getpubkey result");
    if (hex.empty()) return fail(Err::KeyNotRevealed, address);
    PublicKey pub;
    if (loadPublicKey(hex, pub) != Err::Ok) return fail(Err::BadPubKey, "getpubkey key");
    if (!pubKeyMatchesAddress(pub, address, _cfg.net)) return fail(Err::BadPubKey, "getpubkey key != address");
    cachePut(address, hex);
    pubKeyHex = hex;
    return Err::Ok;
}

/* ── publishing ──────────────────────────────────────────────────────────── */

Err DepinClient::resolveGroupRecipients(std::vector<std::vector<uint8_t> > & keys, SendResult & stats) {
    keys.clear();
    Err e = requireReady();
    if (e != Err::Ok) return e;
    char n[16]; snprintf(n, sizeof(n), "%u", (unsigned)_info.maxRecipients);
    std::string id, body;
    e = rpcCall("depingetancestorrecipients", "[" + q(_cfg.token) + "," + n + "," + q(_pin.rootToken) + "]", id, body);
    if (e != Err::Ok) return e;
    ReplyContext ctx; ctx.method = "depingetancestorrecipients"; ctx.token = _cfg.token;
    std::string json; RpcError re;
    Limits lim = _cfg.limits; lim.maxReplyJson = 16384;
    e = openReply(body, id, ctx, ReplyKind::Plain, _poolKey, NULL, json, &re, lim);
    if (e == Err::RpcError) { fail(e, "depingetancestorrecipients"); _last.rpc = re; return e; }
    if (e != Err::Ok) return fail(e, "depingetancestorrecipients");

    DynamicJsonDocument doc(json.size() * 2 + 1024);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::BadJson, "recipients");
    JsonObject o = doc.as<JsonObject>();
    const char * tok = o["token"] | "";
    const char * stop = o["stop_at"] | "";
    if (_cfg.token != tok) return fail(Err::BadReply, "recipients token");
    if (_pin.rootToken != stop) return fail(Err::BadReply, "recipients stop_at");
    if (!o["truncated"].is<bool>() || o["truncated"].as<bool>()) return fail(Err::RecipientsTruncated);
    if (!o["recipients"].is<JsonArray>()) return fail(Err::BadReply, "recipients array");
    JsonArray anc = o["ancestors"];
    if (anc.isNull() || anc.size() == 0 || _cfg.token != (anc[0] | "")) return fail(Err::BadReply, "ancestors");
    JsonArray arr = o["recipients"].as<JsonArray>();
    if (o["returned"].is<int>() && (size_t)o["returned"].as<int>() != arr.size()) return fail(Err::BadReply, "returned count");
    stats.skippedNoPubKey = o["skipped_no_pubkey"] | -1;
    stats.skippedComplete = o["skipped_no_pubkey_complete"] | true;

    bool senderIn = false;
    for (JsonObject r : arr) {
        const char * a = r["address"] | (const char *)NULL;
        const char * k = r["pubkey"] | (const char *)NULL;
        if (!a || !k) return fail(Err::BadReply, "recipient entry");
        PublicKey pub;
        if (loadPublicKey(std::string(k), pub) != Err::Ok) return fail(Err::BadPubKey, a);
        if (!pubKeyMatchesAddress(pub, a, _cfg.net)) return fail(Err::BadPubKey, std::string("recipient key != address ") + a);
        std::vector<uint8_t> sec(33);
        hexDecode(k, 66, sec.data(), 33, NULL);
        bool dup = false;
        for (size_t i = 0; i < keys.size(); i++) if (keys[i] == sec) { dup = true; break; }
        if (!dup) keys.push_back(sec);
        if (memcmp(sec.data(), _pubKey, 33) == 0) senderIn = true;
        if (keys.size() > _cfg.limits.maxRecipients) return fail(Err::TooManyRecipients);
    }
    if (!senderIn) keys.push_back(std::vector<uint8_t>(_pubKey, _pubKey + 33));
    if (keys.size() > _info.maxRecipients) return fail(Err::TooManyRecipients, "final set incl. sender");
    stats.recipients = keys.size();
    return Err::Ok;
}

Err DepinClient::send(const std::string & content, uint8_t type,
                      const std::vector<std::vector<uint8_t> > & recipients, SendResult & out) {
    Err e = requireReady();
    if (e != Err::Ok) return e;
    if (content.empty()) return fail(Err::BadField, "empty content");
    size_t maxContent = _info.maxMessageSize ? _info.maxMessageSize : _cfg.limits.maxContent;
    if (content.size() > maxContent) return fail(Err::TooLarge, "content");
    uint64_t now = _clock.unixMs();
    if (now < 1000000000000ULL) return fail(Err::ClockInvalid);

    DepinMessage m;
    e = messageBuild(_cfg.token, _address, (int64_t)(now / 1000), type,
                     (const uint8_t *)content.data(), content.size(), recipients, _key, m, _cfg.limits);
    if (e != Err::Ok) return fail(e, "build");
    if (m.payload.size() > (size_t)_info.maxMessageSize * _info.maxRecipients) return fail(Err::TooLarge, "payload > size*recipients");
    std::vector<uint8_t> wire;
    if ((e = messageSerialize(m, wire, _cfg.limits)) != Err::Ok) return fail(e, "serialize");
    std::string hex = hexEncode(wire.data(), wire.size());
    uint8_t poolSec[33];
    if (_poolKey.sec(poolSec, 33) != 33) return fail(Err::BadPubKey, "pool key");
    std::vector<uint8_t> env;
    if ((e = wrapForPool(hex, poolSec, env, _cfg.limits)) != Err::Ok) return fail(e, "wrap");

    std::string id, body;
    std::string params = "[{\"sender\":" + q(_address) + ",\"encrypted\":\"" + hexEncode(env.data(), env.size()) + "\"}]";
    e = rpcCall("depinsubmitmsg", params, id, body);
    if (e != Err::Ok) return e;                 /* timeout: outcome unknown, hash kept below */
    out.hash = m.hash();
    ReplyContext ctx; ctx.method = "depinsubmitmsg"; ctx.token = _cfg.token; ctx.address = _address;
    std::string json; RpcError re;
    e = openReply(body, id, ctx, ReplyKind::Bound, _poolKey, &_key, json, &re, _cfg.limits);
    if (e == Err::RpcError) { fail(e, "depinsubmitmsg"); _last.rpc = re; return e; }
    if (e != Err::Ok) return fail(e, "depinsubmitmsg reply");
    DynamicJsonDocument doc(json.size() + 512);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::BadJson, "submit reply");
    const char * res = doc["result"] | "";
    const char * h = doc["hash"] | "";
    if (strcmp(res, "success") != 0 || m.hash() != h) return fail(Err::SubmitMismatch, h);
    out.recipients = recipients.size();
    return fail(Err::Ok);
}

Err DepinClient::sendGroup(const std::string & content, SendResult & out) {
    out = SendResult();
    std::vector<std::vector<uint8_t> > keys;
    Err e = resolveGroupRecipients(keys, out);
    if (e != Err::Ok) return e;
    return send(content, DEPIN_TYPE_GROUP, keys, out);
}

Err DepinClient::sendPrivate(const std::string & targetAddress, const std::string & content, SendResult & out) {
    out = SendResult();
    Err e = requireReady();
    if (e != Err::Ok) return e;
    std::string hex;
    if ((e = getPubKey(targetAddress, hex)) != Err::Ok) return e;
    std::vector<std::vector<uint8_t> > keys;
    std::vector<uint8_t> t(33);
    hexDecode(hex.c_str(), 66, t.data(), 33, NULL);
    keys.push_back(t);
    if (memcmp(t.data(), _pubKey, 33) != 0) keys.push_back(std::vector<uint8_t>(_pubKey, _pubKey + 33));
    return send(content, DEPIN_TYPE_PRIVATE, keys, out);
}

/* ── receiving ───────────────────────────────────────────────────────────── */

void DepinClient::invalidateChallenge() { _challengeValid = false; _challenge.clear(); }

bool DepinClient::hasChallenge() const {
    if (!_challengeValid) return false;
    return (int32_t)(_challengeExpiresMono - _clock.monotonicMs()) > 0;
}

Err DepinClient::ensureChallenge() {
    if (hasChallenge()) return Err::Ok;
    invalidateChallenge();
    uint64_t t = _clock.unixMs();
    if (t < 1000000000000ULL) return fail(Err::ClockInvalid, "wall clock");
    if (t <= _lastSignedMs) return fail(Err::ClockInvalid, "clock did not advance");   /* never reuse a signed ms */
    std::string pre, sig;
    Err e = requestPreimage("receive", _cfg.token, _address, t, pre);
    if (e != Err::Ok) return fail(e, "DEPIN-REQ");
    if ((e = signPreimage(_key, pre, sig)) != Err::Ok) return fail(e, "sign DEPIN-REQ");
    _lastSignedMs = t;
    char ms[24]; snprintf(ms, sizeof(ms), "%llu", (unsigned long long)t);
    std::string id, body;
    e = rpcCall("depinchallenge", "[" + q(_cfg.token) + "," + q(_address) + "," + ms + "," + q(sig) + ",\"receive\"]", id, body);
    if (e != Err::Ok) return e;
    uint32_t t0 = _clock.monotonicMs();
    ReplyContext ctx; ctx.method = "depinchallenge"; ctx.token = _cfg.token; ctx.address = _address;
    std::string json; RpcError re;
    e = openReply(body, id, ctx, ReplyKind::Bound, _poolKey, &_key, json, &re, _cfg.limits);
    if (e == Err::RpcError) { fail(e, "depinchallenge"); _last.rpc = re; return e; }
    if (e != Err::Ok) return fail(e, "depinchallenge reply");
    DynamicJsonDocument doc(json.size() + 256);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::ChallengeInvalid, "json");
    const char * ch = doc["challenge"] | "";
    const char * ty = doc["type"] | "receive";
    int exp = doc["expires_in"] | 30;
    if (!isHex64(ch) || strcmp(ty, "receive") != 0 || exp <= 0 || exp > 3600) return fail(Err::ChallengeInvalid, "fields");
    _challenge = ch;
    /* age from the request start, minus a safety margin */
    uint32_t ttl = (uint32_t)exp * 1000;
    ttl = ttl > 2000 ? ttl - 2000 : 0;
    _challengeExpiresMono = t0 + ttl;
    _challengeValid = ttl > 0;
    return _challengeValid ? Err::Ok : fail(Err::ChallengeInvalid, "ttl");
}

Err DepinClient::normaliseRow(const std::string & rowJson, ReceivedItem & item) {
    item = ReceivedItem();
    DynamicJsonDocument doc(rowJson.size() + 512);
    if (deserializeJson(doc, rowJson) || doc.overflowed() || !doc.is<JsonObject>()) return Err::BadPage;
    JsonObject r = doc.as<JsonObject>();
    const char * tok = r["token"] | (const char *)NULL;
    const char * snd = r["sender"] | (const char *)NULL;
    const char * mt = r["message_type"] | (const char *)NULL;
    const char * pl = r["encrypted_payload_hex"] | (const char *)NULL;
    const char * sg = r["signature_hex"] | (const char *)NULL;
    const char * hs = r["hash"] | (const char *)NULL;
    if (!tok || !snd || !mt || !pl || !sg || !hs || !r["timestamp"].is<long long>()) return Err::BadPage;
    if (!isHex64(hs)) return Err::BadPage;
    DepinMessage & m = item.msg;
    m.token = tok; m.sender = snd;
    m.timestamp = (int64_t)r["timestamp"].as<long long>();
    if (strcmp(mt, "private") == 0) m.type = DEPIN_TYPE_PRIVATE;
    else if (strcmp(mt, "group") == 0) m.type = DEPIN_TYPE_GROUP;
    else return Err::BadMessageType;
    size_t plLen = strlen(pl), sgLen = strlen(sg);
    if (plLen / 2 > _cfg.limits.maxPayload || sgLen / 2 > _cfg.limits.maxSignature) return Err::TooLarge;
    m.payload.resize(plLen / 2); m.signature.resize(sgLen / 2);
    Err e;
    if (hexDecode(pl, plLen, m.payload.data(), m.payload.size(), &e) != m.payload.size()) return Err::BadHex;
    if (hexDecode(sg, sgLen, m.signature.data(), m.signature.size(), &e) != m.signature.size()) return Err::BadHex;
    if ((e = messageDigest(m, _cfg.limits)) != Err::Ok) return e;
    if (m.hash() != hs) return Err::HashMismatch;
    item.hash = hs;
    EciesView v;
    return eciesParse(m.payload.data(), m.payload.size(), v, _cfg.limits);
}

Err DepinClient::receivePage(const std::string & afterHash, size_t limit, ReceivePage & out) {
    out = ReceivePage();
    Err e = requireReady();
    if (e != Err::Ok) return e;
    if (limit == 0) limit = _cfg.pageLimit;
    if (limit > 1000) return fail(Err::BadArg, "limit");
    if (!afterHash.empty() && !isHex64(afterHash)) return fail(Err::BadArg, "afterHash");
    if ((e = ensureChallenge()) != Err::Ok) return e;

    std::string pre, sig;
    if ((e = usePreimage(false, _cfg.token, _address, _challenge, pre)) != Err::Ok) return fail(e, "DEPIN-GET");
    if ((e = signPreimage(_key, pre, sig)) != Err::Ok) return fail(e, "sign DEPIN-GET");
    std::string used = _challenge;
    invalidateChallenge();                  /* consumed by the first valid use, whatever happens next */
    char lim[16]; snprintf(lim, sizeof(lim), "%u", (unsigned)limit);
    std::string params = "[" + q(_cfg.token) + "," + q(_address) + "," + q(used) + "," + q(sig) + ",0," + q(afterHash) + "," + lim + "]";
    std::string id, body;
    uint32_t t0 = _clock.monotonicMs();
    e = rpcCall("depinreceivemsg", params, id, body);
    if (e != Err::Ok) return e;
    ReplyContext ctx; ctx.method = "depinreceivemsg"; ctx.token = _cfg.token; ctx.address = _address; ctx.challenge = used;
    std::string json; RpcError re;
    Limits lim2 = _cfg.limits;
    lim2.maxContent = _cfg.limits.maxReplyHex;   /* a page is much larger than one message */
    e = openReply(body, id, ctx, ReplyKind::Bound, _poolKey, &_key, json, &re, lim2);
    if (e == Err::RpcError) { fail(e, "depinreceivemsg"); _last.rpc = re; return e; }
    if (e != Err::Ok) return fail(e, "depinreceivemsg reply");

    DynamicJsonDocument doc(json.size() + json.size() / 2 + 1024);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::BadPage, "json");
    JsonObject o = doc.as<JsonObject>();
    if (!o["messages"].is<JsonArray>() || !o["has_more"].is<bool>()) return fail(Err::BadPage, "shape");
    JsonArray rows = o["messages"].as<JsonArray>();
    if (rows.size() > limit) return fail(Err::BadPage, "more rows than limit");
    out.serverHasMore = o["has_more"].as<bool>();
    out.received = rows.size();

    /* chained challenge (may be absent if the node failed to issue one) */
    const char * next = o["next_challenge"] | (const char *)NULL;
    if (next && isHex64(next)) {
        int exp = o["next_expires_in"] | 300;
        if (exp > 0 && exp <= 3600) {
            _challenge = next;
            uint32_t ttl = (uint32_t)exp * 1000; ttl = ttl > 2000 ? ttl - 2000 : 0;
            _challengeExpiresMono = t0 + ttl;
            _challengeValid = ttl > 0;
        }
    }

    std::string lastHash;
    for (JsonObject r : rows) {
        std::string rowJson;
        serializeJson(r, rowJson);
        ReceivedItem item;
        Err re2 = normaliseRow(rowJson, item);
        if (re2 != Err::Ok) { out.rejected++; continue; }       /* structurally invalid: no anchor from it */
        if (!lastHash.empty() && lastHash == item.hash) { out.rejected++; continue; }   /* duplicate */
        lastHash = item.hash;                                     /* examined row: transport cursor */
        if (!tokenInScope(item.msg.token, _cfg.token)) { out.rejected++; continue; }
        std::string senderKey;
        if (getPubKey(item.msg.sender, senderKey) != Err::Ok) {
            /* transient key resolution failure: keep the page consistent, do not advance past this row */
            return fail(_last.err == Err::Ok ? Err::Transport : _last.err, "sender key " + item.msg.sender);
        }
        PublicKey pub;
        if (loadPublicKey(senderKey, pub) != Err::Ok || !pubKeyMatchesAddress(pub, item.msg.sender, _cfg.net) ||
            messageVerify(item.msg, pub, item.hash.c_str()) != Err::Ok) { out.rejected++; continue; }
        item.verified = true;
        if (eciesDecrypt(item.msg.payload.data(), item.msg.payload.size(), _key, item.content, _cfg.limits) != Err::Ok) {
            out.rejected++; continue;
        }
        item.decrypted = true;
        out.messages.push_back(item);
    }
    out.nextAfterHash = lastHash.empty() ? afterHash : lastHash;
    out.shouldContinue = out.serverHasMore || (out.received == limit && out.received > 0);
    return fail(Err::Ok);
}

} // namespace depin
