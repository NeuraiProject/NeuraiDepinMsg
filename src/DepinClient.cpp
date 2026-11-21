#include "DepinClient.h"
#include <ArduinoJson.h>
#include <string.h>
#include <stdio.h>
#include <algorithm>

namespace depin {

/* ── helpers ─────────────────────────────────────────────────────────────── */

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
    if (!_cfg.net) _cfg.net = &NeuraiTest;
    if (_cfg.expectedGenesis.empty()) _cfg.expectedGenesis = networkGenesis(_cfg.net);
    if (_cfg.limits.maxRecipients == 0 || _cfg.limits.maxContent == 0) return fail(Err::BadArg, "limits");
    if (!validChallenge(_cfg.expectedGenesis)) return fail(Err::BadField, "expectedGenesis");
    if (_cfg.serviceId.empty() || !validToken(_cfg.token, _cfg.limits)) return fail(Err::BadArg, "serviceId/token");
    if (_cfg.pageLimit == 0 || _cfg.pageLimit > 1000) return fail(Err::BadArg, "pageLimit");
    bool compressed = false;
    Err e = loadPrivateKey(wif, _key, &compressed);
    if (e != Err::Ok) return fail(e, "wif");
    if (!compressed && _cfg.strictEcdsa) return fail(Err::BadPrivKey, "uncompressed WIF");
    PublicKey pub = _key.publicKey();
    pub.compressed = compressed;
    _pubKeySize = pub.sec(_pubKey, sizeof(_pubKey));
    if (!pub.isValid() || _pubKeySize != (compressed ? 33u : 65u)) return fail(Err::BadPrivKey, "pubkey");
    _pubKeyHex = hexEncode(_pubKey, _pubKeySize);
    char strict[64] = {};
    if (_cfg.strictEcdsa) pub.ecdsaAddress(strict, sizeof(strict), _cfg.net);
    _address = _cfg.strictEcdsa ? std::string(strict) : addressForKey(pub, _cfg.net);
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

Err DepinClient::call(RpcRequest & r, std::string & json) {
    const CryptoBackend * backend = cryptoBackend();
    if (!backend) return fail(Err::NoCryptoBackend);
    uint8_t random[32];
    if (!backend->randomBytes(random, sizeof(random))) return fail(Err::Rng);
    r.id = hexEncode(random, sizeof(random));
    uint64_t now = _clock.unixMs();
    if (now < 1000000000000ULL || now > INT64_MAX) return fail(Err::ClockInvalid);
    r.timestampMs = int64_t(now);
    r.service = _service;
    std::string params, hash, id, body;
    Err e = encodeRequest(r, &_key, params, hash);
    if (e != Err::Ok) return fail(e, r.method);
    e = rpcCall(r.method, params, id, body);
    if (e != Err::Ok) return e;
    ReplyEnvelope reply;
    RpcError rpcError;
    e = parseReplyEnvelope(body, id, reply, &rpcError, _cfg.limits);
    if (e == Err::RpcError) { fail(e, r.method); _last.rpc = rpcError; return e; }
    if (e != Err::Ok) return fail(e, r.method);
    e = verifyAndOpen(reply, r, hash, _cfg.expectedGenesis, _cfg.pin, _cfg.trust, _key, json, _cfg.limits);
    if (e != Err::Ok) return fail(e, r.method);
    // Inspect only the error field here. The caller parses the full successful body.
    StaticJsonDocument<128> filter;
    filter["error"] = true;
    DynamicJsonDocument errorDoc(1024);
    if (deserializeJson(errorDoc, json, DeserializationOption::Filter(filter)) || !errorDoc.is<JsonObject>())
        return fail(Err::BadJson, r.method);
    if (reply.service.revision != _service.revision) invalidateChallenge();
    _service = reply.service;
    if (!errorDoc["error"].isNull()) {
        fail(Err::RpcError, r.method);
        _last.rpc.code = errorDoc["error"]["code"] | 0;
        _last.rpc.reason = errorDoc["error"]["data"]["depin_error"] | "";
        _last.rpc.message = errorDoc["error"]["message"] | "";
        return Err::RpcError;
    }
    return Err::Ok;
}

Err DepinClient::bootstrap() {
    if (!_began) return fail(Err::NotBootstrapped, "begin");
    _ready = _pinConfirmed = false;
    invalidateChallenge();
    RpcRequest request;
    request.method = "depingetmsginfo";
    std::string json;
    Err e = call(request, json);
    if (e != Err::Ok) return e;
    DynamicJsonDocument doc(json.size()*2 + 2048);
    if (deserializeJson(doc, json)) return fail(Err::BadJson, request.method);
    if ((e = parsePoolInfo(doc.as<JsonObjectConst>(), _service, _cfg.net, _info)) != Err::Ok) return fail(e, request.method);
    if (!tokenInScope(_cfg.token, _info.token)) return fail(Err::ScopeMismatch);
    _info.maxRecipients = std::min<size_t>(_info.maxRecipients, _cfg.limits.maxRecipients);
    _info.maxMessageSize = std::min<size_t>(_info.maxMessageSize, _cfg.limits.maxContent);
    if (loadPublicKey(_service.poolKey, _poolKey) != Err::Ok) return fail(Err::BadPubKey);
    _candidate.serviceId = _cfg.serviceId;
    _candidate.rootToken = _service.root;
    _candidate.poolPubKeyHex = _service.poolKey;
    _pinConfirmed = _cfg.trust != TrustMode::ExplicitTofu;
    if (_pinConfirmed) _pin = _candidate;
    _ready = true;
    return fail(_pinConfirmed ? Err::Ok : Err::PinNotAccepted);
}

Err DepinClient::acceptPin() {
    if (!_ready) return fail(Err::NotBootstrapped, "bootstrap");
    if (_pinConfirmed) return fail(Err::Ok);
    if (!_candidate.complete()) return fail(Err::PinRequired, "no candidate");
    _pin = _cfg.pin = _candidate;
    _cfg.trust = TrustMode::RequirePin;
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
    if (body.size() > 4096) return fail(Err::TooLarge, "getpubkey");
    DynamicJsonDocument doc(body.size() + 512);
    if (deserializeJson(doc, body) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::BadJson, "getpubkey");
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

Err DepinClient::resolveGroupRecipients(RecipientKeys & keys, SendResult & stats) {
    keys.clear();
    Err e = requireReady();
    if (e != Err::Ok) return e;
    RpcRequest request;
    request.method = "depingetancestorrecipients";
    request.token = _cfg.token;
    request.limit = _info.maxRecipients;
    std::string json;
    if ((e = call(request, json)) != Err::Ok) return e;
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
        std::vector<uint8_t> sec(strlen(k)/2);
        hexDecode(k, strlen(k), sec.data(), sec.size(), NULL);
        bool duplicate = false;
        for (const auto & key : keys) if (key.address == a) duplicate = true;
        if (!duplicate) keys.push_back({sec, a});
        if (_address == a) senderIn = true;
        if (keys.size() > _info.maxRecipients) return fail(Err::TooManyRecipients);
    }
    if (!senderIn) keys.push_back({std::vector<uint8_t>(_pubKey, _pubKey+_pubKeySize), _address});
    if (keys.size() > _info.maxRecipients) return fail(Err::TooManyRecipients, "final set incl. sender");
    stats.recipients = keys.size();
    return Err::Ok;
}

Err DepinClient::send(const std::string & content, uint8_t type,
                      const RecipientKeys & recipients, SendResult & out) {
    Err e = requireReady();
    if (e != Err::Ok) return e;
    if (recipients.size() > _info.maxRecipients) return fail(Err::TooManyRecipients);
    if (content.empty()) return fail(Err::BadField, "empty content");
    size_t maxContent = _info.maxMessageSize ? _info.maxMessageSize : _cfg.limits.maxContent;
    if (content.size() > maxContent) return fail(Err::TooLarge, "content");
    uint64_t now = _clock.unixMs();
    if (now < 1000000000000ULL) return fail(Err::ClockInvalid);

    DepinMessage m;
    e = messageBuild(_cfg.expectedGenesis, _cfg.token, _address, (int64_t)(now / 1000), type,
                     (const uint8_t *)content.data(), content.size(), recipients, _key, m, _cfg.limits);
    if (e != Err::Ok) return fail(e, "build");
    std::vector<uint8_t> wire;
    if ((e = messageSerialize(m, wire, _cfg.limits)) != Err::Ok) return fail(e, "serialize");
    std::string hex = hexEncode(wire.data(), wire.size());
    uint8_t poolSec[33];
    if (_poolKey.sec(poolSec, 33) != 33) return fail(Err::BadPubKey, "pool key");
    std::vector<uint8_t> env;
    if ((e = wrapForPool(_cfg.expectedGenesis, hex, poolSec, env, _cfg.limits)) != Err::Ok) return fail(e, "wrap");

    RpcRequest request;
    request.method = "depinsubmitmsg";
    request.address = _address;
    request.encrypted = hexEncode(env.data(), env.size());
    std::string json;
    if ((e = call(request, json)) != Err::Ok) return e;
    out.hash = m.hash();
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
    RecipientKeys keys;
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
    RecipientKeys keys;
    std::vector<uint8_t> t(hex.size()/2);
    hexDecode(hex.c_str(), hex.size(), t.data(), t.size(), NULL);
    keys.push_back({t, targetAddress});
    if (targetAddress != _address) keys.push_back({std::vector<uint8_t>(_pubKey, _pubKey + _pubKeySize), _address});
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
    RpcRequest request;
    request.method = "depinchallenge"; request.token = _cfg.token; request.address = _address;
    uint32_t t0 = _clock.monotonicMs();
    std::string json;
    Err e = call(request, json);
    if (e != Err::Ok) return e;
    DynamicJsonDocument doc(json.size() + 256);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::ChallengeInvalid, "json");
    const char * ch = doc["challenge"] | "";
    const char * ty = doc["type"] | "";
    int exp = doc["expires_in"] | 0;
    if (!isHex64(ch) || strcmp(ty, "receive") != 0 || exp <= 0 || exp > 3600) return fail(Err::ChallengeInvalid, "fields");
    _challenge = ch;
    /* age from the request start, minus a safety margin */
    uint32_t ttl = (uint32_t)exp * 1000;
    ttl = ttl > 2000 ? ttl - 2000 : 0;
    _challengeExpiresMono = t0 + ttl;
    _challengeValid = ttl > 0;
    return _challengeValid ? Err::Ok : fail(Err::ChallengeInvalid, "ttl");
}

static Err normaliseRow(JsonObjectConst r, ReceivedItem & item, const std::string & genesis, const Limits & limits) {
    item = ReceivedItem();
    if (r.isNull()) return Err::BadPage;
    const char * tok = r["token"] | (const char *)NULL;
    const char * snd = r["sender"] | (const char *)NULL;
    const char * mt = r["message_type"] | (const char *)NULL;
    const char * pl = r["encrypted_payload_hex"] | (const char *)NULL;
    const char * sg = r["signature_hex"] | (const char *)NULL;
    const char * hs = r["hash"] | (const char *)NULL;
    if (!tok || !snd || !mt || !pl || !sg || !hs || !r["timestamp"].is<long long>()) return Err::BadPage;
    if (!isHex64(hs)) return Err::BadPage;
    DepinMessage & m = item.msg;
    m.genesis = genesis; m.token = tok; m.sender = snd;
    m.timestamp = (int64_t)r["timestamp"].as<long long>();
    if (strcmp(mt, "private") == 0) m.type = DEPIN_TYPE_PRIVATE;
    else if (strcmp(mt, "group") == 0) m.type = DEPIN_TYPE_GROUP;
    else return Err::BadMessageType;
    size_t plLen = strlen(pl), sgLen = strlen(sg);
    if (plLen / 2 > limits.maxPayload || sgLen / 2 > limits.maxSignature) return Err::TooLarge;
    m.payload.resize(plLen / 2); m.signature.resize(sgLen / 2);
    Err e;
    if (hexDecode(pl, plLen, m.payload.data(), m.payload.size(), &e) != m.payload.size()) return Err::BadHex;
    if (hexDecode(sg, sgLen, m.signature.data(), m.signature.size(), &e) != m.signature.size()) return Err::BadHex;
    if ((e = messageDigest(m, limits)) != Err::Ok) return e;
    if (m.hash() != hs) return Err::HashMismatch;
    item.hash = hs;
    EciesView v;
    return eciesParse(m.payload.data(), m.payload.size(), v, limits);
}

Err DepinClient::receivePage(const std::string & cursorText, size_t limit, ReceivePage & out) {
    out = ReceivePage();
    Err e = requireReady();
    if (e != Err::Ok) return e;
    if (limit == 0) limit = _cfg.pageLimit;
    if (limit > 1000) return fail(Err::BadArg, "limit");
    RpcRequest request;
    request.method = "depinreceiveseq";
    request.token = _cfg.token; request.address = _address; request.limit = limit;
    if (!cursorText.empty()) {
        DynamicJsonDocument cursor(1024);
        if (cursorText.size() > 512 || deserializeJson(cursor, cursorText) ||
            readCursor(cursor.as<JsonObjectConst>(), request, request.cursor) != Err::Ok)
            return fail(Err::BadArg, "cursor");
    }
    if ((e = ensureChallenge()) != Err::Ok) return e;
    request.challenge = _challenge;
    invalidateChallenge();
    uint32_t t0 = _clock.monotonicMs();
    std::string json;
    if ((e = call(request, json)) != Err::Ok) return e;
    DynamicJsonDocument doc(json.size() + json.size() / 2 + 1024);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return fail(Err::BadPage, "json");
    JsonObject o = doc.as<JsonObject>();
    if (!o["messages"].is<JsonArray>() || !o["has_more"].is<bool>()) return fail(Err::BadPage, "shape");
    JsonArray rows = o["messages"].as<JsonArray>();
    if (rows.size() > limit) return fail(Err::BadPage, "more rows than limit");
    ReceivePage page;
    page.serverHasMore = o["has_more"].as<bool>();
    page.received = rows.size();

    SequenceCursor nextCursor;
    if (readCursor(o["cursor"], request, nextCursor) != Err::Ok ||
        (!request.cursor.stream.empty() && nextCursor.stream != request.cursor.stream) ||
        nextCursor.after < request.cursor.after || (page.serverHasMore && nextCursor.after == request.cursor.after))
        return fail(Err::BadPage, "sequence cursor");
    int64_t previous = request.cursor.after;
    for (JsonObjectConst r : rows) {
        if (!r["sequence"].is<int64_t>()) return fail(Err::BadPage, "sequence");
        int64_t seq = r["sequence"].as<int64_t>();
        if (seq <= previous || seq > nextCursor.after) return fail(Err::BadPage, "sequence range");
        previous = seq;
        const char * senderKey = r["sender_pubkey_hex"] | "";
        if (!*senderKey) return fail(Err::BadPage, "missing sender_pubkey_hex");
        ReceivedItem item;
        PublicKey pub;
        if (normaliseRow(r, item, _cfg.expectedGenesis, _cfg.limits) != Err::Ok ||
            !tokenInScope(item.msg.token, _cfg.token) || loadPublicKey(senderKey, pub) != Err::Ok ||
            !pubKeyMatchesAddress(pub, item.msg.sender, _cfg.net) ||
            messageVerify(item.msg, pub, item.hash.c_str()) != Err::Ok) { ++page.rejected; continue; }
        item.verified = true;
        EnvelopeContext context;
        if (messageContext(item.msg, context) != Err::Ok ||
            eciesDecrypt(item.msg.payload.data(), item.msg.payload.size(), _key, context, _address,
                         item.content, _cfg.limits) != Err::Ok) { ++page.rejected; continue; }
        item.decrypted = true;
        page.messages.push_back(std::move(item));
    }
    serializeJson(o["cursor"], page.nextCursor);
    page.shouldContinue = page.serverHasMore;
    /* chained challenge (may be absent if the node failed to issue one) */
    const char * next = o["next_challenge"] | (const char *)NULL;
    if (next && isHex64(next)) {
        int exp = o["next_expires_in"] | 0;
        if (exp > 0 && exp <= 3600) {
            _challenge = next;
            uint32_t ttl = (uint32_t)exp * 1000; ttl = ttl > 2000 ? ttl - 2000 : 0;
            _challengeExpiresMono = t0 + ttl;
            _challengeValid = ttl > 0;
        }
    }

    out = std::move(page);
    return fail(Err::Ok);
}

} // namespace depin
