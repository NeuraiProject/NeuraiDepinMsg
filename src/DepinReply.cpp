#include "DepinReply.h"
#include <ArduinoJson.h>
#include <string.h>

namespace depin {

static bool evenHex(const std::string & s, size_t maxChars) {
    if (s.empty() || (s.size() & 1) || s.size() > maxChars) return false;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

/* bounded document: the container holds two long strings, so capacity is
 * proportional to the body but never more than the reply limit allows */
static size_t docCapacity(size_t bodyLen, const Limits & lim) {
    size_t cap = bodyLen + 1024;
    size_t max = lim.maxReplyHex + lim.maxReplyJson + 2048;
    return cap > max ? max : cap;
}

/* ── step 1: container ───────────────────────────────────────────────────── */

Err parseReplyEnvelope(const std::string & rpcBody, const std::string & expectedId,
                       ReplyEnvelope & out, RpcError * rpcErr, const Limits & lim) {
    out = ReplyEnvelope();
    if (rpcBody.empty()) return Err::BadArg;
    if (rpcBody.size() > lim.maxReplyHex + lim.maxReplyJson + 2048) return Err::TooLarge;

    DynamicJsonDocument doc(docCapacity(rpcBody.size(), lim));
    DeserializationError de = deserializeJson(doc, rpcBody);
    if (de || doc.overflowed() || !doc.is<JsonObject>()) return Err::BadJson;
    JsonObject root = doc.as<JsonObject>();

    /* id: must be present and equal to what we sent (string or number) */
    JsonVariant id = root["id"];
    if (id.isNull()) return Err::BadJson;
    std::string gotId = id.is<const char *>() ? std::string(id.as<const char *>()) : std::string(id.as<std::string>());
    if (gotId != expectedId) return Err::BadJson;

    JsonVariant err = root["error"];
    if (!err.isNull()) {
        if (rpcErr) {
            rpcErr->code = err["code"] | 0;
            const char * msg = err["message"] | "";
            rpcErr->message.assign(msg, strnlen(msg, 200));
        }
        return Err::RpcError;
    }

    JsonVariant result = root["result"];
    if (!result.is<JsonObject>()) return Err::BadReply;
    JsonObject r = result.as<JsonObject>();
    bool hasBody = r.containsKey("body"), hasEnc = r.containsKey("encrypted");
    if (hasBody == hasEnc) return Err::BadReply;                 /* exactly one */
    const char * wrapper = hasBody ? r["body"].as<const char *>() : r["encrypted"].as<const char *>();
    const char * sig = r["poolsig"].as<const char *>();
    if (!wrapper || !sig) return Err::BadReply;
    std::string bodyStr(wrapper);
    if (!evenHex(bodyStr, lim.maxReplyHex)) return Err::BadReply;
    std::string poolSig(sig);
    if (poolSig.size() != 88) return Err::BadReply;

    out.kind = hasBody ? ReplyKind::Plain : ReplyKind::Bound;
    out.bodyStr.swap(bodyStr);
    out.poolSig.swap(poolSig);
    return Err::Ok;
}

/* ── step 2: signature ───────────────────────────────────────────────────── */

Err verifyReply(const ReplyEnvelope & env, const ReplyContext & ctx, const PublicKey & poolKey) {
    std::string pre;
    Err e = replyPreimage(ctx.method, ctx.token, ctx.address, ctx.challenge, env.bodyStr, pre);
    if (e != Err::Ok) return e;
    return verifyPoolSig(poolKey, pre, env.poolSig);
}

/* ── step 3: open ────────────────────────────────────────────────────────── */

Err openPlainReply(const ReplyEnvelope & env, std::string & json, const Limits & lim) {
    json.clear();
    if (env.kind != ReplyKind::Plain) return Err::ReplyKindMismatch;
    size_t n = env.bodyStr.size() / 2;
    if (n > lim.maxReplyJson) return Err::TooLarge;
    json.resize(n);
    Err e;
    size_t got = hexDecode(env.bodyStr.c_str(), env.bodyStr.size(), (uint8_t *)&json[0], n, &e);
    if (e != Err::Ok || got != n) { json.clear(); return Err::BadReply; }
    return Err::Ok;
}

Err openBoundReply(const ReplyEnvelope & env, const PrivateKey & holder, std::string & json, const Limits & lim) {
    json.clear();
    if (env.kind != ReplyKind::Bound) return Err::ReplyKindMismatch;
    std::vector<uint8_t> envelope(env.bodyStr.size() / 2);
    Err e;
    size_t got = hexDecode(env.bodyStr.c_str(), env.bodyStr.size(), envelope.data(), envelope.size(), &e);
    if (e != Err::Ok || got != envelope.size()) return Err::BadReply;
    std::vector<uint8_t> pt;
    e = eciesDecrypt(envelope.data(), envelope.size(), holder, pt, lim);
    if (e != Err::Ok) return e;
    json.assign((const char *)pt.data(), pt.size());
    secureWipe(pt.data(), pt.size());
    return Err::Ok;
}

Err openReply(const std::string & rpcBody, const std::string & expectedId,
              const ReplyContext & ctx, ReplyKind expected, const PublicKey & poolKey,
              const PrivateKey * holder, std::string & json, RpcError * rpcErr, const Limits & lim) {
    json.clear();
    ReplyEnvelope env;
    Err e = parseReplyEnvelope(rpcBody, expectedId, env, rpcErr, lim);
    if (e != Err::Ok) return e;
    if (env.kind != expected) return Err::ReplyKindMismatch;
    e = verifyReply(env, ctx, poolKey);
    if (e != Err::Ok) return e;
    if (expected == ReplyKind::Plain) return openPlainReply(env, json, lim);
    if (!holder) return Err::BadArg;
    return openBoundReply(env, *holder, json, lim);
}

/* ── bootstrap ───────────────────────────────────────────────────────────── */

Err parsePoolInfo(const std::string & json, PoolInfo & out, const Limits & lim) {
    out = PoolInfo();
    if (json.empty() || json.size() > lim.maxReplyJson) return Err::BadJson;
    DynamicJsonDocument doc(json.size() + 512);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return Err::BadJson;
    JsonObject o = doc.as<JsonObject>();
    if (!o["enabled"].is<bool>() || !o["token"].is<const char *>() || !o["protocol"].is<int>() ||
        !o["depinpoolpkey"].is<const char *>() || !o["maxrecipients"].is<int>() || !o["maxmessagesize"].is<int>())
        return Err::BadJson;
    out.enabled = o["enabled"].as<bool>();
    out.token = o["token"].as<const char *>();
    out.cipher = o["cipher"] | "";
    out.protocolVersion = o["protocol"].as<int>();
    int mr = o["maxrecipients"].as<int>(), ms = o["maxmessagesize"].as<int>(), eh = o["messageexpiryhours"] | 0;
    if (mr <= 0 || mr > 50 || ms <= 0 || ms > 10240 || eh < 0 || eh > 720) return Err::BadJson;
    out.maxRecipients = (uint32_t)mr;
    out.maxMessageSize = (uint32_t)ms;
    out.messageExpiryHours = (uint32_t)eh;
    out.poolPubKeyHex = o["depinpoolpkey"].as<const char *>();
    out.poolAddress = o["depinpoolkeyaddress"] | "";
    if (!validToken(out.token, lim) || out.poolPubKeyHex.size() != 66) return Err::BadJson;
    return Err::Ok;
}

/* untrusted peek: only the fields needed to build the preimage / TOFU check */
static Err peekBody(const ReplyEnvelope & env, std::string & token, std::string & announcedKey,
                    std::string & announcedAddress, const Limits & lim) {
    std::string json;
    Err e = openPlainReply(env, json, lim);
    if (e != Err::Ok) return e;
    DynamicJsonDocument doc(json.size() + 512);
    if (deserializeJson(doc, json) || doc.overflowed() || !doc.is<JsonObject>()) return Err::BadJson;
    const char * t = doc["token"] | (const char *)NULL;
    const char * k = doc["depinpoolpkey"] | (const char *)NULL;
    const char * a = doc["depinpoolkeyaddress"] | "";
    if (!t || !k) return Err::BadJson;
    token = t; announcedKey = k; announcedAddress = a;
    if (!validToken(token, lim) || announcedKey.size() != 66) return Err::BadJson;
    return Err::Ok;
}

static Err checkInfo(const PoolInfo & info) {
    if (info.protocolVersion != 2) return Err::ProtocolMismatch;
    if (info.cipher != "AES-256-GCM") return Err::ProtocolMismatch;
    if (!info.enabled) return Err::ServiceDisabled;
    return Err::Ok;
}

Err bootstrap(const std::string & rpcBody, const std::string & expectedId,
              TrustMode mode, const Pin & pin, const std::string & serviceId,
              const ChainNetwork * net, BootstrapResult & out, RpcError * rpcErr, const Limits & lim) {
    out = BootstrapResult();
    ReplyEnvelope env;
    Err e = parseReplyEnvelope(rpcBody, expectedId, env, rpcErr, lim);
    if (e != Err::Ok) return e;
    if (env.kind != ReplyKind::Plain) return Err::ReplyKindMismatch;

    std::string root, pre, json;
    PublicKey poolKey;

    if (mode == TrustMode::RequirePin) {
        if (!pin.complete()) return Err::PinRequired;
        if ((e = pinPublicKey(pin, poolKey)) != Err::Ok) return e;
        root = pin.rootToken;
        if ((e = replyPreimage("depingetmsginfo", root, "", "", env.bodyStr, pre)) != Err::Ok) return e;
        if ((e = verifyPoolSig(poolKey, pre, env.poolSig)) != Err::Ok) return e;
        /* authenticated: now the body may be read */
        if ((e = openPlainReply(env, json, lim)) != Err::Ok) return e;
        if ((e = parsePoolInfo(json, out.info, lim)) != Err::Ok) return e;
        if (out.info.token != pin.rootToken || out.info.poolPubKeyHex != pin.poolPubKeyHex) return Err::PinMismatch;
        out.candidate = pin;
        out.pinConfirmed = true;
    } else if (mode == TrustMode::PinnedKeyDiscoverRoot) {
        if (!pin.hasKey()) return Err::PinRequired;
        if ((e = pinPublicKey(pin, poolKey)) != Err::Ok) return e;
        std::string announcedKey, announcedAddr;
        if ((e = peekBody(env, root, announcedKey, announcedAddr, lim)) != Err::Ok) return e;   /* untrusted */
        if ((e = replyPreimage("depingetmsginfo", root, "", "", env.bodyStr, pre)) != Err::Ok) return e;
        if ((e = verifyPoolSig(poolKey, pre, env.poolSig)) != Err::Ok) return e;
        if ((e = openPlainReply(env, json, lim)) != Err::Ok) return e;
        if ((e = parsePoolInfo(json, out.info, lim)) != Err::Ok) return e;
        if (out.info.poolPubKeyHex != pin.poolPubKeyHex) return Err::PinMismatch;
        out.candidate = pin;
        out.candidate.rootToken = out.info.token;
        if (out.candidate.serviceId.empty()) out.candidate.serviceId = serviceId;
        out.pinConfirmed = true;
    } else {
        /* ExplicitTofu: self-consistency of the reply, never authentication */
        std::string announcedKey, announcedAddr, signer;
        if ((e = peekBody(env, root, announcedKey, announcedAddr, lim)) != Err::Ok) return e;
        if ((e = replyPreimage("depingetmsginfo", root, "", "", env.bodyStr, pre)) != Err::Ok) return e;
        if ((e = recoverSigner(pre, env.poolSig, signer)) != Err::Ok) return e;
        if (signer != announcedKey) return Err::PoolSigInvalid;
        if ((e = loadPublicKey(announcedKey, poolKey)) != Err::Ok) return e;
        if ((e = openPlainReply(env, json, lim)) != Err::Ok) return e;
        if ((e = parsePoolInfo(json, out.info, lim)) != Err::Ok) return e;
        out.candidate.serviceId = serviceId;
        out.candidate.rootToken = out.info.token;
        out.candidate.poolPubKeyHex = out.info.poolPubKeyHex;
        out.pinConfirmed = false;
    }

    /* the announced address must derive from the (now trusted) key */
    if (!out.info.poolAddress.empty() && !pubKeyMatchesAddress(poolKey, out.info.poolAddress, net)) return Err::PinMismatch;
    return checkInfo(out.info);
}

} // namespace depin
