#include "DepinReply.h"

namespace depin {

Err parseReplyEnvelope(const std::string & body, const std::string & id, ReplyEnvelope & out,
                       RpcError * rpcError, const Limits & lim) {
    out = ReplyEnvelope();
    if (body.size() > lim.maxReplyHex + 4096) return Err::TooLarge;
    DynamicJsonDocument doc(body.size() + 1536);
    if (deserializeJson(doc, body) || doc.overflowed() || id != (doc["id"] | "")) return Err::BadJson;
    if (!doc["error"].isNull()) {
        if (rpcError) {
            rpcError->code = doc["error"]["code"] | 0;
            rpcError->message = std::string(doc["error"]["message"] | "").substr(0,200);
        }
        return Err::RpcError;
    }
    JsonObjectConst r = doc["result"];
    if (!r["protocol"].is<int>() || r["protocol"].as<int>() != 6) return Err::ProtocolMismatch;
    if (r.size() != 12 || !r["body_kind"].is<int>() || !r["membership_height"].is<int32_t>()) return Err::BadReply;
    int kind = r["body_kind"];
    if (kind != 0 && kind != 1) return Err::BadReply;
    out.encrypted = kind == 1;
    out.requestHash = r["request_hash"] | "";
    out.bodyHex = r[kind ? "encrypted" : "body"] | "";
    out.poolSig = r["poolsig"] | "";
    ServiceContext & s = out.service;
    s.network = r["network"] | ""; s.poolKey = r["pool_pubkey"] | ""; s.root = r["pool_root"] | "";
    s.instance = r["instance_id"] | ""; s.revision = r["membership_revision"] | "";
    s.height = r["membership_height"]; s.block = r["membership_blockhash"] | "";
    if (out.bodyHex.size() > lim.maxReplyHex) return Err::TooLarge;
    if (s.height < -1 || !validToken(s.root, lim) || s.poolKey.size() != 66 || out.poolSig.size() != 88 ||
        !validChallenge(s.network) || !validChallenge(s.instance) || !validChallenge(s.revision) ||
        !validChallenge(s.block) || !validChallenge(out.requestHash)) return Err::BadReply;
    return Err::Ok;
}

Err verifyAndOpen(const ReplyEnvelope & reply, const RpcRequest & r, const std::string & hash,
                  const std::string & genesis, const Pin & pin, TrustMode mode, const PrivateKey & holder,
                  std::string & json, const Limits & lim) {
    json.clear();
    const ServiceContext & s = reply.service;
    if (reply.requestHash != hash) return Err::HashMismatch;
    if (reply.encrypted != !r.address.empty()) return Err::ReplyKindMismatch;
    if (s.network != genesis) return Err::PinMismatch;
    if (r.method == "depingetmsginfo") {
        if (mode != TrustMode::ExplicitTofu && s.poolKey != pin.poolPubKeyHex) return Err::PinMismatch;
        if (mode == TrustMode::RequirePin && s.root != pin.rootToken) return Err::PinMismatch;
    } else if (s.poolKey != r.service.poolKey || s.root != r.service.root || s.instance != r.service.instance ||
               s.network != r.service.network) return Err::PinMismatch;

    PublicKey poolKey;
    Err e = loadPublicKey(s.poolKey, poolKey);
    if (e != Err::Ok) return e;
    std::string preimage;
    if ((e = responsePreimage(s, r.method, hash, reply.encrypted, reply.bodyHex, preimage)) != Err::Ok ||
        (e = verifyPoolSig(poolKey, preimage, reply.poolSig)) != Err::Ok) return e;
    size_t size = reply.bodyHex.size()/2;
    if (!reply.encrypted) {
        if (size > lim.maxReplyJson) return Err::TooLarge;
        json.resize(size);
        return hexDecode(reply.bodyHex.c_str(), reply.bodyHex.size(), (uint8_t *)&json[0], size, NULL) == size ? Err::Ok : Err::BadHex;
    }
    Limits bounds = lim;
    bounds.maxContent = lim.maxReplyJson;
    bounds.maxPayload = lim.maxReplyHex/2;
    bounds.maxRecipients = 1;
    EnvelopeContext context;
    if ((e = transportContext(TransportUse::Reply, genesis, context)) != Err::Ok) return e;
    std::vector<uint8_t> wire(size), plaintext;
    hexDecode(reply.bodyHex.c_str(), reply.bodyHex.size(), wire.data(), size, NULL);
    if ((e = eciesDecrypt(wire.data(), size, holder, context, r.address, plaintext, bounds)) != Err::Ok) return e;
    json.assign((const char *)plaintext.data(), plaintext.size());
    secureWipe(plaintext.data(), plaintext.size());
    return Err::Ok;
}

static bool supports(JsonArrayConst versions, int required) {
    bool found = false;
    for (JsonVariantConst v : versions) {
        if (!v.is<int>()) return false;
        found |= v.as<int>() == required;
    }
    return found;
}

Err parsePoolInfo(JsonObjectConst o, const ServiceContext & s, const ChainNetwork * net, PoolInfo & info) {
    if ((o["protocol"] | 0) != 6 || !supports(o["accepted_protocols"], 6) ||
        !supports(o["ecies_formats"], 3) || strcmp(o["cipher"] | "", "AES-256-GCM")) return Err::ProtocolMismatch;
    if (!o["enabled"].is<bool>() || !o["enabled"].as<bool>()) return Err::ServiceDisabled;
    if (s.network != (o["network"] | "") || s.instance != (o["instance_id"] | "") ||
        s.revision != (o["membership_revision"] | "") || s.block != (o["membership_blockhash"] | "") ||
        !o["membership_height"].is<int32_t>() || s.height != o["membership_height"].as<int32_t>() ||
        s.poolKey != (o["depinpoolpkey"] | "") || s.root != (o["token"] | "")) return Err::PinMismatch;
    if (!o["server_time_ms"].is<int64_t>() || o["server_time_ms"].as<int64_t>() <= 0) return Err::BadReply;
    int recipients = o["maxrecipients"] | 0, size = o["maxmessagesize"] | 0;
    if (recipients < 1 || recipients > 50 || size < 1 || size > 10240) return Err::BadReply;
    PublicKey poolKey;
    std::string address = o["depinpoolkeyaddress"] | "";
    if (loadPublicKey(s.poolKey, poolKey) != Err::Ok || (!address.empty() && !pubKeyMatchesAddress(poolKey, address, net)))
        return Err::PinMismatch;
    info.enabled = true; info.protocolVersion = 6; info.token = s.root; info.poolPubKeyHex = s.poolKey;
    info.cipher = "AES-256-GCM"; info.maxRecipients = recipients; info.maxMessageSize = size;
    info.poolAddress = address; info.serverTimeMs = o["server_time_ms"].as<int64_t>();
    info.messageExpiryHours = o["messageexpiryhours"] | 0;
    return Err::Ok;
}
}
