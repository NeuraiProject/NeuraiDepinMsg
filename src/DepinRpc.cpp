#include "DepinRpc.h"
#include "Hash.h"

namespace depin {
namespace {

// The RPC codec uses fixed uint32 lengths. The message codec uses CompactSize.
struct Bytes : std::vector<uint8_t> {
    void number(uint64_t value, size_t width) {
        for (size_t i = 0; i < width; ++i) { push_back(uint8_t(value)); value >>= 8; }
    }
    void text(const std::string & value) {
        number(value.size(), 4);
        insert(end(), value.begin(), value.end());
    }
    bool hex(const std::string & value, size_t sizeBytes) {
        if (value.size() != sizeBytes * 2 || value.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
        size_t start = size();
        resize(start + sizeBytes);
        return !sizeBytes || hexDecode(value.c_str(), value.size(), data()+start, sizeBytes, NULL) == sizeBytes;
    }
    bool hexBlob(const std::string & value) {
        number(value.size()/2, 4);
        return hex(value, value.size()/2);
    }
    bool identity(const ServiceContext & s) {
        if (!hex(s.network, 32) || !hexBlob(s.poolKey)) return false;
        text(s.root);
        return hex(s.instance, 32) && hex(s.revision, 32);
    }
    std::string hash() const {
        uint8_t digest[32];
        sha256(data(), size(), digest);
        return hexEncode(digest, sizeof(digest));
    }
};
}

Err readCursor(JsonObjectConst c, const RpcRequest & r, SequenceCursor & out) {
    if (c.size() != 6 || !c["version"].is<int>() || c["version"].as<int>() != 1 ||
        !c["from_timestamp"].is<int64_t>() || c["from_timestamp"].as<int64_t>() != r.fromTimestamp ||
        r.address != (c["address"] | "") || r.token != (c["scope"] | "") ||
        !validChallenge(c["stream_id"] | "") || !c["after_seq"].is<int64_t>() || c["after_seq"].as<int64_t>() < 0)
        return Err::BadPage;
    out.stream = c["stream_id"].as<const char *>();
    out.after = c["after_seq"].as<int64_t>();
    return Err::Ok;
}

Err encodeRequest(const RpcRequest & r, const PrivateKey * signer, std::string & params, std::string & hash) {
    params.clear(); hash.clear();
    const bool bootstrap = r.method == "depingetmsginfo";
    ServiceContext s = r.service;
    const std::string zero(64, '0');
    if (bootstrap) {
        if (!r.token.empty() || !r.address.empty() || !r.challenge.empty()) return Err::BadField;
        s = ServiceContext();
        s.network = s.instance = s.revision = zero;
    } else {
        PublicKey pool;
        if (!validToken(s.root) || s.poolKey.size() != 66 || loadPublicKey(s.poolKey, pool) != Err::Ok)
            return Err::BadField;
        if (r.method != "depinsubmitmsg" && !tokenInScope(r.token, s.root)) return Err::ScopeMismatch;
    }
    DynamicJsonDocument doc(3072 + r.encrypted.size());
    JsonObject obj = doc.to<JsonArray>().createNestedObject();
    obj["protocol"] = 6;
    obj["request_id"] = r.id;
    obj["timestamp_ms"] = r.timestampMs;
    Bytes args;
    uint8_t kind = 0;
    if (!bootstrap) {
        obj["network"] = s.network; obj["pool_pubkey"] = s.poolKey; obj["pool_root"] = s.root;
        obj["instance_id"] = s.instance; obj["membership_revision"] = s.revision;
        obj["token"] = r.token; obj["address"] = r.address; obj["challenge"] = r.challenge;
        JsonObject a = obj.createNestedObject("args");
        if (r.method == "depinchallenge") {
            kind = 1;
            a["type"] = "receive";
            args.number(0, 1);
        } else if (r.method == "depinsubmitmsg") {
            kind = 1;
            if (!r.token.empty() || r.encrypted.empty() || r.encrypted.size() > 2 * (114 + 32768 + 94) || !args.hexBlob(r.encrypted)) return Err::BadField;
            a["encrypted"] = r.encrypted;
        } else if (r.method == "depingetancestorrecipients") {
            if (!r.limit || r.limit > 10000) return Err::BadField;
            a["max_results"] = r.limit; a["stop_at"] = s.root;
            args.number(r.limit, 8); args.text(s.root);
        } else if (r.method == "depinreceivemsg") {
            kind = 2;
            if (r.limit > 1000 || (!r.afterHash.empty() && !validChallenge(r.afterHash))) return Err::BadField;
            a["timestamp"] = r.fromTimestamp; a["after_hash"] = r.afterHash; a["limit"] = r.limit;
            args.number(r.fromTimestamp, 8); args.hexBlob(r.afterHash); args.number(r.limit, 8);
        } else if (r.method == "depinreceiveseq") {
            kind = 2;
            bool continuation = !r.cursor.stream.empty();
            if (!r.limit || r.limit > 1000 || r.cursor.after < 0 || (!continuation && r.cursor.after != 0)) return Err::BadField;
            if (continuation) {
                JsonObject c = a.createNestedObject("cursor");
                c["version"] = 1; c["stream_id"] = r.cursor.stream; c["after_seq"] = r.cursor.after;
                c["scope"] = r.token; c["address"] = r.address; c["from_timestamp"] = r.fromTimestamp;
            }
            a["limit"] = r.limit; a["from_timestamp"] = r.fromTimestamp;
            args.number(continuation, 1);
            if (!args.hex(continuation ? r.cursor.stream : zero, 32)) return Err::BadField;
            args.number(r.cursor.after, 8); args.number(r.limit, 8); args.number(r.fromTimestamp, 8);
        } else return Err::BadArg;
    }
    const bool addressed = kind != 0;
    if (r.fromTimestamp < 0 || r.timestampMs < 0 || addressed == r.address.empty() ||
        (kind == 2 ? !validChallenge(r.challenge) : !r.challenge.empty())) return Err::BadField;
    Bytes bytes;
    bytes.text("Neurai/DePIN/RPC/request"); bytes.number(6, 2); bytes.text(r.method); bytes.number(kind, 1);
    if (!bytes.identity(s) || !bytes.hex(r.id, 32)) return Err::BadField;
    bytes.number(r.timestampMs, 8); bytes.text(r.token); bytes.text(r.address); bytes.hexBlob(r.challenge);
    bytes.number(args.size(), 4); bytes.insert(bytes.end(), args.begin(), args.end());
    hash = bytes.hash();
    if (!bootstrap) {
        std::string sig;
        if (kind) {
            if (!signer) return Err::BadPrivKey;
            Err e = signPreimage(*signer, "DEPIN-RPC-REQUEST-v6|" + hash, sig, r.address);
            if (e != Err::Ok) return e;
        }
        obj["signature"] = sig;
    }
    if (doc.overflowed()) return Err::TooLarge;
    serializeJson(doc, params);
    return Err::Ok;
}

Err responsePreimage(const ServiceContext & s, const std::string & method, const std::string & requestHash,
                     bool encrypted, const std::string & bodyHex, std::string & preimage) {
    Bytes bytes;
    bytes.text("Neurai/DePIN/RPC/response"); bytes.number(6, 2); bytes.text(method);
    if (!bytes.identity(s)) return Err::BadField;
    bytes.number(uint64_t(int64_t(s.height)), 8);
    if (!bytes.hex(s.block, 32) || !bytes.hex(requestHash, 32)) return Err::BadField;
    bytes.number(encrypted, 1);
    if (bodyHex.empty() || !bytes.hexBlob(bodyHex)) return Err::BadHex;
    preimage = "DEPIN-RPC-RESPONSE-v6|" + bytes.hash();
    return Err::Ok;
}
}
