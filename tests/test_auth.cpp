// Compare RPC calls used by the client with Core's independent Python encoder.
#include "DepinReply.h"
#include <cassert>
#include <fstream>
#include <iostream>

using namespace depin;
static void checkBoundReply() {
    PrivateKey key;
    assert(loadPrivateKey(std::string(63,'0')+"1", key) == Err::Ok);
    PublicKey pub = key.publicKey();
    uint8_t sec[33];
    pub.sec(sec,sizeof(sec));
    RpcRequest request;
    request.method = "depinchallenge";
    request.address = addressForKey(pub,&NeuraiTest);
    request.token = request.service.root = "&TEST";
    request.service.network = networkGenesis(&NeuraiTest);
    request.service.poolKey = hexEncode(sec,sizeof(sec));
    request.service.instance = std::string(64,'1');
    request.service.revision = std::string(64,'2');
    request.service.block = std::string(64,'3');
    request.id = std::string(64,'4');
    ReplyEnvelope reply;
    reply.service = request.service;
    reply.encrypted = true;
    std::string params;
    assert(encodeRequest(request,&key,params,reply.requestHash) == Err::Ok);
    EnvelopeContext context;
    assert(transportContext(TransportUse::Reply,request.service.network,context) == Err::Ok);
    RecipientKeys readers = {{std::vector<uint8_t>(sec,sec+33),request.address}};
    auto seal = [&](const RecipientKeys & recipients) {
        std::vector<uint8_t> encrypted;
        assert(eciesEncrypt((const uint8_t *)"{}",2,recipients,context,encrypted) == Err::Ok);
        reply.bodyHex = hexEncode(encrypted.data(),encrypted.size());
        std::string preimage;
        assert(responsePreimage(reply.service,request.method,reply.requestHash,true,reply.bodyHex,preimage) == Err::Ok);
        assert(signPreimage(key,preimage,reply.poolSig) == Err::Ok);
    };
    std::string json;
    auto open = [&](const ReplyEnvelope & env) {
        return verifyAndOpen(env,request,reply.requestHash,request.service.network,Pin(),TrustMode::RequirePin,key,json,Limits());
    };
    seal(readers);
    assert(open(reply) == Err::Ok && json == "{}");
    ReplyEnvelope altered = reply;
    altered.requestHash[0] ^= 1;
    assert(open(altered) == Err::HashMismatch && json.empty());
    altered = reply; altered.service.network[0] = 'f';
    assert(open(altered) == Err::PinMismatch);
    altered = reply; altered.service.instance[0] = 'f';
    assert(open(altered) == Err::PinMismatch);
    altered = reply; ++altered.service.height;
    assert(open(altered) == Err::PoolSigInvalid);
    altered = reply; altered.encrypted = false;
    assert(open(altered) == Err::ReplyKindMismatch);
    // Two separately authorized destinations may share the same curve point.
    char strict[64];
    assert(pub.ecdsaAddress(strict,sizeof(strict),&NeuraiTest) > 0);
    readers.push_back({readers[0].sec,strict});
    seal(readers);
    assert(open(reply) == Err::TooManyRecipients);
    readers.erase(readers.begin());
    seal(readers);
    assert(open(reply) == Err::NotForRecipient);
    assert(json.empty());
}

int main() {
    DynamicJsonDocument vectors(65536);
    std::ifstream fixture("fixtures/depin_rpc_v6.json");
    assert(!deserializeJson(vectors, fixture));
    PrivateKey key;
    assert(loadPrivateKey(std::string(63,'0')+"1", key) == Err::Ok);
    unsigned checked = 0;
    for (JsonObjectConst item : vectors["cases"].as<JsonArrayConst>()) {
        RpcRequest r;
        r.method = item["method"].as<std::string>();
        JsonObjectConst obj = item["request"], args = obj["args"];
        r.service.network = obj["network"] | ""; r.service.poolKey = obj["pool_pubkey"] | "";
        r.service.root = obj["pool_root"] | ""; r.service.instance = obj["instance_id"] | "";
        r.service.revision = obj["membership_revision"] | "";
        r.id = obj["request_id"].as<std::string>(); r.timestampMs = obj["timestamp_ms"];
        r.address = obj["address"] | ""; r.token = obj["token"] | ""; r.challenge = obj["challenge"] | "";
        if (r.method == "depinreceiveseq") {
            r.limit = args["limit"] | 100;
            r.fromTimestamp = args["from_timestamp"] | 0;
            if (args["cursor"]) assert(readCursor(args["cursor"], r, r.cursor) == Err::Ok);
        } else if (r.method == "depinreceivemsg") {
            r.limit = args["limit"] | 0; r.fromTimestamp = args["timestamp"] | 0; r.afterHash = args["after_hash"] | "";
        } else if (r.method == "depingetancestorrecipients") r.limit = 1000;
        else if (r.method == "depinsubmitmsg") r.encrypted = args["encrypted"].as<std::string>();
        else if (r.method != "depinchallenge" && r.method != "depingetmsginfo") continue;
        std::string params, hash;
        assert(encodeRequest(r, &key, params, hash) == Err::Ok);
        assert(hash == item["hash"].as<std::string>());
        if (!r.address.empty()) {
            DynamicJsonDocument doc(4096);
            assert(!deserializeJson(doc, params));
            std::string signer;
            assert(recoverSigner(item["preimage"], doc[0]["signature"], signer) == Err::Ok);
            assert(signer == r.service.poolKey);
        }
        ++checked;
    }
    assert(checked == 8);
    checkBoundReply();
    assert(validToken("&"+std::string(119,'A')) && !validToken("&"+std::string(120,'A')));
    assert(!validToken("&TEST!") && !validToken("&TEST/") && !validToken("&TEST/ab"));
    std::cout << checked << " RPC 6 request vectors passed\n";
}
