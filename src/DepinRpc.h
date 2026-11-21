#pragma once

#include "DepinAuth.h"
#include <ArduinoJson.h>

namespace depin {

// Metadata authenticated by the pool, using display-order hashes throughout.
struct ServiceContext {
    std::string network, poolKey, root, instance, revision, block;
    int32_t height = -1;
};

struct SequenceCursor {
    std::string stream;
    int64_t after = 0;
};

struct RpcRequest {
    std::string method, id, token, address, challenge;
    int64_t timestampMs = 0;
    int64_t fromTimestamp = 0;
    size_t limit = 0;
    std::string afterHash, encrypted;
    SequenceCursor cursor;
    ServiceContext service;
};

Err readCursor(JsonObjectConst object, const RpcRequest & request, SequenceCursor & out);
Err encodeRequest(const RpcRequest & request, const PrivateKey * signer, std::string & params, std::string & hash);
Err responsePreimage(const ServiceContext & service, const std::string & method, const std::string & requestHash,
                     bool encrypted, const std::string & bodyHex, std::string & preimage);

}
