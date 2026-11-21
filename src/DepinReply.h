#pragma once

#include "DepinRpc.h"

namespace depin {

struct RpcError {
    int code = 0;
    std::string message, reason;
};

struct ReplyEnvelope {
    ServiceContext service;
    bool encrypted = false;
    std::string requestHash, bodyHex, poolSig;
};

struct PoolInfo {
    bool enabled = false;
    std::string token, cipher, poolPubKeyHex, poolAddress;
    int protocolVersion = 0;
    uint32_t maxRecipients = 0, maxMessageSize = 0, messageExpiryHours = 0;
    int64_t serverTimeMs = 0;
};

Err parseReplyEnvelope(const std::string & body, const std::string & id, ReplyEnvelope & out,
                       RpcError * rpcError, const Limits & limits);
Err verifyAndOpen(const ReplyEnvelope & reply, const RpcRequest & request, const std::string & hash,
                  const std::string & genesis, const Pin & pin, TrustMode mode, const PrivateKey & holder,
                  std::string & json, const Limits & limits);
Err parsePoolInfo(JsonObjectConst body, const ServiceContext & service, const ChainNetwork * net, PoolInfo & info);
}
