#ifndef __NEURAI_DEPIN_REPLY_H__
#define __NEURAI_DEPIN_REPLY_H__

#include <string>
#include "DepinCodec.h"
#include "DepinAuth.h"

/*
 * Opening DePIN protocol 2 replies (spec §6.2–§6.4, §8.1) — portable.
 *
 * Every DePIN reply is a JSON-RPC result of one of two shapes, both signed:
 *     { "body": "<hex of UTF-8 JSON>", "poolsig": "<base64>" }         plain
 *     { "encrypted": "<hex CECIESEncryptedMessage>", "poolsig": "<base64>" } bound
 *
 * Order of operations, never relaxed: parse the bounded JSON-RPC container
 * (id must match, error must be null, result must be exactly one wrapper) →
 * verify poolsig against the pinned key with the request context bound into
 * the preimage → only then hex-decode / decrypt → validate the inner JSON.
 * The poolsig covers the *string* received, so the wrapper value is kept
 * verbatim and hashed as is.
 */
namespace depin {

struct RpcError {
    int code = 0;
    std::string message;        /* bounded copy of the node's message        */
};

enum class ReplyKind : uint8_t { Plain, Bound };

struct ReplyContext {
    std::string method;         /* RPC name                                   */
    std::string token;          /* "" for methods without one (pool root for */
                                /* plain replies, see §6.3)                   */
    std::string address;        /* holder / sender, "" for plain replies      */
    std::string challenge;      /* used challenge, "" otherwise               */
};

/* The wrapper as received, before any trust decision. */
struct ReplyEnvelope {
    ReplyKind   kind = ReplyKind::Plain;
    std::string bodyStr;        /* the hex string exactly as received         */
    std::string poolSig;        /* base64                                     */
};

/* Step 1: container. `rpcBody` is the full HTTP body. On a JSON-RPC error
 * returns Err::RpcError and fills *rpcErr (if given). */
Err parseReplyEnvelope(const std::string & rpcBody, const std::string & expectedId,
                       ReplyEnvelope & out, RpcError * rpcErr = NULL,
                       const Limits & lim = defaultLimits());

/* Step 2: poolsig against the pinned key, preimage from `ctx` + bodyStr. */
Err verifyReply(const ReplyEnvelope & env, const ReplyContext & ctx, const PublicKey & poolKey);

/* Step 3: open. Plain: hex → UTF-8 JSON text (bounded). Bound: ECIES
 * decrypt for the holder (bounded by lim.maxContent). */
Err openPlainReply(const ReplyEnvelope & env, std::string & json, const Limits & lim = defaultLimits());
Err openBoundReply(const ReplyEnvelope & env, const PrivateKey & holder, std::string & json,
                   const Limits & lim = defaultLimits());

/* Steps 1–3 in one call, refusing a wrapper of the wrong kind. `holder` is
 * required for Bound replies. */
Err openReply(const std::string & rpcBody, const std::string & expectedId,
              const ReplyContext & ctx, ReplyKind expected, const PublicKey & poolKey,
              const PrivateKey * holder, std::string & json, RpcError * rpcErr = NULL,
              const Limits & lim = defaultLimits());

/* ── bootstrap: depingetmsginfo (§6.4, §9) ───────────────────────────────── */

struct PoolInfo {
    bool        enabled = false;
    std::string token;              /* pool root                              */
    std::string cipher;
    int         protocolVersion = 0;
    uint32_t    maxRecipients = 0;
    uint32_t    maxMessageSize = 0;
    uint32_t    messageExpiryHours = 0;
    std::string poolPubKeyHex;
    std::string poolAddress;
};

struct BootstrapResult {
    PoolInfo info;
    Pin      candidate;             /* (serviceId, root, key) to keep         */
    bool     pinConfirmed = false;  /* true: signed by a pinned key. false:   */
                                    /* TOFU candidate, application must accept */
};

/* Authenticate and decode a depingetmsginfo reply according to `mode`:
 *   RequirePin            pin.complete() required; verified before decoding;
 *                         announced key/root must equal the pin.
 *   PinnedKeyDiscoverRoot pin.hasKey() required; body.token read as untrusted
 *                         input for the preimage only; verified with the key.
 *   ExplicitTofu          no pin used; poolsig signer must equal the announced
 *                         depinpoolpkey (self-consistency, NOT authentication);
 *                         candidate returned with pinConfirmed = false.
 * `net` selects the network for the depinpoolkeyaddress check. */
Err bootstrap(const std::string & rpcBody, const std::string & expectedId,
              TrustMode mode, const Pin & pin, const std::string & serviceId,
              const ChainNetwork * net, BootstrapResult & out,
              RpcError * rpcErr = NULL, const Limits & lim = defaultLimits());

/* Parse + validate the decoded depingetmsginfo body (used by bootstrap). */
Err parsePoolInfo(const std::string & json, PoolInfo & out, const Limits & lim = defaultLimits());

} // namespace depin

#endif /* __NEURAI_DEPIN_REPLY_H__ */
