#ifndef __NEURAI_DEPIN_CLIENT_H__
#define __NEURAI_DEPIN_CLIENT_H__

#include <string>
#include <vector>
#include <map>
#include "DepinCodec.h"
#include "DepinAuth.h"
#include "DepinReply.h"

/*
 * Portable DePIN protocol 2 client core (plan v3 §6–§8, phase 3 scope):
 * bootstrap with a pin, group / private publishing with full recipient
 * resolution, and authenticated paged receiving with challenge chaining.
 *
 * Transport and clocks are injected so the whole flow runs on host against
 * a simulated node (test/host/test_client.cpp). NeuraiDepinClient.h is the
 * Arduino wrapper (DepinTransport + real clocks + String API).
 *
 * Trust: nothing is sent or shown before bootstrap() authenticated the
 * service with the configured TrustMode; a TOFU candidate must be accepted
 * with acceptPin() before any other call works.
 */
namespace depin {

/* ── injected dependencies ──────────────────────────────────────────────── */

struct RpcReply {
    bool        ok = false;         /* transport-level success (HTTP 200)   */
    bool        rateLimited = false;
    uint32_t    retryAfterSec = 0;
    int         httpStatus = 0;
    std::string body;               /* exact bytes received                  */
    std::string transportError;     /* short diagnostic when !ok             */
};

class RpcTransport {
public:
    virtual ~RpcTransport() {}
    /* paramsJson: serialized JSON array ("[]" for none) */
    virtual RpcReply call(const std::string & method, const std::string & paramsJson, const std::string & id) = 0;
};

class Clock {
public:
    virtual ~Clock() {}
    virtual uint64_t unixMs() = 0;        /* real wall clock, milliseconds   */
    virtual uint32_t monotonicMs() = 0;   /* millis()-like, wraps            */
};

/* ── configuration / results ─────────────────────────────────────────────── */

struct ClientConfig {
    std::string serviceId;          /* normalised RPC URL / explicit identity */
    std::string token;              /* channel the device talks on            */
    TrustMode   trust = TrustMode::RequirePin;
    Pin         pin;                /* full pin for RequirePin, key for       */
                                    /* PinnedKeyDiscoverRoot, unused for TOFU */
    const ChainNetwork * net = NULL;/* NeuraiTest for testnet/regtest         */
    Limits      limits;
    size_t      pageLimit = 2;      /* default depinreceivemsg limit          */
    size_t      pubKeyCacheSize = 32;
};

struct SendResult {
    std::string hash;               /* confirmed by the node                  */
    size_t      recipients = 0;     /* entries in the envelope                */
    int         skippedNoPubKey = -1;   /* from the node, -1 if not reported  */
    bool        skippedComplete = true;
};

struct ReceivedItem {
    DepinMessage        msg;        /* normalised, digest computed            */
    std::string         hash;
    std::vector<uint8_t> content;   /* decrypted plaintext                    */
    bool                verified = false;   /* DER verified with sender key   */
    bool                decrypted = false;
};

struct ReceivePage {
    std::vector<ReceivedItem> messages;   /* fully verified + decrypted rows  */
    std::string nextAfterHash;      /* transport cursor: last examined row    */
    bool   serverHasMore = false;
    bool   shouldContinue = false;  /* serverHasMore || page was full (§1.2)  */
    size_t received = 0;            /* rows in the reply                      */
    size_t rejected = 0;            /* rows dropped (signature/scope/decrypt) */
};

struct ClientError {
    Err         err = Err::Ok;
    RpcError    rpc;                /* filled for Err::RpcError               */
    std::string detail;             /* transport diagnostic / context         */
    uint32_t    retryAfterSec = 0;  /* for Err::RateLimited                   */
};

class DepinClient {
public:
    DepinClient(RpcTransport & rpc, Clock & clock);

    /* Load the identity (WIF, compressed, P2PKH on cfg.net) and the config. */
    Err begin(const ClientConfig & cfg, const std::string & wif);
    const std::string & address() const { return _address; }
    const std::string & pubKeyHex() const { return _pubKeyHex; }

    /* depingetmsginfo → authenticated PoolInfo per the trust mode. */
    Err bootstrap();
    bool ready() const { return _ready; }
    const PoolInfo & info() const { return _info; }
    const Pin & pin() const { return _pin; }
    /* TOFU: the candidate from bootstrap() (pinConfirmed == false). */
    const Pin & candidatePin() const { return _candidate; }
    bool pinConfirmed() const { return _pinConfirmed; }
    /* Accept the TOFU candidate (application policy decided). */
    Err acceptPin();

    /* Publishing (§8.3). Content is UTF-8 bytes, non-empty, within limits. */
    Err sendGroup(const std::string & content, SendResult & out);
    Err sendPrivate(const std::string & targetAddress, const std::string & content, SendResult & out);
    /* depingetancestorrecipients for cfg.token: authenticated, deduplicated,
     * sender included, total <= maxRecipients. */
    Err resolveGroupRecipients(std::vector<std::vector<uint8_t> > & keys, SendResult & stats);
    /* getpubkey with address binding and a bounded cache. */
    Err getPubKey(const std::string & address, std::string & pubKeyHex);

    /* Receiving (§8.2). afterHash "" = from the beginning; limit <= 1000. */
    Err receivePage(const std::string & afterHash, size_t limit, ReceivePage & out);
    /* Drop the live challenge (after an error the node state is unknown). */
    void invalidateChallenge();
    bool hasChallenge() const;

    const ClientError & lastError() const { return _last; }
    const ClientConfig & config() const { return _cfg; }

private:
    RpcTransport & _rpc;
    Clock & _clock;
    ClientConfig _cfg;
    PrivateKey _key;
    std::string _address, _pubKeyHex;
    uint8_t _pubKey[33];
    bool _began = false, _ready = false, _pinConfirmed = false;
    Pin _pin, _candidate;
    PoolInfo _info;
    PublicKey _poolKey;
    ClientError _last;
    uint32_t _callSeq = 0;
    uint64_t _lastSignedMs = 0;
    /* live challenge */
    std::string _challenge;
    uint32_t _challengeExpiresMono = 0;
    bool _challengeValid = false;
    /* pubkey cache: address -> hex, insertion order for eviction */
    std::map<std::string, std::string> _pubCache;
    std::vector<std::string> _pubOrder;

    Err fail(Err e, const std::string & detail = std::string());
    std::string nextId();
    Err rpcCall(const std::string & method, const std::string & paramsJson, std::string & id, std::string & body);
    Err requireReady();
    Err ensureChallenge();
    Err send(const std::string & content, uint8_t type,
             const std::vector<std::vector<uint8_t> > & recipients, SendResult & out);
    void cachePut(const std::string & address, const std::string & hex);
};

/* helpers shared with tests / wrappers */
bool tokenInScope(const std::string & messageToken, const std::string & scope);
std::string jsonEscape(const std::string & s);

} // namespace depin

#endif /* __NEURAI_DEPIN_CLIENT_H__ */
