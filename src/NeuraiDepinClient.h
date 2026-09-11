#ifndef __NEURAI_DEPIN_CLIENT_ARDUINO_H__
#define __NEURAI_DEPIN_CLIENT_ARDUINO_H__

#include <Arduino.h>
#include <vector>
#include "DepinClient.h"
#include "DepinTransport.h"

/*
 * Arduino / ESP32 DePIN Messaging Protocol 2 client.
 *
 * A thin wrapper over the portable depin::DepinClient: it supplies the real
 * transport (DepinTransport: HTTPS, byte budget, Retry-After), the wall and
 * monotonic clocks (gettimeofday / millis) and a String-based API close to
 * the 1.0.0 one. Everything security-relevant lives in the portable core and
 * is covered by the host tests.
 *
 * Trust (plan v3 §4): the recommended, unattended setup ships a full pin —
 * service URL, pool root token and pool public key — with the firmware:
 *
 *     NeuraiDepinClient depin;
 *     depin.setCACert(ROOT_CA_PEM);                       // TLS trust anchor
 *     depin.setPoolPin("03649c7a…", "&TEST");             // pool key, pool root
 *     depin.begin("https://rpc-testnet-depin.neurai.org", "&TEST/SEC", myWIF);
 *     if (!depin.bootstrap()) { Serial.println(depin.lastErrorName()); ... }
 *
 * Without a pin, TOFU must be enabled explicitly (setTrustMode) and the
 * candidate accepted with acceptPin() by the application's own policy.
 *
 * Time: DEPIN-REQ needs the real Unix time in milliseconds. Sync NTP (or an
 * RTC) before calling; the client refuses to sign with an unset clock.
 */

struct IncomingMessage {
    String   sender;
    uint64_t timestamp = 0;
    String   content;
    String   timeStr;
    String   type;            /* "private" or "group"                       */
    String   token;
    String   hash;
    bool     decrypted = false;
    bool     verified = false;/* sender DER signature verified               */
};

struct DepinPageResult {
    std::vector<IncomingMessage> messages;
    String nextCursor;        /* pass to the next receivePage()             */
    bool   serverHasMore = false;
    bool   shouldContinue = false;
    size_t received = 0, rejected = 0;
    bool   ok = false;
};

class NeuraiDepinClient {
public:
    NeuraiDepinClient();

    /* ── configuration (before begin) ───────────────────────────────────── */
    void setCACert(const char * pem)      { _transport.setCACert(pem); }
    void setInsecure(bool on)             { _transport.setInsecure(on); }
    void setTimeout(uint32_t ms)          { _transport.setTimeout(ms); }
    void setMaxResponseBytes(size_t n)    { _transport.setMaxResponseBytes(n); }
    void setNetwork(const ChainNetwork * net) { _cfg.net = net; }
    void setTrustMode(depin::TrustMode m) { _cfg.trust = m; }
    /* Full pin: pool public key (66 hex) + pool root token. */
    void setPoolPin(const String & poolPubKeyHex, const String & rootToken);
    void setPageLimit(size_t n)           { _cfg.pageLimit = n; }
    depin::Limits & limits()              { return _cfg.limits; }

    /* ── lifecycle ──────────────────────────────────────────────────────── */
    /* Base URL ("https://host") or full RPC URL; token = channel; WIF of the
     * holder (compressed, revealed on chain). */
    bool begin(const String & rpcUrl, const String & token, const String & wif);
    /* depingetmsginfo + trust decision. Returns true when ready to operate
     * (with TOFU it returns false until acceptPin()). */
    bool bootstrap();
    bool ready() const                    { return _core.ready() && _core.pinConfirmed(); }
    bool acceptPin()                      { return _core.acceptPin() == depin::Err::Ok; }
    String candidatePoolKey() const       { return String(_core.candidatePin().poolPubKeyHex.c_str()); }
    String candidateRoot() const          { return String(_core.candidatePin().rootToken.c_str()); }
    String poolKey() const                { return String(_core.pin().poolPubKeyHex.c_str()); }
    String poolRoot() const               { return String(_core.pin().rootToken.c_str()); }
    uint32_t maxRecipients() const        { return _core.info().maxRecipients; }
    uint32_t maxMessageSize() const       { return _core.info().maxMessageSize; }

    /* ── publishing ─────────────────────────────────────────────────────── */
    /* Return the confirmed message hash, or "" (see lastError()). */
    String sendGroupMessage(const String & message);
    String sendPrivateMessage(const String & targetAddress, const String & message);

    /* ── receiving ──────────────────────────────────────────────────────── */
    /* One authenticated page after `cursor` ("" = from the start). */
    DepinPageResult receivePage(const String & cursor, size_t limit = 0);
    /* 1.0.0-style adapter: pulls one page after `lastHash`, updates
     * lastTimestamp/lastHash to the last examined row. Prefer receivePage(). */
    std::vector<IncomingMessage> receiveMessages(uint64_t & lastTimestamp, int limit = 0, String lastHash = "");
    String lastReceiveCursor() const      { return _lastCursor; }
    bool   hasMore() const                { return _lastShouldContinue; }

    /* ── diagnostics ────────────────────────────────────────────────────── */
    String getMyAddress() const           { return String(_core.address().c_str()); }
    String getMyPubKey() const            { return String(_core.pubKeyHex().c_str()); }
    depin::Err lastError() const          { return _core.lastError().err; }
    const char * lastErrorName() const    { return depin::errName(_core.lastError().err); }
    String lastErrorDetail() const;       /* transport / RPC message         */
    uint32_t retryAfterSec() const        { return _core.lastError().retryAfterSec; }
    void setDebug(bool on)                { _debug = on; }

private:
    /* DepinTransport as the portable RpcTransport */
    struct Rpc : public depin::RpcTransport {
        DepinTransport & t; bool * debug;
        Rpc(DepinTransport & tr, bool * d) : t(tr), debug(d) {}
        depin::RpcReply call(const std::string & method, const std::string & paramsJson, const std::string & id) override;
    };
    struct Clocks : public depin::Clock {
        uint64_t unixMs() override;
        uint32_t monotonicMs() override { return millis(); }
    };
    DepinTransport _transport;
    Rpc _rpc;
    Clocks _clock;
    depin::DepinClient _core;
    depin::ClientConfig _cfg;
    bool _debug = false;
    String _lastCursor;
    bool _lastShouldContinue = false;
    static String fmtTime(uint64_t ts);
};

#endif /* __NEURAI_DEPIN_CLIENT_ARDUINO_H__ */
