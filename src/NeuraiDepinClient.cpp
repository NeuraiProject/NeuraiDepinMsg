#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)

#include "NeuraiDepinClient.h"
#include <sys/time.h>
#include <time.h>

/* ── glue: transport + clocks ────────────────────────────────────────────── */

depin::RpcReply NeuraiDepinClient::Rpc::call(const std::string & method, const std::string & paramsJson, const std::string & id) {
    depin::RpcReply out;
    DepinRpcResult r = t.call(String(method.c_str()), String(paramsJson.c_str()), String(id.c_str()));
    out.httpStatus = r.httpStatus;
    out.retryAfterSec = r.retryAfterSec;
    out.rateLimited = (r.err == DepinTransportErr::RateLimited);
    out.ok = r.ok();
    out.body.assign(r.body.c_str(), r.body.length());
    if (!out.ok) out.transportError = depinTransportErrName(r.err);
    if (*debug) {
        Serial.printf("[depin] %s -> http %d %s, %u bytes\n", method.c_str(), r.httpStatus,
                      depinTransportErrName(r.err), (unsigned)r.body.length());
    }
    return out;
}

uint64_t NeuraiDepinClient::Clocks::unixMs() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return 0;
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);
}

/* ── lifecycle ───────────────────────────────────────────────────────────── */

NeuraiDepinClient::NeuraiDepinClient()
    : _rpc(_transport, &_debug), _core(_rpc, _clock) {
    _cfg.net = &NeuraiTest;             /* protocol 2 is live on testnet/regtest */
    _cfg.trust = depin::TrustMode::RequirePin;
}

void NeuraiDepinClient::setPoolPin(const String & poolPubKeyHex, const String & rootToken) {
    _cfg.pin.poolPubKeyHex = std::string(poolPubKeyHex.c_str(), poolPubKeyHex.length());
    _cfg.pin.rootToken = std::string(rootToken.c_str(), rootToken.length());
    _cfg.trust = depin::TrustMode::RequirePin;
}

bool NeuraiDepinClient::begin(const String & rpcUrl, const String & token, const String & wif) {
    if (!_transport.setUrl(rpcUrl)) return false;
    _cfg.serviceId = std::string(_transport.url().c_str(), _transport.url().length());
    _cfg.pin.serviceId = _cfg.serviceId;
    _cfg.token = std::string(token.c_str(), token.length());
    _lastCursor = ""; _lastShouldContinue = false;
    return _core.begin(_cfg, std::string(wif.c_str(), wif.length())) == depin::Err::Ok;
}

bool NeuraiDepinClient::bootstrap() {
    return _core.bootstrap() == depin::Err::Ok;
}

String NeuraiDepinClient::lastErrorDetail() const {
    const depin::ClientError & e = _core.lastError();
    String s(e.detail.c_str());
    if (e.err == depin::Err::RpcError) {
        s += " rpc "; s += e.rpc.code; s += ": "; s += e.rpc.message.c_str();
    }
    return s;
}

/* ── publishing ──────────────────────────────────────────────────────────── */

String NeuraiDepinClient::sendGroupMessage(const String & message) {
    depin::SendResult r;
    if (_core.sendGroup(std::string(message.c_str(), message.length()), r) != depin::Err::Ok) return String("");
    return String(r.hash.c_str());
}

String NeuraiDepinClient::sendPrivateMessage(const String & targetAddress, const String & message) {
    depin::SendResult r;
    if (_core.sendPrivate(std::string(targetAddress.c_str(), targetAddress.length()),
                          std::string(message.c_str(), message.length()), r) != depin::Err::Ok) return String("");
    return String(r.hash.c_str());
}

/* ── receiving ───────────────────────────────────────────────────────────── */

String NeuraiDepinClient::fmtTime(uint64_t ts) {
    time_t raw = (time_t)ts;
    struct tm ti;
    gmtime_r(&raw, &ti);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ti);
    return String(buf);
}

DepinPageResult NeuraiDepinClient::receivePage(const String & cursor, size_t limit) {
    DepinPageResult out;
    depin::ReceivePage page;
    depin::Err e = _core.receivePage(std::string(cursor.c_str(), cursor.length()), limit, page);
    out.ok = (e == depin::Err::Ok);
    if (!out.ok) { out.nextCursor = cursor; return out; }
    out.received = page.received;
    out.rejected = page.rejected;
    out.serverHasMore = page.serverHasMore;
    out.shouldContinue = page.shouldContinue;
    out.nextCursor = String(page.nextAfterHash.c_str());
    out.messages.reserve(page.messages.size());
    for (size_t i = 0; i < page.messages.size(); i++) {
        const depin::ReceivedItem & it = page.messages[i];
        IncomingMessage m;
        m.sender = it.msg.sender.c_str();
        m.timestamp = (uint64_t)it.msg.timestamp;
        m.timeStr = fmtTime(m.timestamp);
        m.type = (it.msg.type == DEPIN_TYPE_PRIVATE) ? "private" : "group";
        m.token = it.msg.token.c_str();
        m.hash = it.hash.c_str();
        m.verified = it.verified;
        m.decrypted = it.decrypted;
        m.content.reserve(it.content.size());
        for (size_t k = 0; k < it.content.size(); k++) m.content += (char)it.content[k];
        out.messages.push_back(m);
    }
    _lastCursor = out.nextCursor;
    _lastShouldContinue = out.shouldContinue;
    return out;
}

std::vector<IncomingMessage> NeuraiDepinClient::receiveMessages(uint64_t & lastTimestamp, int limit, String lastHash) {
    DepinPageResult page = receivePage(lastHash, limit > 0 ? (size_t)limit : 0);
    for (size_t i = 0; i < page.messages.size(); i++)
        if (page.messages[i].timestamp > lastTimestamp) lastTimestamp = page.messages[i].timestamp;
    return page.messages;
}

#endif /* ESP32 */
