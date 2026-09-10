#if defined(ESP32) || defined(ARDUINO_ARCH_ESP32)

#include "DepinTransport.h"
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

const char * depinTransportErrName(DepinTransportErr e) {
    switch (e) {
        case DepinTransportErr::None:          return "none";
        case DepinTransportErr::NotConfigured: return "not-configured";
        case DepinTransportErr::Connect:       return "connect";
        case DepinTransportErr::Timeout:       return "timeout";
        case DepinTransportErr::HttpStatus:    return "http-status";
        case DepinTransportErr::RateLimited:   return "rate-limited";
        case DepinTransportErr::TooLarge:      return "too-large";
        case DepinTransportErr::Truncated:     return "truncated";
        case DepinTransportErr::Memory:        return "memory";
    }
    return "unknown";
}

/* Write-only Stream with a hard cap: HTTPClient::writeToStream() de-frames
 * chunked bodies into it; once the cap is hit the rest is counted but
 * discarded (the read side is a stub, writeToStream only writes). */
namespace {
class CappedSink : public Stream {
public:
    CappedSink(String & out, size_t cap) : _out(out), _cap(cap) {}
    int available() override { return 0; }
    int read() override { return -1; }
    int peek() override { return -1; }
    void flush() override {}
    size_t write(uint8_t c) override { return write(&c, 1); }
    size_t write(const uint8_t * buf, size_t n) override {
        _seen += n;
        if (_overflow) return 0;                                   /* abort the transfer */
        if (_out.length() + n > _cap) { _overflow = true; return 0; }
        if (!_out.concat((const char *)buf, n)) { _memory = true; _overflow = true; return 0; }
        return n;
    }
    bool overflow() const { return _overflow; }
    bool memory() const { return _memory; }
    size_t seen() const { return _seen; }
private:
    String & _out;
    size_t _cap;
    size_t _seen = 0;
    bool _overflow = false;
    bool _memory = false;
};
}

bool DepinTransport::setUrl(const String & url) {
    _url = "";
    String u = url;
    u.trim();
    if (!u.startsWith("http://") && !u.startsWith("https://")) return false;
    int schemeEnd = u.indexOf("://") + 3;
    int slash = u.indexOf('/', schemeEnd);
    String hostPort = (slash < 0) ? u.substring(schemeEnd) : u.substring(schemeEnd, slash);
    String path = (slash < 0) ? "" : u.substring(slash);
    if (hostPort.length() == 0) return false;
    while (path.endsWith("/")) path.remove(path.length() - 1);
    if (path.length() == 0) path = "/rpc";          /* base URL: add /rpc exactly once */
    _url = u.substring(0, schemeEnd) + hostPort + path;
    return true;
}

DepinRpcResult DepinTransport::call(const String & method, const String & paramsJson, const String & id) {
    DepinRpcResult r;
    if (_url.length() == 0 || method.length() == 0) { r.err = DepinTransportErr::NotConfigured; return r; }

    String body;
    body.reserve(64 + method.length() + paramsJson.length() + id.length());
    body += "{\"jsonrpc\":\"2.0\",\"id\":\"";
    body += id;
    body += "\",\"method\":\"";
    body += method;
    body += "\",\"params\":";
    body += paramsJson.length() ? paramsJson : String("[]");
    body += "}";

    WiFiClientSecure secure;
    WiFiClient plain;
    WiFiClient * client;
    if (_url.startsWith("https://")) {
        if (_insecure) secure.setInsecure();
        else if (_caCert) secure.setCACert(_caCert);
        else { r.err = DepinTransportErr::NotConfigured; return r; }   /* TLS without trust anchor */
        client = &secure;
    } else {
        client = &plain;
    }

    HTTPClient http;
    http.setTimeout(_timeoutMs);
    http.setReuse(false);
    static const char * headers[] = { "Retry-After", "Content-Length" };
    http.collectHeaders(headers, 2);
    if (!http.begin(*client, _url)) { r.err = DepinTransportErr::Connect; return r; }
    http.addHeader("Content-Type", "application/json");

    int status = http.POST((uint8_t *)body.c_str(), body.length());
    r.httpStatus = status;
    if (status < 0) {
        r.err = (status == HTTPC_ERROR_READ_TIMEOUT) ? DepinTransportErr::Timeout : DepinTransportErr::Connect;
        http.end();
        return r;
    }

    /* bounded body read (handles chunked encoding inside the core) */
    int declared = http.getSize();          /* -1 when unknown / chunked */
    if (declared > 0 && (size_t)declared > _maxBody) {
        r.err = DepinTransportErr::TooLarge;
        http.end();
        return r;
    }
    if (!r.body.reserve((declared > 0) ? (size_t)declared : 1024)) {
        r.err = DepinTransportErr::Memory;
        http.end();
        return r;
    }
    CappedSink sink(r.body, _maxBody);
    int written = http.writeToStream(&sink);
    if (status == 429 && http.hasHeader("Retry-After")) r.retryAfterSec = (uint32_t)http.header("Retry-After").toInt();
    http.end();

    /* an aborted sink makes writeToStream() return a negative code: classify
     * by the sink's own flags first */
    if (sink.memory()) { r.body = ""; r.err = DepinTransportErr::Memory; return r; }
    if (sink.overflow()) { r.body = ""; r.err = DepinTransportErr::TooLarge; return r; }
    if (written < 0) { r.body = ""; r.err = (written == HTTPC_ERROR_READ_TIMEOUT) ? DepinTransportErr::Timeout : DepinTransportErr::Connect; return r; }
    if (declared > 0 && sink.seen() != (size_t)declared) { r.body = ""; r.err = DepinTransportErr::Truncated; return r; }

    if (status == 429) { r.err = DepinTransportErr::RateLimited; return r; }
    if (status != 200) { r.err = DepinTransportErr::HttpStatus; return r; }   /* body kept: may be a JSON-RPC error */
    r.err = DepinTransportErr::None;
    return r;
}

#endif /* ESP32 */
