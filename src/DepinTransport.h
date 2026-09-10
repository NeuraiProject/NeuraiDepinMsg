#ifndef __NEURAI_DEPIN_TRANSPORT_H__
#define __NEURAI_DEPIN_TRANSPORT_H__

#include <Arduino.h>
#include <stdint.h>

/*
 * Bounded JSON-RPC transport for the DePIN client (plan v3 §9.2).
 *
 * One code path for every call: same TLS policy, timeout, byte budget and
 * error model. The response body is read through HTTPClient::writeToStream
 * (so chunked transfer encoding is de-framed by the core) into a capped
 * buffer; anything above the budget, a body shorter than Content-Length or
 * a timeout is a complete failure, never a truncated JSON handed to the
 * parser. Retry-After is captured on HTTP 429 without sleeping here.
 *
 * The transport does not interpret JSON-RPC; it hands back the raw body so
 * the caller can hash the exact string it received (§6.3 sha256hex) before
 * parsing it.
 */

enum class DepinTransportErr : uint8_t {
    None = 0,
    NotConfigured,      /* setUrl() not called or URL unusable            */
    Connect,            /* TCP/TLS connection failed                       */
    Timeout,            /* no / incomplete response within the timeout     */
    HttpStatus,         /* non-200 status (see httpStatus, body may hold  */
                        /* a JSON-RPC error object)                        */
    RateLimited,        /* HTTP 429; retryAfterSec set when the header was */
                        /* present                                         */
    TooLarge,           /* body over the byte budget (discarded)           */
    Truncated,          /* body shorter than Content-Length                */
    Memory              /* could not reserve the response buffer           */
};
const char * depinTransportErrName(DepinTransportErr e);

struct DepinRpcResult {
    DepinTransportErr err = DepinTransportErr::NotConfigured;
    int      httpStatus = 0;
    uint32_t retryAfterSec = 0;
    String   body;                          /* exact bytes received (<= budget) */
    bool ok() const { return err == DepinTransportErr::None; }
};

class DepinTransport {
public:
    /* Accepts a base URL ("https://host[:port]") — "/rpc" is appended once —
     * or a full RPC URL whose path is kept as is. Returns false if unusable. */
    bool setUrl(const String & url);
    const String & url() const { return _url; }

    /* TLS: a CA certificate (PEM) is the normal mode. Insecure mode must be
     * requested explicitly and is reported by insecure(). */
    void setCACert(const char * pem) { _caCert = pem; _insecure = false; }
    void setInsecure(bool on) { _insecure = on; if (on) _caCert = NULL; }
    bool insecure() const { return _insecure; }

    void setTimeout(uint32_t ms) { _timeoutMs = ms; }
    /* Largest response body we accept (default 64 KB). */
    void setMaxResponseBytes(size_t n) { _maxBody = n; }
    size_t maxResponseBytes() const { return _maxBody; }

    /* POST a JSON-RPC 2.0 request. `paramsJson` is an already-serialized JSON
     * array (e.g. "[\"&TOKEN\",20,\"&ROOT\"]") or "" for no params. */
    DepinRpcResult call(const String & method, const String & paramsJson, const String & id = "esp32");

private:
    String   _url;
    const char * _caCert = NULL;
    bool     _insecure = false;
    uint32_t _timeoutMs = 30000;
    size_t   _maxBody = 65536;
};

#endif /* __NEURAI_DEPIN_TRANSPORT_H__ */
