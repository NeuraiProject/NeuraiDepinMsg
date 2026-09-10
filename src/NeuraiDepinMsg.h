#ifndef __NEURAI_DEPIN_MSG_H__
#define __NEURAI_DEPIN_MSG_H__

#include <Arduino.h>
#include <Neurai.h>
#include <vector>
#include "DepinCodec.h"

/*
 * Arduino-facing DePIN message codec: a thin adapter over DepinCodec.h that
 * keeps the 1.0.0 call shapes (buildDepinMessage / decryptPayload /
 * wrapMessageForServer) and adds typed errors and message verification.
 *
 * Every function that can fail records the reason in
 * NeuraiDepinMsg::lastError() (a depin::Err) so callers no longer have to
 * guess from an empty String. Security checks live in the codec; nothing is
 * decoded, displayed or returned unless it fully verified.
 */

struct DepinMessageResult {
    String hex;                     /* serialized CDepinMessage, hex            */
    String messageHash;             /* display hash = hex(reverse(sha256d))     */
    std::vector<uint8_t> messageHashBytes;   /* unreversed digest               */
    String encryptedPayloadHex;     /* the ECIES envelope alone, hex            */
    depin::Err error = depin::Err::Ok;
    bool ok() const { return error == depin::Err::Ok; }
};

struct DepinParams {
    String token;
    String senderAddress;
    String senderPubKey;            /* 66 hex chars; must match privateKey     */
    String privateKey;              /* WIF or 64 hex chars                     */
    uint64_t timestamp = 0;         /* seconds                                 */
    String message;
    std::vector<String> recipientPubKeys;   /* 66 hex chars each               */
    String messageType = "group";   /* "private" or "group"                    */
    bool includeSender = true;      /* add the sender as a reader (1.0.0 did)  */
};

/* A received message normalised from the RPC row fields (§8.2) or parsed
 * from the wire, plus what verification established. */
struct DepinReceivedMessage {
    depin::DepinMessage msg;        /* token, sender, timestamp, type, payload, signature, digest */
    String hash;                    /* announced hash (RPC) or computed        */
    bool verified = false;          /* DER verified with the sender's key      */
};

class NeuraiDepinMsg {
public:
    /* Build, encrypt for the recipients and sign. */
    static DepinMessageResult buildDepinMessage(const DepinParams & params);

    /* Decrypt an ECIES envelope (hex) for `recipientPrivateKey` (WIF or hex).
     * Returns "" and sets lastError() on any failure — including a
     * plaintext larger than `limits().maxContent`. */
    static String decryptPayload(const char * encryptedPayloadHex, const String & recipientPrivateKey);
    /* Binary variant for callers that must not copy into a String. */
    static depin::Err decryptPayload(const char * encryptedPayloadHex, const PrivateKey & key,
                                     std::vector<uint8_t> & plaintext);

    /* §8.3 step 5: envelope of the ASCII hex of a signed message for the pool
     * key (66 hex chars). Returns "" and sets lastError() on failure. */
    static String wrapMessageForServer(const String & messageHex, const String & serverPubKeyHex);

    /* Normalise a depinreceivemsg row into a DepinMessage (validates types,
     * hex, sizes, recomputes the digest and checks it against `hashHex`). */
    static depin::Err fromRpcFields(const String & token, const String & sender, int64_t timestamp,
                                    const String & messageType, const String & encryptedPayloadHex,
                                    const String & signatureHex, const String & hashHex,
                                    DepinReceivedMessage & out);
    /* Parse a wire-serialized message (hex). */
    static depin::Err parseDepinMessage(const String & messageHex, DepinReceivedMessage & out);
    /* Verify the DER signature with the sender's revealed key (66 hex). */
    static depin::Err verifyDepinMessage(DepinReceivedMessage & m, const String & senderPubKeyHex);

    /* Policy limits used by every call (see depin::Limits). */
    static depin::Limits & limits();
    static depin::Err lastError();
    static const char * lastErrorName();

private:
    static depin::Err s_lastError;
    static depin::Limits s_limits;
    static void fail(depin::Err e) { s_lastError = e; }
};

#endif /* __NEURAI_DEPIN_MSG_H__ */
