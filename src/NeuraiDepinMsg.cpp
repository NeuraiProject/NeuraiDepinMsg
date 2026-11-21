#include "NeuraiDepinMsg.h"

using depin::Err;

Err          NeuraiDepinMsg::s_lastError = Err::Ok;
depin::Limits NeuraiDepinMsg::s_limits;

depin::Limits & NeuraiDepinMsg::limits() { return s_limits; }
Err NeuraiDepinMsg::lastError() { return s_lastError; }
const char * NeuraiDepinMsg::lastErrorName() { return depin::errName(s_lastError); }

static std::string toStd(const String & s) { return std::string(s.c_str(), s.length()); }

static Err hexToVec(const String & hex, std::vector<uint8_t> & out, size_t maxBytes) {
    size_t n = hex.length() / 2 + 1;
    if (hex.length() / 2 > maxBytes) return Err::TooLarge;
    out.resize(n);
    Err e;
    size_t got = depin::hexDecode(hex.c_str(), hex.length(), out.data(), out.size(), &e);
    if (e != Err::Ok) { out.clear(); return e; }
    out.resize(got);
    return Err::Ok;
}

/* ── build ───────────────────────────────────────────────────────────────── */

DepinMessageResult NeuraiDepinMsg::buildDepinMessage(const DepinParams & params) {
    DepinMessageResult r;
    s_lastError = Err::Ok;

    PrivateKey key;
    Err e = depin::loadPrivateKey(toStd(params.privateKey), key);
    if (e != Err::Ok) { fail(e); r.error = e; return r; }

    /* the sender's key must be the one behind senderPubKey / senderAddress */
    uint8_t mySec[65];
    size_t mySecLen;
    {
        PublicKey mine = key.publicKey();
        mySecLen = mine.sec(mySec, sizeof(mySec));
        if (!mine.isValid() || (mySecLen != 33 && mySecLen != 65)) { fail(Err::BadPrivKey); r.error = Err::BadPrivKey; return r; }
        if (params.senderPubKey.length()) {
            std::vector<uint8_t> given;
            if (hexToVec(params.senderPubKey, given, 65) != Err::Ok || given.size() != mySecLen ||
                memcmp(given.data(), mySec, mySecLen) != 0) {
                fail(Err::BadPubKey); r.error = Err::BadPubKey; return r;
            }
        }
        if (params.senderAddress.length() && !depin::pubKeyMatchesAddress(mine, toStd(params.senderAddress))) {
            fail(Err::BadField); r.error = Err::BadField; return r;
        }
    }

    uint8_t type;
    if (params.messageType == "private")    type = DEPIN_TYPE_PRIVATE;
    else if (params.messageType == "group") type = DEPIN_TYPE_GROUP;
    else { fail(Err::BadMessageType); r.error = Err::BadMessageType; return r; }

    depin::RecipientKeys recipients;
    if (!params.recipientAddresses.empty() && params.recipientAddresses.size() != params.recipientPubKeys.size()) {
        fail(Err::BadField); r.error = Err::BadField; return r;
    }
    recipients.reserve(params.recipientPubKeys.size() + 1);
    for (size_t i = 0; i < params.recipientPubKeys.size(); i++) {
        std::vector<uint8_t> pk;
        e = hexToVec(params.recipientPubKeys[i], pk, 65);
        if (e != Err::Ok || (pk.size() != 33 && pk.size() != 65)) { fail(Err::BadPubKey); r.error = Err::BadPubKey; return r; }
        recipients.push_back({pk, params.recipientAddresses.empty() ? "" : toStd(params.recipientAddresses[i])});
    }
    if (params.includeSender) recipients.push_back({std::vector<uint8_t>(mySec, mySec + mySecLen), toStd(params.senderAddress)});

    depin::DepinMessage m;
    e = depin::messageBuild(toStd(params.genesis), toStd(params.token), toStd(params.senderAddress),
                            (int64_t)params.timestamp, type,
                            (const uint8_t *)params.message.c_str(), params.message.length(),
                            recipients, key, m, s_limits);
    if (e != Err::Ok) { fail(e); r.error = e; return r; }

    std::vector<uint8_t> wire;
    e = depin::messageSerialize(m, wire, s_limits);
    if (e != Err::Ok) { fail(e); r.error = e; return r; }

    r.hex = String(depin::hexEncode(wire.data(), wire.size()).c_str());
    r.messageHash = String(m.hash().c_str());
    r.messageHashBytes.assign(m.digest, m.digest + 32);
    r.encryptedPayloadHex = String(depin::hexEncode(m.payload.data(), m.payload.size()).c_str());
    r.error = Err::Ok;
    return r;
}

/* ── decrypt ─────────────────────────────────────────────────────────────── */

Err NeuraiDepinMsg::decryptPayload(const DepinReceivedMessage & message, const String & recipientAddress, const PrivateKey & key,
                                   std::vector<uint8_t> & plaintext) {
    plaintext.clear();
    s_lastError = Err::Ok;
    depin::EnvelopeContext context;
    const auto & m = message.msg;
    Err e = depin::messageContext(m, context);
    if (e == Err::Ok) e = depin::eciesDecrypt(m.payload.data(), m.payload.size(), key, context,
                                               toStd(recipientAddress), plaintext, s_limits);
    if (e != Err::Ok) fail(e);
    return e;
}

String NeuraiDepinMsg::decryptPayload(const DepinReceivedMessage & message, const String & recipientAddress, const String & recipientPrivateKey) {
    PrivateKey key;
    Err e = depin::loadPrivateKey(toStd(recipientPrivateKey), key);
    if (e != Err::Ok) { fail(e); return String(""); }
    std::vector<uint8_t> pt;
    if (decryptPayload(message, recipientAddress, key, pt) != Err::Ok) return String("");
    String out;
    out.reserve(pt.size());
    for (size_t i = 0; i < pt.size(); i++) out += (char)pt[i];
    depin::secureWipe(pt.data(), pt.size());
    return out;
}

/* ── pool envelope ───────────────────────────────────────────────────────── */

String NeuraiDepinMsg::wrapMessageForServer(const String & genesis, const String & messageHex, const String & serverPubKeyHex) {
    s_lastError = Err::Ok;
    std::vector<uint8_t> pool;
    Err e = hexToVec(serverPubKeyHex, pool, 33);
    if (e != Err::Ok || pool.size() != 33) { fail(Err::BadPubKey); return String(""); }
    std::vector<uint8_t> env;
    e = depin::wrapForPool(toStd(genesis), toStd(messageHex), pool.data(), env, s_limits);
    if (e != Err::Ok) { fail(e); return String(""); }
    return String(depin::hexEncode(env.data(), env.size()).c_str());
}

/* ── received messages ───────────────────────────────────────────────────── */

Err NeuraiDepinMsg::fromRpcFields(const String & genesis, const String & token, const String & sender, int64_t timestamp,
                                  const String & messageType, const String & encryptedPayloadHex,
                                  const String & signatureHex, const String & hashHex,
                                  DepinReceivedMessage & out) {
    s_lastError = Err::Ok;
    out.verified = false;
    depin::DepinMessage & m = out.msg;
    m = depin::DepinMessage();
    m.genesis = toStd(genesis);
    m.token = toStd(token);
    m.sender = toStd(sender);
    m.timestamp = timestamp;
    if (messageType == "private")    m.type = DEPIN_TYPE_PRIVATE;
    else if (messageType == "group") m.type = DEPIN_TYPE_GROUP;
    else { fail(Err::BadMessageType); return Err::BadMessageType; }
    Err e = hexToVec(encryptedPayloadHex, m.payload, s_limits.maxPayload);
    if (e != Err::Ok) { fail(e); return e; }
    e = hexToVec(signatureHex, m.signature, s_limits.maxSignature);
    if (e != Err::Ok) { fail(e); return e; }
    e = depin::messageDigest(m, s_limits);
    if (e != Err::Ok) { fail(e); return e; }
    /* the envelope itself must be well formed before anything is shown */
    depin::EciesView v;
    e = depin::eciesParse(m.payload.data(), m.payload.size(), v, s_limits);
    if (e != Err::Ok) { fail(e); return e; }
    String computed(m.hash().c_str());
    if (hashHex.length()) {
        if (!computed.equalsIgnoreCase(hashHex)) { fail(Err::HashMismatch); return Err::HashMismatch; }
    }
    out.hash = computed;
    return Err::Ok;
}

Err NeuraiDepinMsg::parseDepinMessage(const String & genesis, const String & messageHex, DepinReceivedMessage & out) {
    s_lastError = Err::Ok;
    out.verified = false;
    std::vector<uint8_t> wire;
    Err e = hexToVec(messageHex, wire, s_limits.maxPayload + 512);
    if (e != Err::Ok) { fail(e); return e; }
    e = depin::messageParse(wire.data(), wire.size(), toStd(genesis), out.msg, s_limits);
    if (e != Err::Ok) { fail(e); return e; }
    out.hash = String(out.msg.hash().c_str());
    return Err::Ok;
}

Err NeuraiDepinMsg::verifyDepinMessage(DepinReceivedMessage & m, const String & senderPubKeyHex) {
    s_lastError = Err::Ok;
    m.verified = false;
    PublicKey pub;
    Err e = depin::loadPublicKey(toStd(senderPubKeyHex), pub);
    if (e != Err::Ok) { fail(e); return e; }
    /* the key must be the one behind the announced sender address */
    if (!depin::pubKeyMatchesAddress(pub, m.msg.sender)) { fail(Err::BadPubKey); return Err::BadPubKey; }
    e = depin::messageVerify(m.msg, pub, m.hash.length() ? m.hash.c_str() : NULL);
    if (e != Err::Ok) { fail(e); return e; }
    m.verified = true;
    return Err::Ok;
}
