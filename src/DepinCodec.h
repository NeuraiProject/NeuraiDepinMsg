#ifndef __NEURAI_DEPIN_CODEC_H__
#define __NEURAI_DEPIN_CODEC_H__

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>
#include "Neurai.h"
#include "DepinCrypto.h"

/*
 * Portable DePIN Messaging Protocol 2 codec (spec: Neurai/doc/depin-messaging-
 * protocol.md, §3.1 serialization, §4 ECIES envelope, §5 CDepinMessage).
 *
 * Works on raw bytes / std::string only — no Arduino types, no JSON, no
 * transport — so it compiles on host (uNeurai -DUSE_STDONLY + an AES-GCM
 * backend) and the protocol vectors are checked without hardware.
 * NeuraiDepinMsg.h is the Arduino-String adapter on top of this.
 *
 * Strictness (plan v3 §5): every parser validates lengths, minimal
 * CompactSize encodings, hex alphabet, curve points, recipient-entry sizes
 * (exactly 60 bytes), canonical ordering, duplicates and trailing bytes, and
 * returns a typed error. Nothing is returned on failure — no partial
 * plaintext, no partial envelope.
 */
namespace depin {

enum class Err : uint8_t {
    Ok = 0,
    BadArg,             /* NULL / empty where a value is required           */
    NoCryptoBackend,    /* setCryptoBackend() was never called               */
    Rng,                /* random source failed                              */
    Crypto,             /* AES-GCM / ECDH / key serialisation failed         */
    BadHex,             /* odd length or non-hex character                   */
    BadCompactSize,     /* non-minimal or truncated CompactSize              */
    Truncated,          /* field runs past the end of the buffer             */
    TrailingBytes,      /* bytes left after the last field                   */
    TooLarge,           /* over a Limits value                               */
    BadPrivKey,         /* WIF / hex private key invalid or out of range     */
    BadPubKey,          /* not 33 bytes / not a curve point                  */
    BadEphemeral,       /* ephemeral key not 33 bytes or not on the curve    */
    BadPayload,         /* payload shorter than nonce+tag                    */
    BadRecipientEntry,  /* entry not 60 bytes                                */
    RecipientOrder,     /* entries not in canonical (bytewise hash160) order */
    DuplicateRecipient, /* same hash160 twice                                */
    TooManyRecipients,  /* over Limits::maxRecipients                        */
    NotForRecipient,    /* no entry for our hash160                          */
    KeyUnwrapFailed,    /* recipient entry GCM tag failed                    */
    PayloadAuthFailed,  /* payload GCM tag failed                            */
    BadMessageType,     /* not 0x01 / 0x02                                   */
    BadTimestamp,       /* negative / out of range                           */
    BadField,           /* token / address / content empty or too long       */
    BadSignature,       /* DER malformed                                     */
    SignatureInvalid,   /* DER does not verify with the sender key           */
    HashMismatch,       /* announced hash != recomputed digest               */
    /* authentication / replies (DepinAuth.h, DepinReply.h) */
    BadPreimageField,   /* token/address/challenge/type unusable in a preimage */
    RpcError,           /* JSON-RPC error object in the reply                */
    BadJson,            /* container / body is not the expected JSON shape   */
    BadReply,           /* wrapper: not exactly one of body|encrypted + poolsig */
    ReplyKindMismatch,  /* got body where encrypted was expected, or vice versa */
    PoolSigInvalid,     /* poolsig does not recover the pool key             */
    PinRequired,        /* trust mode needs a pin that is not configured     */
    PinMismatch,        /* announced key/root differ from the pin            */
    ProtocolMismatch,   /* protocol != 2 / unsupported cipher                */
    ServiceDisabled,    /* enabled == false                                  */
    /* client (DepinClient.h) */
    NotBootstrapped,    /* begin()/bootstrap() not done                       */
    PinNotAccepted,     /* TOFU candidate pending acceptPin()                 */
    ClockInvalid,       /* wall clock not set / not advancing                 */
    Transport,          /* HTTP / TLS / timeout / size failure                */
    RateLimited,        /* HTTP 429, see ClientError::retryAfterSec           */
    RecipientsTruncated,/* node could not return the full holder set          */
    KeyNotRevealed,     /* address has no revealed public key on chain        */
    SubmitMismatch,     /* node confirmed a different hash / no success       */
    ScopeMismatch,      /* row token outside the requested scope              */
    ChallengeInvalid,   /* challenge reply malformed / expired                 */
    BadPage             /* receive page JSON malformed                        */
};
const char * errName(Err e);

/* Local policy limits. The node's own defaults are 20 recipients (hard cap 50)
 * and 1024-byte content (payload cap = size × recipients). These are the
 * client-side ceilings; a server can never raise them. */
struct Limits {
    size_t maxRecipients   = 50;      /* protocol hard cap                     */
    size_t maxContent      = 1024;    /* plaintext bytes we agree to send/read */
    size_t maxPayload      = 32768;   /* serialized ECIES envelope bytes       */
    size_t maxToken        = 128;     /* DEPIN token name, bytes               */
    size_t maxAddress      = 64;      /* base58 address, bytes                 */
    size_t maxSignature    = 80;      /* DER                                   */
    size_t maxReplyHex     = 131072;  /* body/encrypted hex string chars       */
    size_t maxReplyJson    = 8192;    /* decoded plain-reply JSON bytes        */
};
const Limits & defaultLimits();

/* ── Primitives ──────────────────────────────────────────────────────────── */

/* Strict hex: even length, [0-9a-fA-F] only. Returns bytes written, 0 on
 * error (and *err set). `hexLen` may be 0 to use strlen(). */
size_t hexDecode(const char * hex, size_t hexLen, uint8_t * out, size_t cap, Err * err);
std::string hexEncode(const uint8_t * data, size_t len);      /* lowercase */

/* CompactSize (Bitcoin varint), minimal encoding enforced on read. */
size_t writeCompactSize(uint64_t v, uint8_t * out, size_t cap);
Err    readCompactSize(const uint8_t * d, size_t len, size_t & off, uint64_t & v);

/* KDF_SHA256 (node depinecies.cpp): SHA256(secret || BE32(counter)), counter from 1. */
void kdfSha256(const uint8_t * secret, size_t secretLen, uint8_t * out, size_t outLen);

/* Load a private key from WIF (any known network) or 64-hex. Validates the
 * scalar range 0 < d < n before touching the curve. */
Err loadPrivateKey(const std::string & wifOrHex, PrivateKey & out, bool * compressed = NULL);
/* 33-byte compressed SEC → PublicKey, validating the point. */
Err loadPublicKey(const uint8_t * sec33, size_t len, PublicKey & out);
Err loadPublicKey(const std::string & hex, PublicKey & out);

/* True if `address` is a P2PKH address (version byte of `net`, or of any
 * known network when net is NULL; P2SH rejected) whose payload equals
 * hash160(compressed pub). Network-independent way to bind a revealed key to
 * a sender / recipient address. */
bool pubKeyMatchesAddress(const PublicKey & pub, const std::string & address, const ChainNetwork * net = NULL);

/* ── ECIES envelope (§4) ─────────────────────────────────────────────────── */

#define DEPIN_ECIES_ENTRY_LEN 60   /* nonce(12) || wrapped key(32) || tag(16) */
#define DEPIN_ECIES_NONCE_LEN 12
#define DEPIN_ECIES_TAG_LEN   16

/* Zero-copy view of a parsed, fully validated envelope. Pointers reference
 * the caller's buffer. */
struct EciesView {
    const uint8_t * ephemeral;      /* 33 bytes                              */
    const uint8_t * payload;        /* nonce || ciphertext || tag            */
    size_t          payloadLen;
    size_t          recipientCount;
    const uint8_t * entries;        /* recipientCount × (20 || 0x3c || 60)   */
    size_t          entriesLen;
};

/* Parse + validate every field of a serialized envelope. */
Err eciesParse(const uint8_t * data, size_t len, EciesView & view, const Limits & lim = defaultLimits());
/* Locate the 60-byte entry for `keyId` (hash160). NULL if absent. */
const uint8_t * eciesFindEntry(const EciesView & view, const uint8_t keyId[20]);

/* Decrypt for `key` (the holder). `plaintext` receives the content. */
Err eciesDecrypt(const uint8_t * data, size_t len, const PrivateKey & key,
                 std::vector<uint8_t> & plaintext, const Limits & lim = defaultLimits());

/* Encrypt `plaintext` for the given recipients (33-byte compressed keys).
 * Duplicates are removed; entries are emitted in canonical order. Fails
 * (with no output) if any recipient key is invalid, the count exceeds
 * `lim.maxRecipients`, or any crypto step fails. */
Err eciesEncrypt(const uint8_t * plaintext, size_t len,
                 const std::vector<std::vector<uint8_t> > & recipientPubKeys,
                 std::vector<uint8_t> & envelope, const Limits & lim = defaultLimits());

/* ── CDepinMessage (§5) ──────────────────────────────────────────────────── */

#define DEPIN_TYPE_PRIVATE 0x01
#define DEPIN_TYPE_GROUP   0x02

struct DepinMessage {
    std::string          token;
    std::string          sender;          /* P2PKH address                     */
    int64_t              timestamp = 0;   /* seconds                           */
    uint8_t              type = 0;        /* DEPIN_TYPE_*                      */
    std::vector<uint8_t> payload;         /* serialized ECIES envelope          */
    std::vector<uint8_t> signature;       /* DER over digest                    */
    uint8_t              digest[32];      /* SHA256d of the first five fields   */
    std::string hash() const;             /* hex(reverse(digest)) — the "hash"  */
};

/* Validate fields and compute `digest` from the first five fields. */
Err messageDigest(DepinMessage & m, const Limits & lim = defaultLimits());
/* Wire serialization (§5.1): the five fields + ser_vector(signature). */
Err messageSerialize(const DepinMessage & m, std::vector<uint8_t> & out, const Limits & lim = defaultLimits());
/* Parse a wire message; validates every field and recomputes the digest. */
Err messageParse(const uint8_t * data, size_t len, DepinMessage & out, const Limits & lim = defaultLimits());
/* Sign: computes the digest and fills `signature` (DER, low-S). */
Err messageSign(DepinMessage & m, const PrivateKey & senderKey, const Limits & lim = defaultLimits());
/* Verify `signature` against `senderPub` (33-byte SEC). High-S is normalised
 * like the node does. If `expectedHashHex` is given it must equal hash(). */
Err messageVerify(const DepinMessage & m, const PublicKey & senderPub,
                  const char * expectedHashHex = NULL);

/* Convenience: build + encrypt + sign in one go (the old buildDepinMessage).
 * The sender's own key is NOT added automatically; pass it in `recipients`
 * if the device wants to re-read its own messages. */
Err messageBuild(const std::string & token, const std::string & senderAddress,
                 int64_t timestamp, uint8_t type,
                 const uint8_t * content, size_t contentLen,
                 const std::vector<std::vector<uint8_t> > & recipientPubKeys,
                 const PrivateKey & senderKey, DepinMessage & out,
                 const Limits & lim = defaultLimits());

/* §8.3 step 5: the pool envelope wraps the ASCII hex of the signed message. */
Err wrapForPool(const std::string & messageHex, const uint8_t poolPubKey33[33],
                std::vector<uint8_t> & envelope, const Limits & lim = defaultLimits());

} // namespace depin

#endif /* __NEURAI_DEPIN_CODEC_H__ */
