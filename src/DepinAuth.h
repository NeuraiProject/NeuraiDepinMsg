#ifndef __NEURAI_DEPIN_AUTH_H__
#define __NEURAI_DEPIN_AUTH_H__

#include <string>
#include "DepinCodec.h"

/*
 * DePIN Messaging Protocol 2 authentication primitives (spec §3.3, §6.3,
 * §6.4, §7): preimages, holder signatures, pool-signature verification and
 * the pin. Portable (std::string), built on uNeurai's Message.h.
 *
 * The DePIN profile is stricter than the generic signmessage primitive:
 *   - signatures are the canonical 88-char base64 of 65 bytes;
 *   - the header byte MUST be 31..34 (compressed keys only; uncompressed
 *     signatures that uNeurai would accept are rejected here);
 *   - preimage fields must not contain '|' or control characters, the
 *     challenge is 64 lowercase hex, the request type is receive|admin.
 */
namespace depin {

/* ── pin (§6.4) ──────────────────────────────────────────────────────────── */

struct Pin {
    std::string serviceId;      /* normalised RPC URL or explicit identity     */
    std::string rootToken;      /* pool root token                             */
    std::string poolPubKeyHex;  /* 33-byte compressed SEC, hex                 */
    bool hasKey() const  { return poolPubKeyHex.size() == 66; }
    bool complete() const { return !serviceId.empty() && !rootToken.empty() && hasKey(); }
};

enum class TrustMode : uint8_t {
    RequirePin,             /* default: full pin, verify before decoding     */
    PinnedKeyDiscoverRoot,  /* key pinned; read body.token to learn the root */
    ExplicitTofu            /* first contact: self-consistency only, the     */
                            /* application must accept the candidate pin     */
};

/* Validate + load the pinned pool key. */
Err pinPublicKey(const Pin & pin, PublicKey & out);

/* ── preimages (§7.1, §7.2, §6.3) ────────────────────────────────────────── */

/* Field rules shared by every preimage: non-empty, <= max, printable ASCII,
 * no '|'. Tokens additionally start with '&'. */
bool validPreimageField(const std::string & s, size_t max);
bool validToken(const std::string & token, const Limits & lim = defaultLimits());
bool validChallenge(const std::string & challenge);   /* 64 lowercase hex   */

/* "DEPIN-REQ|" type "|" token "|" address "|" unixMs       type: receive|admin */
Err requestPreimage(const std::string & type, const std::string & token,
                    const std::string & address, uint64_t unixMs, std::string & out);
/* "DEPIN-GET|" token "|" address "|" challenge   (clear=false)
 * "DEPIN-CLEAR|" scope "|" address "|" challenge (clear=true) */
Err usePreimage(bool clear, const std::string & token, const std::string & address,
                const std::string & challenge, std::string & out);
/* "DEPIN-RESP|" method "|" token "|" address "|" challenge "|" sha256hex(bodyStr)
 * token / address / challenge may be "" (see §6.3); bodyStr is the ASCII hex
 * exactly as received. */
Err replyPreimage(const std::string & method, const std::string & token,
                  const std::string & address, const std::string & challenge,
                  const std::string & bodyStr, std::string & out);

/* lowercase hex of SHA-256 over the bytes of `s` */
std::string sha256Hex(const std::string & s);

/* ── signatures ──────────────────────────────────────────────────────────── */

/* Holder signature (DEPIN-REQ / DEPIN-GET / DEPIN-CLEAR). The key must be
 * compressed; output is the canonical base64. */
Err signPreimage(const PrivateKey & key, const std::string & preimage, std::string & sigB64);

/* Recover the signer of a DePIN-profile signature (header 31..34). */
Err recoverSigner(const std::string & preimage, const std::string & sigB64, std::string & pubKeyHex);

/* poolsig: recover(sig, msghash(preimage)) must equal `poolKey`. */
Err verifyPoolSig(const PublicKey & poolKey, const std::string & preimage, const std::string & sigB64);

/* P2PKH address of a key for `net` (used to check depinpoolkeyaddress). */
std::string addressForKey(const PublicKey & key, const ChainNetwork * net);

} // namespace depin

#endif /* __NEURAI_DEPIN_AUTH_H__ */
