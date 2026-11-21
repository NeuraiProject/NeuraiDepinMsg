#ifndef __NEURAI_DEPIN_AUTH_H__
#define __NEURAI_DEPIN_AUTH_H__

#include <string>
#include "DepinCodec.h"

/* RPC 6 pool pins, section grammar and recoverable Neurai signatures. */
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
bool tokenInScope(const std::string & messageToken, const std::string & scope);
bool validChallenge(const std::string & challenge);   /* 64 lowercase hex   */

/* ── signatures ──────────────────────────────────────────────────────────── */

/* Sign the RPC 6 preimage using the magic hash for this destination family. */
Err signPreimage(const PrivateKey & key, const std::string & preimage, std::string & sigB64, const std::string & address = "");

/* Recover the signer of a DePIN-profile signature (header 31..34). */
Err recoverSigner(const std::string & preimage, const std::string & sigB64, std::string & pubKeyHex);

/* poolsig: recover(sig, msghash(preimage)) must equal `poolKey`. */
Err verifyPoolSig(const PublicKey & poolKey, const std::string & preimage, const std::string & sigB64);

/* P2PKH address of a key for `net` (used to check depinpoolkeyaddress). */
std::string addressForKey(const PublicKey & key, const ChainNetwork * net);

} // namespace depin

#endif /* __NEURAI_DEPIN_AUTH_H__ */
