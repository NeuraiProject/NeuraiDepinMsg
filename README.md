# NeuraiDepinMsg for ESP32

An Arduino C++ client and codec for **Neurai DePIN Messaging Protocol 6**.
Send encrypted group and private messages, verify signed pool replies, and
receive authenticated messages through Neurai Core RPC.

Use `NeuraiDepinClient` for network communication or `NeuraiDepinMsg` to build,
parse, verify, and decrypt messages with your own transport.

## Features

- Group messaging with on-chain recipient discovery and private messaging to a specific address.
- Format-3 ECIES envelopes with HKDF-SHA256, AES-256-GCM and a content-key commitment. The message digest binds the chain genesis, token, exact sender address, timestamp, type and envelope.
- Explicit pool public-key and root-token pinning, plus HTTPS certificate verification.
- Signed RPC 6 requests, request-bound pool replies and admission-sequence pagination.
- Typed errors for transport, RPC, trust, signature, and decoding failures.
- Compatibility with Neurai Core and the JavaScript `@neuraiproject/neurai-depin-msg` library.

## Dependencies and installation

The build target is **ESP32-S3**. The examples compile using
Arduino-ESP32 **2.0.17** through PlatformIO's `espressif32` **7.0.1** platform.

| Dependency | Validated version | Purpose |
| --- | --- | --- |
| [uNeurai](https://github.com/NeuraiProject/uNeurai) | 0.3.1 | Keys, addresses, hashing, and secp256k1 signatures |
| [ArduinoJson](https://github.com/bblanchon/ArduinoJson) | 6.21.6 | RPC request and response processing |
| [mldsa-esp32](https://github.com/NeuraiProject/mldsa-esp32) | 0.2.0 | Required by the tested uNeurai configuration |
| mbedTLS | Bundled with Arduino-ESP32 | AES-GCM and TLS |

Clone or download this repository into your Arduino sketchbook's `libraries`
directory as `NeuraiDepinMsg`, and install the dependencies above.
Both dependency manifests require **ArduinoJson 6.21 or later within 6.x**.

The tested uNeurai configuration enables post-quantum support and therefore
needs `mldsa-esp32`; DePIN message signatures themselves use secp256k1.
With PlatformIO, ensure its dependency discovery makes `MLDSA44.h` available
when compiling uNeurai.

Arduino IDE/CLI installation and Arduino-ESP32 3.x have not yet been validated.
Other ESP32 models are outside the current hardware validation scope.

## Before connecting

Obtain these settings from the operator of your DePIN pool:

- The RPC service URL and its TLS root CA certificate in PEM format.
- The pool's compressed public key: **66 hexadecimal characters**, obtained through a trusted channel.
- The pool root token and the channel token, for example `&TEST` and `&TEST/SEC` in a local regtest fixture.
- The WIF for an authorized Legacy P2PKH or strict ECDSA witness-v3 identity. Reveal its public key on-chain by spending from that exact address. Strict ECDSA requires a compressed key.

Connect Wi-Fi and synchronize the device's UTC clock before requesting
challenges. Keep private keys and Wi-Fi credentials in local configuration or
provisioned storage, outside source control. Start Wi-Fi before encrypting
messages so the ESP32 random source has RF entropy available.

A TLS certificate and a pool pin serve different purposes: configure both.
A root-token or pool-key mismatch is an error to investigate, not a reason to
automatically accept a replacement pin.

## Client usage

The following application fragments assume Wi-Fi is connected and the clock
is synchronized. Replace every placeholder with settings for the same pool.
The client defaults to testnet genesis and Legacy P2PKH. For regtest, call
`client.setExpectedGenesis(hash)` with the trusted result of `getblockhash 0`
before `begin()`. Testnet and regtest share address prefixes. For a strict
ECDSA holder call `client.setStrictEcdsa(true)` before `begin()`. The same
key can hold independent memberships at its Legacy and strict addresses.

```cpp
#include <NeuraiDepinClient.h>

NeuraiDepinClient client;
String cursor;  // Restore a previously committed cursor from storage if needed.

bool startMessaging(const char *rootCA, const char *holderWIF) {
  client.setCACert(rootCA);  // Keep the PEM buffer alive while using the client.
  client.setPoolPin("YOUR_66_HEX_POOL_PUBLIC_KEY", "&YOURPOOL");
  client.setPageLimit(2);

  if (!client.begin("https://YOUR_RPC_HOST", "&YOURPOOL/CHANNEL", holderWIF))
    return false;
  return client.bootstrap();
}

void publishMessages(const String &recipientAddress) {
  String groupHash = client.sendGroupMessage("Hello everyone!");
  if (groupHash.isEmpty()) {
    Serial.println(client.lastErrorName());
    return;
  }

  String privateHash = client.sendPrivateMessage(recipientAddress, "Hello privately!");
  if (privateHash.isEmpty()) Serial.println(client.lastErrorName());
}

void pollMessages() {
  if (!client.ready()) return;

  // Bound work per poll. Continue from the saved cursor on the next poll.
  for (unsigned pageNumber = 0; pageNumber < 4; ++pageNumber) {
    DepinPageResult page = client.receivePage(cursor, 2);
    if (!page.ok) {
      Serial.println(client.lastErrorName());
      return;  // Do not advance the cursor after a failed request.
    }

    for (const auto &message : page.messages) {
      Serial.printf("[%s] %s\n", message.type.c_str(), message.content.c_str());
    }
    if (page.rejected) Serial.printf("Rejected rows: %u\n", (unsigned)page.rejected);

    // Commit only after successfully processing the page's messages.
    cursor = page.nextCursor;
    // Persist cursor here if processing must resume after a reboot.
    if (!page.shouldContinue) break;
  }
}
```

Call `publishMessages()` only after `startMessaging()` succeeds. For detailed
diagnostics, use `lastError()`, `lastErrorName()`, and `lastErrorDetail()`.
When `lastError()` is `depin::Err::RateLimited`, defer retries according to
`retryAfterSec()` rather than polling immediately.

### Pagination and memory

An empty cursor starts a `depinreceiveseq` read. Persist the entire
`page.nextCursor` string, including after an empty successful poll. It
contains the pool stream ID, 64-bit admission sequence, scope, address and
timestamp filter. `shouldContinue` follows the authenticated `has_more`
flag. Restarting from an empty cursor rereads retained history.

The client checks the signed page and cursor, verifies each sender using
the row's `sender_pubkey_hex`, and decrypts for the configured destination.
`page.rejected` counts rows that failed message validation or decryption.
On a failed page, retain the previously committed cursor.

A page limit bounds the number of rows, not their byte size. Configure
`client.limits()` and `setMaxResponseBytes()` before `begin()`, and measure
memory with your intended payload sizes and recipient counts. The default page size is two. `limits().maxReplyJson` bounds the decoded
page, and `setMaxResponseBytes()` bounds the HTTP body.

## Codec API

`NeuraiDepinMsg` provides these operations without managing an RPC connection:

| Method | Purpose |
| --- | --- |
| `buildDepinMessage(params)` | Encrypt content for recipients and sign the serialized message |
| `wrapMessageForServer(genesis, messageHex, poolKey)` | Encrypt the signed message's ASCII hex for submission to the pool |
| `parseDepinMessage(genesis, messageHex, out)` | Parse the serialized message |
| `fromRpcFields(...)` | Normalize an RPC row and check its announced hash |
| `verifyDepinMessage(message, senderKey)` | Verify the sender signature and address/key correspondence |
| `decryptPayload(parsedMessage, recipientAddress, privateKey)` | Derive the message context and decrypt for the exact destination |

`DepinParams` requires the display-order, lowercase genesis hash in `genesis`, a token, sender address and public key, WIF or hex private
key, timestamp in **Unix seconds**, content, recipient public keys, and a
`group` or `private` message type. It includes the sender as a recipient by
default. Supply `recipientAddresses` alongside `recipientPubKeys` to select
exact destinations, including strict ECDSA. A public key alone selects its
Legacy address in that SEC serialization. Check `DepinMessageResult::ok()` and `NeuraiDepinMsg::lastErrorName()`.

`result.hex` is the signed wire message. To submit it with a custom
transport, wrap its ASCII hex for the pool using the submit context and
sign the RPC 6 request. Pass the trusted genesis to `fromRpcFields()` or
`parseDepinMessage()` on receive. Verify the DER signature before delivering
the result of `decryptPayload()` to the application.

Bootstrap requires a pool advertising protocol 6 and ECIES format 3 during bootstrap.

## Wallet-owned identities

The codec can use a `depin::IdentityProvider` instead of receiving a WIF or
`PrivateKey`. Implement three synchronous operations: `publicKey()`,
`signDigest()`, and `ecdh()`. Signing returns DER for the supplied 32-byte
digest. ECDH returns SHA-256 of the compressed shared point, matching Neurai.

Pass the provider to the `messageBuild()`, `messageSign()`, or `eciesDecrypt()`
overloads. The library borrows it only for the duration of the call and does
not retain private keys. The provider must enforce wallet readiness and
permission checks on every operation and keep the identity stable during a
call. This interface does not add thread synchronization or hardware isolation.
Returned signatures are verified against the provider's public key and sender
address before signing succeeds.

For bounded embedded buffers, use the `eciesDecrypt()` overload taking an
output pointer, capacity, and written length. It checks capacity before ECDH
and wipes plaintext produced by a failed authentication attempt. Output and
input buffers must not overlap.

Applications with their own transport can define
`NEURAI_DEPIN_NO_ARDUINO_CLIENT` globally to omit the Arduino HTTP transport and
`NeuraiDepinClient` implementation. The portable codec remains available.
The high-level client still uses its existing WIF-based initialization; the
external identity API currently applies to the codec.

## Examples and validation

- [Basic host tests](tests/README.md): codec, authentication, and client regression tests. After installing the documented dependencies, run `make -C tests run`. No board, node, or credentials are required.
- [EasyMessaging](examples/EasyMessaging/EasyMessaging.ino): Wi-Fi client setup, publishing, and polling. Replace its Wi-Fi, WIF, token, pool-key, and CA placeholders with a consistent configuration. Configure a CA for verified TLS; the sketch's insecure fallback is for lab use only.
- [ProtocolVectors](examples/ProtocolVectors/ProtocolVectors.ino): offline verification and decryption of Core's format-3 known-answer message. The embedded test key is public.

The host suite includes Core's RPC 6 and format-3 fixtures. The portable
codec also exchanged signed messages in both directions with JavaScript SDK
5.0.0. Both Arduino examples compiled for ESP32-S3.

On a physical ESP32-S3 rev. 0.2, the codec verified and decrypted Core's
format-3 reference message and rejected a modified timestamp. The portable
client ran in RAM against two `DePIN-Test` regtest nodes at `ad83bd8`.
The S3 authenticated the pool, published a group message from a Legacy
holder and a private message from a strict ECDSA holder, and verified and
decrypted both messages for each holder using one-row pages. RPC requests
used a USB bridge. Wi-Fi/TLS operation and heap use during HTTPS requests
remain untested on the board.

## License

[MIT](LICENSE)
