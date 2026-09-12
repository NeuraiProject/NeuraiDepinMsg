# NeuraiDepinMsg for ESP32

An Arduino C++ client and codec for **Neurai DePIN Messaging Protocol 2**.
Send encrypted group and private messages, verify signed pool replies, and
receive authenticated messages through Neurai Core RPC.

Use `NeuraiDepinClient` for network communication or `NeuraiDepinMsg` to build,
parse, verify, and decrypt messages with your own transport.

## Features

- Group messaging with on-chain recipient discovery and private messaging to a specific address.
- Hybrid ECIES encryption using secp256k1 and AES-256-GCM, with sender signature verification.
- Explicit pool public-key and root-token pinning, plus HTTPS certificate verification.
- Authenticated challenges, cursor-based pagination, and configurable response and message limits.
- Typed errors for transport, RPC, trust, signature, and decoding failures.
- Compatibility with Neurai Core and the JavaScript `@neuraiproject/neurai-depin-msg` library.

## Dependencies and installation

The hardware configuration validated so far is **ESP32-S3**, using
Arduino-ESP32 **2.0.17** through PlatformIO's `espressif32` **7.0.1** platform.

| Dependency | Validated version | Purpose |
| --- | --- | --- |
| [uNeurai](https://github.com/NeuraiProject/uNeurai) | 0.0.11 | Keys, addresses, hashing, and secp256k1 signatures |
| [ArduinoJson](https://github.com/bblanchon/ArduinoJson) | 6.21.6 | RPC request and response processing |
| [mldsa-esp32](https://github.com/NeuraiProject/mldsa-esp32) | 0.2.0 | Required by the tested uNeurai configuration |
| mbedTLS | Bundled with Arduino-ESP32 | AES-GCM and TLS |

Clone or download this repository into your Arduino sketchbook's `libraries`
directory as `NeuraiDepinMsg`, and install the dependencies above. Use
**ArduinoJson 6**, not version 7: the Arduino dependency manifest currently
specifies a minimum version and does not enforce that upper bound.

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
- A compressed WIF for a P2PKH identity authorized for that channel. Its public key must be revealed on-chain by spending from the address.

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
The client defaults to testnet/regtest address encoding; use `setNetwork()`
before `begin()` if your deployment requires another network.

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

Use `page.nextCursor` rather than the last delivered message's hash: the
transport cursor can also account for examined rows that were rejected.
`page.messages` contains successfully verified and decrypted messages;
`page.rejected` reports rows that were not delivered.

Follow `page.shouldContinue`, not just `page.serverHasMore`. Some node versions
report `has_more=false` for a full page, so the client conservatively requests
another page. An empty final page is expected when the total is an exact
multiple of the page size.

A page limit bounds the number of rows, not their byte size. Configure
`client.limits()` and `setMaxResponseBytes()` before `begin()`, and measure
memory with your intended payload sizes and recipient counts. Two messages
per page is a tested starting point, not a guarantee for every workload.

## Codec API

`NeuraiDepinMsg` provides these operations without managing an RPC connection:

| Method | Purpose |
| --- | --- |
| `buildDepinMessage(params)` | Encrypt content for recipients and sign the serialized message |
| `wrapMessageForServer(messageHex, poolKey)` | Encrypt the signed message's ASCII hex for submission to the pool |
| `parseDepinMessage(messageHex, out)` | Parse the serialized message |
| `fromRpcFields(...)` | Normalize an RPC row and check its announced hash |
| `verifyDepinMessage(message, senderKey)` | Verify the sender signature and address/key correspondence |
| `decryptPayload(payloadHex, privateKey)` | Decrypt the recipient's ECIES payload |

`DepinParams` accepts a token, sender address and public key, WIF or hex private
key, timestamp in **Unix seconds**, content, recipient public keys, and a
`group` or `private` message type. It includes the sender as a recipient by
default. Check `DepinMessageResult::ok()` and `NeuraiDepinMsg::lastErrorName()`.

`result.hex` is the signed serialized message; it is **not the complete
Protocol 2 submission request**. A custom transport must also implement the
pool envelope and authenticated RPC flow. Parsing or decrypting alone does
not establish sender authenticity: verify the signature as well.

## Examples and validation

- [EasyMessaging](examples/EasyMessaging/EasyMessaging.ino): Wi-Fi client setup, publishing, and polling. Replace its Wi-Fi, WIF, token, pool-key, and CA placeholders with a consistent configuration. Its example token and key are not a verified pin for the public URL shown. Configure a CA for verified TLS; the sketch's insecure fallback is for lab use only.
- [ProtocolVectors](examples/ProtocolVectors/ProtocolVectors.ino): offline protocol vectors with heap, stack, and timing output. Embedded keys are public regtest fixtures and must never hold funds.

On an ESP32-S3 with PSRAM disabled, the protocol vectors passed **32 checks**.
A separate Wi-Fi/HTTPS regtest run completed pinned bootstrap, group/private
publication, and verification and decryption of six messages across pages of
**2 + 2 + 2 + 0**. JavaScript **3.1.0** independently verified and decrypted
the same messages against a real Neurai node running in Docker.

These results cover the tested workloads. Public testnet operation, maximum
payload/recipient sizing, and sustained hardware stress testing remain pending.
Development test tools are maintained locally and are not included in this repository.

## License

[MIT](LICENSE)
