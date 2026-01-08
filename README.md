# NeuraiDepinMsg Library for ESP32

Build, encrypt, sign, and serialize DePIN messages compatible with Neurai Core.

This library allows ESP32 devices to produce the hex payload required for the Neurai RPC method `depinsubmitmsg`. It replicates the functionality of the `@neuraiproject/neurai-depin-msg` JavaScript library in a C++ environment optimized for microcontrollers.

## Features

- **Hybrid ECIES Encryption**: AES-256-GCM message encryption with recipient key wrapping.
- **Hardware Acceleration**: Leverages ESP32's `mbedtls` for high-performance AES-GCM encryption.
- **Core Compatibility**: Produces serialization identical to Neurai Core (Bitcoin-style).
- **Self-Contained Signing**: Handles secp256k1 signing using the `uNeurai` library.
- **Automatic Recipient Handling**: Automatically includes the sender's public key as a recipient so the device can decrypt its own messages.

## Dependencies

This library depends on:
1.  **[uNeurai](https://github.com/NeuraiProject/uNeurai)**: For Neurai-specific cryptography (ECDSA, Hashing, Base58/WIF).
2.  **mbedtls**: Bundled with the ESP32 Arduino Core (used for AES-GCM).

## Installation

1.  Download or clone this repository.
2.  Copy the `NeuraiDepinMsg` folder into your Arduino `libraries` directory.
3.  Ensure you have the `uNeurai` library also installed in your Arduino IDE.

## High-Level Client (Recommended)

For most applications, it is recommended to use the `NeuraiDepinClient` class. It encapsulates all the RPC communication and encryption complexity.

```cpp
#include <WiFi.h>
#include <NeuraiDepinClient.h>

NeuraiDepinClient depin;
uint64_t lastTimestamp = 0;
String lastHash = "";

void setup() {
  // 1. Connect WiFi and sync NTP (User managed)
  
  // 2. Initialize the client
  depin.begin("https://rpc-depin.neurai.org", "MYTOKEN", "MY_WIF_KEY");

  // 3. Sending Messages
  // Send to everyone holding the token
  depin.sendGroupMessage("Hello everyone!");
  
  // Send to a specific address (fetches pubkey automatically)
  depin.sendPrivateMessage("NUSS...CV", "Hello friend!");
}

void loop() {
  // 4. Poll and Detect Message Type (Batch Limit: 5)
  auto msgs = depin.receiveMessages(lastTimestamp, 5, lastHash);
  
  for (auto &m : msgs) {
    if (m.hash.length() > 0) lastHash = m.hash; // Update pagination cursor

    if (m.decrypted) {
      Serial.print("[" + m.type + "] "); // "private" or "group"
      Serial.println(m.content);
    }
  }
  delay(15000);
}
```

## Batch Message Reception (Pagination)

For devices with limited memory (like ESP32), you can request messages in smaller batches using the `limit` and `lastHash` parameters.

```cpp
// Receive up to 5 messages starting after the 'lastHash'
std::vector<IncomingMessage> msgs = depin.receiveMessages(lastTimestamp, 5, lastHash);
```

- **limit**: Maximum number of messages to retrieve in one call.
- **lastHash**: The hash of the last received message. The server will return messages *after* this hash.

Always ensure you update `lastHash` with `msg.hash` from the received messages to properly advance the cursor.

## Low-Level Usage

If you prefer to handle the RPC communication yourself, you can use the static methods in `NeuraiDepinMsg`.

```cpp
#include <NeuraiDepinMsg.h>

void setup() {
  DepinParams params;
  params.token = "MYTOKEN";
  params.senderAddress = "N...";
  params.senderPubKey = "02..."; // 33-byte compressed hex
  params.privateKey = "WIF_OR_HEX"; 
  params.timestamp = 1704542400;
  params.message = "Hello from ESP32!";
  params.recipientPubKeys = {"03..."}; // Add recipient compressed pubkeys
  params.messageType = "private"; // or "group"

  DepinMessageResult res = NeuraiDepinMsg::buildDepinMessage(params);

  Serial.print("Hex for depinsubmitmsg: ");
  Serial.println(res.hex);
}
```

## Technical Details

### Encryption (Hybrid ECIES)
The library follows Neurai Core's cryptographic standards:
- **Ephemeral Keys**: A new secp256k1 key pair is generated for every message.
- **KDF**: Uses `KDF_SHA256` for key derivation.
- **AES-256-GCM**: Encrypts the payload and the per-recipient keys with 12-byte nonces and 16-byte authentication tags.

### Data Structure
The final hex payload is a serialized `CDepinMessage`:
1. `token` (String)
2. `senderAddress` (String)
3. `timestamp` (Int64)
4. `messageType` (Uint8)
5. `encryptedPayload` (Vector)
6. `signature` (Vector)

## License

MIT
