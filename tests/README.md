# Basic host tests

Run the portable library tests on Linux without an ESP32, Docker, a running
node, or network credentials. Requests in the client tests go to an in-process
simulated node. The test crypto backend uses OpenSSL instead of ESP32 mbedTLS.

| Executable | Coverage |
| --- | --- |
| `test_codec` | Protocol vectors, serialization, encryption/decryption, signatures, recipient ordering, and malformed inputs |
| `test_auth` | Authentication preimages, pool pins, signed replies, and request/reply binding |
| `test_client` | Bootstrap, group/private publication, challenges, pagination, malformed rows, and error handling |

## Setup

Install GNU Make, a C/C++ compiler, Git, and OpenSSL development headers. On
Debian/Ubuntu, the packages are `build-essential`, `git`, and `libssl-dev`.
Then run these commands from the repository root:

```sh
mkdir -p tests/deps
git clone --depth 1 --branch v0.0.11 https://github.com/NeuraiProject/uNeurai.git tests/deps/uNeurai
git clone --depth 1 --branch v6.21.6 https://github.com/bblanchon/ArduinoJson.git tests/deps/ArduinoJson
make -C tests -j4 run
```

Dependencies are downloaded only during setup; the tests themselves run
offline. `tests/deps/` and generated `build/` directories are ignored by Git.
Host builds do not require Arduino-ESP32 or mldsa-esp32.

Alternatively, supply existing dependency checkouts:

```sh
make -C tests -j4 run UNEURAI=/path/to/uNeurai ARDUINOJSON=/path/to/ArduinoJson
```

Use uNeurai 0.0.11 and ArduinoJson 6.21.6 for the validated configuration.
Run `make -C tests clean` before switching dependency paths or compiler options.

## Results and scope

Each executable prints its check and failure counts and returns a nonzero
status on failure. `make run` stops if any executable fails. The current suite
contains 149 codec checks, 93 authentication checks, and 111 client checks.

`fixtures/vectors.txt` contains public regtest vectors, with their upstream
source revision recorded in its header. These keys are test data and must
never hold funds. No Wi-Fi credentials or live wallet keys are needed.

These tests do not validate Arduino adapters, hardware memory usage, TLS on
the ESP32, or interoperability against a real node. Those integration tools
remain in the separate local `test/` directory, which is not published.
