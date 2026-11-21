# Basic host tests

Run the portable library tests on Linux without an ESP32, Docker, a running
node, or network credentials. Requests in the client tests go to an in-process
simulated node. The test crypto backend uses OpenSSL instead of ESP32 mbedTLS.

| Executable | Coverage |
| --- | --- |
| `test_codec` | Protocol vectors, serialization, encryption/decryption, signatures, recipient ordering, external identity providers, and malformed inputs |
| `test_auth` | Authentication preimages, pool pins, signed replies, and request/reply binding |
| `test_client` | Bootstrap, group/private publication, challenges, pagination, malformed rows, and error handling |

## Setup

Install GNU Make, a C/C++ compiler, Git, and OpenSSL development headers. On
Debian/Ubuntu, the packages are `build-essential`, `git`, and `libssl-dev`.
Then run these commands from the repository root:

```sh
mkdir -p tests/deps
git clone https://github.com/NeuraiProject/uNeurai.git tests/deps/uNeurai
git -C tests/deps/uNeurai checkout e371779e9adbcba7e080614ca46370cf864c146c
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

Use uNeurai 0.3.1 and ArduinoJson 6.21.6 for the validated configuration.
Run `make -C tests clean` before switching dependency paths or compiler options.

## Fixtures and real-node integration

`fixtures/depin_rpc_v6.json` and `fixtures/depin_format3.json` are copied
from Core's `src/test/data` on `DePIN-Test` at `ad83bd8`. The RPC tests
cover the eight vectors for the six methods supported by the RPC codec. The codec
tests check message and transport contexts, hash, signature, key commitment,
recipient ordering and authenticated decryption. `vectors.txt`
supplies public key fixtures for WIF and address tests.

For a real-node run, build Core with wallet support and install its Python
functional-test dependencies. From this directory run the following commands,
with `NEURAI_SOURCE` pointing at the branch checkout. The driver creates and
stops two temporary regtest nodes and passes their fixture keys through pipes.

```sh
make build/regtest
DEPIN_CLIENT_TEST="$PWD/build/regtest" python3 integration/regtest.py --srcdir="$NEURAI_SOURCE/src"
```

The integration exercises group and private publication and paged reads
from a Legacy and a strict ECDSA wallet. The physical ESP32 transport uses
mbedTLS and Arduino HTTPClient, which are outside the host suite.
