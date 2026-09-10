#!/usr/bin/env python3
"""Cross-check envelopes/messages produced by the C++ codec with the node's
reference Python (Neurai/contrib/depin/verify_vectors.py: pure-Python
secp256k1 + `cryptography` AES-GCM). Usage:

    python3 crosscheck.py <path/to/verify_vectors.py> <path/to/vectors.txt>

Runs build/test_codec in --dump mode, then decrypts the payload with the
holder WIF, recomputes the message hash and verifies the DER signature using
only the reference implementation."""
import subprocess, sys, struct, os

if len(sys.argv) != 3:
    print(__doc__); sys.exit(2)
ref_path, vectors = sys.argv[1], sys.argv[2]
src = open(ref_path).read()
ns = {}
exec(src.split("V = {}")[0], ns)          # function definitions only (no top-level checks)
V = {}
for line in open(vectors):
    if '=' in line and not line.startswith('#'):
        k, v = line.rstrip('\n').split('=', 1); V[k] = v

here = os.path.dirname(os.path.abspath(__file__))
out = subprocess.run([os.path.join(here, 'build', 'test_codec'), vectors, '--dump'],
                     capture_output=True, text=True, check=True).stdout
D = dict(l.split('=', 1) for l in out.strip().splitlines() if '=' in l)

d = ns['wif_to_priv'](V['holder_wif']); pub = ns['compress'](ns['mul'](d, ns['G']))
plain = ns['ecies_decrypt'](D['payload'], d, pub)
assert plain == D['content'], plain
print("ok  C++ envelope decrypts with the reference ECIES ->", repr(plain))

ser = (ns['ser_str']('&TEST/SEC') + ns['ser_str'](V['holder_address']) + struct.pack('<q', 1787377444)
       + bytes([2]) + ns['ser_bytes'](bytes.fromhex(D['payload'])))
digest = ns['sha256d'](ser)
assert digest[::-1].hex() == D['hash'], "hash"
assert ns['verify_der'](pub, digest, bytes.fromhex(D['signature'])), "DER"
print("ok  C++ message hash and DER signature verified by the reference")
# wire = five fields + ser_vector(signature)
assert bytes.fromhex(D['wire']) == ser + ns['ser_bytes'](bytes.fromhex(D['signature'])), "wire layout"
print("ok  wire serialization matches ser_string/ser_bytes layout")
print("CROSSCHECK OK")
