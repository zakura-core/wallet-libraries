# Public reference vectors

All wallet seeds and private-key inputs here are public test data. Never use them
for a real wallet.

The SHA2-128f NIST key-generation fixtures come from group 3, case 21; SHA2-192s
uses group 5, case 41 of the pinned
[NIST ACVP source](https://github.com/usnistgov/ACVP-Server/blob/112690e8484dba7077709a05b1f3af58ddefdd5d/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json).
They are copied unchanged from Common PR 650 at
`bf7a07455e5ac9ff41d1366940f5dc03e8868890`.

`derivation_128f.json` and `derivation_192s.json` contain synthetic wallet seeds,
12-byte version 2 origins, SLIP-0021 root fingerprints, HKDF material and public
keys. Python standard HMAC derives the root independently; OpenSSL implements
HKDF and SLH-DSA. Both schemes cover network, account, branch, full-width index,
seed length and seed changes.

`derived_{128f,192s}_openssl.sig` sign "PQ wallet lifecycle vector" with context
`zakura-pq-keys/test-v1`. The primitive `sha2_*_openssl.sig` fixtures sign
32 bytes of 0x2a with context `common/slh-dsa/test`. All use deterministic
Pure SLH-DSA. OpenSSL 4.0.3 generated and independently verified these signatures.

Run `python3 regenerate.py` to check or add `--write` to replace generated
fixtures. OpenSSL 3.5+ is required only for regeneration; Rust tests run offline.

Version 1 derivation and firmware fixtures are superseded and removed. Version 2
firmware agreement has not been established; software vectors prove no hardware
qualification.
