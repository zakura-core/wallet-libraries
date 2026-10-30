# Public reference vectors

Every seed and private-key input in this directory is public test material.
Never use these values for a real wallet.

`sha2_192s_nist.seed` and `sha2_192s_nist.pk` come from NIST ACVP
[keyGen internalProjection.json, group 5, case 41](https://github.com/usnistgov/ACVP-Server/blob/112690e8484dba7077709a05b1f3af58ddefdd5d/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json).
The parameter set is SLH-DSA-SHA2-192s. The 72-byte input concatenates `skSeed`,
`skPrf`, and `pkSeed`; the public key is the published 48-byte `pk`.
These two files are copied without modification from Common's corresponding
public fixtures at `a1cdfc0e066e33db7b6f469eddd8d0194f58a185`.

`derivation.json` contains synthetic wallet seeds, encoded origins, 72-byte
SLIP-0021 root fingerprints, HKDF-SHA-512 outputs, and public keys. Python's
standard HMAC implementation derives the purpose root; OpenSSL 4.0.3 independently
performs HKDF and SLH-DSA operations.
The cases vary network, account, receiving/change branch, index, and wallet seed.
They include index high-bit boundaries and maximum account/index values.

`firmware.json` retains the shared public vectors from the Keystone and Ledger
derivation POCs. They cover the published BIP39 `abandon ... about` mnemonic,
empty and `TREZOR` passphrases, and seven origins for each seed. Tests compare
root fingerprints, child-material fingerprints, and complete public keys with
the firmware fixtures. Ledger's ARM implementation reproduced these values in
Speculos; Keystone reproduced them through its native C boundary. These are
compatibility checks, not physical-device qualification.

`derived_openssl.sig` signs `PQ wallet lifecycle vector` under the
`main_receive_0` key with context `zakura-pq-keys/test-v1`.
`sha2_192s_openssl.sig` signs 32 bytes of `0x2a` under the published NIST key
with context `common/slh-dsa/test`. Both use deterministic Pure SLH-DSA and were
generated and verified by OpenSSL. The Rust tests compare complete signatures
and verify them; no signature hash substitutes for the independent fixtures.
These contexts are tests only and do not select a transaction protocol context.
Their spelling is fixed reference-vector input and does not change with the crate name.

To reproduce the generated fixtures with OpenSSL 3.5 or newer:

```sh
python3 zakura/transparent-pq-keys/tests/vectors/regenerate.py
```

Pass `--openssl /path/to/openssl` to select another installation. The default
checks bytes without editing files; `--write` regenerates the three derived
files. The NIST inputs and firmware compatibility fixtures remain fixed. The generator uses Python HMAC for SLIP-0021 and OpenSSL for HKDF,
key generation, signing, and verification, without importing the Rust crate.
Temporary test keys are deleted when it exits and each subprocess has a timeout.
