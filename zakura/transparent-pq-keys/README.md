# Transparent PQ wallet keys

`transparent-pq-keys` implements the first wallet milestone: deterministic private
derivation of distinct SLH-DSA-SHA2-128f and SLH-DSA-SHA2-192s key pairs, public-key
export, signing, verification, and seed-based recovery. It is unpublished
and not connected to address issuance or transaction signing. It does not enable PQ
funds.

Every origin gets a complete key pair with fresh `SK.seed`, `SK.prf`, and `PK.seed`. The
wallet seed only derives keys; it is not a shared signing key. Recovering the same
origin reproduces the same key, including its usage history. Changing an address tag or
selecting another internal SLH-DSA leaf is not key rotation.

## Derivation version 2

Input is 32 through 64 bytes of wallet seed material. These are decoded wallet seed
bytes, not mnemonic text or a password. The caller must provide adequate entropy: input
length is not proof of entropy, and expanding an existing weaker seed does not increase
its security. In particular, a 64-byte mnemonic-derived seed need not contain 512 bits
of entropy.

Derive a dedicated secret using
[SLIP-0021](https://github.com/satoshilabs/slips/blob/master/slip-0021.md), then use
[HKDF-SHA-512 (RFC 5869)](https://www.rfc-editor.org/rfc/rfc5869):

```text
master = HMAC-SHA512(key=ASCII("Symmetric key seed"), message=wallet_seed)
node = HMAC-SHA512(key=master[0..32], message=0x00 || ASCII("Zcash/TransparentPQ/v2"))
pq_root = node[32..64]                       # SLIP-0021 Key(node)
salt = ASCII("Zcash/PQWallet/SLH-DSA-SHA2-" + scheme + "/v2")  # no trailing NUL
info = version || parameter_set || network || account_be32 || branch || index_be32
PRK = HKDF-Extract(salt, pq_root)
n = 16 for 128f, 24 for 192s
material = HKDF-Expand(PRK, info, 3*n)

SK.seed = material[0..n]
SK.prf  = material[n..2*n]
PK.seed = material[2*n..3*n]
```

Version 2 replaces the unreleased version 1 derivation and rejects old recovery
encodings. Version 2 does not reproduce version 1 keys. There is no implicit
configuration: origins and public-key imports require an explicit parameter set.

SLIP-0021 gives Ledger applications a supported OS derivation operation without access
to the wallet seed. The construction is intended for portable recovery; version 2
firmware alignment has not been verified. Passphrase processing belongs to the caller's
seed format; this crate consumes the resulting seed bytes. The purpose label is this
design's identifier, not a registered SLIP assignment. The versioned purpose root
separates this derivation from version 1.

The root is spending authority, not an extended public key. It must stay inside the
signer. SLIP-0021 does not enable watch-only child derivation. This crate does not
expose a hardware-root import API or connect to a hardware device.

Generate the selected SLH-DSA key using those three inputs in the order specified by
[FIPS 205, Algorithm 18](https://doi.org/10.6028/NIST.FIPS.205). The public root must be
computed from the secret material; `PK.seed` is not a watch-only derivation seed.
Public-key encoding is `PK.seed || PK.root` (32 bytes for 128f, 48 bytes for 192s).

The exact origin encoding is 12 bytes:

| Field | Encoding |
| --- | --- |
| Version | One byte, `2` |
| Parameter set | One byte: SHA2-128f `1`, SHA2-192s `2` |
| Network namespace | One byte: mainnet `0`, testnet `1`, regtest `2` |
| Account | Four-byte unsigned big-endian integer |
| Branch | One byte: receiving `0`, change `1` |
| Child index | Four-byte unsigned big-endian integer |

Accounts and indices include the entire `u32` range, including the high bit. They are
not BIP 32 child numbers and do not encode hardening. This provides `2^32` child indices
per account and branch, unrelated to the per-key signature budget. Unknown
versions/parameter-set/network/branch codes and non-exact lengths are rejected. All
regtest chains share the regtest namespace. Use different seeds or accounts for distinct
regtest wallets. Network namespaces are not activation checks.

The version, parameter set, network, account, branch, and index must be preserved for
recovery. The encoded origin is recovery metadata, not a final xpub or backup container.
It is not an authenticated association with a public key. A wallet importing origins
must validate their association with its wallet configuration.

The caller must reserve each issuance index durably and coordinate concurrent issuance.
Repeated derivation of the same origin is intentional recovery. Paying an old receiving
address does not generate a new key. This library does not allocate indices, search the
chain, or track which addresses were issued.

## Signing and public export

`WalletSeed::derive_key` returns a `DerivedSigningKey`. Its `public_key` and `origin`
methods export public verification and recovery metadata only. There is no public child-
derivation API, serialization of secrets, secret-key export, or debug/clone
implementation on either secret type.

`sign` and `PublicKey::verify` use deterministic **Pure SLH-DSA** through the
standardized external interface, including its message/context framing. The caller
supplies the exact application message and context (0 through 255 bytes). They do not
use HashSLH-DSA or invent a transaction digest. A signature is exactly 17,088 bytes for
128f or 16,224 bytes for 192s, without a transaction signature-hash selector.
Verification rejects truncation and trailing bytes before cryptographic work.

Each complete key has its own signing budget. Both standardized configurations are
designed for at most `2^64` messages per key (FIPS 205 section 11). The library does not
persist or enforce a lifetime counter; enforcing a lower operational cap across multiple
devices and restores is later wallet-policy work. All signing activity matters even if a
transaction is never broadcast. A key is reusable and is not exhausted by one signature.

## Security assumptions and limits

The adversary may see public keys, origins, and chosen-message signatures and may supply
malformed encodings. The seed and derived secret keys must remain private. Under
SLIP-0021's HMAC and HKDF's pseudorandomness assumptions with sufficiently strong input
material, distinct, unambiguously encoded origins produce pseudorandom 48-byte (128f) or
72-byte (192s) key-generation inputs. Splitting that output supplies separate secret and
public seeds. The scheme/version salt separates this derivation from other uses of the
purpose-specific root; SLIP-0021 separates that root from other wallet purposes. SLH-DSA
unforgeability and its multi-key security still depend on the selected primitive and
parameter set.

This is a construction rationale, not an independent security review or a complete-
system NIST security-category claim. No stronger assurance follows merely from passing
vectors. Deterministic wallet derivation is an application layer; the crate does not
claim FIPS module validation or compliance with all FIPS random-bit-generator
requirements.

The implementation uses RustCrypto's `hkdf`, `sha2`, and `slh-dsa` crates. The SLH-DSA
version matches Common's PQ primitive implementation in [Common PR
650](https://github.com/zakura-core/common/pull/650) at
`bf7a07455e5ac9ff41d1366940f5dc03e8868890`, which this workspace now pins while Common 5
is unpublished, so the build carries one copy of the primitive. This crate depends on
`slh-dsa` directly rather than on Common, so it stays usable without the transaction
stack. Transaction integration must use Common's agreed digest and execution rules.
RustCrypto documents that its SLH-DSA implementation has not been independently audited.
Review remains required before production use.

Owned wallet seed bytes, SLIP-0021 node/root buffers, and derived-material buffers use
`Zeroizing`; the primitive's `zeroize` feature clears stored secret seeds on drop.
Caller-owned input copies, compiler temporaries, and HKDF/HMAC internal state are not
covered by a complete-erasure guarantee. The library does not claim hardened memory,
side-channel certification, or hardware-wallet qualification.

## Validation

From the repository root:

```sh
python3 scripts/dev.py test --config transparent-pq-keys
python3 scripts/dev.py lint --config transparent-pq-keys
```

Tests cover independent OpenSSL derivation/public-key/signature vectors, NIST ACVP key-
generation vectors for both schemes, restoration, separate public seeds across tested
origins, full-width indices, seed and context boundaries, malformed encodings, wrong
keys/messages/contexts, modified signatures, and repeated signing. Fixture provenance
and regeneration are in [tests/vectors/README.md](tests/vectors/README.md).

Tests use public synthetic or published vector material only. They run offline without
OpenSSL. Regenerating reference vectors requires OpenSSL 3.5 or newer.

Index allocation, batch replenishment and restore discovery are in
[`transparent-pq-pool`](../transparent-pq-pool/README.md). This milestone leaves
address/script formats, watch-only descriptor formats, multisig coordination, PCZT,
transaction transport, fee policy, activation, and public derivation extensions to
later work.