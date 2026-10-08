# Dynamic IVKs

Unpublished implementation of the draft v1 dynamic IVK and refund-memo
conventions. A dynamic key keeps the account's spending authority (`ak` and `nk`)
with its own `rivk`, so each has its own incoming viewing key and address, and a
wallet trial-decrypts with a changing set of them. Wallets use them for swap refund
and incoming addresses. The derivation still requires cryptographic review before
issuing live addresses.

## Wallet integration

1. Reserve a purpose-specific index durably before exposing an address.
2. Call `KeyId::new(purpose, index).derive(account_external_fvk)` and select
   `address_at(0u32, Scope::External)` for the receiver.
3. Register that FVK for scanning and retain its purpose/index with received notes.
4. For a refund, encode `RefundMemo` in an ordinary internal note in the funding
   transaction, whose only transparent output pays the P2PKH or P2SH deposit.
   Decode only after note authentication and verification that the transaction
   was the wallet's own send, including zero-value and spent notes.
5. Reconstruct inputs with their derived FVKs. Use the account's spending key to
   sign, and its ordinary internal key for change.

`has_same_spending_authority` compares the `ak` and `nk` of valid FVKs. It does not
replace recipient, nullifier, signature, value, or change validation. The wallet
owns reservation, persistence, coverage, lifecycle, and note selection. There is
no alternate balance store in this crate.

The SQLite backend implements this contract with its `orchard` feature: durable
key registration, scanning, completion, and the restore sweeps that
`zakura-pir-receiver` runs. Its rustdoc, starting at
`zcash_client_sqlite::wallet::dynamic_ivk`, documents the calls a wallet makes.

Software PCZT signing of dynamic-key notes works through the same builder.
Hardware signers need firmware qualification before dynamic keys are enabled for
hardware accounts.

## Derivation

A dynamic key keeps the account's `ak` and `nk` and replaces its external `rivk`:

```text
rivk' = ToScalar(PRF^expand_rivk([0x85] || ak || nk || [purpose] || I2LEOSP_64(index)))
```

`PRF^expand` is BLAKE2b-512 personalized with `Zcash_ExpandSeed` over
`rivk || input`, and `ToScalar` reduces its little-endian output modulo the Pallas
scalar order. `purpose` is 0 for refund and 1 for incoming. This is ZIP 32's
internal-key derivation (first byte `0x83`, no suffix) with a different first byte
and a 9-byte suffix. The input fits one BLAKE2b block, as the internal key's does,
so a ZIP 2005 recovery circuit could accept dynamic keys as one more `rivk` case
with purpose and index as private inputs. Network and pool identify stored keys
but are not derivation inputs.

`0x85` was unused by the protocol specification and ZIPs when chosen. Reserve it
with the ZIP editors before issuing live addresses. Parsing the result validates
both external and internal incoming viewing keys; with negligible probability an
index has no valid key, and derivation returns an error.

## Refund memo

| Offset | Bytes | Field |
|---|---:|---|
| 0 | 5 | `FF 5A 53 57 50` (`0xFF`, `ZSWP`) |
| 5 | 1 | Version `1` |
| 6 | 1 | Refund purpose `0` |
| 7 | 8 | Index, little-endian |
| 15 | 497 | Reserved: written as zero, ignored on decode |

The memo does not store the deposit address. A restored refund key needs none: it
is swept once and, if the provider was given its address in the last day, scans for
another 24 hours, with no provider lookups. Incoming indices are
recovered through lookahead, not this memo. `RefundMemo::decode` returns `None`
for any memo that is not a v1 record. A wallet that selects records by their
`REFUND_MEMO_MAGIC` prefix keeps one it cannot decode pending, without failing,
and refund issuance waits for it, since it may hold a refund index.

## Validation

From the workspace root:

```sh
cargo test -p zakura-dynamic-ivk --locked
cargo test -p zakura-client-sqlite --features orchard,test-dependencies --locked dynamic_ivk
```

Regenerate the KDF vectors from this directory with
`python3 tests/vectors/generate.py > tests/vectors/rivk.csv`.

## Protocol baseline

Zcash Protocol Specification **v2026.7.0-202-gafa086, NU6.3 proposal**, commit
`afa086bd976e316612a5c06fb139429958d07d84`:

- [§4.2.3, Key Components, pp.40–41](https://github.com/zcash/zips/blob/afa086bd976e316612a5c06fb139429958d07d84/protocol/protocol.tex#L5753-L5909),
  PDF anchor `orchardkeycomponents`.
- [§5.6.4.4, Raw Full Viewing Keys, p.123](https://github.com/zcash/zips/blob/afa086bd976e316612a5c06fb139429958d07d84/protocol/protocol.tex#L13077-L13104),
  PDF anchor `orchardfullviewingkeyencoding`.

The dynamic IVK KDF and memo format are proposed wallet conventions, separate from
these protocol requirements. Passing these tests is not a cryptographic review.
