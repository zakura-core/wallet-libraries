# One-time IVKs

Implementation of the draft v1 one-time IVK and refund-memo
conventions. A one-time key keeps the account's spending authority (`ak` and `nk`)
with its own `rivk`, so each has its own incoming viewing key and address, and a
wallet authenticates individual payments returned by receiver PIR. Wallets use them for swap refund
and incoming addresses. The derivation still requires cryptographic review before
issuing live addresses.

## Wallet integration

1. Reserve a purpose-specific index durably before exposing an address.
2. Call `KeyId::new(purpose, index).derive(account_external_fvk)` and select
   `address_at(0u32, Scope::External)` for the receiver.
3. Register the receiver identity for PIR and retain its purpose/index with authenticated received notes.
4. For a refund, encode `swap::RefundMemo` in an ordinary internal note in the
   funding transaction, whose only transparent output pays the P2PKH or P2SH
   deposit. Decode only memos on ordinary notes the wallet decrypts with its
   internal key, including zero-value and spent notes. Only the wallet can create
   such an output, so the funding inputs need not be known.
5. Reconstruct inputs with their derived FVKs. Use the account's spending key to
   sign, and its ordinary internal key for change.

The wallet owns reservation, persistence, coverage, lifecycle, and note selection.
There is no alternate balance store in this crate.

The SQLite backend implements this contract with its `orchard` feature: durable
key registration, bounded issuance, a durable recovery queue and payment admission.
`zakura-pir-client`'s `receiver-wallet` feature supplies its network steps. Its rustdoc, starting at
`zcash_client_sqlite::wallet::one_time_ivk`, documents the calls a wallet makes.

Software PCZT signing of one-time-key notes works through the same builder.
Hardware signers need firmware qualification before one-time keys are enabled for
hardware accounts.

## Layout

- Crate root: `KeyId`, `Purpose`, and derivation.
- `swap`: the refund memo and the provider-neutral lifecycle types
  (`Observation`, `OperationStatus`, `ReceiptExpectation`) that a provider
  adapter produces; `zakura-near-intents` normalizes NEAR Intents 1Click
  statuses.

## Derivation

A one-time key keeps the account's `ak` and `nk` and replaces its external `rivk`:

```text
rivk' = ToScalar(PRF^expand_rivk([0x85] || ak || nk || [purpose] || I2LEOSP_64(index)))
```

`PRF^expand` is BLAKE2b-512 personalized with `Zcash_ExpandSeed` over
`rivk || input`, and `ToScalar` reduces its little-endian output modulo the Pallas
scalar order. `purpose` is 0 for refund and 1 for incoming. This is ZIP 32's
internal-key derivation (first byte `0x83`, no suffix) with a different first byte
and a 9-byte suffix. The input fits one BLAKE2b block, as the internal key's does,
so a ZIP 2005 recovery circuit could accept one-time keys as one more `rivk` case
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
is queried through receiver PIR until a payment is authenticated. A funded key
leaves automatic monitoring only once every local operation on it is conclusive:
the provider reported that no refund is coming, or the expected refund was received
and settled. A key restored from its memo alone has no local operation, so it stays
monitored until the account's filter marker reaches 90 days of chain time after its funding.
A later refund is found only by an explicit history check. Incoming indices are recovered through four-index lookahead. `RefundMemo::decode` returns `None`
for any memo that is not a v1 record, and a wallet ignores such a memo even when it
starts with `swap::REFUND_MEMO_MAGIC`.

## Validation

From the workspace root:

```sh
python3 scripts/dev.py test --config default -p zakura-one-time-ivk
python3 scripts/dev.py test --config orchard -p zakura-client-sqlite one_time_ivk
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

The one-time IVK KDF and memo format are proposed wallet conventions, separate from
these protocol requirements. Passing these tests is not a cryptographic review.
