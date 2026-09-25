# Swap receiving POC

Unpublished implementation of the draft v1 receiving-key and refund-memo
conventions. It supports refund and incoming keys with the account's existing
spending authority. The derivation still requires cryptographic review before
issuing live addresses.

## Wallet integration

1. Reserve a purpose-specific index durably before exposing an address.
2. Call `derive_full_viewing_key(account_external_fvk, purpose, index)` and select
   `address_at(0u32, Scope::External)` for the receiver.
3. Register that FVK for scanning and retain its purpose/index with received notes.
4. For a refund, encode `RefundMemo` in an ordinary internal note in the funding
   transaction. Decode only after note authentication and verification that the
   transaction was the wallet's own send, including zero-value and spent notes.
5. Reconstruct inputs with their derived FVKs. Use the account's spending key to
   sign, and its ordinary internal key for change.

`has_same_spending_authority` compares the `ak` and `nk` of valid FVKs. It does not
replace recipient, nullifier, signature, value, or change validation. The wallet
owns reservation, persistence, coverage, lifecycle, and note selection. There is
no alternate balance store in this crate.

## Derivation

The HMAC key is the account's canonical 32-byte external `rivk`. The message is
the one-byte label length, ASCII label, little-endian `u64` index, and
little-endian `u32` retry counter. Labels are `swap-refund-v1` and `swap-receive-v1`.
Network and pool identify stored keys but are not v1 derivation inputs.

Interpret HMAC-SHA-512 output as a little-endian integer and reduce modulo the
Pallas scalar order. Keep the account's `ak` and `nk`, replace `rivk`, and accept
the first valid FVK starting at retry zero. Parsing validates both external and
internal incoming viewing keys. Exhaustion returns an error.

## Refund memo

| Offset | Bytes | Field |
|---|---:|---|
| 0 | 5 | `FF 5A 53 57 50` (`0xFF`, `ZSWP`) |
| 5 | 1 | Version `1` |
| 6 | 1 | Refund purpose `0` |
| 7 | 8 | Index, little-endian |
| 15 | 2 | Address length, little-endian |
| 17 | N | Exact ASCII deposit address, 1–495 bytes |
| 17 + N | 495 − N | Zero padding |

Address validation uses the funding transaction's network and supported wallet
address types. Incoming indices are recovered through lookahead, not this memo.
The decoder distinguishes unrelated memos from malformed or unsupported records.
Callers must retain unsupported records as incomplete recovery work.

## Validation

From the workspace root:

```sh
cargo test -p zakura-swap-receiving --locked
```

The tests check independent Python HMAC/scalar vectors, purpose separation,
boundary indices, retry behavior, authority substitutions, and malformed memos.
Regenerate the vectors from this directory with
`python3 tests/vectors/generate.py > tests/vectors/rivk.csv`.

The protocol POC builds Ironwood outputs and discards the derived keys. It
decrypts a zero-value internal recovery memo, reconstructs the refund key and
an incoming lookahead key, then spends those notes with an ordinary note. It
verifies real proofs and spend/binding signatures and decrypts ordinary internal
change. It also checks that ordinary viewing keys cannot read the swap notes and
that zero OVK reveals the fixture payouts but not the recovery marker.

This is a bundle-level test with synthetic commitments as signing messages and a
local commitment tree. It does not yet exercise SQLite persistence, a complete
transaction on a chain, Vizor, PIR, incoming gap discovery, or Keystone. Those
integrations remain required for the receive/restore/spend milestone.

## Protocol baseline

Zcash Protocol Specification **v2026.7.0-202-gafa086, NU6.3 proposal**, commit
`afa086bd976e316612a5c06fb139429958d07d84`:

- [§4.2.3, Key Components, pp.40–41](https://github.com/zcash/zips/blob/afa086bd976e316612a5c06fb139429958d07d84/protocol/protocol.tex#L5753-L5909),
  PDF anchor `orchardkeycomponents`.
- [§5.6.4.4, Raw Full Viewing Keys, p.123](https://github.com/zcash/zips/blob/afa086bd976e316612a5c06fb139429958d07d84/protocol/protocol.tex#L13077-L13104),
  PDF anchor `orchardfullviewingkeyencoding`.

The swap KDF and memo format are proposed wallet conventions, separate from
these protocol requirements. Passing the POC is not a cryptographic review.
