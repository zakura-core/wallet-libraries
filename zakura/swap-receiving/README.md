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

The SQLite backend's `experimental-swap-receiving` feature adds durable key
registration. `reserve_swap_receiving_key` advances a purpose's sequence,
`recover_swap_receiving_key` records validated recovery evidence, and
`watch_swap_receive_key` retains an unpaid incoming lookahead key without
advancing allocation. `get_swap_receiving_keys` reconstructs and verifies stored
receivers after reopen. These are `WalletDb` methods, also usable inside its
transaction helpers so a reservation and an application's operation record can
commit together. Do not expose an address until that transaction commits.

The registry stores full `u64` indices as fixed-width big-endian blobs for SQLite
ordering. This is an internal storage encoding; the KDF and memo remain
little-endian. Registration retains the earliest requested scan height, not
proof that its history was scanned. The feature is disabled by default.

Compact scanning records the keys actually used in each batch, atomically with
its notes and blocks. `get_swap_receiving_scan_ranges` returns their disjoint,
end-exclusive coverage. Registration queues missing history through the known
tip. Later scans and tip updates preserve those gaps until replay completes.
Rewinds trim coverage even in builds without swap support. Refresh the chain tip
before scanning after reopening, including after enabling the feature again.

For a newly issued address, use the next height after the accepted tip as
`scan_from`. For recovery, use the earliest height at which that address could
have received a payment. Requesting older history queues replay and can delay
spending until that history is checked. Key retirement remains a separate step.

The planned selector will prefer swap notes during ordinary sends when doing so
adds neither inputs nor fees, respecting existing input constraints. Confirmed
ordinary internal change then uses normal account recovery. This preference will
not trigger separate transactions or delete receiving keys.

## Completion policy

`lifecycle::Lifecycle` holds one operation's completion state. Store its terminal
observation, receipt expectation, and reconciliation state together. Restore them
with `from_parts` so reopening and later policy changes preserve saved deadlines.
The route adapter supplies an explicit zero, positive, or unknown Zcash receipt
expectation. Missing API data stays unknown.

On the first terminal observation, save the accepted tip, a grace target 10 blocks
later, and a reconciliation time 12 hours later. Repeated observations preserve
those deadlines. `scan_decision` checks actual per-key coverage through the target
and current canonical receipt accounting. Positive expectations require confirmed
notes with enough on-chain value. Unknown expectations also require completed
directory reconciliation. Ambiguous operation attribution remains unresolved.

`key_needs_scanning` combines every linked operation's decision. Unresolved uses
and restored keys without operation history remain active. A `Retire` decision
only stops trial decryption. Preserve the key, reservation, and delayed query.

When due, `begin_reconciliation` saves a fixed chain target across retries and
pages. Validate publication coverage, chain binding, and all returned payments
before calling `finish_reconciliation`. Incomplete results leave the query pending.
Transport failures and unknown statuses preserve state. Backoff belongs to the
caller's network scheduler.

After a supported status regression call `resume`. After a reorg call `rewind`
and update coverage and receipt accounting in the same storage transaction.
Recompute scan decisions even for retired keys. Never credit a note to multiple
operations sharing a receiver.

This helper is unit tested. SQLite operation persistence and active-key filtering
are the next integration step. SQLite currently scans every registered key.

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
local commitment tree. Separate SQLite registry tests cover durable allocation,
reopening, lookahead, recovery bounds, rollback, and concurrent connections:

```sh
cargo test -p zakura-client-sqlite --features experimental-swap-receiving --locked swap_receiving
```

The SQLite integration tests also scan both purposes alongside ordinary keys,
reopen the database, and construct a mixed-input transaction whose change returns
to the ordinary internal key. They check replay, late payments, and invalid note
metadata. Registered keys currently remain in every subsequent compact scan.
Full-transaction retrieval authenticates swap memos before or after compact
scanning, including self-payments also recoverable through the ordinary OVK.
Enhance PIR resolves the registered key after restart and rejects altered
ciphertext without clearing pending work. A build without swap support reports
an error for that retrieval instead of trying the ordinary account key.

Per-key historical coverage, retirement,
automatic seed restore and gap extension, PCZT/firmware qualification, Vizor,
and receiver PIR remain required before live use. Registration after an earlier
scan does not yet schedule the missing history automatically.

## Protocol baseline

Zcash Protocol Specification **v2026.7.0-202-gafa086, NU6.3 proposal**, commit
`afa086bd976e316612a5c06fb139429958d07d84`:

- [§4.2.3, Key Components, pp.40–41](https://github.com/zcash/zips/blob/afa086bd976e316612a5c06fb139429958d07d84/protocol/protocol.tex#L5753-L5909),
  PDF anchor `orchardkeycomponents`.
- [§5.6.4.4, Raw Full Viewing Keys, p.123](https://github.com/zcash/zips/blob/afa086bd976e316612a5c06fb139429958d07d84/protocol/protocol.tex#L13077-L13104),
  PDF anchor `orchardfullviewingkeyencoding`.

The swap KDF and memo format are proposed wallet conventions, separate from
these protocol requirements. Passing the POC is not a cryptographic review.
