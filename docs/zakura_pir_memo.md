# Zakura Ironwood memo-PIR wallet integration plan

## Goal

Replace the privacy-sensitive transaction-ID lookup used to complete memos
after compact scanning with private iPIR+SP lookups keyed by Ironwood note
commitment-tree position. The wallet-side design must support a server snapshot
covering the Ironwood pool in full, while retaining the shard-stability and
horizontal-growth properties described in the Vizor PIR design.

This document records the implementation plan agreed before work began. It is
not the server or Vizor integration specification.

## Scope of the first milestone

1. Add an unpublished hand-written `zakura-pir-memo` client crate under
   `zakura/pir-memo`.
2. Pin iPIR+SP to commit
   `e875404cef33661906ab60af236dfb327e6b28b1`. A developer may use a local
   checkout through an uncommitted Cargo override, but no absolute path is
   committed.
3. Add the exact `zakura-pir-memo` Cargo feature to the Zakura backend, SQLite
   store, and compatibility facade.
4. Leave `TransactionDataRequest::Enhancement(txid)` and its queue unchanged.
   Memo PIR uses a separate queue and API so callers can migrate independently.
5. Create and backfill a durable SQLite queue keyed uniquely by Ironwood note
   commitment-tree position. A compact-scanned note with no memo is queued;
   storage of a full transaction or a valid PIR result removes it.
6. Expose a transport-neutral PIR session plus a default HTTPS wrapper. Return
   an entire decoded row so one query can complete every pending position in
   that row.
7. Accept only schema-compatible snapshots with full Ironwood coverage starting
   at position zero. Before querying, applications compare the advertised
   anchor height, block hash, and Ironwood tree size to locally scanned state.
8. Expose only an authenticated completion path: decrypt the returned full
   ciphertext with the recorded account and key scope, require Ironwood note
   plaintext V3, and require the recovered note to equal the compact-scanned
   note before atomically storing its memo and deleting the queue entry.
9. Keep `zakura-pir-memo` a direct dependency of the future Vizor integration;
   do not re-export it through the published facade.

## Client protocol

The client consumes `/memo/metadata`, `/memo/params`,
`/memo/public-params`, and `/memo/query`. The fixed record is 792 bytes
(schema version 2): the action's nullifier, the ephemeral key, the complete
580-byte encrypted-note ciphertext, `cv_net`, the 80-byte outgoing ciphertext,
the transaction ID in internal byte order, and the little-endian block height.
Memo completion reads only the ephemeral key and ciphertext; the other fields
serve DAG-sync. Eight records form a 6,336-byte PIR row. A note at position `p`
maps to global row `p / 8` and slot `p % 8`.

The snapshot advertises the seed of the deterministic public offline-query setup,
and the client requires it to equal a value this protocol version pins: the first
eight bytes, little-endian, of
`SHA-256("zcash/ironwood-memo-pir/setup-seed/v1")`. The seed is domain separated
so that it can never coincide with the nullifier-PIR deployment's, and it is
carried on the wire rather than agreed out of band so that a server built against
a different setup is rejected with a clear error instead of returning rows the
client silently fails to decrypt. The server expands it to 32 bytes exactly as
`nullifier_pir::backend::seed_from_u64` does.

Every query uses fresh randomness. A request begins with the snapshot generation
followed by serialized packing keys and the modulus-switched iPIR query. A
response begins with the generation and public-parameter epoch; its total size
is checked exactly before decoding. Metadata, parameter, and response bodies
have explicit limits. The production transport requires HTTPS.

The client rejects windowed snapshots. This is intentional: a restored wallet
must be able to retrieve any Ironwood memo discovered from its birthday onward,
and adding server machines or sealing old shards must not silently create a
wallet coverage gap.

## Database lifecycle

The queue table has one row per unresolved received note and a unique nonnegative
commitment-tree position. Its foreign key cascades when the received note is
deleted. Migration backfill includes all existing Ironwood received notes whose
memo is null and whose position is known, whether spent or unspent.

After every Ironwood received-note upsert, queue state is reconciled from the
final database row. This matters because a compact record may arrive after a
full record, and the existing upsert deliberately preserves non-null memo and
position fields. Successful PIR completion updates the memo and deletes the
queue entry in one SQLite transaction. Stale completion attempts are harmless.

## Integration sequence after this milestone

1. Add Vizor scheduling that groups pending positions by PIR row, validates the
   snapshot anchor, issues real and policy-selected cover queries, and applies
   every applicable record from a returned row.
2. Add retry/backoff and generation-refresh policy without recording requested
   positions in logs or metrics.
3. Run both completion paths while measuring unresolved memo behavior. The
   legacy tx-ID queue remains the fallback during this stage.
4. Remove Vizor's memo use of `GetTransactionEnhancement` only after full-pool
   server availability, restore-wallet tests, reorg tests, and production
   telemetry demonstrate equivalent completeness.

## Explicit non-goals

This milestone does not modify Vizor, deploy a PIR service, remove existing
transaction enhancement APIs, define cover-traffic policy, or publish the
client crate. It also does not use cuckoo hashing: the stable Ironwood tree
position is the PIR address.
