# Zakura wallet core

A proposal for a simplified wallet library built from first principles, supporting
Orchard, Ironwood and transparent only, with a sync engine designed for
throughput and bounded memory, a schema small enough to hold in the head, and
open seams for Enhance PIR and BIP-158 compact block filters.

This document describes a greenfield core that depends on the published
`zakura-*` crypto crates and on nothing in `librustzcash/`. It does not propose
changing the existing fork, which continues to serve consumers that need Sapling,
zcashd import, PCZT, or the ZIP 318 migration engine.

## Why

The forked wallet layer is 121,000 lines:

| | Today |
| --- | --- |
| SQLite objects | 49 tables, 46 indexes, 15 views |
| Migrations | 67 files, ~19,000 lines, a schemerz DAG with 24 public release anchors |
| Storage contract | ~87 trait methods (`WalletRead` 37, `WalletWrite` 26, `WalletCommitmentTrees` 13, `InputSource` 11); ~135 with `ll` and PIR |
| Test scaffolding | ~18,500 lines (`data_api/testing/pool.rs` alone is 10,102) |
| Pools | Sapling, Orchard and Ironwood, hand-duplicated at every layer |
| Transaction construction | `data_api/wallet.rs` 4,148 + `input_selection.rs` 2,954 + `proposal.rs` 2,113 + `fees/` 3,564 |

Little of that is essential complexity. It is Sapling; zcashd `wallet.dat` import
(`zewif.rs`, 2,753 lines); the ZIP 318 pool-migration state machine (8 tables);
backend genericity, where every storage decision is expressed as a trait so third
parties can reimplement it; roughly 19 view-only migrations and 9 bug-repair
migrations; and three copies of what is structurally one pool.

The opportunity is specific. **Ironwood is Orchard.** It uses the same
`orchard::note::Note`, the same nullifier algorithm, the same `MerkleHashOrchard`,
the same circuit, the same Orchard receiver and the same ZIP 32 keys. It differs
in four places: note plaintext V3 (lead byte `0x03`, `rcm_v3`), a distinct
`IronwoodDomain`, its own commitment tree, anchors and nullifier set, and
transaction v6 only. The fork carries it as a third hand-written pool because
retrofitting a generic pool onto upstream was not possible.

Three observations from the current code make the case concrete.

`ScanSummary` in `zcash_client_backend/src/data_api/chain.rs` has Sapling and
Orchard counters and no Ironwood ones, although `scan_block_with_runners`
produces Ironwood spends and outputs. A third hand-written copy was required and
one of them was missed.

`zcash_client_sqlite` already performs runtime pool dispatch, through
`TableConstants` in `src/wallet/common.rs`, which templates
`format!("... {table_prefix}_received_notes ...")`. That is the right idea, pool
as data, implemented at the wrong layer: string-built SQL over three parallel
table families.

`scan_cached_blocks` traverses the block source twice and accumulates the whole
range in memory before a single `put_blocks`. The double traversal exists only
because `BlockSource` is a callback trait rather than a value.

Assumptions this design is built on: the server is ours to change; the consumer
is a Rust core now with an FFI later; the core reuses only the crypto crates; the
first deliverable is a working prototype.

The target is a wallet that syncs to tip and spends, in roughly 17,000 lines of
non-test Rust.

## Crates

A seam earns its place only if it has two real implementations today, or if the
compile and test cost on either side differs by an order of magnitude.

| Crate | Owns | Why the seam |
| --- | --- | --- |
| `zakura-wallet-core` | `PoolId`, the `ShieldedPool` trait and the `Orchard`/`Ironwood` types, `dispatch`, `ScanRange`/`ScanPriority`/`SpanningTree`, `DetectedBatch`, frontiers | No I/O, no async, no SQL. Breaks the dependency cycle, and is the only crate an FFI type layer needs to see. |
| `zakura-wallet-scan` | `detect_batch(..) -> Result<DetectedBatch, ScanError>`, rayon trial decryption, `PositionTracker` | The highest-value seam. Pure CPU; compiles and tests in seconds; property tests need no SQLite. |
| `zakura-wallet-store` | Schema, `WalletDb` over `rusqlite`, the unified shard store | One concrete type, no storage trait. |
| `zakura-wallet-sync` | The engine: stages, scan-queue policy, reorg, progress, cancellation. Defines `ChainSource`, `Enhancer`, `BlockPrefilter` | `ChainSource` has three real implementations: gRPC, an in-memory test chain, and later a Tor-wrapped transport. |
| `zakura-wallet-tx` | Input selection, fees, proposals, bundle building, ZIP 318 crossing | Pulls in the proving stack; keeping it out preserves store and scan build times and lets watch-only builds drop it entirely. |
| `zakura-lwd` | Proto codegen, tonic, retry and backoff; `impl ChainSource` | Proto churn and tonic's dependency weight should not reach store or scan. |

A thin `zakura-wallet` facade assembles these and is what an FFI layer binds to.

**There is no storage trait in v1.** `WalletDb` is a concrete struct with inherent
methods. Genericity over storage is the largest single source of the 58k/63k
split and buys nothing until a second backend exists. Dropping it removes
`WalletRead`, `WalletWrite`, `WalletCommitmentTrees` and `LowLevelWalletWrite`
(about 6,000 lines of trait surface), every `DbT: WalletWrite` bound, and
`MockWalletDb`. If a second backend ever appears, the trait can be extracted
then, with the benefit of knowing what it actually needs.

## The pool abstraction

```rust
pub trait ShieldedPool: Copy + 'static {
    const ID: PoolId;                  // Orchard = 3, Ironwood = 4, as in encoding.rs
    const SHARD_HEIGHT: u8;            // 16
    const ACTIVATION: NetworkUpgrade;  // Nu5 / Nu6_3
    type Domain: BatchDomain<Note = orchard::note::Note> + ...;

    fn actions(tx: &CompactTx) -> &[CompactOrchardAction];
    fn tree_size(meta: &ChainMetadata) -> u32;
    fn domain_for(action: &CompactAction) -> Self::Domain;
    fn ivks(keys: &ScanKeys) -> &[TaggedIvk<Self>];
}

pub struct Orchard;
pub struct Ironwood;
```

`Note`, `Node = MerkleHashOrchard`, `Nullifier` and `CompactAction` stay concrete
and shared rather than becoming associated types. They are the same types, and
saying so in the trait is what keeps the abstraction from leaking. `Self::Domain`
is the only real variation, and it is exactly the ZIP 2005 difference.

Excluding Sapling is what makes this clean. Sapling would force all four to
become associated types; the eight closure parameters of `find_received` in
`zcash_client_backend/src/scanning.rs` are the price of exactly that.

Runtime dispatch uses a visitor, so the `match` over pools appears once in the
whole workspace:

```rust
pub trait PoolVisitor { type Out; fn visit<P: ShieldedPool>(self) -> Self::Out; }

pub fn dispatch<V: PoolVisitor>(id: PoolId, v: V) -> V::Out {
    match id {
        PoolId::Orchard  => v.visit::<Orchard>(),
        PoolId::Ironwood => v.visit::<Ironwood>(),
    }
}
```

Two boundaries stay deliberately non-generic.

**Transparent is not a `ShieldedPool`.** It has no trial decryption, no
commitment tree, no positions and no nullifiers. Detection is set membership:
`vout.script` against a watch set for receives, `vin.outpoint` against the UTXO
set for spends. Unification happens one level up, at
`enum Funds { Shielded { .. }, Transparent { .. } }`, used by input selection and
balance. Giving transparent outputs an always-`None` `commitment_tree_position`
is how a schema acquires invariants nobody can state.

**Transaction construction is not pool-generic.** Ironwood is v6-only, permits
cross-address transfers through flags bit 2, and ZIP 318 crossing is a property
of the ordered pair Orchard to Ironwood rather than of one pool. `wallet-tx`
takes `PoolId` explicitly and keeps a non-generic `crossing` module. Stating this
up front is worth more than the code it would save.

## Sync engine

```
[Tip]    GetLatestBlock -> update_chain_tip -> scan_queue
[Plan]   suggest_ranges, chunked by BYTES, not blocks
[Fetch]  GetBlockRange, ALL pools    ==> bounded mpsc<Vec<CompactBlock>>  depth 2
[Detect] rayon, pure detect_batch    ==> bounded mpsc<DetectedBatch>      depth 2
[Apply]  single writer thread, ONE sqlite transaction per batch:
             blocks, notes, nullifier_map, shardtree (rayon build_subtrees),
             link stored unlinked nullifiers, scan_complete with shard widening,
             mark_stabilized_notes
[Enhance]     tx_retrieval_queue -> GetTransaction, later PIR
[Transparent] gap-limit extension + GetAddressUtxos
```

### Detection is a pure function

```rust
pub fn detect_batch(
    params: &impl Parameters,
    keys:   &ScanKeys,
    nfs:    &NullifierSnapshot,   // immutable, epoch-stamped
    anchor: &BlockAnchor,         // (height, hash, per-pool tree sizes)
    blocks: &[CompactBlock],
) -> Result<DetectedBatch, ScanError>;
```

No database handle, no async, no trait bounds on storage. `DetectedBatch` is a
plain owned value: block headers, per-pool commitments with retention, detected
notes, unlinked nullifiers, transparent hits, and Ironwood enhance candidates. It
is serializable, diffable and golden-testable, and the crate carries no SQLite in
its dev-dependencies.

Two subtleties keep this honest. First, the fork mutates the nullifier set
mid-batch, so a note received in block *n* can be seen spent in block *n+3* of the
same batch; preserve that with a local mutable overlay over the immutable
snapshot, which remains pure with respect to inputs. Second, the snapshot can go
stale relative to the writer; stamp it with a monotonic epoch and have the writer
re-run the cheap linking step, joining `nullifier_map` against `received_notes.nf`,
inside the same transaction.

### One traversal, same parallelism

Full rayon parallelism requires queueing every trial decryption in a batch before
collecting any result. That property is worth keeping. The double *traversal of
the block source* is not: it is an artifact of `BlockSource::with_blocks` being a
callback. With `blocks: &[CompactBlock]` in hand, pass one is a `par_iter` over
every compact output producing a `HashMap<(TxId, u32), DecryptResult>`, and pass
two is a serial fold over the same slice assembling positions, nullifier links
and commitments.

This removes `BlockSource`, `BlockCache`, `FsBlockDb`, `block_deletions` and the
"waiting for cached blocks to be deleted" cycle in `sync.rs`. They exist because
download and scan were decoupled through the filesystem. In a bounded in-memory
pipeline, blocks are transient.

### Bounded memory

Chunk by bytes, not blocks. The fork's `batch_size: u32` is a block count, and
mainnet compact block sizes vary by four orders of magnitude, so a block-count
batch is either pointlessly small or an out-of-memory kill on a phone. The budget
is `max_in_flight_bytes` — on the order of 16 MiB on mobile and 128 MiB on
desktop — and the fetch stage stops reading the stream when it is reached. The
bounded channels are the backpressure.

### Concurrency

Tokio owns tip, fetch, enhance and transparent work. Rayon owns detection only,
entered through a single `spawn_blocking`, so the boundary is one function call.
A dedicated writer thread owns the `rusqlite::Connection`; this is a correctness
choice rather than a performance one, because it turns SQLite writer
serialization into a type-level fact instead of a `BUSY` retry loop. Reads for the
UI use a separate read-only connection in WAL mode.

### Descending recovery by default

The server already supports it: `GetBlockRange` streams in decreasing height
order when `start > end`. Ironwood is a tip pool and spendable value concentrates
near the tip, so recovery runs tip to birthday in shard-aligned descending chunks.

This makes `ScanPriority::LatestPoolActivation` unnecessary. That level exists to
work around ascending-only recovery, and it is derived at `suggest_scan_ranges`
time rather than stored. Removing it takes the priority ladder from nine levels to
eight and deletes `derive_latest_pool_activation` from the storage layer.

The price is that receives are discovered after their spends. That is paid
entirely by `nullifier_map` and the Apply-time linking step, both of which are
needed regardless.

### Reorgs

Two detectors, both retained. Continuity checking inside `detect_batch` catches a
`prev_hash` or height discontinuity for free and handles the common case. The
`Verify` priority re-fetches `VERIFY_LOOKAHEAD` (10) blocks above the maximum
scanned height before any `ChainTip` work, and catches the case where the tip
moved under us.

Handling is one transaction: delete blocks and transactions above the target
height, unmark spends, `ShardTree::truncate_to_checkpoint`, and requeue the range
at `Verify`.

Rewind depth is engine policy, not caller policy. The fork's documented example
hardcodes `err.at_height().saturating_sub(10)` and leaves the real decision to the
consumer, which every consumer gets wrong. The policy here starts at 10, doubles
on repeated failure, caps at `PRUNING_DEPTH` (100), and beyond that falls back to
a full rescan from birthday.

### Engine state, progress, cancellation

`sync.rs::running` returns `Result<bool>` where `true` means "scan ranges changed,
start over" — a state machine encoded as a return value. Make it explicit
(`NeedTip`, `NeedVerify`, `Scanning`, `Enhancing`, `Idle`) and expose
`run(cancel) -> impl Stream<Item = SyncEvent>` rather than an `async fn` that
loops internally forever.

Progress is note-commitment coverage rather than blocks scanned: a per-pool ratio
of positions covered to tree size, plus transparent, published through a
`tokio::sync::watch`. It is lossy, cheap, and expressible across an FFI boundary
as a poll rather than a marshalled callback.

Cancellation is checked between batches only. One invariant makes that safe: a
batch is applied in exactly one SQLite transaction, and the scan queue is marked
`Scanned` inside that same transaction. Cancelling is dropping the engine;
resuming is re-reading `scan_queue`. There is no partially-applied state to
reason about.

## Storage

Two database files. The split is what makes "the database is a derived cache"
structurally true rather than aspirational: with a single file, someone will
eventually need to preserve one derived table across a version bump, will write a
migration, and there will be migrations again.

### `wallet.db`, durable, hand-migrated

| Table | Contents |
| --- | --- |
| `accounts` | uuid, kind, seed fingerprint, HD account index, ufvk, uivk NOT NULL, birthday height, birthday Orchard and Ironwood frontiers, has-spend-key, anchor retention interval |
| `sent_outputs` | txid, output pool, output index, from account, to address, to account, value, memo. Generalized over the fork's `sent_notes` to cover transparent outputs. |
| `raw_transactions` | txid to bytes |
| `user_metadata` | txid, key, value: labels, address book |
| `wallet_meta` | network, `detection_version`, `layout_version`, `tree_version`, gap limits |

Birthday frontiers are not derivable from local data and may not be re-fetchable
if the server prunes.

### `cache.db`, derived, dropped and rebuilt

| Table | Contents |
| --- | --- |
| `blocks` | height PK, hash, time, Orchard and Ironwood tree sizes and action counts |
| `scan_queue` | range start, range end, priority |
| `transactions` | txid, block height, tx index, expiry height, mined height, min observed height, target height, fee, zip318 kind |
| `received_notes` | **`pool` column.** tx id, action index, account id, diversifier, value, rho, rseed, note version, nf, is-change, memo, recipient key scope, commitment tree position, witness stabilized. `UNIQUE(tx_id, pool, action_index)`, index on `(pool, nf)`. |
| `received_note_spends` | junction, not a `spent` column, so expired-but-created spends stay recorded |
| `transparent_received_outputs` | tx id, output index, account id, address, script, value, max observed unspent height |
| `transparent_received_output_spends` | junction |
| `transparent_spend_map` | prevout to spending transaction, for out-of-order recovery |
| `addresses` | account id, key scope (0 external, 1 internal, 2 ephemeral), diversifier index, unified address, transparent child index as an integer for gap queries, transparent address, transparent script, exposed-at height |
| `nullifier_map` | `(pool, nf)` PK, block height, tx index |
| `tree_shards` | `(pool, shard_index)` PK, subtree end height, root hash, shard data |
| `tree_checkpoints` | `(pool, checkpoint_id)` PK, position, `retained_for` (non-null marks anchor-grid retention, folding in the fork's separate retained-checkpoints table) |
| `tree_checkpoint_marks_removed` | pool, checkpoint id, mark removed position |
| `tree_cap` | `pool` PK, cap data |
| `enhance_candidates` | Ironwood outgoing candidates; see the PIR section |
| `tx_retrieval_queue` | txid, query type, dependent transaction id, nullable `routing` that PIR grows into |

Fifteen tables against roughly thirty-five in the fork. Five tree tables per pool
across three pools become four tables, served by one shard store parameterized by
a runtime `PoolId` rather than three instantiations over three table prefixes. Two
note tables per pool become one with a `pool` column; the reason the fork needs
separate tables is that an Orchard action and an Ironwood action in the same
transaction can share an `action_index` and would collide, which adding `pool` to
the key resolves. Fifteen views become none: `v_transactions` is 225 lines of SQL,
and that aggregation belongs in Rust where it can be tested and profiled. The
eight ZIP 318 state tables and `zewif` import go entirely. No SQL is built with
`format!` anywhere.

Gap limits are not a table. They live in `wallet_meta` as external 10, internal 5,
ephemeral 10, and the invariant — keep a full gap of unused addresses above the
highest used index — is a query re-evaluated during Apply whenever a transparent
hit lands.

## Migrations

The natural rule is that the database is a derived cache, so a schema version bump
triggers a rescan rather than a migration. That is nearly right, and it has one
real hole and one real cost.

**A rescan cannot recover outgoing recipients or memos.** They come from OVK
recovery over the raw transaction, and a rescan yields compact blocks. Recovering
them means re-enhancing every historical wallet-funded transaction from the
server — and for Ironwood-only transactions under Enhance PIR, from a snapshot
that may since have rotated. `zakura_pir_enhance.md` is explicit that a stale
record produces no mutation and no public fallback. A naive rescan therefore
loses outgoing history silently. This is why `sent_outputs`, `raw_transactions`
and `user_metadata` live in `wallet.db`.

**A rescan is not bounded by user patience.** Mainnet from a 2019 birthday across
two pools is hours on a phone over cellular. Triggering that because a column was
added is user-hostile.

Three version numbers, each with a different blast radius:

| Version | A bump means | Cost |
| --- | --- | --- |
| `detection_version` | A true chain rescan | Bumps only when trial decryption, tree parameters, or position derivation change. Should bump close to never. |
| `layout_version` | A local reindex: drop and rebuild the derived tables from `raw_transactions` and the retained shards | No network. Covers the overwhelming majority of schema changes. |
| `tree_version` | Refetch subtree roots | Kept separate because refetching is a large network cost and the birthday frontier is a one-shot `GetTreeState` that may not be reproducible. Trees are retained across a layout bump. |

One further guard: refuse to rescan while an unmined transaction is outstanding.
Otherwise its expiry and target heights and its pending outputs vanish, and the
wallet re-broadcasts or double-spends. It is one check.

## Seams for Enhance PIR and BIP-158

Neither is built now. Four commitments make both retrofittable without a rescan.

### PIR

The seam is enhancement, but scanning has to carry the payload.

`DetectedBatch` carries Ironwood enhance candidates. For every Ironwood action in
a wallet-funded transaction that the wallet did not decrypt as its own, record
the tree position, action index, nullifier, cmx, ephemeral key, compact ciphertext
prefix and funding accounts — the shape already produced in
`zcash_client_backend/src/scanning/compact.rs` — into `enhance_candidates`. Store
it. Positions are otherwise recoverable only from the raw transaction, which is
circular, and skipping this means enabling PIR later forces a full rescan.

Never filter the compact stream to Ironwood only. From `zakura_pir_enhance.md`:
"The compact source must include all shielded pools: a stream filtered to Ironwood
cannot safely establish eligibility." Bake that into the fetch stage as a hard
constraint with a comment pointing at the document, because `poolTypes` will look
like an obvious optimization to a future contributor.

Define `trait Enhancer { async fn enhance(&self, reqs: &[EnhanceRequest]) -> ...; }`
with an LWD implementation as the only one. The nullable
`tx_retrieval_queue.routing` column (`NULL`, `PrivateCandidate`, `LwdRequired`) is
a layout-only addition. The sticky `LwdRequired` rule and the
single-SQL-transaction revalidation live in Apply, which already has the
one-transaction-per-batch discipline they require. The document's core property
must be preserved: capture `(position, txid, action index)` locally before network
I/O, send only the position, and recheck the identity inside the applying
transaction, which is what stops a reorg from letting a stale response mutate a
new position's occupant.

### BIP-158

Nothing exists in this repository today, and the honest framing matters: filters
cannot help shielded receive detection. Trial decryption has no membership test,
and only a detection-key scheme in the style of fuzzy message detection would
change that. Filters buy two things.

The first is transparent discovery, and it is the real prize. Today the wallet
polls `GetTaddressTxids` per address, which lets a server cluster a wallet's
addresses — precisely the reason the gap limits are 10/5/10 rather than BIP 44's
20. A per-block filter over scriptPubKeys removes that leak. The second is
skipping spend detection in blocks that provably touch none of our nullifiers.

The seam is
`trait BlockPrefilter { async fn candidate_blocks(&self, range, watch) -> Option<BTreeSet<BlockHeight>>; }`
between planning and fetching, defaulting to `None`.

**Server prerequisite, worth adding now:**
`GetCompactHeaders(BlockRange) -> stream CompactHeader`, roughly 44 bytes per
block carrying height, hash, previous hash, time, and the Orchard and Ironwood
tree sizes. It is trivial for a server we control. Skipping a block still requires
advancing tree sizes and hash continuity, so without it BIP-158 can skip nothing.
It also gives cheap tip-reorg detection without re-downloading real blocks, and
fast bootstrap of `blocks` for progress reporting. If nothing else is built for
BIP-158, build this: retrofitting is technically fine, but by then position
tracking will have been designed around always having the full block, and
unwinding that is structural.

## What must not be simplified away

Ordered by how easily each is deleted by accident.

**Shard-boundary range widening.** `extend_range` and `scan_complete` in
`zcash_client_sqlite/src/wallet/scanning.rs`. A note whose containing shard is not
fully scanned has no witness and is silently unspendable. This looks like a
scheduling optimization and is a correctness requirement; the `FoundNote` priority
exists solely to serve it.

**`nullifier_map` and unlinked nullifiers.** Without them, out-of-order and
descending scanning produce a wallet that finds a note and never notices it was
spent. Prune below `tip - PRUNING_DEPTH` only once recovery is complete: a note
received at height 500,000 may be spent at 2,000,000.

**`PositionTracker::check_end_of_compact_block_consistency`** in
`scanning/compact.rs`. The only defense against a server omitting one action and
shifting every subsequent commitment position by one, which corrupts every witness
from that point onward and is not detected downstream until a proof fails. Keep
both halves: derivation from prior block metadata, and the cross-check against
`block.chain_metadata`.

**`AnchorRetention` and retained checkpoints**, in
`zcash_client_backend/src/data_api/anchor_retention.rs`. ZIP 318 pool-crossing
transfers prove against the tree state at a boundary block on a shared 144-block
grid rather than at the tip, and are proved long after the boundary has passed.
Pruning on the plain `PRUNING_DEPTH` rule makes such a transfer permanently
unprovable. The set-of-intervals design, where a wallet may owe retention to more
than one grid at once, is not overengineering.

**ZIP 318 canonical-crossing indistinguishability**,
`data_api/wallet.rs:800-1030` (`canonical_crossing_candidate`,
`step_is_canonical_crossing`) together with `zcash_protocol::zip318`. A
speculative Orchard-only first selection pass, `PreferSingle`, a bucketed anchor
from `pool_migration_params()`, and a fee compared against
`canonical_crossing_fee`. If an Orchard-to-Ironwood transfer is not byte-shape
identical to every other one, the sender is deanonymized at the moment they cared.
The on-chain classification is deliberately weaker than the construction-side one
— it admits more, never less — and that asymmetry should not be "fixed" into
symmetry. This belongs in the prototype, and it needs only `PoolMigrationParams`,
which is configuration derived from a 144-block interval, not the eight-table
migration state machine.

**The `min()` across per-pool shard tips** in `update_chain_tip`. Ironwood is
sparse after NU6.3, and following the Orchard tip alone leaves the Ironwood tree
unwitnessable.

**`witness_stabilized` and `mark_stabilized_notes`.** These distinguish "a witness
is computable" from "a witness a reorg cannot invalidate", which is what governs
spend eligibility. One `UPDATE` per Apply.

**`Verify` priority and `VERIFY_LOOKAHEAD`.** Without them, reorgs are discovered
when a spend is rejected.

**A checkpoint at every scanned block height**, not only at heights carrying
wallet notes — what `ensure_checkpoints` in `data_api/ll/wallet.rs` maintains.
`truncate_to_height(h)` requires a checkpoint at `h`, and imprecise rewind is how
a tree becomes corrupt.

**Spend junction tables** rather than a `spent` boolean.

**`is_change` and the internal-versus-external key scope.** These drive balance
display, OVK selection, and whether an Ironwood action becomes a PIR outgoing
candidate at all: change is encrypted under the internal OVK, so an outgoing entry
for it could never resolve, and would keep its transaction protected, and
therefore un-enhanced, forever.

**Expiry accounting**, `tx_unexpired_condition` in `wallet/common.rs`. Without it,
funds stay locked behind an unmined transaction indefinitely. The
`min_observed_height + DEFAULT_TX_EXPIRY_DELTA` fallback for transactions of
unknown expiry is subtle and correct.

**Gap limits below BIP 44's 20.** The 10/5/10 defaults exist because light-wallet
servers can cluster addresses queried together.

## Build order

| Milestone | Deliverable | Done when |
| --- | --- | --- |
| M1 ✅ | `core`: `ShieldedPool`, the two pool types, `dispatch`, `ScanRange` and `SpanningTree` ported | **Done.** All 13 upstream `scanning.rs` and `spanning_tree.rs` tests pass verbatim against the port. |
| M2 ✅ | `scan`: `detect_batch`, rayon decryption, `PositionTracker` | **Done.** 55 tests, 99% line coverage, no storage crate anywhere in the dependency graph. See "M2 as built" below. |
| M3 ✅ | `store`: schema and the shard store over unified tables | **Done.** 46 tests, 97% line coverage. See "M3 as built" below. |
| M4 ✅ | Apply stage: `DetectedBatch` to SQLite in one transaction | **Done.** 160 tests across the three crates, 98% line coverage. See "M4 as built" below. |
| M5 ✅ | `sync` engine plus an in-memory `ChainSource` | **Done.** 191 tests across four crates, 97.7% line coverage. See "M5 as built" below. |
| M6 ✅ | `zakura-lwd` and descending recovery | **Done, against Zcash mainnet with live Ironwood.** 1.6× faster than the fork on detect-plus-store over identical blocks. See "M6 as built" below. |
| M7 | Transparent detection and gap limits | A receive to a t-address extends the gap and surfaces the address; the UTXO spends; a reorg unspends it correctly |
| M8 🔶 | `tx`: selection, fees, build, broadcast | **Mostly done.** Selection, fees, witnesses, proven and verified bundles, and v6 transaction assembly with a real signature hash. **Broadcast is not built.** See "M8 as built" below. |
| M9 ✅ | ZIP 318 crossing construction | **Done.** A crossing builds, proves and verifies, and the wallet's own `classify` call reports it as conforming. |
| M10 | PIR and BIP-158 seams exercised with stubs | `Enhancer` and `BlockPrefilter` each gain a second, stub implementation that compiles and passes M5's suite, proving the seams are real rather than aspirational |

Out of scope for the prototype: Sapling, multi-step and TEX/ZIP 320 ephemeral
chains, PCZT and hardware signers, the ZIP 318 migration state machine, zcashd
import, Tor, note locking, and consolidation-aware selection.

Size expectation: core about 1,500 lines, scan 2,000, store 6,000, sync 2,500, tx
4,000, lwd 1,000 — roughly 17,000 in total. Test scaffolding about 2,500: reuse
the fork's test vectors and scenarios but not `TestBuilder`, whose 18,500 lines
exist to be generic over `ShieldedPoolTester`, backend and feature flags. With one
backend and a real pool trait, the same coverage costs a seventh as much.

## M2 as built

Three decisions were made while implementing detection that the plan did not
settle, and one deliberate deviation from upstream.

**Trial decryption belongs to the pool trait.** `ShieldedPool` gained a
`batch_decrypt` method. Without it, every generic function that scans a block
carries a `where CompactAction: ShieldedOutput<P::Domain, COMPACT_NOTE_SIZE>`
bound, because the compiler cannot see that `P::Domain` is always a
`NoteEncryptionDomain<V>`. Discharging that once, in the two concrete impls,
keeps the bound out of the scanner entirely. It also states the abstraction
more honestly: a pool is a thing that can trial-decrypt its own compact actions.

**The anchor always carries tree sizes, which deletes two error variants.**
Upstream must cope with a compact block that omits its chain metadata, and
carries `TreeSizeUnknown` and `TreeSizeInvalid` to reconstruct or reject in that
case. Because we control the server and because a range always begins from a
known predecessor — the wallet's own record, or `GetTreeState` at the birthday —
the starting size is never in doubt. A new `ActionsBeforeActivation` variant was
added in their place: a block below a pool's activation height containing that
pool's actions is a faulty or hostile source, and accepting it would mean
deriving positions in a tree that does not yet exist.

**Nullifier matching uses a hash lookup, not constant-time comparison.**
Upstream scans its whole nullifier list for every spend, in constant time. This
is O(1) instead of O(notes), which is what makes descending recovery affordable
on a large wallet. The cost, stated plainly: a hash lookup takes measurably
different time on a hit than on a miss, so an attacker who can observe this
process's timing could in principle learn whether a block contained one of the
wallet's nullifiers. Both inputs are already local, so this matters only against
a co-resident attacker, and upstream's own comment questions whether the
constant-time comparison earns its cost. `find_spends` in `detect.rs` is the one
place to change if that threat comes into scope.

**Enhancement candidates are captured now**, as §6 requires: every Ironwood
action of a wallet-funded transaction that the wallet did not itself receive is
recorded with its position, nullifier, commitment, ephemeral key and 52-byte
ciphertext prefix. Actions the wallet received are excluded — change is
encrypted under the internal outgoing key, so a job for it could never resolve.

## M3 as built

The 15-table schema and the pool-keyed shard store are in place, and all four
gate conditions hold: both pools, a witness that verifies against an
independently recomputed root, a truncation that round-trips, and a retained
anchor that outlives ordinary pruning.

**The `pool` column works, and it is where the saving comes from.** One
`WalletShardStore` serves both pools; the five-tables-per-pool-per-protocol
family in the fork becomes four tables total, and the `format!`-templated SQL
disappears with it. The store is 560 lines against the fork's 2,211.

**`shard_data` is `NOT NULL`, and an unscanned shard is a leaf.** The plan
imagined a row carrying a server-supplied root hash with no contents. That is
not how it works: `shardtree` cannot annotate an empty tree, so backfill stores
such a shard as a *single ephemeral leaf holding the root hash*, exactly as the
fork does. The nullable column and the branches that read it were removed.

**Tree errors are a concrete type.** `TreeError` distinguishes a storage failure
from a tree-logic one (`ShardTreeError`) rather than making every caller supply
an error type with two `From` bounds. This follows the same reasoning as having
no storage trait: the store is concrete, so its errors can be too.

**Retention is a column, and it can be recorded ahead of the tree.** The fork
keeps retained checkpoints in a separate table per pool. Here `retained_for` on
`tree_checkpoints` does the same job, and retention may be recorded for a height
the tree has not reached yet — the ZIP 318 anchor grid is known in advance, and
forgetting a boundary before the tree arrives at it would lose exactly the
anchor a pending transfer is counting on.

**The shard encoding is byte-identical to the fork's**, deliberately: the
differential test at M6 needs both implementations to agree about what is in the
trees, not merely about the balances derived from them. It is monomorphised for
`MerkleHashOrchard` rather than generic over `HashSer`, because that trait would
have exactly one implementor here.

## M4 as built

The apply stage, the scan queue and rewinding are in place. A batch's data and
the queue entry recording it as scanned land in one transaction, so there is no
partially-applied state for cancellation or resumption to reason about.

**Descending recovery is incompatible with `ShardTree::append`.** This is the
finding that mattered most, and the plan did not anticipate it. `append` places
a leaf after the tree's current rightmost one and rejects any checkpoint that is
not above every existing checkpoint. Under descending recovery an earlier range
is applied *after* a later one, so almost no batch continues from the tip and
`append` fails with `CheckpointOutOfOrder`. Insertion must instead be
position-addressed, through `ShardTree::batch_insert` at an explicit start
position. `DetectedBatch` therefore gained a `start_anchor`: the batch's results
are not enough on their own, storage also needs to know where in the trees they
belong. Blocks that add no commitments to a pool get their checkpoint written
directly against the current tree state, since there is no leaf to carry it.

**Nullifier linking has to run in both directions.** Linking a spend to a note
when the *spend* arrives is the obvious half, and it is the only half the plan
described. The other half — a note arriving for a spend recorded earlier — is
the one descending recovery actually exercises, because the send is scanned
before the note that funded it. Both now run inside the applying transaction,
which also repairs a caller whose nullifier snapshot went stale mid-batch.

**`nullifier_map` stores the transaction id inline.** The fork keeps a
`(height, tx_index) → txid` locator table so the map can store eight bytes
instead of thirty-two. Here the map is bounded by the scan window, and one fewer
table and one fewer join is worth more than the bytes.

**A shard's end height advances only on blocks that added commitments to it.**
Advancing it on every scanned block makes a note look buried while its shard is
still open, which would mark notes spendable whose witnesses a reorg could still
invalidate. This was caught by a test, not by review.

**Table count, corrected:** the derived database has **17** tables and the
durable one **5**, not the 15 the section above estimated — `enhance_candidates`
needs a companion table for its funding accounts, and the original count was one
short. Twenty-two against the fork's forty-nine, with no views against its
fifteen.

## M5 as built

The engine syncs to tip, converges after reorgs at depth 5 and 50, and resumes
after cancellation into a database identical to an uninterrupted run. It is
about 380 lines.

**One step at a time, not one loop.** The engine's unit of work is
[`SyncEngine::step`], which advances by exactly one batch and returns what it
did — scanned, rewound, idle, or cancelled. `run` is a loop over it. Exposing
the step is what makes the failure modes testable at the granularity they occur
at, and it is also the state machine the plan asked for, expressed as a return
value rather than a hidden field.

**A rewind must requeue what it discarded.** Truncating deleted the blocks and
the queue entries above the rewind point, which left a hole: nothing above it
would be scanned again until the tip moved far enough for `update_chain_tip` to
notice, and in the meantime the wallet was quietly missing blocks. The discarded
range now comes back as `Verify`, forced past the `Scanned` marking it used to
carry. This was found by a coverage gap, not by review.

**A reorg is only discovered when new blocks arrive.** A competing chain of the
same length delivers nothing above the wallet's scanned tip, so no continuity
check runs and the wallet correctly notices nothing. That is not a gap — a
same-length fork has not won — but it does mean the reorg tests have to model a
chain that wins by being longer, which is what a real reorg does.

**Rewind exhaustion is only reachable on a long chain.** The doubling rewind
gives up past the checkpoint window, but it also clamps at the birthday, so on a
wallet with less than `PRUNING_DEPTH` of scanned history the engine runs out of
queued work before it runs out of rewind. Both outcomes are correct; the give-up
path is the one that needs a chain long enough to reach it.

**Flow control lives in the source, not the engine.** `fetch(range, budget)`
returns blocks from the start of the range and stops when the budget is spent,
because that is where a real implementation can actually stop reading a server
stream. One block larger than the entire budget is still returned, or a wallet
would stall permanently on a single busy block.

**Progress is commitment coverage.** Blocks are a poor proxy: the empty
stretches of the chain scan orders of magnitude faster than the busy ones, so a
block-count bar moves in lurches and lies about the time remaining. A watch
channel with no receivers is not an error — progress is advisory, and the engine
must not stop because nobody is listening.

## Engineering trade-offs

Everything below was decided while building M1 to M5. Each entry says what the
decision bought, what it cost, what would justify revisiting it, and how
expensive reversing it would be. The reversal cost is the number that matters:
a cheap decision can be made now and revisited on evidence, an expensive one has
to be right the first time.

Nothing here is a defect. The known gaps — work deliberately deferred rather
than traded away — are listed separately at the end.

### Expensive to reverse

These shape the type system or the stored format. Reversing one means touching
every layer, or migrating deployed wallets.

**Sapling is out of scope.** *Bought:* the pool abstraction. Orchard and
Ironwood share `Note`, `Nullifier`, `MerkleHashOrchard` and `CompactAction`, so
those stay concrete and the trait carries one associated type. *Cost:* the
wallet cannot see Sapling funds at all. *Revisit if:* users must sweep legacy
Sapling balances in-app rather than through a separate tool. *Reversal:* all four
shared types become associated, and `find_received`'s eight-closure signature in
the fork is what that costs. Effectively a rewrite of the scanner's generics.

**Positions come from the batch's `start_anchor`, so the source must serve tree
state at arbitrary heights.** *Bought:* descending recovery, and the deletion of
`TreeSizeUnknown`/`TreeSizeInvalid` — the starting tree size is never in doubt.
*Cost:* a server that has pruned, or that only serves tree state at the tip,
cannot serve this wallet. *Revisit if:* the wallet must work against a
lightwalletd we do not run. *Reversal:* reintroduce the fork's reconstruct-or-
reject logic, and give up descending recovery, which is load-bearing for the
Ironwood-first experience.

**The shard encoding is byte-identical to the fork's.** *Bought:* the
differential test can compare tree contents, not just balances. *Cost:* the
format is now a compatibility surface. *Revisit if:* the differential test is
retired and a denser encoding measurably helps. *Reversal:* a `tree_version`
bump and a subtree-root refetch, which is a real network cost.

**Enhance candidates are recorded eagerly, for every wallet-funded Ironwood
action.** *Bought:* private enhancement can be switched on later without a
rescan. *Cost:* storage and write amplification for every user, including those
who never enable it — roughly 150 bytes per non-received action of a funded
transaction. *Revisit if:* measurement shows this dominates write volume on a
busy wallet. *Reversal:* dropping the table is trivial; getting the data back is
a full rescan, which is the whole reason it is written eagerly.

**Two database files.** *Bought:* "the cache is derived" is structurally true —
rescan is a file deletion, and nobody can quietly add a migration to preserve a
derived table. *Cost:* SQLite cannot enforce a foreign key across attached
databases, so `cache.received_notes.account_id` references `main.accounts.id` by
convention only. *Revisit if:* that unenforced reference is implicated in a real
corruption. *Reversal:* merging the files reintroduces exactly the pressure the
split exists to resist.

### Moderate to reverse

Contained to one crate, but with real work behind them.

**No storage trait.** *Bought:* about 6,000 lines of trait surface not written,
and no `DbT: WalletWrite` bound anywhere. *Cost:* a second backend cannot be
written without extracting the trait first. *Revisit if:* a second backend is
actually wanted — an in-memory store for tests does not count, because the
SQLite one already runs in memory. *Reversal:* extract the trait from the
concrete type, which is easier than designing it speculatively.

**Detection is all-or-nothing per batch.** *Bought:* a batch's results are
either wholly trustworthy or absent; no partial state to reason about. *Cost:*
one malformed block discards up to a batch's worth of completed decryption
work. *Revisit if:* a real source is unreliable enough that batches are commonly
partially bad. *Reversal:* moderate — the assembly pass would need per-block
commit points, and the atomicity argument would have to be restated.

**Zero SQL views; aggregation in Rust.** *Bought:* `v_transactions` is 225 lines
of SQL in the fork; queries that can be tested and profiled are worth more.
*Cost:* the transaction-history and balance queries a UI needs have not been
written yet, and writing them in Rust is more code than a view would be.
*Revisit if:* the Rust versions turn out slower than SQLite's query planner on
real data. *Reversal:* cheap to add a view; the cost is having two places where
the same aggregation lives.

**Nullifier matching is a hash lookup, not constant-time.** *Bought:* O(1)
instead of O(notes) per spend, which is what makes descending recovery
affordable on a large wallet. *Cost:* a hit and a miss take measurably different
time, so an attacker who can observe this process's timing could learn whether a
block touched the wallet's nullifiers. Both inputs are local — the block is
public and the nullifiers are the wallet's own — so this matters only against a
co-resident attacker, and the fork's own comment questions whether its
constant-time version earns its cost. *Revisit if:* co-resident attackers enter
the threat model, which for a mobile wallet they plausibly do. *Reversal:* cheap
and local — `find_spends` in `detect.rs` is the only site.

### Cheap to reverse

Local decisions, kept here so they are decisions rather than accidents.

| Decision | Bought | Cost | Revisit if |
| --- | --- | --- | --- |
| `ScanPriority::LatestPoolActivation` removed | One fewer level; the priority existed only to work around ascending recovery | Ascending recovery would need it back | Recovery direction changes |
| `nullifier_map` stores the txid inline | One fewer table, one fewer join | 24 bytes per row over the fork's locator scheme | The map stops being bounded by the scan window |
| Rewind depth 10, doubling, capped at `PRUNING_DEPTH` | The caller cannot get it wrong | Untuned against real reorg depths | Measurement on mainnet suggests otherwise |
| `DECRYPT_CHUNK = 512` | Amortised batch decryption with usable parallelism | Untuned; the right value is hardware-dependent | Profiling on target devices |
| `TreeError` concrete, not generic | No two-`From`-bound signature at every call site | A caller with its own error type converts at the boundary | Never, realistically |
| `batch_decrypt` on `ShieldedPool` | `ShieldedOutput` bounds stay out of generic code | `core` depends on `zcash_note_encryption` | Never, realistically |
| Progress recomputed by querying on each publish | No cached counters to keep correct | Several queries per batch | Batches get small enough that this shows up |
| Epoch is the scanned-block count | A cheap staleness signal that changes exactly when the note set can | Coarse; unrelated writes do not bump it | Apply-time re-linking stops being sufficient |

### The largest open trade-off: the engine is sequential

> **Updated after M6.** The measurement below was taken before mainnet numbers
> existed. It turned out that storage, not decryption, dominated — 63% against
> 7% — and fixing that gave 1.9×. After the fix, fetch dominates at 48% and
> pipelining is worth roughly 4s of an 8.3s recovery. So the reasoning here was
> right about the shape and wrong about which phase mattered; measure before
> building the pipeline, not after.

This design describes fetch, detect and apply as concurrent stages joined by
bounded channels, so that block *n+k* is being downloaded while block *n* is
being decrypted. **What is built is a sequential loop**: fetch a batch, then
detect it, then apply it, then fetch the next. Rayon parallelises trial
decryption *within* a batch, but there is no overlap between network and CPU,
and no dedicated writer thread.

*Bought:* the engine is 380 lines instead of perhaps 900, the atomicity argument
is trivially true, and every failure mode is testable through a single
`step()` call.

*Cost:* on a real network the wallet is idle for the whole of each fetch, and
the server is idle for the whole of each decrypt. The upper bound on the loss is
roughly the smaller of the two phases, so it could plausibly be a third to half
of recovery wall-clock.

*This is the specific thing M6 should measure.* If sequential sync already beats
the fork on wall-clock, pipelining is an optimisation to schedule rather than a
correction. If it does not, the pipeline is the reason and should be built
before anything else. The seam is already in the right place — `step()` isolates
fetch, detect and apply — so adding channels between them does not disturb the
storage or detection layers.

*Reversal:* moderate, and it is additive rather than a rewrite.

### Known gaps, not trade-offs

Work deferred by the build order, listed so it is not mistaken for a decision.

The gaps listed here have since been closed; see "Closing the gaps" below.
What remains is one performance item and one correction:

- **The engine is sequential**, and pipelining is worth roughly half of recovery
  wall-clock. Measured, understood, and additive to build. See the trade-off
  above.
- **Descending recovery makes the apply stage more expensive.** Inserting a
  batch below existing tree data costs more than appending above it: apply was
  29% of a forward sync and is 43% of a backward one. That is the price of
  showing a restoring user their newest funds first, and it is worth paying,
  but it means the pipelining work should be measured against a descending
  recovery rather than the earlier forward numbers.

Two entries that were listed here were wrong rather than deferred, and are
corrected below:

- `link_stored_nullifiers` was described as an unindexed join. It was in fact
  fully indexed on both sides — `EXPLAIN QUERY PLAN` shows covering-index
  lookups — so the cost was linear in the nullifier map rather than quadratic.
  It has since been rewritten to be driven by the batch's own notes, which makes
  it linear in the *batch* instead, because during a long recovery the map grows
  over the whole scanned span.
- `commitment_coverage` reported the span between the lowest and highest tree
  size seen, which counts every commitment in the gaps the wallet has not
  reached. It now sums the actions in the blocks actually scanned.

## M6 as built

`zakura-wallet-lwd` is a tonic client over the existing protocol definitions,
implementing `ChainSource`. It is the only crate that knows the wire format
exists, and the only one with a build-time tool dependency (`protoc`).

### Ironwood is live on mainnet, and the public server serves it

Measured against `us.zec.stardust.rest:443` on 2026-09-05:

| | |
| --- | --- |
| Chain tip | 3,473,212 |
| NU6.3 activation | 3,428,143 |
| Consensus branch | `37a5165b` = `BranchId::Nu6_3` |
| Ironwood commitments | 233,175 |
| Orchard commitments | 50,446,897 |

In a recent 200-block window: **2,479 Ironwood actions against 474 Orchard
actions.** Ironwood is not a future pool to design for, it is where most of the
current shielded activity is, and the wallet's whole scanning cost is
proportional to it.

The live tests check the property that would otherwise fail silently: a server
that omits Ironwood actions *and* reports a zero Ironwood tree size is
self-consistent, so the scanner's tree-size check passes and the wallet simply
never sees any Ironwood funds. The test asserts the tree grew by exactly the
number of actions served.

### The tree state is a legacy `CommitmentTree`, not a frontier

`TreeState.orchardTree` and `.ironwoodTree` carry the *legacy* commitment-tree
encoding — optional left, optional right, then a vector of optional parents —
not the v1 frontier format. The leaf count is
`left + right + Σ 2^(i+1) for each present parent at level i`. Decoding it as a
frontier produced sizes off by billions, which the wallet caught immediately
because every note position would have been wrong. Only the count is decoded;
the nodes would drag a hash type and a tree implementation into the transport
layer for nothing.

### The bottleneck was storage, not decryption

Where the time went, before any tuning, over 2,000 mainnet blocks:

| Phase | Time | Share |
| --- | --- | --- |
| Fetch | 1.70s | 30% |
| Detect | 0.39s | **7%** |
| Apply | 3.59s | **63%** |

That inverts the assumption the design was built on. Trial decryption — the
thing the rayon batch runner, the chunk-size constant and most of the scanning
literature are about — was seven per cent of the cost. Writing to SQLite was
nearly two thirds.

The cause was in `put_commitments`: it inserted each block's commitments
separately, and every `ShardTree` insertion does a `get_shard`/`put_shard`
cycle that deserialises and re-serialises the entire shard — up to 2^16 leaves.
The cost therefore grew with *blocks × shard size* rather than with the number
of commitments. Batching the whole batch into one insertion, with the per-block
checkpoints riding along inside the retentions, gave a **1.9× end-to-end
speedup**: 333 → 638 blocks/s, with apply falling from 63% to 29%.

This is what the milestone existed to find, and it would not have shown up in
any test: every correctness test passed before and after.

### Against the fork

Both stacks scanning byte-identical blocks, downloaded once and handed to each
in turn, so the network is excluded and what is measured is detection plus
storage — the part this rewrite replaces.

| Blocks | Workload | Fork | New core | Ratio |
| --- | --- | --- | --- | --- |
| 5,000 | 8,083 Orchard + 101,871 Ironwood actions | 3.27s (1,528 blk/s) | 2.91s (1,720 blk/s) | 1.13× |
| 10,000 | 14,055 Orchard + 118,888 Ironwood actions | 5.55s (1,801 blk/s) | 3.47s (2,883 blk/s) | **1.60×** |

The margin widens with range size, which is consistent with the per-block shard
write pattern the fork still has.

**Two caveats, stated plainly.** First, the fork is doing strictly more work: its
seed-derived account carries a Sapling key, so it trial-decrypts Sapling outputs
that this wallet does not have. Part of the margin is scope rather than
architecture, and a like-for-like figure would be smaller. Second, the peak-RSS
figures the harness prints are process-wide cumulative highwater marks measured
after each phase in one process, so they are indicative at best; a real memory
comparison needs separate processes.

### The verdict on the gate

The rewrite is faster, but not dramatically so, and some of the margin is
Sapling. The honest summary is that **it is not slower**, which is what the gate
was really asking — the case for it rests on 17,000 lines against 121,000, and
that case is not undermined by the performance numbers.

The clearer result is that the milestone found a 1.9× storage regression that no
correctness test could have caught, which is an argument for having built the
measurement at all.

### End-to-end, over the network

10,000 mainnet blocks, 16 MiB budget, after the fix:

```
blocks scanned      10001        elapsed    8.67s
throughput          1153 blocks/s
downloaded          21.4 MiB (2241 bytes/block)
peak RSS            176.8 MiB
fetch  4.03s (48%)   detect 0.77s (9%)   apply 3.54s (42%)
```

Fetch now dominates, so **pipelining is the next optimisation**, with about 4s of
the 8.3s accounted time recoverable. Peak RSS of 177 MiB against a 16 MiB block
budget is worth noting: the budget bounds block data in flight, not process
memory — the detected batch, the shard trees and SQLite's page cache are all
outside it.

### A gap this milestone exposed

**Recovery is not actually descending yet.** The scan queue orders ranges by
priority and then by descending end height, so the *latest range* is chosen
first — but within a range the engine fetches from `range.start` forwards. With
a single `Historic` range covering everything from the birthday, recovery
therefore runs ascending, which is the opposite of what this design argues for.
Making it genuinely descending means chunking from a range's end backwards, and
the position-addressed insertion built in M4 is what makes that possible. It
does not affect the throughput measured here, but it does affect how soon a
recovering user sees their newest funds.

## Differential correctness against the fork

M6 established that the rewrite is not slower. It did not establish that it
reaches the *same conclusions*, because both sides scanned with keys that owned
nothing. `zakura/wallet-lwd/tests/differential.rs` closes that: both stacks are
given the same Orchard viewing key and byte-identical blocks, and their results
are compared field by field.

The blocks are synthetic, because they have to be — no key we can generate owns
anything on mainnet, and a comparison of two empty sets says nothing. They carry
real notes encrypted with the real note-encryption domains, so the cryptography
under test is the one that runs against the chain. Four tests: a hand-written
chain covering both pools, both scopes, other people's notes, padding and empty
blocks; a wallet-funded spend producing change; a wallet that owns nothing; and
a property test over arbitrary chain layouts.

**Note identity matched exactly** — pool, value, commitment tree position,
nullifier and key scope — on every note, in every case. That is the result
worth having: a mis-derived nullifier or a position off by one would make every
witness built from it invalid, and would surface only when a spend proof was
rejected.

### The one divergence, and why it is deliberate

The two disagree about `is_change`, and only about that.

The fork marks a note as change when *the receiving account also spent notes in
the same transaction*. Scope is tracked separately, in `recipient_key_scope`.

This wallet adds a second rule: **a note received on the account's internal
address is change regardless**, because that address is never handed out.

The addition is not cosmetic, and it is a consequence of recovering descending.
A change note is scanned *before* the note that funded it, so at scan time the
spend cannot be linked and the fork's rule alone reports genuine change as an
incoming payment. The scope-based rule does not depend on scan order. The
apply-stage linking added in M4 repairs the spend association afterwards, but by
then the note has already been presented to the user, and a payment that later
turns into change is a worse experience than one that was never mislabelled.

The test asserts this precisely rather than tolerating it: for every note,
`new.is_change == fork.is_change || scope == internal`. Any *other* difference
fails. That turns a known divergence into a checked invariant instead of noise
that would mask a real regression later.

## M8 as built

`zakura-wallet-tx` selects notes, computes ZIP 317 fees, pulls witnesses from
the trees, and builds, proves and **verifies** a bundle for each pool. It is
kept apart from the rest of the core because it is the only part that needs the
proving stack, so a watch-only build and the scanner's own tests never pay for
halo2.

**The proof verifies.** `an_ironwood_payment_proves_and_verifies` takes a note
the scanner found, builds a real bundle spending it, proves it and checks the
proof. A witness taken at the wrong position, or against a tree that has drifted
from the chain's, produces a proof that does not verify — so this is the end-to-end
check that detection, storage and witness generation are right together, and it
is the thing this milestone existed to establish. A companion test swaps two
notes' authentication paths and asserts the result cannot both build and verify,
so the check is not passing vacuously.

### Consensus enforces the pool crossing; it is not a policy we chose

The design treats ZIP 318 canonical crossing as a non-negotiable privacy
property that a careless implementation could skip. Building the spend path
showed something stronger: **from NU6.3 the Orchard pool prohibits
cross-address transfers outright**, and the bundle builder refuses
`add_output` in an Orchard bundle whether or not the recipient is ours. Value
leaves the Orchard pool only through a bundle's value balance, into an Ironwood
bundle that makes the payment.

So an Orchard payment to a third party is *necessarily* a pool crossing. There
is no Orchard payment path to take by accident. That is a better guarantee than
the one the plan described, and it means the remaining risk is in getting the
crossing's *shape* canonical — action counts, expiry, anchor grid, fee — rather
than in remembering to cross at all.

Two consequences for the builder:

- Orchard bundles use `Flags::CROSS_ADDRESS_DISABLED`; Ironwood uses
  `Flags::ENABLED`. Asking for the wrong one is not a subtle bug: the builder
  rejects the flags as unrepresentable for the bundle version.
- In a bundle with cross-address disabled, *every* retained output goes through
  `add_change_output`, which pairs it with a fabricated zero-valued spend at the
  same address. `add_output` refuses there unconditionally.

`Error::CrossingRequired` names this at the wallet's own boundary rather than
letting `CrossAddressDisabled` surface from three layers down.

### Transaction assembly

The order is forced by the protocol and is not the obvious one. Spend
authorisation signatures commit to the transaction's signature hash, and that
hash is computed *from the transaction* — so the transaction has to be assembled
before it can be signed. What makes it possible is that a v6 signature hash does
not commit to the bundle proofs, so the sequence is: build each bundle unproven,
assemble them into a transaction, take its signature hash, prove and sign
against that hash, reassemble. A wallet that signed first would produce
signatures over nothing, and the failure would appear as a rejected transaction
rather than as a mistake.

`transaction::assemble` does this, and the builders stop at an unproven bundle
so that they can. Ironwood exists only in v6 transactions and both pools' bundles
ride in the same one, so the version is not a choice.

Tested: the assembled transaction is v6 and its proofs still verify; the value
balance across both bundles equals the fee; the transaction serialises, parses
back with the same txid, re-serialises to identical bytes, and still verifies;
and two transactions differing only in expiry carry different binding
signatures, which is what shows the authorisation is not independent of the
transaction it authorises.

### What is not built yet

- **Broadcast.** `SendTransaction` is not wired into the light client, so a
  signed transaction cannot be sent.
- **Ironwood-funded payments work end to end otherwise**, because they need no
  crossing.

### Selection

Largest notes first, which keeps the input count — and so the fee, and the
number of proofs — down, at the cost of fragmenting the wallet's largest notes
first. A wallet that cared about note-size distribution would choose
differently; this one optimises for what the user waits on.

The fee and the input count are settled together, because each depends on the
other: adding a note changes the action count, which changes the fee, which
changes what has to be covered. A change output worth nothing is dropped rather
than created, since it would cost an action and hand the wallet a zero-value
note to trip over later.

Notes are withheld unless their witnesses are stable. A note whose containing
shard is not fully scanned and buried has no witness a reorg cannot invalidate,
and a proof against an anchor the chain abandons is worthless. Relaxing that is
possible and is for tests.

## M9 as built: the pool crossing

`crossing::plan` and `crossing::build` construct the two bundles a crossing is
made of, and `crossing::conforms` reads the result with
`zcash_protocol::zip318::classify` — **the same function the network uses**. A
wallet that decided for itself what conformance meant would drift from the
definition, and the drift would be invisible until somebody's transaction stood
out.

`a_crossing_builds_proves_and_verifies` plans a crossing, checks it conforms,
builds both bundles, proves them and verifies both proofs.

### The shape, and why each part of it is load-bearing

| Requirement | What getting it wrong reveals |
| --- | --- |
| Exactly 2 Orchard actions | The number of notes the wallet had to spend |
| Exactly 1 Ironwood action, unpadded | That this crossing differs from the rest |
| A canonical one-two-five denomination | The actual amount, which no other crossing carries |
| The canonical expiry window | Roughly when the wallet was online |
| An anchor on the shared 144-block grid | Which wallet built it |
| The canonical fee, fixed by shape not contents | The wallet's note composition |
| No transparent or Sapling bundle alongside | That this is a payment, not a migration |

The wallet refuses rather than adjusts. A crossing that is nearly the right
shape is worse than none, because it stands out from the ones that are —
so a non-canonical denomination, or an anchor off the grid, is an error and not
a rounding.

### A crossing spends exactly one note

Two source actions means one spend and one change output, so a crossing is
funded by a *single* note that covers the denomination and the fee on its own.
Three notes that together cover it cannot fund one; such a wallet has to
consolidate first, which is what ZIP 318 preparation transactions exist for and
which this wallet does not yet build.

Selection here is the *opposite* of ordinary selection: it takes the
**smallest** sufficient note, leaving the larger ones intact for the crossings
that will need them. Ordinary selection takes the largest, to keep the input
count down.

### The two bundles are joined by their value balances

The Orchard bundle gives up the denomination plus the fee; the Ironwood bundle
takes the denomination; the difference is what the transaction pays. For one ZEC
that is `+100,015,000` and `-100,000,000`, summing to the 15,000 fee. The
builder checks this against the plan after proving rather than trusting it,
because a mistake here produces a transaction the network rejects once the
expensive part is already paid for.

Padding to two source actions also hides whether the funding note was consumed
exactly: with no change the bundle carries one real spend and a padding dummy,
and looks identical to one that kept change.

### The conformance check is not vacuous

`the_classifier_refuses_shapes_that_are_not_crossings` takes the canonical
evidence and makes one deviation at a time — a third source action, a second
destination action, another bundle alongside, an ordinary expiry, an anchor off
the grid, a non-canonical fee, a value off the denomination series — and asserts
each is refused. Without it, `conforms` returning true would mean nothing.

It also pins that missing evidence yields `Unknown` rather than a refusal.
`Unknown` is "no label yet", not "not a migration"; rendering it as the latter
would make transaction rows relabel themselves as evidence arrives.

## Closing the gaps

The things the plan assumed and the build order skipped past.

### Accounts and keys

`accounts` was a table that existed and was never written. An account is now
derived from a ZIP 32 seed through `zcash_keys` — the wallet does not
reimplement unified key or address encoding, because those are
consensus-adjacent formats where a subtle difference is an address nobody can
pay. The seed is used and dropped: only the viewing key is stored, so the
ability to spend does not sit in the same place as the ability to see.

The incoming viewing key is the account's identity, and adding the same one
twice is refused: two accounts sharing one would see the same notes, and every
balance would double. The wallet birthday is now the earliest of its accounts'
rather than a single value in `wallet_meta`, since scanning below it can produce
nothing for any of them.

Addresses are issued in diversifier order and recorded as they go, so the wallet
knows which of its addresses have been exposed. Two calls return two different
addresses: reusing one lets anybody who has seen it link the payments made to
it. Not every diversifier index yields a valid address, so issuance searches
forward rather than failing at the first gap.

### Balance and history

The design deletes all fifteen of the fork's SQL views on the grounds that an
aggregation which can be tested and profiled beats one embedded in 225 lines of
view. This is that aggregation.

A balance is three figures, not one, and they are the same funds at different
stages of becoming usable:

- **spendable** — received, unspent, and with a witness a reorg can no longer
  invalidate;
- **pending** — received and unspent, but not yet buried. Real money that cannot
  yet be sent. A wallet that showed this as spendable would offer funds and then
  refuse to send them;
- **spent, unconfirmed** — committed by a transaction that is not yet mined:
  gone from the user's point of view and not yet from the chain's.

History reports what each transaction did to the wallet, with unmined
transactions above mined ones because those are what somebody is waiting on. A
transaction whose every received note is change is the wallet paying *out*, and
is flagged as such rather than presented as an incoming payment.

### Broadcast

`send` relays a signed transaction. The response carries its own error code
distinct from the RPC status, and a transport that succeeded can still carry a
rejection — reporting that as success would tell somebody their payment was sent
when it was not. Acceptance means the transaction reached the network, not that
it will be mined.

### Transparent attribution and the gap limit

`transparent_received_outputs.account_id` was hardcoded to `0`. The watch set
now carries which account each script belongs to and which of that account's
addresses it is, so a multi-account wallet no longer attributes every
transparent receipt to the same place.

The gap limit is the width of the window of unused addresses the wallet watches
ahead of the used ones. The defaults are **10 external, 5 internal** — below
BIP 44's twenty, deliberately: a light server sees every address a wallet asks
about together and can cluster them into one wallet on that basis, so every
extra address in the window is another address in that cluster. Internal is
narrower still, because nobody else can pay an address they were never given.

What consumes the window is an address being *paid*, not one being generated:
generating costs nothing and reveals nothing.

### Descending recovery, and the subtree roots it needs

The design argues throughout for recovering from the tip downwards, and the
engine was not doing it: the queue preferred the latest *range* but consumed it
forwards, so a single `Historic` range covering everything from the birthday was
scanned oldest-first — the opposite of the claim.

`ChainSource::fetch` now takes a direction, and the light server does the work:
`GetBlockRange` streams downwards when its start is above its end, so descending
recovery is a server feature rather than something the wallet simulates by
guessing how many blocks will fit in a budget. Whichever end a batch comes from,
the blocks arrive in chain order, because everything above expects that. The
anchor can no longer be resolved before fetching — it belongs to whichever block
turned out to be lowest — so it is resolved after.

Which direction a range is fetched in depends on what the range is *for*:
recovery works backwards, tip-following forwards, because at the tip the next
block is the one that matters and there is nothing below it left to find.

That alone would not have helped. A note found near the tip cannot be witnessed
until the roots of every other shard are known, so without subtree roots a
restoring wallet would show its newest balance and be unable to spend any of it.
`put_subtree_roots` records server-supplied roots: `ShardTree::insert` at a
shard's own root address puts the hash in the *cap*, which is what makes the
shards either side reachable without their contents — no level-shifting by hand,
unlike the fork. The cap insertion writes no shard row, so the row is written
separately, as a single ephemeral leaf holding the root hash. Roots are taken
only in a contiguous run from the first index the wallet lacks: a shard the tree
cannot be walked across is worse than a missing one, because it makes every
witness beyond it unbuildable and nothing would say so.

### Consolidation, so that a small wallet can cross

A crossing spends exactly one note, so a wallet whose Orchard notes are all too
small could not cross at all. ZIP 318 gives that consolidation its own canonical
shape — an Orchard-only send-to-self padded to exactly sixteen actions — for the
same reason crossings have one: a preparation transaction that looked like an
ordinary consolidation would mark its wallet as one that is about to cross.

`plan_preparation` selects largest-first up to the action limit, and the planned
output covers the crossing *and* both fees, so the note it produces can actually
do the job it was made for. A wallet that could not afford the crossing even
after consolidating everything is told that, because it is a different problem
and no transaction solves it.

## Verification

Unit tests run `detect_batch` against fixtures covering receives, spends, change,
reorgs, continuity errors, cross-pool transactions, Ironwood before activation,
and the dropped-action position shift.

A differential test syncs testnet from a birthday to tip and compares balance,
note set and per-pool tree sizes against the existing fork's `WalletDb` over the
same range. This is the strongest oracle available and belongs in the repository.

Reorg tests drive the in-memory chain through reorgs at depths 1, 10, 99 and 101
and assert the resulting state matches a from-scratch scan of the final chain.

Spend tests run on regtest and testnet: Orchard to Ironwood, asserting the
canonical ZIP 318 shape; Ironwood to transparent; and transparent to Orchard
shielding. Each must mine.

Performance is measured as wall-clock time and peak RSS over a fixed 100,000-block
range, new core against the fork, reporting blocks per second, bytes downloaded
and peak memory.

Schema tests assert that `cache.db` contains exactly its table list, that a
`layout_version` bump rebuilds it from `raw_transactions` with no network access,
and that such a bump never touches `wallet.db`.

## Reference points in the existing tree

To port or study, not to depend on.

| Path | Use |
| --- | --- |
| `zcash_client_backend/src/data_api/scanning.rs`, `scanning/spanning_tree.rs` | Port, with their tests |
| `zcash_client_backend/src/scan.rs` | `Batch` and `OutputReplier`; roughly 500 lines of it exist for a non-rayon wasm fallback, skippable if wasm is not a target |
| `zcash_client_backend/src/scanning/compact.rs` | `PositionTracker`, `find_spent`, `find_received`, the enhance-candidate shape |
| `zcash_client_sqlite/src/wallet/scanning.rs` | `update_chain_tip`, `scan_complete`, `extend_range` |
| `zcash_client_sqlite/src/wallet/commitment_tree.rs` | `SqliteShardStore` |
| `zcash_client_backend/src/data_api/ll/wallet.rs` | `put_blocks`, `build_subtrees`, `ensure_checkpoints` |
| `zcash_client_backend/src/data_api/anchor_retention.rs` | The retention grid |
| `zcash_client_backend/src/data_api/wallet.rs:800-1030` | Canonical crossing |
| `zcash_client_sqlite/src/wallet/transparent.rs` | `find_gap_start`, `utxo_query_height` |
| `zcash_client_sqlite/src/wallet/common.rs` | `TableConstants`, the pattern this design replaces |
| `docs/zakura_pir_enhance.md` | Correctness requirements for the PIR seam |
