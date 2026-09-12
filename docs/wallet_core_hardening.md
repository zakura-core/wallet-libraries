# Hardening and pipelining the Zakura wallet core

A follow-on to `wallet_core_rewrite.md`. That document proposed the core and
recorded what was built through M9. This one records what a review of the built
code found, and what to do about it.

The review's conclusion on the architecture was that the central bet paid off.
`ShieldedPool` with a single associated type is the right abstraction, and
keeping `Note`, `Nullifier`, `MerkleHashOrchard` and `CompactAction` concrete is
what stops it leaking. The pure `detect_batch` seam is real — no storage crate
appears in the scanning crate's dependency graph. The `pool`-column schema
genuinely collapses the fork's parallel table families. Position-addressed
`batch_insert` in place of `append` was the correct finding at M4, and the
descending fetch that M6 listed as an open gap is now closed.

What the review found underneath is three classes of problem, and they are not
the same kind of thing. One is a trust boundary the descending design opened
and did not close. One is a set of mechanisms that were built correctly and
never connected to a policy, so they are dead code that reads as complete. The
last is the performance work the parent document already predicted, plus a
handful of per-batch costs that scale with wallet size rather than with batch
size.

## The trust boundary descending recovery opened

Under ascending recovery, a note's position is derived from the tree size at the
previous block, which the wallet recorded when it scanned that block, which was
derived from the block before it, and so on back to the birthday. The chain is
rooted in one server assertion — `GetTreeState` at the birthday — and every link
after that is the wallet's own arithmetic. `PositionTracker`'s end-of-block
check against `block.chain_metadata` is a cross-check on each link.

Descending recovery breaks that chain. A range that does not continue from
anything scanned has no local predecessor, so `resolve_anchor` falls through to
`source.anchor(below)` — a fresh `GetTreeState` — and under descending recovery
that is nearly every batch. `apply::put_batch` then uses the returned tree sizes
as the absolute position to insert the batch's commitments at, and nothing
checks them.

The cross-check that exists does not cover this. `PositionTracker::finish`
compares the batch's derived tree size against `block.chain_metadata`, but both
come from the same server in the same conversation. A source that reports a
wrong anchor and block metadata consistent with it is self-consistent, and the
wallet accepts it. Every commitment in the batch lands at the wrong absolute
position, every witness built from that region is invalid, and nothing notices
until a proof is rejected — which the parent document correctly identifies as
the worst failure shape available, because it can be months later.

The parent document does name the dependency, under "expensive to reverse":
positions come from the batch's `start_anchor`, so the source must serve tree
state at arbitrary heights. What it does not say is that this converts a
locally-verified chain into a per-batch trusted assertion, and that the defence
it lists as load-bearing — `check_end_of_compact_block_consistency` — cannot
detect consistent lying, only inconsistency.

### Pinning the anchor against local data

The fix is cheaper than it first looks, and it needs no new engine state at all.

`put_batch` validates the anchor against the wallet's own record wherever one
exists, at both ends of the batch:

- the block *at* `start_anchor.height`, if scanned, must be the block the anchor
  names and must have left the trees the size it claims; and
- the block *above* `end_anchor.height`, if scanned, must have started from the
  size the batch ends at — its recorded size less its own actions.

Those two cover both directions, from opposite sides. Ascending, the block below
a batch is what the wallet just scanned, so the first check fires. Descending,
the useful geometry is that batch N's start anchor sits at exactly the height
batch N+1's *last* block occupies: the batch descends into a region whose upper
neighbour is already stored, so the second check fires. Every batch after the
first in either direction is pinned against something the wallet recorded
itself.

An earlier draft of this document proposed carrying the previous batch's anchor
forward in the engine to achieve the same thing. That state is redundant — it
would re-derive what the stored block above already says — and it was removed
rather than kept as belt and braces, because a second source of the same truth
is a second thing that can disagree.

The per-batch `GetTreeState` under descending recovery therefore stays, and
should. It is what makes the check meaningful: the anchor is an *independent*
assertion, and deriving it from the batch's own first block instead would make
the scanner's end-of-block check tautological.

A mismatch is a hard error rather than a rewind. A rewind is the response to the
chain having moved; this is the response to the source contradicting the wallet,
and retrying it against the same source would only produce the same answer.

## Mechanisms without policies

Three pieces of the design are implemented, tested in isolation, and never
invoked. They are worse than absent, because the schema and the store make the
feature look present.

**Anchor retention.** `WalletShardStore::add_retained_checkpoint` is correct,
including the subtle case the parent document calls out — recording retention
for a height the tree has not reached yet, because the ZIP 318 grid is known in
advance and forgetting a boundary before the tree arrives at it would lose
exactly the anchor a pending transfer is counting on. Nothing calls it outside
tests. No code computes the 144-block grid. `retained_checkpoints()` therefore
always returns empty, and the ordinary `PRUNING_DEPTH` pruner discards grid
boundaries like any other checkpoint.

**Grid anchor selection.** `witness::anchors` returns `common_anchor_height`,
the most recent height both trees hold a checkpoint for. That is right for an
ordinary spend and wrong for a crossing, which must anchor on the shared grid.
Since the most recent common checkpoint is essentially never a grid boundary,
`crossing::plan` rejects with `NotCanonical` on any wallet that has actually
scanned a chain. M9 is green because its fixture arranges an anchor that
happens to sit on the grid.

**Conformance checking.** `crossing::evidence` builds its `Zip318Evidence` from
the plan and from constants: `source_actions` and `destination_actions` are the
canonical constants rather than measurements, `other_bundles_present` is a
literal `false`, and `source_is_send_to_self` a literal `true`. The remaining
fields — denomination, expiry, anchor-on-grid, fee — are precisely what `plan`
already rejected on. So `conforms` restates the plan's own preconditions and
cannot observe a defect in what was built. The parent document's claim that the
wallet classifies its own transaction with the same function the network will is
true of the call and not of the input.

The fix in each case is the policy, not the mechanism. Compute the grid from the
`PoolMigrationConstants` the crossing module already carries; retain boundaries
from the apply stage, inside the applying transaction, alongside the checkpoints
they protect. Add a grid-anchor selector beside `common_anchor_height` rather
than changing it, because ordinary spends should keep taking the most recent
anchor. Build a second evidence value from the assembled transaction, using the
action counts and bundle presence that `build::action_counts` already reports,
and check it after building. The plan-derived check stays: checking before the
expensive part is worth having. It is simply not the check that means something.

### A related gap in construction

The parent document argues, correctly, that consensus makes an Orchard payment
necessarily a crossing, and concludes that the remaining risk is in the
crossing's shape rather than in remembering to cross. The built code has a third
case neither covers.

`build::bundles` raises `CrossingRequired` only when the Orchard bundle is the
one making the payment. A proposal with Orchard inputs and an Ironwood
`output_pool` never enters that branch: the Orchard side is spend-only with a
positive value balance, the Ironwood side carries the output, and the result is
a pool crossing assembled ad hoc — with `select`'s action counts and fee rather
than the canonical ones. Nothing refuses it.

So the guard belongs one level earlier. `select` should refuse a proposal whose
inputs and output pool straddle the pools, and `build::bundles` should refuse the
same shape rather than relying on a branch that shape does not reach. The
canonical path through `crossing::plan` is then the only one available, which is
what the design intended.

## Costs that scale with the wallet rather than the batch

The parent document's M6 measurement is the right frame: fetch at 48% of an 8.3s
recovery, with `pipelining_headroom` already reporting the recoverable time. Two
things sit alongside it.

The first is that the engine's concurrency does not match the design. The
document specifies rayon entered through a single `spawn_blocking` and a
dedicated writer thread owning the connection, and describes the latter as a
correctness choice rather than a performance one. What is built calls
`detect_batch` and `put_batch` directly on the async task, so a tokio worker is
parked for the whole of both. The document's "the engine is sequential"
trade-off covers the missing pipeline, not the missing runtime boundary. A
consumer running a UI on the same runtime — which is the stated destination, a
Rust core with an FFI later — will feel this before it feels the pipeline.

Compounding it, `wallet-lwd` holds one mutex around the tonic client across
every RPC, including the whole of a block stream. `CompactTxStreamerClient` is
`Clone` and multiplexes over a single HTTP/2 connection, so the mutex is not
required for correctness; it is a deliberate statement that requests serialise.
That statement forecloses the pipeline, and it also means a tip poll blocks for
the duration of a batch download.

The second is a set of per-batch costs proportional to the wallet's note set
rather than to the batch:

| Cost | Shape |
| --- | --- |
| `unspent_nullifiers` | A `COUNT(*)` over every scanned block, then a full scan of `received_notes` with a `NOT IN` anti-join, then a Pallas canonicity check per note. Once per batch. |
| The detect overlay | Clones the whole snapshot so a note received mid-batch can be seen spent later in it. Once per batch. |
| `publish` | Two full scans of `blocks` through `commitment_coverage`, plus `block_height_extrema` and `suggest_scan_ranges`. Once per batch. |
| Uncached statements | `tx_ref`, `link_nullifier`'s lookup, `mark_stabilized_notes`, `get_shard` and `check_shard_continuity` build SQL with `format!` and re-prepare on every call — some once per note, some once per shard write. |

The `COUNT(*)` is the sharpest of these because it buys nothing. It computes
`snapshot_epoch`, which is threaded through `DetectedBatch` and never read: the
writer re-links unconditionally instead of comparing epochs, which is a
defensible simplification but leaves the epoch as a full table scan per batch in
service of a field with no consumer.

The remedy for the first two rows is the same one the detect overlay already
implements: the engine holds the snapshot and updates it from each applied
batch's own received notes and spends, rebuilding fully only after a rewind. The
information needed is exactly what the batch already carries.

One item the parent document lists as an open gap is already closed.
`link_stored_nullifiers` no longer joins the whole nullifier map against the
whole note set on every batch; it is now a point lookup on the map's primary key
driven by the batch's own notes, with the quadratic argument stated in a comment
at the call site.

## Two invariants that are subtly wrong

Both are about when a note becomes spendable, and both fail conservatively in
the common case and unsafely in an uncommon one.

**Stabilisation is measured against the batch, not the chain.**
`mark_stabilized_notes` is passed `batch.end_anchor.height`, so the burial
threshold is the end of whichever range happened to be scanned last. During
recovery that is usually far below the tip and merely conservative. But it makes
spend eligibility a function of scan order: a wallet that finishes recovery on a
historic range leaves notes near the tip unstabilized — shown in the balance,
refused by selection — until an unrelated high batch lands. The engine holds the
observed tip and should pass it.

**`subtree_end_height` does not mean what its consumers think.**
`update_shard_end_heights` sets it to the height of the block carrying the
batch's last commitment for that shard, monotonically. For a shard that is only
partly filled, that is a height far below where the shard actually closes. Both
consumers read it as completeness: `mark_stabilized_notes` gates spendability on
it, and `extend_range` and `tip_shard_end_height` gate scan-range widening on
it. The result is notes reported spendable whose shard still has unscanned
leaves — which the parent document identifies, under "what must not be
simplified away", as producing a note that is silently unspendable.

The value is only authoritative when it comes from `put_subtree_roots`, where
the server is describing a complete shard, or when a scanned block's commitment
lands at the shard's final position. Everything else should leave it unset.
`truncate_to` should also lower it, since today it can outlive the block it
names.

## The pipeline

The seam is in the right place already — `step()` isolates fetch, detect and
apply — so this is additive rather than a rewrite, which is what the parent
document predicted.

The order that matters is runtime boundaries first, channels second. Moving
detection behind `spawn_blocking` and the connection onto a writer thread is
worth doing on its own, because it is what stops the engine starving a shared
runtime, and it is a prerequisite for overlapping anything. Dropping the lwd
mutex is likewise a prerequisite: with it in place, two stages cannot both be
talking to the server and there is nothing to overlap.

`WalletDb` holds a single `Connection` and hands out `&Connection` for reads, so
moving it to a writer thread requires deciding where the engine's own reads go.
The scan queue, the anchors and the birthday are all read on the hot path. A
second connection opened read-only in WAL mode is the answer the schema already
anticipates — the comment justifying WAL refers to reader connections for the
UI, which do not yet exist. Note that `journal_mode` is currently set with
`pragma_update(None, ..)` after `cache` is attached, so it applies to `main`
only, and `cache` is where essentially all the write traffic goes.

The invariants to hold while doing it:

- A batch is applied in exactly one SQLite transaction with the queue marked
  inside it. This is what makes cancellation trivial, and it survives
  pipelining unchanged.
- Cancellation discards in-flight batches rather than applying them. The queue
  is the only record of what was scanned, so discarding is always safe.
- A continuity failure drains and discards everything in flight before
  rewinding, because in-flight batches above the rewind point are stale.
- The planner reserves ranges optimistically and subtracts in-flight ranges from
  what it picks next, since the queue only becomes authoritative on commit.

Anchor chaining is load-bearing here as well as for correctness. Without it the
fetch stage cannot run ahead, because each batch's anchor requires an RPC whose
answer depends on the batch before it.

## Corrections to the parent document

Three claims in `wallet_core_rewrite.md` no longer describe the code and should
be amended rather than left to contradict it.

**"No SQL is built with `format!` anywhere."** It is used throughout, for the
attached schema prefix. The value is a constant and there is no injection
surface, so the practice is fine; the claim is not.

**M9 is marked done.** The crossing builds, proves and verifies against a
fixture. On a wallet that has scanned a chain it cannot currently plan, because
no anchor on the grid is retained or selected. The milestone should read as
blocked on the retention policy rather than complete.

**The concurrency section describes a design that was not built.** Rayon behind
one `spawn_blocking` and a dedicated writer thread are specified as decided;
neither exists. The "engine is sequential" trade-off should be widened to say
so, since a reader today would take the runtime boundary as settled.

## Smaller findings

Recorded so they are decisions rather than oversights.

| Finding | Why it matters |
| --- | --- |
| `enhance_candidates` upserts only `transaction_id` and `action_index` on a position conflict | A reorged position can pair one action's txid with another action's nullifier, cmx and ciphertext — which is precisely the material that authenticates a PIR response. |
| An empty fetch returns `Step::Idle` | `run` ends with a success summary, so a transient source failure is indistinguishable from being fully synced, and the range stays unscanned. The comment claims it is marked scanned; it is not. |
| `rewind_depth` resets on any clean batch | Under descending recovery the queue interleaves the reorged tip range with historic ranges, so a successful historic batch resets escalation before the tip range is retried. The doubling never escalates. |
| `min_shard_tip` drops a pool with no shard end heights | Rather than treating it as unknown. This is the Ironwood-follows-Orchard failure the parent document names, reachable through a missing value instead of a wrong `max()`. |
| `tx_requests` has no foreign key to `transactions` | Rewound transactions leave enhancement requests queued against an abandoned chain. |
| Memos are `[0u8; 512]` | Per ZIP 302 a leading `0x00` is an empty text memo, not an absent one, which is `0xF6`. Recipient-visible. |
| `select` discards its `change_scope` parameter | A public signature advertising configurability that does not exist. |
| `select` does not constrain inputs to one account | Nothing at that boundary prevents linking two of the wallet's accounts on chain. |

## Order of work

Phases one to three are independent of each other; all three land before the
pipeline, so that it is built on state whose invariants are checked rather than
assumed.

| Phase | Contents |
| --- | --- |
| 1 ✅ | Anchor validation, stabilisation against the tip, `subtree_end_height` semantics, the crossing guard in selection and building, and the smaller findings above. |
| 2 ✅ | Grid retention, grid anchor selection, and evidence derived from the assembled transaction. |
| 3 ✅ | Statement caching, indices and pragmas; the unread `snapshot_epoch` and its `COUNT(*)` deleted. The incremental nullifier snapshot is deliberately not built — see below. |
| 4 ✅ | The lwd mutex removed, detection and storage moved off the runtime, and the next batch's fetch overlapped with the current batch's work. A dedicated writer thread was not built — see below. |

Phase three begins with measurement rather than with the list. The M6 lesson was
that the assumed bottleneck was wrong by an order of magnitude, and that the
milestone's value was in having built the measurement at all.

Performance is tracked with the harness that produced the M6 numbers, so the
figures stay comparable:

```
ZAKURA_LWD=https://us.zec.stardust.rest:443 \
  cargo run --release -p zakura-wallet-lwd --example sync_bench -- --blocks 10000 --budget 16
```

A baseline is recorded before phase one, and the fetch, detect and apply shares
are compared after each phase. The target for phase four is the headroom the
harness itself already reports.

Baseline, 10,000 mainnet blocks from tip 3,473,313 at a 16 MiB budget:

| | |
| --- | --- |
| Elapsed | 11.05s, 905 blocks/s, 2 batches |
| Fetch | 3.54s (36%) |
| Detect | 1.38s (14%) |
| Apply | 4.94s (50%) |
| Pipelining headroom | 3.54s |
| Peak RSS | 179.3 MiB against a 16 MiB block budget |

One caveat about what this harness measures, which matters for choosing phase
three's targets. It syncs with a key that owns nothing, and a 16 MiB budget over
this range yields only two batches. So it measures commitment and tree write
throughput, and it does not exercise the per-batch costs that scale with the
note set — `unspent_nullifiers`, the detect overlay clone, the stabilisation
update — because there are no notes and almost no batches. Those need a separate
measurement over a wallet with a populated note set and a smaller budget;
`wallet-store/tests/accounts.rs` already has a `plant_note` helper that
fabricates note rows directly for exactly this kind of setup.

## Phases one and two as built

Three things came out differently from the plan, and each is worth recording
because the reasoning changed rather than the intent.

**Anchor chaining turned out to be unnecessary.** The plan proposed carrying the
previous batch's start anchor forward in the engine as the next batch's expected
end. Working through the geometry, that state is redundant: batch N's start
anchor sits at exactly the height batch N+1's *last* block occupies, so under
descending recovery the block above a new batch has always already been scanned.
The store's "meets the block above" check therefore covers that seam by itself,
and the two directions reach the same guarantee from opposite sides — ascending
checks against the block below, descending against the block above. The engine
needs no new state at all, and the half-built version was removed.

It does mean the per-batch `GetTreeState` under descending recovery stays. That
call is what makes the check meaningful — the anchor is an *independent*
assertion, and deriving it from the batch's own first block instead would make
the scanner's end-of-block check tautological.

Verified against mainnet rather than only in tests: a 6,000-block descending
recovery at a 1 MiB budget runs 19 batches, so 18 seams, and the real server's
tree state agreed with the wallet's record at every one.

**The rewind escalation cannot be keyed to the failing height.** The first
attempt reset the doubling whenever the failure moved. That is wrong for the
reason the escalation exists: the previous rewind is what moves it, so the depth
reset on every attempt and a source that was simply broken would be retried
forever. Escalation is cleared by *progress* instead — a batch that applies and
covers the height being rewound at — which leaves the unrelated-historic-range
case fixed without breaking the give-up path.

**Retention has to be bounded, and the plan did not say so.** Retaining every
grid boundary ever scanned adds a row per interval per pool for the whole chain,
and — the part that actually costs — stops the tree pruning the marks beneath
them, so a recovering wallet would carry the entire history's retained subtrees.
A crossing's canonical expiry sits at most `EXPIRY_WINDOW` above the height it
targets, so a boundary older than that cannot back a transfer that would still
be valid when it was sent. Retention is therefore granted only inside that
window and released as boundaries fall out of it, which bounds the set at about
480 boundaries per pool.

One near-miss worth recording: the first version of that release step also
deleted checkpoint rows whose position was `NULL`, on the theory that they were
spent retention placeholders. They are not — a `NULL` position is a checkpoint
taken when the tree was empty, which every block below a pool's first commitment
has. A test caught it. The placeholder path turns out to be unreachable from
here anyway, since retention runs after the commitments are inserted.

### Where this leaves the measurements

| | Baseline | After phases one and two |
| --- | --- | --- |
| Elapsed | 11.05s | 10.74s |
| Throughput | 905 blk/s | 931 blk/s |
| Fetch | 3.54s (36%) | 4.77s (51%) |
| Detect | 1.38s (14%) | 0.73s (8%) |
| Apply | 4.94s (50%) | 3.94s (42%) |

The difference is inside run-to-run variance on a live server, which is the
point: the added checks and the retention writes cost nothing measurable. Fetch
dominating at around half the accounted time is the stable result across every
run, and it is what phase four is for.

## Phases three and four as built

### The measurement that reframed both

The parent document's lesson from M6 was that the assumed bottleneck was wrong by
an order of magnitude, and that the milestone's value lay in having built the
measurement. That repeated here, in the same shape.

Pipelining was built, and it worked: the fetch a batch waits for now overlaps the
detection and storage of the batch before it. On a 19-batch recovery it cut the
time spent waiting on fetch roughly in half. And wall-clock did not improve at
all.

Adding one timer explained why. **Resolving a batch's starting anchor was 8.58
seconds of a 15-second recovery — 56% of accounted time, more than fetching the
blocks.** Under descending recovery a range continues from nothing the wallet has
scanned, so every batch pays a `GetTreeState` round trip, and that round trip
overlapped nothing: the batch cannot be detected without it.

It had never been measured because it sits between the timed phases, and because
the harness's default 16 MiB budget over 10,000 blocks produces two batches, so
two round trips. It only becomes visible when batches are small enough to be
numerous — which is exactly what a real recovery over millions of blocks is.

The fix follows from the diagnosis rather than from the plan: the anchor request
moved *into* the prefetch task, so it happens while the previous batch is being
detected and applied. It now costs zero measured time. The accounting gap closed
at the same time, which is the sign that the phases now describe the whole of the
work.

### What the numbers say

At the harness's default budget, against the pre-phase-one baseline:

| | Baseline | After |
| --- | --- | --- |
| Elapsed | 11.05s | 9.35s / 9.74s |
| Throughput | 905 blk/s | 1069 / 1027 blk/s |
| Anchor | unmeasured | 0.00s (fully overlapped) |

Two cautions on reading that. Run-to-run variance against a live server is large
— apply alone has been seen between 2.68s and 4.66s on identical code — so the
elapsed figures are directional, not a 15% claim. And detect-plus-store measured
with the network excluded is stable at **3.05s ± 2%** over 10,000 blocks across
repeated runs, which is the number worth tracking; the *ratio* against the fork
is not, because the fork's own timing swings between 4.14s and 5.82s on the same
blocks.

At a 1 MiB budget the pipeline cannot help, and it is worth saying why: with 19
batches the prefetch takes about 0.62s per batch while the detect-and-apply it
overlaps takes about 0.19s, so there is simply less work to hide the network
behind than there is network. Smaller batches are worse than larger ones, and no
amount of overlapping changes that.

### The remaining round trip, and why it was left alone

The per-batch `GetTreeState` is now hidden, not removed. It could be removed:
under descending recovery the tree sizes below a batch are derivable from the
stored block above it, less the batch's own action counts, which is local
arithmetic and needs no server.

That was not done, because it trades away the check phase one just added.
Today the source must assert the anchor in one response and the block metadata in
another, and the scanner verifies they agree; deriving the anchor from the blocks
makes that check tautological, and a source wrong about both would no longer be
caught. The cost of keeping it is now near zero in wall-clock terms, which is
what makes keeping it easy to justify.

If it is ever revisited, the thing to preserve is that *something* independent
pins the derivation — the stored block above is local data, so a derivation
anchored there is much stronger than one anchored in the batch's own first block.

### Storage

The per-batch costs the review listed were addressed where they were
unambiguous waste rather than where they were merely suspected:

| Change | Why |
| --- | --- |
| `snapshot_epoch` removed | Threaded through `DetectedBatch` and read by nothing, at the cost of a `COUNT(*)` over every scanned block on every batch. The mechanism it existed for — the writer re-running nullifier linking when the snapshot went stale — now runs unconditionally, which is strictly stronger. |
| Journal mode and synchronous set on `cache` too | They are per-database, and an unqualified pragma sets only `main`. The derived database, which carries essentially all the write traffic, was left on the rollback journal. |
| `cache_size`, `temp_store`, `busy_timeout` | A batch rewrites whole shards, so the page cache is doing real work between statements; the 2 MiB default is sized for a connection reading a row at a time. |
| Hot statements cached | `tx_ref`, the three statements in `link_stored_nullifier`, `get_shard`, and `check_shard_continuity` were re-prepared per note or per shard written. |
| Two indices | `transactions(mined_height)` for rewinds, and a partial index on the not-yet-stabilised notes. |

The incremental nullifier snapshot was **not** built. It is the largest remaining
per-batch cost in principle, and there is still no measurement showing it matters,
because the harness syncs with a key that owns nothing. Building it would mean
holding wallet state in the engine across batches, which is exactly the kind of
thing that should follow evidence rather than precede it. The measurement it
needs is a funded wallet with a populated note set; `wallet-store/tests/accounts.rs`
already has a `plant_note` helper that can fabricate one.

### The writer thread

The plan called for moving the connection onto a dedicated writer thread. What was
built instead is `spawn_blocking` around detection and storage together, with the
wallet moved into the task and back out.

That achieves the thing the writer thread was for — no runtime worker is parked on
rayon or on a SQLite transaction — with less machinery. The parent document
justifies the writer thread as "a correctness choice rather than a performance
one, because it turns SQLite writer serialization into a type-level fact". Here
that fact is already enforced: there is one `WalletDb`, `put_batch` takes `&mut
self`, and the borrow checker will not permit a second writer. A dedicated thread
would restate a guarantee the type system is already making.

It becomes worth building when there is a second writer — a UI that records a
label while a sync is running, say — and at that point the reader connection the
schema's WAL comment already anticipates is the other half of it.
