# Receiver PIR

Receiver PIR lets a wallet find payments to its one-time IVK receivers in a receiver
directory without revealing which receiver it looks up. It follows the [PIR
package](pir-packages.md) structure: each role package has a `receiver` module, selected
with its `receiver` feature.

| Role | Package and feature | Main contents |
| --- | --- | --- |
| Shared formats | `zakura-pir-protocol`, `receiver` | `wire`, `record`, `snapshot`, `witness`, `blocks`, `shards`, `session`, `inventory`, and `native` with the `native` feature |
| Validation | `zakura-pir-protocol`, `receiver-crypto` | `crypto`: receivers, records, zero-OVK recovery and checked tree hashing |
| Publication builder | `zakura-pir-publisher`, `receiver` | `snapshot::{SnapshotPublisherExt, assign_ordinals}`, `witness::TablePublisherExt` |
| Witness paths | `zakura-pir-publisher`, `receiver-crypto` | `witness::{ShardPaths, payloads}` |
| Query server | `zakura-pir-query-server`, `receiver` | `server::{Server, WitnessServer}` |
| Wallet client | `zakura-pir-client`, `receiver` | `Client`, `WitnessClient`, `transport` |
| Wallet recovery steps | `zakura-pir-client`, `receiver-wallet` | `publication`, `lookup`, `lookup_pages`, `witness`, `screen` |

Each role module re-exports the shared formats, so a consumer imports one package. The
query server needs nothing from the publisher, and the wallet client compiles neither
server role. Rolling block and shard filters, which share private keying between their
encoder and matcher, are built and matched in the shared formats. Inventories are too,
because the query server assembles them from the segments it serves.

## Records and validation

A receiver directory serves, over PIR, the payments that were sent to each Ironwood
receiver with the public all-zero outgoing viewing key, and for each payment table a
companion witness table of lower Merkle paths proving those payments' note
commitments. Serving packages consume this library-owned format. The raw codec
(`receiver::wire`) and the cryptographic acceptance checks (`receiver::crypto`, feature
`receiver-crypto`) remain distinct:

- `crypto::Receiver` accepts only bytes that decode to an Ironwood address.
- `wire::RawRecord` reads and writes the fixed 289-byte record, checking structure only.
  Its `ordinal` selects the payment's slot in the companion witness table of the payment
  table that carried it, and means nothing under any other table.
- `wire::{decode_payload, encode_payload, supplied, is_final}` define the 512-byte
  witness payload: a payment's sixteen siblings inside its Ironwood shard, supplied only
  where complete at the table's construction tree size, every other slot zero.
- `crypto::Record` uses the same codec and refuses noncanonical note commitments and
  nullifiers and invalid ephemeral keys. Only an entirely zero slot is empty.
- `crypto::recovery::Action` recovers the receiver of a zero-OVK Action, authenticating
  the note plaintext.
- `zakura-pir-publisher`'s `receiver::witness::ShardPaths` (feature `receiver-crypto`)
  builds payloads from one Ironwood shard's commitments and extends incrementally as the
  shard fills; `receiver::witness::payloads` rebuilds them from a commitment prefix. A payload is never trusted on its own: the wallet reconstructs the
  rest of the path from its own tree and checks it against its own root.
- `crypto::witness::{combine, empty_root}` provides checked byte-array hashing for
  external tree layouts: combine levels are 0 through 31, empty-root heights
  are 0 through 32, and malformed node encodings are refused.

A payload whose shard is still filling is provisional: it is usable only with the
wallet's tree at exactly the construction block. Once the shard is full the payload is
final on that chain and usable at any later accepted anchor.

A protocol consumer that only transports records selects `receiver` alone and uses
`wire::{RawRecord, Payment, RECORD_BYTES, PAYLOAD_BYTES}` without any cryptography or
Common dependencies. The raw codec never grants a payment cryptographic validity.

## Directory publications

The canonical layout a receiver PIR service publishes and a wallet looks up. A match is
a candidate, never proof of ownership or spendability.

- `record`: the 289-byte payment record, re-exported from `wire`.
- `blocks`: bounded rolling GCS hints, separate from full payment history.
- `shards`: one GCS receiver filter per sealed shard, with its own bounds.
- `snapshot`: publication manifests and their revision, row placement, snapshot
  validation, continuation-page rules, and row lookup. The publisher builds snapshots
  (`SnapshotPublisherExt::build`). Each record's witness ordinal is the rank of its note
  position (the publisher's `assign_ordinals`), so a payment table's identity fixes its
  companion mapping.
- `witness`: companion witness tables, which the publisher builds
  (`TablePublisherExt::build`). Ordinal `o` lives in row `o / 8`, slot `o % 8`.
  The manifest binds the payment table's revision, one payload per record and the
  construction tree, so a witness-only replacement keeps the payment table and its
  ordinals, and a replaced payment table needs a new companion.

The formats parse structure only. Callers validate receivers, Action fields and
inclusion proofs at their trust boundaries with `receiver::crypto`. Durable payment and
proof stores stay with the services in wallet-pir, which consume these packages. Nothing
here depends on wallet-pir.

### Rolling block hints

`blocks::Head` advertises a network, correction revision, the first served height and the tip. `blocks::Range` covers up to `MAX_RANGE_BLOCKS` consecutive heights within 4 MiB, starting exactly at the requested height, and a server may return a shorter prefix to honor the byte limit. Only blocks that pay a receiver carry a set; missing ranges are errors, never empty sets. `blocks::RangeSize` reports the encoded bytes from a height to the tip.

The batch binds the captured revision and requested range, and checks parent linkage. Consumers must still compare block identities with their independently synced chain before using negative hints or advancing progress. The service is trusted for complete indexing. Matches only schedule PIR queries; payment authentication, inclusion and spend checks happen separately. Newly exposed receive indexes need historical PIR checks even if their blocks were already processed.

`IWRANGE2` encodes the little-endian correction revision (`u64`), first height (`u32`), height count (`u32`), the hash before the first height, the hash at the last height, the entry count (`u32`), then for each block that pays a receiver a CompactSize height gap and its self-delimiting GCS set. Hashes use protocol byte order. GCS uses P=20 and M=1,569,792 with a salt derived from network and height only, so a wallet can match history below its birthday without block hashes. The publisher is trusted for which chain the sets were built on, as for their completeness; a wallet compares the end hash with its own block where it holds one. No permanent seen set or scan/cache state is part of this format.

PIR manifests require `history_revision`, the operator correction generation also advertised by rolling hints. It is bound into the immutable publication/session identity. Clients must retain the required generation with unfinished work and reject answers from an older generation, even when block heights and hashes match. Reorgs still use chain hashes.

Snapshots contain only the manifest and payment rows; witnesses live in the companion table. Aggregate `paid`, provider `seen` and `recent` sets and the `IWFLT1` envelope are removed. This is an incompatible change to the unlaunched format. It does not prune PIR history or change row placement.

### Sealed shard filters

`shards::ShardFilter` encodes a sealed shard's distinct receivers: `IWSHARD1`, the
genesis hash, the correction generation (`u64`), the shard's first and last heights
(`u32`) and last block hash, then the length (`u32`) and the GCS set. It uses the block
hints' P=20 and M=1,569,792, keyed by network and coverage. A shard can hold up to
8,388,608 receivers in at most 24 MiB, well past one block's 65,536. Decoding and
matching stream the set, so memory does not grow with the shard. A wallet checks the
digest its inventory names before use; a missing, malformed or matching filter means PIR.

## Sessions and inventories

Encrypted row retrieval from a receiver directory publication over the shared native
two-mask profile, one row per 2,048-coefficient packing block.

- `session`: manifests (`Manifest`, `WitnessManifest`), their IDs, and the geometry and
  size limits, with the profile and exact message sizes in `native`. `Publication` pairs a payment session with the companion witness session
  bound to it: one segment.
- `inventory`: sealed Receiver shards and the immutable inventory listing them, behind a
  small `Head` and fetched in bounded `Chunk`s.
- The client's `Client`/`Query` and `WitnessClient`/`WitnessQuery`: request construction and
  response decoding for payment rows and witness payloads.
- The client's `transport`: the wallet `Transport` interface, `Inventories` for public head, chunk
  and rolling-hint reads, and `InventoryClient`, which reads pages, witness payloads and
  shard filters against one captured inventory. Both query kinds share
  `/receiver/v1/query`; the session ID in the header selects the table.
- The query server's `server::{Server, WitnessServer}`, which answer requests by
  scanning the rows with `ipir-sp`, as Transparent's workers do.

Results are candidates for wallet validation, not chain proofs. A witness query is sent
only after a candidate is found, so its timing reveals that candidate recovery occurred;
PIR hides which ordinal was read. The HTTP
service, its routers and processes stay in wallet-pir and consume these packages.

### Shards and inventories

History is split into contiguous shards covering every block, including empty ones:
immutable sealed shards, then at most one recent tier that each publication replaces.
A shard holds one or more fixed-geometry segments, each a payment session and its
companion witness session covering exactly the shard; a block too large for one table
spans several segments, and pages and totals are segment-local. A sealed shard may name
a GCS receiver filter (`receiver::shards`) by digest, size and count.

`/receiver/v1/inventory` serves the `Head` (at most 16 KiB): protocol, network,
correction generation, shard count, coverage and the inventory identity, which binds
every shard's coverage, segment session IDs and filter in order.
`/receiver/v1/inventory/{inventory}/{chunk}` serves 16 shards per chunk, each chunk at
most 1 MiB. A capture checks each chunk and its shards as it arrives, stopping at the
first mismatch, and retains at most 128 MiB by default (`Inventories::capture_within`
takes another budget). It then proves the chunks are the complete ordered list, so a
missing or replaced chunk is an error, never a shorter history. A wallet accepts the
inventory's end against its own chain with `Inventory::accept`, then opens segment
sessions lazily through `InventoryClient`.

`/receiver/v1/shard-filters/{digest}` serves a filter by the digest its shard names.
`InventoryClient` keeps fetched filters within a byte budget (64 MiB by default, see
`with_filter_budget`) and opened segment sessions' public setup within another (16 MiB,
about 560 segments, see `with_segment_budget`), evicting the least recently used and
fetching or opening it again when needed. With the 128 MiB capture budget, these bound what
one client retains however much history a restore covers.
Filters are fetched without a receiver and checked against the digest, size, network,
correction and coverage before use; any failure means PIR for that shard. Cursors,
negative filters and ordinals are meaningful only under the inventory they were captured
with. Serving must retain a captured inventory's objects long enough for a restore to
finish.

PIR hides the selected row within a queried table. It does not hide which shards and
segments a wallet queries, their historical interval, query timing or count, and a
witness query reveals that candidate recovery occurred. This metadata privacy assumes an
honest publisher, in addition to trusting it for complete indexing.

### Rolling filter transport

`Inventories::block_head` reads `/receiver/v1/block-filters/head` with a 16 KiB limit and checks the configured network. `Inventories::range_size` reads `/receiver/v1/block-filters/size/{revision}/{from}`, and `Inventories::block_range` reads `/receiver/v1/block-filters/{revision}/{from}/{limit}` within 4 MiB. Transport errors, unavailable ranges and changed revisions never mean negative membership. Refresh metadata or use direct PIR according to the wallet policy. These public requests contain no receiver and open no PIR session. The wallet owns scheduling and chain checks; ordinary sync must not wait for these requests.

## Wallet recovery

`zakura-pir-client` provides bounded network steps for private receiver lookups. With the `receiver-wallet` feature, `publication`, `lookup` and `witness` connect a captured shard inventory to the SQLite wallet's recovery queue. The application owns networking and scheduling. No network future holds a database handle or lock.

### Wallet flow

1. Enable recovery for each account with `set_one_time_recovery_enabled`. Ordinary block sync continues independently.
2. Fetch the inventory head with `Inventories::head`, capture its chunks with `Inventories::capture_cached` and a durable `DescriptorStore` (or `Inventories::capture` without one), and accept its end and activation coverage against a locally scanned block with `Inventory::accept` before opening an `InventoryClient`. Use one captured inventory per pass. Pass `publication` to `begin_one_time_recovery`. Choose whether sealed shards' filters may replace PIR; blind reads cost more queries and fewer downloads.
3. Cover the gap since the account's `filter_frontier` (activation when unset) with filters or a complete check. For filters, fetch ranges from just past the frontier, match each against `one_time_receivers`, and commit it with `record_one_time_filter_span`, passing its revision, first height, parent hash, end block and each hit's height. The store commits a span that ends at a block the wallet has fully scanned with the same hash, or at least 1,000 blocks (the node's reorg limit) below its scanned tip, and that continues the committed frontier or replays a chunk from inside it with the wallet's own block as parent. Otherwise it answers `Wait`, `Mismatch`, `Stale` or `Restart` (see `FilterOutcome`). A newer revision restarts coverage from activation. Each hit queues a lookup from that key's coverage. Filters only advance coverage: a key that starts being watched, such as one the window just exposed, gets one bootstrap lookup from its history start through the processed frontier, so filters never re-check history they passed. A negative match makes no receiver query. An unavailable or pruned range is never a negative.
4. For a complete check, the alternative to filters, call `begin_one_time_recovery` with `complete = true`. Every monitored key, paid receive keys and monitored refund keys included, gets a lookup from just past its coverage through the publication's end, and the frontier moves there. For a fresh account (`RecoveryStatus::fresh`) the first complete check is the four-lookup seed window. A funded refund key stops being monitored automatically once every local operation on it is conclusive: the provider reported that no refund is coming, or the expected refund was received and settled. A refund key with an active or inconclusive operation, or a disputed or unplaced receipt, stays monitored. One with no local operation, such as a key learned from its funding memo, stays monitored until its own coverage reaches 90 days of chain time after its funding height, and a reorg that moves the funding moves that bound. The manual history check still covers retired keys.
5. `one_time_new_work` is a cheap counter of new recovery obligations, such as a funding memo enhancement stored. Run a round when it changes.
6. Read bounded work with `one_time_recovery`. Call `lookup` outside the wallet lock, then commit with `record_one_time_lookup`. Each step covers sealed shards a validated filter excludes, then reads pages of at most one segment, up to `RECOVERY_PAGE_LIMIT` (32) of them. `lookup_pages` takes a smaller cap for a slow transport: a step that stops mid-segment returns a cursor the wallet records and the next step resumes from. Every shard reaching the request's first unchecked height is required, including one that straddles it, and the recent tier is always read. Failures, including an expired captured session, use `defer_one_time_lookup`, never an empty result. `session::Error::Unsupported` from any step, including the head, capture and witness reads, is different: the service needs a newer client. Call `require_one_time_upgrade` and ask the user to update the app instead of deferring. Pending work is kept and resumes when a later `begin_one_time_recovery` accepts a publication this client captured. Recapture for a replacement inventory: a cursor from another inventory is never resumed, only progress through whole checked shards carries over.
7. For each witness request, call `witness` to read the payment's companion payload by its ordinal and pass the answer to `record_one_time_witness`. A request bound to another payment session returns `Revision`; call `refresh_one_time_witness`, which re-reads the payment under the current session instead of reinterpreting its ordinal. The wallet authenticates the note, rebuilds the rest of the path from its own tree, checks it against its own root, then checks spend coverage and records ordinary wallet ownership. A provisional payload is usable only at its exact construction block within the pruning depth; a final one at any later anchor. Unusable or missing witnesses leave the payment pending.

Seed recovery walks receive indexes until four consecutive complete empty histories from activation through a captured frontier. The birthday bounds credited history, not this walk: an authenticated pre-birthday payment marks its index used. A paid key resets the gap only after authentication and inclusion. New lookahead keys get their bootstrap lookup through the already processed frontier in the same transaction. An empty counts with a completed lookup or with filter coverage and nothing left to read, so an account that never swapped finishes the walk with its four bootstrap lookups. Receive issuance reuses the lowest unpaid eligible hole within the four-index window that payments mined on the wallet's chain justify. Refund identities come from authenticated funding memos or locally funded operations, not an index sweep. Recovering funding before the account birthday requires lowering that birthday and rescanning ordinary history.

`check_one_time_history` starts or resumes an explicit history check. An optional exclusive receive bound crosses the normal four-empty stopping point. `cancel_one_time_history` pauses that manual work without losing its cursor or independent positive hints.

### Repeat payments

Each address is meant to be paid once. Filters and complete checks both keep watching paid keys, so a second payment to a monitored address is found automatically. A key out of automatic monitoring, such as a retired refund key, is checked only by the manual history check, `check_one_time_history`.

### Boundaries

Turning recovery off invalidates held callbacks and exposes no discovery work. It preserves existing notes, spending and reorg repair. There are no one-time-key scan watches, compact-block caches, aggregate filters, provider seen gates or restore passes. Targeted authentication of a PIR-returned payment remains necessary.

PIR hides the receiver within a query and the ordinal within a witness query. Query timing, count and which shards are read stay visible, so recovery reveals historical intervals, and a witness query reveals that a lookup found a candidate. This metadata privacy assumes an honest publisher. The service is trusted for complete indexing and honest negative answers. Wallet authentication and chain proofs prevent it from crediting an invented payment.

`zakura-pir-client`'s `tests/receiver/discovery.rs` uses the production snapshot, witness, shard filter and inventory builders and the encrypted PIR evaluator against a real SQLite wallet, including sealed and recent shards, multi-segment shards, substituted filters, replaced inventories and corrections. The service router and full application scheduling are tested in their owning repositories.
