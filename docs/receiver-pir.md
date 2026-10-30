# Receiver PIR

Receiver PIR lets a wallet find payments to its one-time IVK receivers in a receiver
directory without revealing which receiver it looks up. It follows the [PIR
package](pir-packages.md) structure: each role package has a `receiver` module, selected
with its `receiver` feature.

| Role | Package and feature | Main contents |
| --- | --- | --- |
| Shared formats | `zakura-pir-protocol`, `receiver` | Directory and companion tables (`Entry`, `Directory`, `Companion`, `Session`, `Publication`), `wire`, `record`, `blocks`, `shards`, `session`, `inventory`, and `native` with the `native` feature |
| Validation | `zakura-pir-protocol`, `receiver-crypto` | `crypto`: receivers, records, zero-OVK recovery and checked tree hashing |
| Publication builder | `zakura-pir-publisher`, `receiver` | `Projection`, `build` |
| Witness paths | `zakura-pir-publisher`, `receiver-crypto` | `witness::{ShardPaths, payloads}` |
| Query server | `zakura-pir-query-server`, `receiver` | `server::Server` |
| Wallet client | `zakura-pir-client`, `receiver` | `Client`, `transport` |
| Wallet recovery steps | `zakura-pir-client`, `receiver-wallet` | `publication`, `lookup`, `lookup_with`, `Pace`, `Step`, `Stop`, `screen` |

Each role module re-exports the shared formats, so a consumer imports one package. The
query server needs nothing from the publisher, and the wallet client compiles neither
server role. Rolling block and shard filters, which share private keying between their
encoder and matcher, are built and matched in the shared formats. Inventories are too,
because the query server assembles them from the segments it serves.

## Records and validation

A receiver directory serves, over PIR, the payments that were sent to each Ironwood
receiver with the public all-zero outgoing viewing key. Each segment is a directory of
salted receiver tags and a companion of full records, each with the lower Merkle path
proving its note commitment. Serving packages consume this library-owned format. The raw codec
(`receiver::wire`) and the cryptographic acceptance checks (`receiver::crypto`, feature
`receiver-crypto`) remain distinct:

- `crypto::Receiver` accepts only bytes that decode to an Ironwood address.
- `wire::RawRecord` reads and writes the fixed 289-byte record, checking structure only.
  Its `ordinal` is the payment's companion slot, meaningful only under that segment.
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
- The directory: 2,048 rows of 186 22-byte entries, each a receiver's 14-byte tag under
  the segment's salt, its first companion slot, its payment count and its last payment's
  height offset. A per-segment choice object, served by digest, names which of a tag's
  two candidate rows holds it, so a lookup is one directory query per segment.
- The companion: up to 65,536 rows of five 801-byte slots, each a record and its
  witness payload. A receiver's payments fill consecutive slots in page order, and a
  query covers the companion's `query_rows` prefix. The manifest binds the directory
  revision it serves and the tree its payloads were built at.
- `Publication` pairs a segment's directory and companion sessions, and
  `DirectoryTable::validate` and `CompanionTable::validate` repeat every whole-segment
  check a publisher, a server and a wallet rely on. The publisher's `Projection` places
  each block's new receivers under the segment's salt and `build` lays out the tables.

The formats parse structure only. Callers validate receivers, Action fields and
inclusion proofs at their trust boundaries with `receiver::crypto`. Durable payment and
proof stores stay with the services in wallet-pir, which consume these packages. Nothing
here depends on wallet-pir.

### Rolling block hints

`blocks::Head` advertises a network, correction revision, the first served height and the tip. `blocks::Range` covers up to `MAX_RANGE_BLOCKS` consecutive heights within 4 MiB, starting exactly at the requested height, and a server may return a shorter prefix to honor the byte limit. Only blocks that pay a receiver carry a set; missing ranges are errors, never empty sets.

The batch binds the captured revision and requested range, and checks parent linkage. Consumers must still compare block identities with their independently synced chain before using negative hints or advancing progress. The service is trusted for complete indexing. Matches only schedule PIR queries; payment authentication, inclusion and spend checks happen separately. Newly exposed receive indexes need historical PIR checks even if their blocks were already processed.

`IWRANGE2` encodes the little-endian correction revision (`u64`), first height (`u32`), height count (`u32`), the hash before the first height, the hash at the last height, the entry count (`u32`), then for each block that pays a receiver a CompactSize height gap and its self-delimiting GCS set. Hashes use protocol byte order. GCS uses P=20 and M=1,569,792 with a salt derived from network and height only, so a wallet can match history below its birthday without block hashes. The publisher is trusted for which chain the sets were built on, as for their completeness; a wallet compares the end hash with its own block where it holds one. No permanent seen set or scan/cache state is part of this format.

PIR manifests require `history_revision`, the operator correction generation also advertised by rolling hints. It is bound into the immutable publication/session identity. Clients must retain the required generation with unfinished work and reject answers from an older generation, even when block heights and hashes match. Reorgs still use chain hashes.

Aggregate `paid`, provider `seen` and `recent` sets and the `IWFLT1` envelope are removed.

### Sealed shard filters

`shards::ShardFilter` encodes a sealed shard's distinct receivers: `IWSHARD1`, the
genesis hash, the correction generation (`u64`), the shard's first and last heights
(`u32`) and last block hash, then the length (`u32`) and the GCS set. It uses the block
hints' P=20 and M=1,569,792, keyed by network and coverage. A shard can hold up to
8,388,608 receivers in at most 24 MiB, well past one block's 65,536. Decoding and
matching stream the set, so memory does not grow with the shard. A wallet checks the
digest its inventory names before use; a missing, malformed or matching filter means PIR.

## Sessions and inventories

Encrypted row retrieval from directory and companion tables over the shared native P8
profile, one 4,096-byte row as two 2,048-coefficient packing blocks.

- `Session`: a table's manifest and its public setup digest, whose ID pins every query.
  `session` holds the shared errors and size limits, and `native` the profile and exact
  message sizes.
- `inventory`: sealed Receiver shards and the immutable inventory listing them, behind a
  small `Head` and fetched in bounded `Chunk`s.
- The client's `Client`/`Query`: fresh request construction and response decoding for
  one table.
- The client's `transport`: the wallet `Transport` interface, `Inventories` for public head, chunk
  and rolling-hint reads, and `InventoryClient`, which opens sessions, fetches choice
  objects and shard filters and sends queries against one captured inventory. Both table
  kinds share `/receiver/v1/query`; the session ID in the header selects the table.
- The query server's `server::Server`, which answers a directory or companion's requests
  by scanning its rows with `ipir-sp`, as Transparent's workers do.

Results are candidates for wallet validation, not chain proofs. The HTTP service, its
routers and processes stay in wallet-pir and consume these packages.

### Shards and inventories

History is split into contiguous shards covering every block, including empty ones:
immutable sealed shards, then at most one recent tier that each publication replaces.
A shard holds one or more segments, each a directory and companion session covering
exactly the shard; a block too large for one segment spans several, and pages and totals
are segment-local. A sealed shard may name
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

`/receiver/v1/shard-filters/{digest}` serves a filter by the digest its shard names, and
`/receiver/v1/choice/{digest}` a directory's choice object by the digest, length and key
count its manifest binds. `/receiver/v1/public/{session}` serves either table's setup.
`InventoryClient` keeps fetched filters within a byte budget (64 MiB by default, see
`with_filter_budget`), opened sessions' public setup within another (16 MiB, see
`with_segment_budget`) and choice objects within a third (4 MiB, see
`with_choice_budget`), each checked against its digest, evicting the least recently used
and fetching it again when needed. With the 128 MiB capture budget, these bound what
one client retains however much history a restore covers.
Filters are fetched without a receiver and checked against the digest, size, network,
correction and coverage before use; any failure means PIR for that shard. Cursors and
negative filters are meaningful only under the inventory they were captured with.
Serving must retain a captured inventory's objects long enough for a restore to
finish.

PIR hides the selected row within a queried table. It does not hide which shards and
segments a wallet queries, their historical interval, query timing or count, and
companion queries reveal a hit at or past the lookup's floor. This metadata privacy assumes an
honest publisher, in addition to trusting it for complete indexing.

### Rolling filter transport

`Inventories::block_head` reads `/receiver/v1/block-filters/head` with a 16 KiB limit and checks the configured network. `Inventories::block_range` reads `/receiver/v1/block-filters/{revision}/{from}/{limit}` within 4 MiB. Transport errors, unavailable ranges and changed revisions never mean negative membership. Refresh metadata or use direct PIR according to the wallet policy. These public requests contain no receiver and open no PIR session. The wallet owns scheduling and chain checks; ordinary sync must not wait for these requests.

## Wallet recovery

`zakura-pir-client` provides bounded network steps for private receiver lookups. With the `receiver-wallet` feature, `publication` and `lookup` connect a captured shard inventory to the SQLite wallet's recovery queue. The application owns networking and scheduling. No network future holds a database handle or lock.

### Wallet flow

1. Enable recovery for each account with `enable_one_time_recovery`. A refund memo that decodes and is mined on an account's internal note enables it too, in the transaction that accepts the memo, even when the 100-index gap rule defers the memo. A memo is accepted when the blocks that mine its transaction are stored, or when its transaction is stored after its block. Rounds, enabling and refund issuance read the account's memos again, which is where a deferred memo is accepted once the gap closes. A deferred memo activates the account, but its own refund key isn't watched until the gap closes or the wallet proves it owns the funding input. An account whose swaps only ever went into ZEC leaves no funding memo, so a second device with detection off doesn't watch it until the app enables it or a history check runs. A holder of the account's viewing key can also activate monitoring by paying the internal address with a refund memo. That costs PIR traffic but credits nothing. `RecoveryStatus::used` reports durable evidence that the account used one-time addresses, set whether or not recovery is enabled and never cleared: a receive address or refund key handed out, the wallet's own refund funding, a payment candidate at or after the birthday, or an accepted refund memo. Ordinary block sync continues independently.
2. Fetch the inventory head with `Inventories::head`, capture its chunks with `Inventories::capture_cached` and a durable `DescriptorStore` (or `Inventories::capture` without one), and accept its end and activation coverage against a locally scanned block with `Inventory::accept` before opening an `InventoryClient`. Use one captured inventory per pass. Pass `publication` to `begin_one_time_recovery`. Choose whether sealed shards' filters may replace PIR; blind reads cost more queries and fewer downloads.
3. `filter_frontier` is the account's marker: the block through which filters were read. With a marker, read filters from just past it to the scanned tip, match each range against `one_time_receivers`, and commit it with `record_one_time_filter_span`, passing its revision, first height, parent hash, end block and each hit's height. The store commits only a range that starts just past the marker with the marker's hash as its parent, and that ends at a block the wallet has fully scanned with the same hash. Any other start is an error. Otherwise it answers `Wait`, `Mismatch`, `Stale` or `Restart` (see `FilterOutcome`). A newer revision clears the marker. Filters are only a trigger: each hit queues a lookup of that key from its history start through the hit, which a hit inside completed PIR history settles without a query, and a negative is never stored for a key. A key that starts being watched, such as one the window just exposed, gets one bootstrap lookup from its history start through the processed frontier. A negative match makes no receiver query. An unavailable or pruned range is never a negative. With no marker, or a marker below the first height the server still serves, run a complete check instead.
4. For a complete check, call `begin_one_time_recovery` with `complete = true`. Every monitored key, paid receive keys and monitored refund keys included, gets a lookup from its last PIR check through the publication's end. The marker moves to the highest block at or below both that end and the wallet's fully scanned block, and stays where it is when there is none, so the next round asks again after more sync. A funded refund key stops being monitored automatically once every local operation on it is conclusive: the provider reported that no refund is coming, or the expected refund was received and settled. A refund key with an active or inconclusive operation, or a disputed or unplaced receipt, stays monitored. One with no local operation, such as a key learned from its funding memo, stays monitored until the account's marker reaches 90 days of chain time after its funding height, and a reorg that moves the funding moves that bound. With no marker it stays monitored. The manual history check still covers retired keys.
5. Run a round for an account when `RecoveryStatus::round_due` is set: a lookup is due, whatever queued it (a filter hit, a bootstrap, a refund memo, a witness refresh, a correction, a rewind, or a step of the seed walk or a manual check), the seed walk hasn't captured a publication, or the marker is missing or more than 10 blocks below the fully scanned block. A lookup waiting out its retry delay or for a later publication doesn't make a round due. The marker never passes the fully scanned block, so a wallet that is still syncing isn't asked for rounds it can't finish.
6. Read bounded work with `one_time_recovery`, passing the captured inventory's end so the listed lookups are ones it can answer, even when more than four others wait for a later publication. `waits_for_retry` and `waits_for_publication` say why any other lookup waits. Call `lookup` outside the wallet lock, then commit its page with `record_one_time_lookup`. Each step covers sealed shards a validated filter excludes, then reads at most one segment: one directory query and, on a hit whose last payment is at or past `max(from, birthday)`, one companion query per record, up to `RECOVERY_PAGE_LIMIT` (32) records, each with its witness payload. A hit below that floor reads no companion. `lookup_with` takes a `Pace`: a smaller record cap for a slow transport, and retries of a request that fails in transport, each freshly encrypted. A step is all or nothing: a step that stops mid-segment at its cap returns a cursor the wallet records and the next step resumes from, reading the receiver's entry again first, while a failed request fails the whole step and records nothing. Check a deadline before starting a step, not during one. A cursor from another inventory is never resumed, so a segment needing more than one step must finish under one captured inventory; a recapture keeps only progress through whole checked shards. Every shard reaching the request's first unchecked height is required, including one that straddles it, and the recent tier is always read. A failed answer uses `defer_one_time_lookup`, never an empty result, and backs the lookup off from a minute up to twelve hours. A transport failure or `Revision` needs no deferral: the lookup stays due for the app's next round, and `Revision` means a session is gone, so capture again. Starting a history check makes backed-off lookups due at once. `session::Error::Unsupported` from any step, including the head and capture, is different: the service needs a newer client. Call `require_one_time_upgrade` and ask the user to update the app instead of deferring. Pending work is kept and resumes when a later `begin_one_time_recovery` accepts a publication this client captured.
7. `record_one_time_lookup` stores each new candidate with its payload, then admits it: the wallet authenticates the note, rebuilds the rest of the path from its own tree, checks it against its own root, then checks spend coverage and records ordinary wallet ownership. A provisional payload is usable only at its exact construction block within the pruning depth; a final one at any later anchor. A payload that waits for the scan stays with the payment; an unusable one drops it and reads the key's history again for a fresh one.

Seed recovery walks receive indexes until four consecutive complete empty histories from activation through a captured frontier. The wallet doesn't handle payments before the account birthday: a lookup passes over such a record before storing anything for it, so it is neither credited, nor a payment that extends the walk, nor evidence of use. Receive keys' history still starts at activation. Complete recovery therefore needs a birthday before the account's first one-time address use. For example, if I0 was paid before the birthday, I1 to I3 are empty and I4 was paid after it, the walk stops at I3, I4 isn't found, and I0 can be issued again. Lowering the birthday queues known histories again; run a history check after it. A paid key resets the gap only after authentication and inclusion. New lookahead keys get their bootstrap lookup through the already processed frontier in the same transaction. An empty counts only with a completed lookup, so an account that never swapped finishes the walk with its four bootstrap lookups. Receive issuance reuses the lowest unpaid eligible hole within the four-index window that payments mined on the wallet's chain justify, once that index's lookup completed and the account's marker is within 10 blocks of the chain tip. Otherwise it returns `ReservationPolicy::ReceiveHistory`, and `round_due` asks for the round that catches the marker up once sync allows it. A refund key is the next index above every known one, once ordinary sync is within 10 blocks of the tip and every refund memo is recovered. Refund identities come from authenticated funding memos or locally funded operations, not an index sweep. Recovering funding before the account birthday requires lowering that birthday and rescanning ordinary history.

`check_one_time_history` starts or resumes an explicit history check. An optional exclusive receive bound crosses the normal four-empty stopping point. `check_one_time_history_for` starts every listed account's check in one transaction, or none of them if any account refuses, and names that account, so a wallet-wide check never runs for only some accounts. `cancel_one_time_history` pauses that manual work without losing its cursor or independent positive hints.

### Repeat payments

Each address is meant to be paid once. Filters and complete checks both keep watching paid keys, so a second payment to a monitored address is found automatically. A key out of automatic monitoring, such as a retired refund key, is checked only by the manual history check, `check_one_time_history`.

### Boundaries

Recovery has no pause. Once enabled, an account stays enabled, and an app stops querying it by leaving it out of its rounds. An account that isn't enabled exposes no work, while its existing notes, spending and ordinary sync are kept. There are no one-time-key scan watches, compact-block caches, aggregate filters, provider seen gates or restore passes. Targeted authentication of a PIR-returned payment remains necessary.

PIR hides the receiver within a directory query and the slot within a companion query. Query timing, count and which shards are read stay visible, so recovery reveals historical intervals, and companion queries reveal a hit at or past the floor, also when re-reading a payment the wallet already holds. This metadata privacy assumes an honest publisher. Nothing ties filter contents to the chain, so a publisher that suspects a receiver can list it in a filter and see whether a lookup follows. That is Transparent's accepted "A filter lists a script the service already knows" leak (see `pir-remaining-leaks-plan.md`, section 8), and it waits for the same cover. Tor removes the link to the network address. The service is trusted for complete indexing and honest negative answers. Wallet authentication and chain proofs prevent it from crediting an invented payment.

`zakura-pir-client`'s `tests/receiver/discovery.rs` uses the production segment, payload, shard filter and inventory builders and the encrypted PIR evaluator against a real SQLite wallet, including sealed and recent shards, multi-segment shards, substituted filters, replaced inventories and corrections. The service router and full application scheduling are tested in their owning repositories.
