# zakura-receiver-pir

Encrypted row retrieval from a receiver directory publication over the shared
`zakura-pir-protocol` two-mask profile, one row per 2,048-coefficient packing
block.

- Session manifests (`Manifest`, `WitnessManifest`), their IDs, and the geometry and
  size limits. `Publication` pairs a payment session with the companion witness session
  bound to it: one segment.
- `inventory`: sealed Receiver shards and the immutable inventory listing them, behind a
  small `Head` and fetched in bounded `Chunk`s.
- `Client`/`Query` and `WitnessClient`/`WitnessQuery`: request construction and
  response decoding for payment rows and witness payloads.
- `transport`: the wallet `Transport` interface, `Inventories` for public head, chunk
  and rolling-hint reads, and `InventoryClient`, which reads pages, witness payloads and
  shard filters against one captured inventory. Both query kinds share
  `/v1/receiver/query`; the session ID in the header selects the table.
- With the `server` feature, `Server` and `WitnessServer`, which answer requests by
  scanning the rows with `ipir-sp`, as Transparent's workers do.

Results are candidates for wallet validation, not chain proofs. A witness query is sent
only after a candidate is found, so its timing reveals that candidate recovery occurred;
PIR hides which ordinal was read. The HTTP
service, its routers and processes stay in wallet-pir and consume this crate.

## Shards and inventories

History is split into contiguous shards covering every block, including empty ones:
immutable sealed shards, then at most one recent tier that each publication replaces.
A shard holds one or more fixed-geometry segments, each a payment session and its
companion witness session covering exactly the shard; a block too large for one table
spans several segments, and pages and totals are segment-local. A sealed shard may name
a GCS receiver filter (`receiver_directory::shards`) by digest, size and count.

`/v1/receiver/inventory` serves the `Head` (at most 16 KiB): protocol, network,
correction generation, shard count, coverage and the inventory identity, which binds
every shard's coverage, segment session IDs and filter in order.
`/v1/receiver/inventory/{inventory}/{chunk}` serves 16 shards per chunk, each chunk at
most 1 MiB. A capture checks each chunk and its shards as it arrives, stopping at the
first mismatch, and retains at most 128 MiB by default (`Inventories::capture_within`
takes another budget). It then proves the chunks are the complete ordered list, so a
missing or replaced chunk is an error, never a shorter history. A wallet accepts the
inventory's end against its own chain with `Inventory::accept`, then opens segment
sessions lazily through `InventoryClient`.

`/v1/receiver/shard-filters/{digest}` serves a filter by the digest its shard names.
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

The library target keeps wallet-pir's name, `receiver_pir`.

## Rolling filter transport

`Inventories::block_head` reads `/v1/receiver/block-filters/head` with a 16 KiB limit and checks the configured network. `Inventories::block_batch` reads `/v1/receiver/block-filters/{revision}/{from}/{limit}` with the shared batch bound. Transport errors, unavailable ranges and changed revisions never mean negative membership. Refresh metadata or use direct PIR according to the wallet policy. These public requests contain no receiver and open no PIR session. The wallet owns scheduling and chain checks; ordinary sync must not wait for these requests.
