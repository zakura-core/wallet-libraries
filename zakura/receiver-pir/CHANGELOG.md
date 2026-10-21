# Changelog

## [Unreleased]

### Changed

- Publications are inventories of sealed Receiver shards and a recent tier. A shard's
  segments are `Publication`s: a payment session and its companion `WitnessManifest`.
  `/v1/receiver/inventory` serves the `inventory::Head` and
  `/v1/receiver/inventory/{inventory}/{chunk}` its bounded chunks. `Client::new` no
  longer takes an anchor: the wallet accepts the whole inventory with `Inventory::accept`.

### Added

- `Inventories::capture_cached` and `capture_cached_within` reuse settled shard descriptors
  (`Shard::settled`) saved in a host `transport::DescriptorStore` and download only new
  shards, sealed shards with provisional witnesses and the recent tier. The full inventory
  identity is still checked, and any mismatch recaptures every chunk.
- `WitnessClient`, `WitnessQuery`, `server::WitnessServer` and `InventoryClient::witness`:
  one PIR query per witness payload, by ordinal, under its own session ID.
- `inventory::{Inventory, Head, Chunk, Shard, FilterRef}`, `transport::Inventories` and
  `transport::InventoryClient`: captured shard inventories, lazily opened segment
  sessions and shard filters fetched by digest. Captures check each chunk as it arrives
  within a byte budget (`Inventories::capture_within`), and fetched filters are kept in a
  byte-bounded cache (`InventoryClient::with_filter_budget`), as are opened segment sessions
  (`InventoryClient::with_segment_budget`).
- Fetch rolling block-filter availability and bounded batches independently of PIR sessions through the caller-owned transport.

### Removed

- `DirectoryClient`, `AcceptedCoverage` and `/v1/receiver/init`: one session for all
  history. Its rolling-hint reads moved to `Inventories`.
- `DirectoryClient::witnesses` and `transport::MAX_WITNESS_BYTES`: the common witness file.
- Remove aggregate filter downloads and evaluator storage. Rolling block hints are independent of full-history PIR sessions.
- Remove `server::Server::rows` and `server::Server::new_reusing_rows`, which only tests used. A prepared server no longer keeps a second copy of its encoded rows.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use receiver directory, PIR client and server crates `0.0.1-rc2`.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Use the updated receiver directory, PIR client and server release candidates
  for the Common `4.0.0-rc3` dependency family.

## [0.0.1-rc0] - 2026-10-19

### Added

- The crate, moved from wallet-pir's `receiver-pir` at main 6703f263, using the native helpers in `zakura-pir-client`.

### Changed

- `transport::DirectoryClient` reads histories over PIR only, one page per query with
  `DirectoryClient::page`. The row file, `prefer_directory_file`, `MAX_PIR_PAGES` and
  `use_file_for_work` are gone, and `connect_manifest` no longer takes a lookup count.
