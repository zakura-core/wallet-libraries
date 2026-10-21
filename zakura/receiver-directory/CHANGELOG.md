# Changelog

## [Unreleased]

### Changed

- Records are 289 bytes with a witness ordinal. Snapshots require ordinals to rank records
  by note position; `snapshot::assign_ordinals` sets them.

### Removed

- Remove the aggregate paid/seen/recent filter envelope and manifest fields, with the `filter` module (`Filters`, `FilterSet`, `ProviderSet`, `PAID`, `SEEN`, `RECENT`, `MAX_FILTERS_BYTES`, `check_filters` and `valid_label`). Snapshots retain the complete payment rows and coverage checks.

### Added

- Add `shards::ShardFilter`: one GCS receiver filter per sealed shard, with bounds separate
  from block hints and streaming, bounded-memory decoding and matching.

- Add `witness`: companion witness tables of 512-byte lower paths addressed by ordinal,
  with a manifest bound to its payment table and construction tree.

- Bind the required history correction generation into PIR publication identity so unfinished work can fence older answers after a same-chain correction.

- Add bounded, consecutive Receiver block-filter batches for rolling hints, with explicit network, correction revision, block identities and parent linkage. Reuse the validated GCS decoder.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use receiver cryptography `0.0.1-rc2`.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Use `zakura-receiver-crypto 0.0.1-rc1`, which updates the Common dependency
  family to `4.0.0-rc3`; the directory still uses only its structural wire codec.

## [0.0.1-rc0] - 2026-10-19

### Added

- The crate, moved from wallet-pir's `receiver-directory` at main 6703f263, without the `store` feature: the indexer store and `ProviderStore` stay in wallet-pir, and `Error` no longer carries their `Sql` variant.
- `snapshot::capacity` is public, for the stores that size publications outside
  this crate.
