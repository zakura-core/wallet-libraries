# Changelog

## [Unreleased]

### Added

- The crate, moved from wallet-pir's `receiver-directory` at main 6703f263, without the `store` feature: the indexer store and `ProviderStore` stay in wallet-pir, and `Error` no longer carries their `Sql` variant.
- `snapshot::capacity` is public, for the stores that size publications outside
  this crate.
- Recovery objects: `paid::PaidSet` for fixed 48-block paid buckets and cumulative
  paid sets, `seen::SeenSet` for the monotone seen set, and `catalog::CatalogHead`
  and `catalog::BucketIndex`, which name them by digest. Each has a canonical
  binary encoding with strict decoding limits, and `tests/fixtures/recovery-vectors.json`
  pins their bytes.

### Changed

- `snapshot::Manifest` gains `catalog_sha256`, the digest of the publication's
  catalog head, which its revision binds.
