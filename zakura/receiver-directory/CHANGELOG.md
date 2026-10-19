# Changelog

## [Unreleased]

### Added

- Bounded archive pages, immutable heads and a sparse authenticated range index, with explicit empty coverage and PIR archive/epoch/chain compatibility declarations. Compatibility can be checked through a captured matched block when the filter head is newer than the PIR publication.

- Canonical per-block receiver hint filters and durable fixed-universe provider `seen` sets, with bounded strict decoding and network binding. These primitives do not yet replace the existing publication or wallet recovery paths.

- The crate, moved from wallet-pir's `receiver-directory` at main 6703f263, without the `store` feature: the indexer store and `ProviderStore` stay in wallet-pir, and `Error` no longer carries their `Sql` variant.
- `snapshot::capacity` is public, for the stores that size publications outside
  this crate.
