# Changelog

## [Unreleased]

### Added

- The crate, moved from wallet-pir's `receiver-directory` at main 6703f263, without the `store` feature: the indexer store and `ProviderStore` stay in wallet-pir, and `Error` no longer carries their `Sql` variant.
- `snapshot::capacity` is public, for the stores that size publications outside
  this crate.
