# Changelog

## [Unreleased]

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
