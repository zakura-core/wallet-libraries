# Changelog

## [Unreleased]

### Fixed

- Classify unknown recent map geometries as unsupported before private requests.
- Reject impossible overflow segment counts and query replies exceeding the wallet's 8 MiB budget before fetching segment setups.

### Added

- The crate, moved unchanged from wallet-pir's `transparent-txid-client` 0.1.0-rc.4.
