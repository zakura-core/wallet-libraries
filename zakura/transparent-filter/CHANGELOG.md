# Changelog

## [Unreleased]

### Fixed

- Bound HTTP bodies while reading them, including streamed responses and error diagnostics.

- Decode shard filters using the map's registered profile and reject unknown or mismatched profiles before matching.

### Added

- The crate, moved from wallet-pir's `transparent-filter` 0.1.0-rc.4.
