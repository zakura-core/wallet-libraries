# Changelog

## [Unreleased]

### Fixed

- Reject reversed per-block ranges and unknown per-block profiles before fetching or reporting coverage.

- Validate whole-map shape once at admission; batch checks inspect only advertised format and requested records.

- Reject unsupported shard-map envelope versions before accepting a publication, including passes with no remaining filters.

- Bound HTTP bodies while reading them, including streamed responses and error diagnostics.

- Decode shard filters using the map's registered profile and reject unknown or mismatched profiles before matching.

### Added

- The crate, moved from wallet-pir's `transparent-filter` 0.1.0-rc.4.
