# Changelog

## [Unreleased]

### Added

- The crate, from the parts of `zakura-transparent-events`,
  `zakura-transparent-filter`, `zakura-transparent-shard` and
  `zakura-transparent-native` that the wallet and the publisher both use, under
  the modules `events`, `filter`, `shard` and `native`. Encodings, digests,
  identifiers, seeds and validation are unchanged.
- `shard::placement`: a script's candidate directory rows (`candidate_rows`,
  `DIRECTORY_CHOICES`, `bucket_for`, `bucket_salts`, `candidates`), formerly in
  the shard builder.
- `shard::choice::{positions, bit_bytes}` and
  `shard::txid::DisplayEntry::validate`, which the publisher's builders use.

### Changed

- `native` no longer re-exports `zakura-pir-native`; it re-exports only the
  profile types its tables name (`Profile`, `P8`, `P16`, `NativeSetup`). Its
  `public_query_masks` keeps returning a refused shape as an error.
- The license is MIT. The code moved from wallet-pir was MIT; the native
  profile code was MIT or Apache-2.0.

### Fixed

Carried from the replaced crates, unreleased under their names:

- Reject reversed per-block ranges and unknown per-block profiles before
  fetching or reporting coverage.
- Validate whole-map shape once at admission; batch checks inspect only
  advertised format and requested records.
- Reject unsupported shard-map envelope versions before accepting a
  publication, including passes with no remaining filters.
- Validate display revision digests as canonical lowercase SHA-256 hexadecimal
  and expose structural checks independent of geometry support.
- Reject display manifests whose block spans or bucket record totals overflow.
