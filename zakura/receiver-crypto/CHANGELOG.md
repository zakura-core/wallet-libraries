# Changelog

## [Unreleased]

### Changed

- `wire::RawRecord` and `Record` carry a `u32` witness `ordinal`, growing a record to 289
  bytes (still 14 per 4,096-byte row). It selects the payment's slot in its payment table's
  companion witness table.

### Added

- `wire::{PAYLOAD_BYTES, LOWER_LEVELS, supplied, is_final, decode_payload, encode_payload}`:
  the 512-byte companion witness payload, available without default features.
- `witness::{ShardPaths, SHARD_LEAVES, payloads}`: lower paths built per Ironwood shard,
  extended incrementally as the shard fills.

### Removed

- The common `IWPROOF1` witness file: `witness::{WitnessSnapshot, WitnessCache,
  Publication, MAX_WITNESS_BYTES}`.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Update the public cryptography and protocol types to the compatible Common
  `4.0.0-rc3` dependency family.

## [0.0.1-rc0] - 2026-10-19

### Added

- `Receiver`, `Record` and `Payment`: receiver directory row slots, validated
  cryptographically over the library-owned wire codec.
- `recovery::Action`: zero-OVK receiver recovery.
- `witness::{WitnessSnapshot, WitnessCache, Publication}`: building and checking the
  common inclusion-proof file.
- `wire::{RawRecord, Payment, RECORD_BYTES}`: the canonical fixed record format,
  available without default features or external dependencies. Raw parsing checks
  structure; the default `crypto` feature retains all cryptographic acceptance checks.
