# Changelog

## [Unreleased]

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
