# Changelog

## [Unreleased]

### Added

- `Receiver`, `Record` and `Payment`: receiver directory row slots, validated
  cryptographically over the `receiver-wire` codec.
- `recovery::Action`: zero-OVK receiver recovery.
- `witness::{WitnessSnapshot, WitnessCache, Publication}`: building and checking the
  common inclusion-proof file.
