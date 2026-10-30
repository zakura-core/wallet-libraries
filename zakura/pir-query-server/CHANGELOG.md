# Changelog

## [Unreleased]

### Changed

- The Receiver evaluator performs its native-ring matrix scan directly, keeping
  IPIR's server, client and kernel wrappers out of production dependencies. IPIR
  remains a development dependency for independent comparisons. Wire formats,
  public setup and responses are unchanged.

## [0.0.1-rc4] - 2026-10-26

### Changed

- Use PIR protocol and server core `0.0.1-rc4`.

## [0.0.1-rc3] - 2026-10-23

### Added

- The `receiver` product: `receiver::server::{Server, WitnessServer}`, the receiver PIR
  evaluator, which scans rows with `ipir-sp`. It no longer depends on the PIR client.

### Changed

- Use PIR protocol and server core `0.0.1-rc3`.

### Removed

- The receiver evaluator formerly behind `zakura-receiver-pir`'s `server` feature;
  `zakura-receiver-pir` is removed.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use PIR protocol and server core `0.0.1-rc2`.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Use the updated protocol and server-core release candidates for the Common
  `4.0.0-rc3` dependency family.

## [0.0.1-rc0] - 2026-10-19

### Added

- Query parsing and response evaluation for Enhance, Status and Transparent,
  selected with explicit product features, separately from publication placement
  and wallet code.
