# Changelog

## [Unreleased]

## [0.0.1-rc4] - 2026-10-26

### Changed

- Use PIR protocol and server core `0.0.1-rc4`.

## [0.0.1-rc3] - 2026-10-23

### Added

- The `receiver` product: `receiver::snapshot::{SnapshotPublisherExt, assign_ordinals}`
  for payment table placement and `receiver::witness::TablePublisherExt` for companion
  witness tables. The `receiver-crypto` feature adds `receiver::witness::{ShardPaths,
  payloads}`, the lower inclusion paths. Built publications are byte-identical.

### Changed

- Use PIR protocol and server core `0.0.1-rc3`.

### Removed

- Receiver publication construction formerly in `zakura-receiver-directory` and
  `zakura-receiver-crypto`, which are removed.

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

- Publication construction for Enhance, Status and Transparent, selected with
  explicit product features, separately from query evaluation and wallet code.
