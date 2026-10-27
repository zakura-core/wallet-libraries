# Changelog

## [Unreleased]

### Changed

- Receiver block hints are sparse and keyed by height. `blocks::Range`
  (`IWRANGE2`) carries the parent and end hashes and one `HeightSet` per block
  that pays a receiver, so an empty block costs nothing. A set's key comes from
  the network and height alone, so a wallet can match history below its
  birthday. One range covers up to `MAX_RANGE_BLOCKS` heights within
  `MAX_RANGE_BYTES`. `blocks::Head` now describes a sealed archive and a tail,
  and `blocks::RangeSize` reports what serving from a height would cost.
- Breaking: `blocks::BlockFilter`, `blocks::Batch` (`IWBATCH1`),
  `MAX_BLOCKS`, `MAX_BATCH_BYTES` and `Head::check_request` are removed.

### Added

- The `receiver` product: the receiver wire codec, payment and companion witness table
  formats, rolling block and sealed shard filters, PIR session manifests and shard
  inventories, with the receiver PIR profile and message sizes under `native`. Every
  format, constant and serialization is unchanged.
- The `receiver-crypto` feature: `receiver::crypto`, with address, record and zero-OVK
  recovery validation and checked note-tree hashing.

### Removed

- `zakura-receiver-directory` and `zakura-receiver-crypto` are removed; their formats and
  validation live here. Witness path construction moved to `zakura-pir-publisher`.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Update Common protocol and transparent transaction types to the compatible
  `4.0.0-rc3` dependency family.

## [0.0.1-rc0] - 2026-10-19

### Added

- Shared Enhance, Status and Transparent records, manifests and native profile
  identities for the separate client, publisher and query-server packages.
- Transparent recovery records formerly provided by
  `zakura-transparent-recovery-types`.

### Compatibility

- Consolidate the package names without changing serialized field order, hashes,
  native setup identities or query framing.

## pir-enhance-types history

# Changelog

## Changes carried into consolidation

## [0.0.1-rc1] - 2026-10-13

### Fixed

- Include the MIT and Apache license texts in the crate package. Wire records
  and encoding validation are unchanged.

## [0.0.1-rc0] - 2026-09-24

Initial release candidate for the shared Ironwood enhancement record types.

### Added

- Schema-11 records with a fixed 653-byte encoding: encrypted-note suffix,
  value commitment, outgoing ciphertext, transparent flags, expiry height,
  and optional fee.
- `EnhanceRecord`, `EnhanceRecordParts`, and `EnhanceTransactionMetadata`
  with typed accessors, byte conversion, and shared layout constants.
- Encoding validation for reserved flags, absent-fee payloads, expiry heights,
  and the maximum fee, with `InvalidEnhanceRecord` errors.
- Frozen schema-11 vectors and round-trip, malformed-input, and boundary tests.

### Security boundary

- Encoding validation does not authenticate ciphertext or transaction metadata.
  Wallets must authenticate decrypted notes and preserve request identities;
  transaction metadata and some send-only associations require server trust.
