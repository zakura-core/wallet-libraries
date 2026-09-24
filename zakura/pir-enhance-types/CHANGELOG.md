# Changelog

## [Unreleased]

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
