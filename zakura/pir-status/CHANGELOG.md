# Changelog

## [Unreleased]

### Added

- `Error::Unreadable`: a reply that matched its session but whose row failed to
  decrypt or decode. It is a content outcome. A reply that does not match the
  session (manifest, header echo, length) stays `Malformed`, a request outcome.

### Changed

- A row that fails validation, which was `Malformed`, and a row that fails to
  decrypt, which was `Pir`, are now `Unreadable`.

## [0.0.1-rc1] - PLANNED

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Changed

- Queries upload a selection dithered to 44 bits instead of rounded to nearest
  at 49 bits, so a request body shrinks from 77,876 to 72,756 bytes. The
  protocol `status-pir-v3-native-two-mask-m29`, the `SPN1` magic and the
  session material are unchanged. Requires a server that accepts 44-bit
  requests; earlier servers reject them by length.

- Updated the native PIR dependency to `0.0.1-rc1`.

## [0.0.1-rc0] - 2026-09-27

Initial release candidate for private transaction-status observation.

### Added

- The `status-pir-v3-native-two-mask-m29` row format and transport-neutral
  client.
- Wallet-verified anchor acceptance, bounded clock-skew checks, and exact
  request, session, and response length validation.
- Coverage-aware observations that keep absent records inconclusive without a
  conservative earliest-inclusion bound.

### Security

- Status rows and coverage are server assertions, not inclusion proofs.
  Applications must reconcile observations with wallet-verified chain state.
