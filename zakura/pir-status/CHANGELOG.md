# Changelog

## [Unreleased]

### Changed

- Queries upload a selection dithered to 44 bits instead of rounded to nearest
  at 49 bits, so a request body shrinks from 77,876 to 72,756 bytes. The
  protocol `status-pir-v3-native-two-mask-m29`, the `SPN1` magic and the
  session material are unchanged. Requires a server that accepts 44-bit
  requests; earlier servers reject them by length.

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
