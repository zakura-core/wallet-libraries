# Changelog

## [Unreleased]

### Changed

- `swap::Observation` has `receipts`, the Zcash transactions the provider reports as the operation's payouts or refunds, and no longer implements `Copy`.

### Removed

- Provider-read freshness and scan-watch completion limits. Quote ownership and receipt expectations remain independent of PIR discovery scheduling.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Update cryptography and protocol types to the compatible Common `4.0.0-rc3`
  dependency family.

## [0.0.1-rc1] - 2026-10-19

### Changed

- Use the published Zakura Common `4.0.0-rc2` dependency family.

### Added

- Add `swap::provider_read_is_current`, with `PROVIDER_READ_MAX_AGE_SECS` (15
  minutes) and `PROVIDER_READ_CLOCK_SKEW_SECS` (1 minute): when a provider's
  set of given receivers, by the start of its last complete read, can rule a
  receiver out. Discovery's recent sets and issuance's seen sets share it.

## [0.0.1-rc0] - 2026-10-14

### Added

- Add one-time IVK derivation (`KeyId::derive`): each key keeps the
  account's `ak` and `nk` with its own `rivk`, identified by purpose and index.
  Add the `swap::RefundMemo` funding record, which carries only the refund
  index, and its `REFUND_MEMO_MAGIC` prefix, with independent KDF vectors and
  an Ironwood receive/reconstruct/spend proof test.
- Add the shared completion limits in `swap`, `RESTORE_WATCH_SECS` (24 hours
  for restored keys) and `COMPLETION_LIMIT_SECS` (30 days), and the
  provider-neutral `Observation`, `OperationStatus`, and `ReceiptExpectation`
  that an app's provider adapter produces. Scheduling and receipt accounting
  are left to the wallet's store, such as `zakura-client-sqlite` with
  `orchard`.
