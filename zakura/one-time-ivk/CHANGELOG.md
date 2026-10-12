# Changelog

## [Unreleased]

- Add one-time IVK derivation (`KeyId::derive`): each key keeps the
  account's `ak` and `nk` with its own `rivk`, identified by purpose and index.
  Add the `swap::RefundMemo` funding record, which carries only the refund
  index, and its `REFUND_MEMO_MAGIC` prefix, with independent KDF vectors and
  an Ironwood receive/reconstruct/spend proof test.
- Add the shared completion limits in `swap`, `RESTORE_WATCH_SECS` (24 hours
  for restored keys) and `COMPLETION_LIMIT_SECS` (30 days), and the
  provider-neutral `Observation`, `OperationStatus`, and `ReceiptExpectation`
  that an app's provider adapter produces. Scheduling and receipt accounting
  are left to the wallet's store.
- Add transport-independent incoming-note authentication and commitment-path
  validation for privately discovered payments.
