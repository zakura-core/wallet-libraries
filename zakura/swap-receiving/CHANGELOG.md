# Changelog

## [Unreleased]

- Add unpublished swap receiving-key derivation (`KeyId::derive`), shared
  purpose/index identities, and the `RefundMemo` funding record, which carries
  only the refund index, with independent KDF vectors and an Ironwood
  receive/reconstruct/spend proof test.
- Add the shared completion limits, `RESTORE_WATCH_SECS` (24 hours for restored
  keys) and `COMPLETION_LIMIT_SECS` (30 days), and direction-aware NEAR
  status normalization, `lifecycle::near_observation`, including refunded amounts
  and exact-output leftovers. Durable scheduling and receipt accounting live in
  SQLite.
- Add transport-independent incoming-note authentication and commitment-path
  validation for privately discovered swap payments.
