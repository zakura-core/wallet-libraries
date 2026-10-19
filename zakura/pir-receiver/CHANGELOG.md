# Changelog

## [Unreleased]

### Added

- `discover`, behind the `wallet` feature, which runs one account's discovery of its
  one-time keys for any store implementing the backend's
  `one_time_ivk::restore::OneTimeIvkRestoreWrite`, with `Transport`, `WriteLock`,
  `Discovered`, `Error`, `FIRST_WINDOW`, `GAP`, `KEYS_PER_RUN` and `MAINNET_GENESIS`.
  `wallet` enables the backend's `orchard` feature.
- `recover` and `check_history`, behind the `wallet` feature: continuous recovery of an
  account's one-time keys from a directory's catalog, paid buckets, cumulative
  snapshots and seen set, for any store implementing the backend's
  `one_time_ivk::coverage::OneTimeIvkCoverageWrite`, and "Check swap history", which reads
  every window receiver's history over PIR whatever the paid sets say. They return
  `Recovered` and `Delay`, with `DERIVE_PER_RUN`, `OBJECTS_PER_RUN` and
  `SEEN_REFRESH_SECS`.
- `fetch_seen` and `Seen`: a publication's swap provider seen sets, which a wallet
  checks before issuing a swap address. They need no `wallet` feature.

### Changed

- Builds on the library's `zakura-receiver-directory` and `zakura-receiver-pir`
  instead of wallet-pir's receiver crates, re-exported as `receiver_directory` and
  `receiver_pir`. Their lookups return records checked structurally only, so
  discovery validates receivers, every looked-up payment and the common witness file
  with `zakura-receiver-crypto`; refusals keep their directory errors. Only the
  records of the looked-up receiver are checked cryptographically; other records
  sharing a row are parsed structurally. The re-exported crates return unchecked
  data.
