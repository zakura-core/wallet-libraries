# Changelog

## [Unreleased]

### Added

- `recover` and `check_history`, behind the `wallet` feature: continuous recovery of an
  account's one-time keys from a directory's catalog, paid buckets, cumulative
  snapshots and seen set, for any store implementing the backend's
  `one_time_ivk::coverage::OneTimeIvkCoverageWrite` and
  `one_time_ivk::restore::OneTimeIvkRestoreWrite`, and "Check swap history", which
  reads every window receiver's history over PIR whatever the paid sets say. They take
  a `Transport` and a `WriteLock`, return `Recovered`, `Delay` and `Error`, with
  `DERIVE_PER_RUN`, `OBJECTS_PER_RUN`, `SEEN_REFRESH_SECS` and `MAINNET_GENESIS`.
  `wallet` enables the backend's `orchard` feature. Neither uses the publication's
  filter file, so the publisher's session-bound filter route has no wallet client.
- `fetch_seen` and `Seen`: a publication's monotone seen set, through its catalog head,
  which a wallet checks before issuing a swap address. They need no `wallet` feature.

### Changed

- Builds on the library's `zakura-receiver-directory` and `zakura-receiver-pir`
  instead of wallet-pir's receiver crates, re-exported as `receiver_directory` and
  `receiver_pir`. Their lookups return records checked structurally only, so
  recovery validates receivers, every looked-up payment and the common witness file
  with `zakura-receiver-crypto`; refusals keep their directory errors. Only the
  records of the looked-up receiver are checked cryptographically; other records
  sharing a row are parsed structurally. The re-exported crates return unchecked
  data.
