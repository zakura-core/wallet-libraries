# Changelog

## [Unreleased]

### Added

- Compatible receiver-history sessions bind coverage to the actual PIR manifest and permit covered historical matches while filters are ahead of PIR preparation.

- `discover`, behind the `wallet` feature, which runs one account's discovery of its
  one-time keys for any store implementing the backend's
  `one_time_ivk::restore::OneTimeIvkRestoreWrite`, with `Transport`, `WriteLock`,
  `Discovered`, `Error`, `FIRST_WINDOW`, `GAP`, `KEYS_PER_RUN` and `MAINNET_GENESIS`.
  `wallet` enables the backend's `orchard` feature.
- `fetch_seen` and `Seen` read permanent provider membership through the public archive, independently of PIR preparation. The exact object digest supports resumable issuance checks. They need no `wallet` feature.
- Bounded block-filter requests own captured wallet fences across network waits and verify complete archive pages before committing membership judgments.

### Changed

- Builds on the library's `zakura-receiver-directory` and `zakura-receiver-pir`
  instead of wallet-pir's receiver crates, re-exported as `receiver_directory` and
  `receiver_pir`. Their lookups return records checked structurally only, so
  discovery validates receivers, every looked-up payment and the common witness file
  with `zakura-receiver-crypto`; refusals keep their directory errors. Only the
  records of the looked-up receiver are checked cryptographically; other records
  sharing a row are parsed structurally. The re-exported crates return unchecked
  data.
