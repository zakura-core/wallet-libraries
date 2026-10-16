# Changelog

## [Unreleased]

### Added

- `sweep`, behind the `wallet` feature, which runs one account's receiver-directory
  restore sweeps of its one-time keys for any store implementing the backend's
  `one_time_ivk::restore::OneTimeIvkRestoreWrite`, with `Transport`, `WriteLock`,
  `Swept`, `Error` and `MAINNET_GENESIS`. `wallet` enables the backend's
  `orchard` feature.
- `fetch_seen` and `Seen`: a publication's swap provider seen sets, which a wallet
  checks before issuing a swap address. They need no `wallet` feature.

### Changed

- Builds on the library's `zakura-receiver-directory` and `zakura-receiver-pir`
  instead of wallet-pir's receiver crates, re-exported as `receiver_directory` and
  `receiver_pir`. Their lookups return records checked structurally only, so the
  sweep validates receivers, every looked-up payment and the common witness file
  with `zakura-receiver-crypto`; refusals keep their directory errors.
