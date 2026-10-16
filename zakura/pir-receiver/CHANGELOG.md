# Changelog

## [Unreleased]

### Changed

- The receiver directory crates are this repository's `zakura-receiver-directory`
  and `zakura-receiver-pir`, at their current structural API, instead of
  wallet-pir's `transparent-v0.1.0-rc.7` release. `receiver_directory`,
  `receiver_pir` and now `zakura_receiver_crypto` are re-exported. The sweep checks
  each receiver, every looked-up payment's note commitment, Action nullifier and
  ephemeral key, and the common witness file's binding to the manifest with
  `zakura-receiver-crypto`, the checks the old release made while decoding.
- The end-to-end sweep test, which serves a directory through wallet-pir's receiver
  service, moved to wallet-pir's wallet interoperability suite.

### Added

- `sweep`, behind the `wallet` feature, which runs one account's receiver-directory
  restore sweeps of its one-time keys for any store implementing the backend's
  `one_time_ivk::restore::OneTimeIvkRestoreWrite`, with `Transport`, `WriteLock`,
  `Swept`, `Error` and `MAINNET_GENESIS`. `wallet` enables the backend's
  `orchard` feature.
- `fetch_seen` and `Seen`: a publication's swap provider seen sets, which a wallet
  checks before issuing a swap address. They need no `wallet` feature.
