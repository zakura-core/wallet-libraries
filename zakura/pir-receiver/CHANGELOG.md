# Changelog

## [Unreleased]

### Added

- `sweep`, behind the `wallet` feature, which runs one account's receiver-directory
  restore sweeps of its one-time keys for any store implementing the backend's
  `OneTimeIvkWrite`, with `Transport`, `NoteSource`, `EnhanceNotes`, `WriteLock`,
  `Swept`, `Error` and `MAINNET_GENESIS`. The receiver PIR client moved here from
  Vizor.
- `fetch_seen` and `Seen`: a publication's swap provider seen sets, which a wallet
  checks before issuing a swap address. They need no `wallet` feature.
