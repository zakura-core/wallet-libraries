# Changelog

## [Unreleased]

### Added

- `sweep`, behind the `wallet` feature, which runs a restored wallet's
  receiver-directory sweeps of its dynamic keys for any store implementing the
  backend's `DynamicIvkWrite`, with `Transport`, `NoteSource`, `EnhanceNotes`, `WriteLock`,
  `Swept`, `Error` and `MAINNET_GENESIS`. It reads a publication's labeled filter
  sets `paid` and each provider's `seen`. The receiver PIR client moved here from
  Vizor.
- `fetch_seen` and `Seen`: a publication's swap provider seen sets, which a wallet
  checks before issuing a swap address. They need no `wallet` feature.
