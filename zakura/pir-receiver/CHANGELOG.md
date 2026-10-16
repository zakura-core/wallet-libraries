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
- `begin_early_restore`, `EarlyRestore`, `LookedUp`, `FIRST_WINDOW`, `GAP` and `MAX_KEYS`,
  behind the `wallet` feature: before a restore scan, registers an account's one-time keys
  from a publication's public filters, then looks up only the paid ones while the scan runs,
  so the wallet finds each payment as the scan covers its block.

### Changed

- Builds on the library's `zakura-receiver-directory` and `zakura-receiver-pir`
  instead of wallet-pir's receiver crates, re-exported as `receiver_directory` and
  `receiver_pir`. Their lookups return records checked structurally only, so the
  sweep validates receivers, every looked-up payment and the common witness file
  with `zakura-receiver-crypto`; refusals keep their directory errors. Only the
  records of the looked-up receiver are checked cryptographically; other records
  sharing a row are parsed structurally. A forged payment is refused after its
  lookup reads every page its record declares, up to the client's page limit,
  rather than at the first page. The re-exported crates return unchecked data.
