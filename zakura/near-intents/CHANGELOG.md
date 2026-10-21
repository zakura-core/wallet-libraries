# Changelog

## [Unreleased]

### Added

- `NearStatus::origin_tx_hashes` and `NearStatus::destination_tx_hashes` carry the status response's `swapDetails` transaction hashes. `near_observation` reads an incoming key's receipts from the destination chain and a refund key's from the origin chain.

## [0.0.1-rc3] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use one-time IVK `0.0.1-rc3`.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use `zakura-one-time-ivk 0.0.1-rc2` and the compatible Common `4.0.0-rc3`
  protocol dependency.

## [0.0.1-rc1] - 2026-10-19

### Changed

- Use `zakura-one-time-ivk 0.0.1-rc1` and the current Common protocol dependency.

## [0.0.1-rc0] - 2026-10-14

### Added

- Add `NearStatus` and `near_observation`, which normalize a NEAR Intents
  1Click execution status into the `zakura_one_time_ivk::swap::Observation`
  that a one-time IVK store records.
