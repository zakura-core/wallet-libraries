# Changelog

## [Unreleased]

## [0.0.1-rc3] - 2026-10-16

### Changed

- Require private Status PIR `0.0.1-rc2`, which carries the updated native PIR dependency.

## [0.0.1-rc2] - 2026-10-14

### Changed

- Update the wallet backend dependency to `0.1.0-rc9`. Status routing and
  observation behavior are unchanged.

## [0.0.1-rc1] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Added

- `lightwalletd::observe_response` accepts a response from an application's
  authorized transport while retaining cancellation, timeout, transaction ID
  and payload validation. It never retries or falls back to another source.

### Changed

- Updated the private status protocol dependency to `0.0.1-rc1` and the wallet
  backend dependency to `0.1.0-rc8`.

## [0.0.1-rc0] - 2026-09-27

Initial release candidate for policy-bound transaction status observation.

### Added

- `StatusReader`, which selects one public or private status source per batch
  without cross-source fallback.
- A lightwalletd source that validates the transaction ID returned by
  `GetTransaction` and discards the transaction payload.
- Typed source-opening, observation, transport, and local-storage errors.
