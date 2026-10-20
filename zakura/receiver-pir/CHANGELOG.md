# Changelog

## [Unreleased]

### Added

- Fetch rolling block-filter availability and bounded batches independently of PIR sessions through the caller-owned transport.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use receiver directory, PIR client and server crates `0.0.1-rc2`.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Use the updated receiver directory, PIR client and server release candidates
  for the Common `4.0.0-rc3` dependency family.

## [0.0.1-rc0] - 2026-10-19

### Added

- The crate, moved from wallet-pir's `receiver-pir` at main 6703f263, using the native helpers in `zakura-pir-client`.

### Changed

- `transport::DirectoryClient` reads histories over PIR only, one page per query with
  `DirectoryClient::page`. The row file, `prefer_directory_file`, `MAX_PIR_PAGES` and
  `use_file_for_work` are gone, and `connect_manifest` no longer takes a lookup count.
