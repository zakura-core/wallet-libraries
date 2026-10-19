# Changelog

## [Unreleased]

## [0.0.1-rc0] - 2026-10-19

### Added

- The crate, moved from wallet-pir's `receiver-pir` at main 6703f263, using the native helpers in `zakura-pir-client`.

### Changed

- `transport::DirectoryClient` reads histories over PIR only, one page per query with
  `DirectoryClient::page`. The row file, `prefer_directory_file`, `MAX_PIR_PAGES` and
  `use_file_for_work` are gone, and `connect_manifest` no longer takes a lookup count.
