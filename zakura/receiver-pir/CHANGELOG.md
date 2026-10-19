# Changelog

## [Unreleased]

- Add bounded public archive transport for block-filter heads, authenticated pages, complete seen objects and session coverage tied to archive epochs.

### Added

- The crate, moved from wallet-pir's `receiver-pir` at main 6703f263, over `zakura-pir-native`.

### Changed

- `transport::DirectoryClient` reads histories over PIR only, one page per query with
  `DirectoryClient::page`. The row file, `prefer_directory_file`, `MAX_PIR_PAGES` and
  `use_file_for_work` are gone, and `connect_manifest` no longer takes a lookup count.
