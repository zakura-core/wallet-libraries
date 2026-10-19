# Changelog

## [Unreleased]

### Added

- The crate, moved from wallet-pir's `receiver-pir` at main 6703f263, over `zakura-pir-native`.
- `transport::DirectoryClient::fetch_catalog`, `fetch_bucket_index`, `fetch_bucket`,
  `fetch_paid` and `fetch_seen` download the catalog head a manifest commits to and
  the objects it names, from immutable routes by digest. `fetch_pinned_paid` downloads a
  cumulative paid set an earlier head named, which a wallet pinned.

### Changed

- `transport::DirectoryClient` reads histories over PIR only, one page per query with
  `DirectoryClient::page`. The row file, `prefer_directory_file`, `MAX_PIR_PAGES` and
  `use_file_for_work` are gone, and `connect_manifest` no longer takes a lookup count.
- Session IDs change with the directory manifest's new `catalog_sha256` field.
