# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Made the Zakura wallet stack the default and kept LRZ as the explicit
  `default-features = false, features = ["lrz"]` alternative.
- Exposed Zakura dependencies under their clean upstream crate names while
  retaining `lrz-*` aliases for the upstream stack.
- Replaced the weak cross-family `orchard` selector with explicit
  `zakura-orchard` and `lrz-orchard` combinations, preventing disabled
  packages from leaking into downstream lockfiles and metadata while retaining
  base backend modes without Orchard. The old `orchard` name remains a
  compatibility alias for `zakura-orchard`; `zakura-voting` and `lrz-voting`
  provide the complete capability sets required by `zcash_voting`.

## [0.1.0-rc3] - 2026-08-25

### Changed
- Updated the Zakura wallet backend to `zakura-client-backend 0.1.0-rc3`
  and `zakura-client-sqlite 0.1.0-rc3`, which prioritize scanning the Ironwood
  era before older history during wallet recovery.

## [0.1.0-rc2] - 2026-08-21

### Changed
- Updated the Zakura backend to the RC3 cryptography family through
  `zakura-pczt 0.1.0-rc1`, `zakura-client-backend 0.1.0-rc2`, and
  `zakura-client-sqlite 0.1.0-rc2`.

## [0.1.0-rc1] - 2026-08-19

### Added
- Added the selectable upstream and Zakura wallet backend facade.
