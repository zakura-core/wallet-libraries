# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc4] - 2026-08-28

### Changed
- Made the Zakura wallet stack the default and kept LRZ as the explicit
  `default-features = false, features = ["lrz"]` alternative.
- Exposed Zakura dependencies under their clean upstream crate names while
  retaining `lrz-*` aliases for the upstream stack.
- Replaced the weak cross-family capability selectors with two complete
  backend modes: `zakura` and `lrz`. Each includes Orchard and the capability
  set required by `zcash_voting`, while keeping the unselected family out of
  downstream lockfiles and metadata.
- Pinned the RC5 Zakura family exactly so fresh downstream lockfiles cannot
  select newer RCs with a higher Rust version or incompatible type family.
- Updated the Zakura cryptography stack to the RC5 release family and raised
  the MSRV to Rust 1.91.

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
