# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc9.5] - 2026-10-26

### Changed

- Use backend and SQLite `0.1.0-rc9.5` for the Zakura backend.

## [0.1.0-rc9.4] - 2026-10-23

### Changed

- Use backend and SQLite `0.1.0-rc9.4` for the Zakura backend.

## [0.1.0-rc9.3] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use backend and SQLite `0.1.0-rc9.3` and PCZT `0.1.0-rc9` for the Zakura backend.

## [0.1.0-rc9.2] - 2026-10-20

### Changed

- Use backend and SQLite `0.1.0-rc9.2` and PCZT `0.1.0-rc8` for the Zakura
  backend, including the new scan helpers and NU7 wallet acceptance checks.

- Updated the published Zakura Common dependency family to `4.0.0-rc3`.
  Compatible newer releases are allowed so consumers can share Common packages
  with the node libraries without matching exact dependency pins.

## [0.1.0-rc9] - 2026-10-19

### Changed

- Updated the Zakura Common dependency family to `4.0.0-rc2`, including the
  Orchard backend and proof API changes. The Zakura backend no longer enables
  the removed `unstable-voting-circuits` feature.

- Update the Zakura backend and SQLite dependencies to `0.1.0-rc9.1` and
  PCZT to `0.1.0-rc7`, including one-time key discovery and NU7 block-spacing support.


## [0.1.0-rc8] - 2026-10-14

### Changed

- Updated the Zakura Common stack to 3.0.0, including the shared note-encryption
  fork, and raised the minimum supported Rust version to 1.97.
- Updated the selectable upstream backend to the prerelease family using
  stable bip32 0.6 so both backends can resolve in the same workspace lockfile.

- Update the Zakura backend and SQLite dependencies to `0.1.0-rc9`, including
  one-time incoming keys and the private recovery and receipt retry changes.
- Update the PCZT dependency to `zakura-pczt 0.1.0-rc6` for Common 3.0.0.

## [0.1.0-rc7] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Changed
- Updated the Zakura PCZT dependency to `zakura-pczt 0.1.0-rc5`.
- Pinned the Common v2 dependencies exactly so a fresh consumer cannot select
  `2.1.0` while this facade requires the `2.0.0` family.
- Updated backend and SQLite dependencies to `0.1.0-rc8`.

## [0.1.0-rc6] - 2026-09-27

### Changed
- Updated the Zakura backend and SQLite dependencies to `0.1.0-rc7`.

### Removed
- The facade's unused `zakura-pir-enhance` feature. Enhance PIR APIs are now
  always present in the backend and are included with SQLite Orchard storage;
  applications still depend on the `zakura-pir-enhance` client directly.

## [0.1.0-rc5] - 2026-09-09

### Changed
- Updated the complete Zakura cryptography stack to the stable 1.2 release
  family.
- Updated the Zakura wallet crates to `zakura-pczt 0.1.0-rc3`,
  `zakura-client-backend 0.1.0-rc5`, and
  `zakura-client-sqlite 0.1.0-rc5`.

## [0.1.0-rc4] - 2026-08-28

### Changed
- Updated the Zakura cryptography stack to the stable 1.0 release family.
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
