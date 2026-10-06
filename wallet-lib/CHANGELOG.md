# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Updated the Zakura PCZT dependency to `zakura-pczt 0.1.0-rc4`.
- Updated the Zakura backend to the Common v2 release family (`2.0`), at the
  revision that migrates it to `bip32 0.6`, `secp256k1 0.33`, and
  `zcash_script 0.6`. Transparent signing in the re-exported crates no longer
  takes a `secp256k1` context: `TransparentSignatureContext`,
  `Bundle<Unauthorized>::prepare_transparent_signatures`, and the transparent
  PCZT `Input::{sign, append_signature}` drop their context parameters, and
  `zcash_keys::keys::transparent::Key::{pubkey_with_context,
  der_encode_with_context}` are replaced by `pubkey` and `der_encode`. Until
  Common publishes that revision, consumers must declare the
  `[patch.crates-io]` table from this repository's `manifests/sources.toml`.
- Updated the LRZ backend to `zcash_client_backend 0.25.0-pre.1`,
  `zcash_client_sqlite 0.23.0-pre.1`, `zcash_keys 0.17.0-pre.1`,
  `orchard 0.16`, `pczt 0.10.0-pre.1`, and `zcash_primitives 0.31.0-pre.1`.

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
