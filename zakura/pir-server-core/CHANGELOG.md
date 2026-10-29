# Changelog

## [Unreleased]

## [0.0.1-rc4] - 2026-10-26

### Changed

- Use PIR protocol `0.0.1-rc4`.

## [0.0.1-rc3] - 2026-10-23

### Changed

- Use PIR protocol `0.0.1-rc3`.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use PIR protocol `0.0.1-rc2`.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Use `zakura-pir-protocol 0.0.1-rc1` with the Common `4.0.0-rc3` dependency family.

## [0.0.1-rc0] - 2026-10-19

### Added

- Shared hint and packing preparation used independently by publishers and
  query servers, with explicit Enhance, Status and Transparent features.

## pir-native history

# Changelog

## Changes carried into consolidation

## [0.0.1-rc2] - 2026-10-16

### Added

- The server-side operations of the profile, moved from wallet-pir's
  `pir-native` so one copy serves clients and servers: `Profile`, `P16` and
  the 8-bit `P8`; `hint`, `preprocess`, `publish`, `pack` and `response`;
  `parse_with`, `parse_bits`, `parse_accepted`, `parse_selection`,
  `accepted_query_bits` and `accepted_query_shape`; `prepare_dithered_with`;
  the `Entry` trait; re-exported `NativeKeys` and `NativePreprocessed`; and
  the `P_BITS`, `GADGET_BITS`, `ELL`, `INSTANCE_BYTES`,
  `BLOCK_PUBLIC_BYTES`, `BLOCK_RESPONSE_BYTES` and `PREPARED_*` constants.
  `Profile::public_query_masks` returns a refused shape as an error; the free
  `public_query_masks` still panics on one.

### Changed

- The free functions are wrappers over `P16`, and `test_server::Database`
  builds its hint, preprocessing, published masks and responses with the
  crate's server operations while keeping its own scalar scan. Request bytes,
  their randomness consumption, and response and published bytes are
  unchanged; `tests/golden.rs` pins them.

## [0.0.1-rc1] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Added

- `prepare_dithered`, `DITHERED_QUERY_BITS` (44) and `request_len_bits`: a
  selection query rounded to 44 bits with a fresh coin per coefficient,
  rounding up with probability equal to the dropped fraction so rounding
  errors are independent and zero-mean. `prepare_with` and `request_len`
  still produce and measure the unchanged 49-bit request.

### Changed

- Depend on ipir-sp `0.1.0-rc.7` (with `reinspiring 0.1.3-rc.1` and
  `inspiring 0.1.0-rc.3`), the release the published transparent PIR crates
  use. ipir-sp keeps every setup ID, wire layout and certificate unchanged.

- `test_server::Database::answer` accepts both 49-bit and 44-bit requests,
  including whole-block prefix selections over a zero tail. It identifies
  the query width and prefix length from the exact request length.

## [0.0.1-rc0] - 2026-09-27

Initial release candidate for the native two-mask PIR primitives shared by
Zakura protocol clients.

### Added

- Client-side query generation and response decoding for 49-bit queries,
  22-bit responses, and two 29-bit published masks.
- Exact request, response, and public-session length helpers.
- Optional `test-server` counterparts for protocol round-trip tests.
