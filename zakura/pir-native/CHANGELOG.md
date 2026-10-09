# Changelog

## [Unreleased]

### Added

- `prepare_dithered`, `DITHERED_QUERY_BITS` (44) and `request_len_bits`: a
  selection query rounded to 44 bits with a fresh coin per coefficient,
  rounding up with probability equal to the dropped fraction so rounding
  errors are independent and zero-mean. `prepare_with` and `request_len`
  still produce and measure the unchanged 49-bit request.

### Changed

- `test_server::Database::answer` accepts both 49-bit and 44-bit requests,
  telling them apart by exact length.

## [0.0.1-rc0] - 2026-09-27

Initial release candidate for the native two-mask PIR primitives shared by
Zakura protocol clients.

### Added

- Client-side query generation and response decoding for 49-bit queries,
  22-bit responses, and two 29-bit published masks.
- Exact request, response, and public-session length helpers.
- Optional `test-server` counterparts for protocol round-trip tests.
