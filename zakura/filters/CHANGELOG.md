# Changelog

## [Unreleased]

### Added

- `hash_to_range`, the shared BIP 158 SipHash-2-4 mapping used by encoding and
  wallet matching. It returns zero for a zero range; callers validate ranges.

### Changed

- `BitStreamReader`, `GcsFilterWriter`, `read_compact_size` and
  `write_compact_size` use `std::io` traits and errors instead of `bitcoin_io`.
  Custom readers/writers must implement the standard traits, or use the
  `bitcoin_io::ToStd` bridge in the caller. Existing slice/`Vec` callers need no
  change. Byte encoding, truncated-input consumption, interrupted-I/O retries
  and the previous `UnexpectedEof` result for zero-length writes are preserved.
- Use the existing `siphasher` dependency family for the same SipHash-2-4
  operation, removing the Bitcoin hash, I/O and consensus-encoding wrappers.

## [0.0.1-rc0] - 2026-10-19

### Added

- Shared filter codec used by PIR publication builders and clients. The package
  keeps filter formats separate from wallet orchestration and server operations.
