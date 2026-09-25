# Changelog

## [Unreleased]

### Added

- Optional `native-reinspiring` feature selecting the experimental native
  two-mask protocol `ironwood-enhance-pir-v9-native-two-mask-m29` at compile
  time (49-bit queries, 22-bit responses, 29-bit published masks, one uploaded
  `K_g` key per request). The default build still speaks v7 only; unit tests
  pin the v7 `parameter_id` and request length so the switch cannot move the
  supported wire contract.
- `types::session_public_len`, `types::response_len` and (under the feature)
  `types::request_len` give exact protocol lengths for a shard.

### Changed

- `ipir-sp` now comes from the `valargroup/ipir-sp` git tag `v0.1.0-rc.6`
  instead of the `=0.1.0-rc.3` crates.io release. The v7 wire contract is
  unchanged.

### Fixed

- An expired client now reports HTTP 410 from every query entry point.
  `query_positions_with_cover` previously returned 409 after expiry, while
  `query_batch` and `query_dummy` returned 410. A live client that is merely
  due for a routing refresh still reports 409.
- Cover-traffic and dummy queries now apply the same response-length cap as
  batch queries when a custom `Transport` returns a body larger than the
  request's limit.

### Removed

- The `https-client` feature, `EnhancePirClient`, `PendingEnhancePirClient`,
  `transport::ReqwestTransport`, `ClientError::Http`, and the `reqwest`
  dependency. The crate now has no default features; applications supply their
  own `transport::Transport` implementation.
- Unused `types::QueryShard::locate` (use `Coverage::locate`),
  `types::RETAINED_GENERATIONS`, `types::ROW_PAYLOAD_BYTES`, and the
  write-only `Lifecycle::identities` and `Lifecycle::next_id` fields.
  `Lifecycle::coverage` now takes `&self`.

## [0.0.1-rc0] - 2026-09-24

Initial release candidate for the mainnet Ironwood enhancement client.

### Added

- Enhance v7 routing with canonical fixed storage domains, composed successor
  tails, schema-11 records, and the P16Q48 SimplePIR profile. Each row contains
  33 records of 653 bytes.
- Wallet acceptance of locally scanned anchors before session setup or routing
  rebinding, with configurable setup and session-cache limits.
- Reuse of unchanged public session material across routing and placement
  changes, with affected sessions invalidated by recovery epochs. Each query
  uses fresh randomness and a request ID in its 116-byte `EPQ7` binding.
- Bounded HTTPS transport, lazy session loading, row-deduplicated streaming
  queries, and optional wallet helpers for preserving request identities and
  grouping same-transaction row queries.
- Explicit routing refresh and expiry handling. HTTP 409/410 requires renewed
  wallet acceptance; HTTP 429/503 supports bounded application retries.
- Optional birthday-based cover traffic with randomized domain order, uniform
  rounds, and whole-round overload retries. Record validation errors do not
  change the scheduled traffic, and cancellation preserves observed expiry.

### Compatibility and privacy

- Requires an Enhance v7 server; older protocol revisions are rejected.
- Uses the published `ipir-sp = "=0.1.0-rc.3"` dependency with CUDA disabled.
- Cover traffic is opt-in. Timing, round counts, birthday coverage, and
  cross-interval intersection remain observable; ordinary queries also reveal
  the queried domains and row counts.
- Record decoding validates encoding. Wallet note authentication and stale
  request checks remain required; transaction metadata and some send-only
  associations require trust in the server.
