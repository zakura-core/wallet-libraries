# Changelog

## [Unreleased]

## [0.0.1-rc3] - 2026-10-14

### Added

- `PreparedWork::waiting` counts positions not yet due
  (`EnhancePirWork::Waiting`). They are not queried, and work with waiting
  positions is incomplete, as with suspended ones.
- Rejected-position suspensions (`EnhancePirSuspension::Rejected`) are counted
  as incomplete and are not queried, like other suspensions.
- `PreparedWork::batches_by_tx_and_row` documents reporting a batch whose
  record bytes fail to decode with
  `EnhancePirWrite::record_ironwood_enhance_unreadable`, and never reporting
  request failures.
- `PreparedWork::requests_in_row(txid, row)` returns the requests of one
  `batches_by_tx_and_row` batch, so a caller holding only the transaction and
  row of an undecodable reply can report it.
- The rejection cap counts per `EnhancePirSession` (in `zakura-client-sqlite`),
  in memory. Callers keep one session per wallet for the app's lifetime; a new
  session, such as after an app restart, restores the full allowance.

### Changed

- Update the wallet backend and SQLite dependencies to `0.1.0-rc9`.

## [0.0.1-rc2] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Added

- `native` re-exports `prepare_dithered`, `DITHERED_QUERY_BITS` and
  `request_len_bits` from `zakura-pir-native`.

### Changed

- Depend on ipir-sp `0.1.0-rc.7` (with `reinspiring 0.1.3-rc.1` and
  `inspiring 0.1.0-rc.3`), the release the published transparent PIR crates
  use. ipir-sp keeps every setup ID, wire layout and certificate unchanged.

- Updated the shared enhancement record and native PIR dependencies to
  `0.0.1-rc1`, and the wallet backend and SQLite dependencies to `0.1.0-rc8`.

- Queries upload a selection dithered to 44 bits instead of rounded to nearest
  at 49 bits, so a 32,768-row request shrinks from 228,468 to 207,988 bytes.
  `NativeSession::prepare` and `types::request_len` follow. The protocol
  revision, `parameters()` (`query_bits = 49`) and parameter IDs are
  unchanged. Requires a server that accepts 44-bit requests; earlier servers
  reject them by length.

- Growing shards upload only the rows their published capacity can hold,
  rounded up to 2,048-row blocks. For 18,313 used rows, a request is 129,140
  bytes instead of the full 207,988 bytes. The length depends on public shard
  capacity; real and cover queries for the same shard have the same length.

## [0.0.1-rc1] - 2026-09-27

### Added

- Native two-mask protocol `ironwood-enhance-pir-v9-native-two-mask-m29`
  support (49-bit queries, 22-bit responses, 29-bit published masks, one
  uploaded `K_g` key per request).
- `types::session_public_len`, `types::response_len` and
  `types::request_len` give exact protocol lengths for a shard.

### Changed

- The protocol-neutral native primitives (`params`, `public_query_masks`,
  `prepare_with`, `decode_cols` and the length helpers) moved to the new
  `zakura-pir-native` crate and are re-exported from `native` unchanged.
- The client now speaks v9 exclusively. The `native-reinspiring` feature and
  the legacy v7 implementation and fixtures have been removed.
- `ipir-sp =0.1.0-rc.6` and `reinspiring =0.1.2` now come from crates.io
  instead of the `=0.1.0-rc.3` crates.io release.

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
