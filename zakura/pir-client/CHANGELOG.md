# Changelog

## [Unreleased]

## [0.0.1-rc4] - 2026-10-26

### Changed

- Enhance and Status requests use the canonical `/enhance/v1` and `/status/v1`
  product routes under the configured server base.
- Use PIR protocol and server crates `0.0.1-rc4` and SQLite `0.1.0-rc9.5`.

- Transparent clients address only the canonical `/transparent/v1` routes:
  `/v2/<route>` becomes `/transparent/v1/<route>` (shard map, filters, init,
  manifests, setup, queries and txid display), and `/v1/filters/<route>` and
  `/v1/health` move below `/transparent/v1`. Nothing falls back to a legacy
  route. `HttpShardTransport`, `HttpFilterSource` and the filter
  `HttpTransport` validate their base with `Endpoint::parse` and keep its path
  prefix. `ShardRequest::route`, `HttpRequest::path` and `TxidRequest::path`
  are origin-relative paths below the namespace.
- Receiver requests use `{base}/receiver/v1/<operation>`, preserving the configured
  base path. Invalid bases fail with `receiver::session::Error::Endpoint` before
  any request; clients do not fall back to `/v1/receiver/...`.

### Added

- `receiver::lookup_pages`, a one-time IVK lookup step that reads at most a caller-chosen
  number of pages. A wallet on a slow transport can record progress through an address
  with many payments in one segment instead of timing out and starting over.

## [0.0.1-rc3] - 2026-10-23

### Added

- The `receiver` product: `receiver::{Client, WitnessClient}` and `receiver::transport`,
  which read payment rows, witness payloads, inventories and filters over a caller-owned
  transport.
- The `receiver-wallet` feature: `receiver::{publication, lookup, witness, screen}`, the
  bounded network steps the wallet recovery queue consumes.

### Changed

- Use PIR protocol and server crates `0.0.1-rc3` and SQLite `0.1.0-rc9.4`.

### Removed

- `zakura-receiver-pir` and the unpublished `zakura-pir-receiver` are removed; their
  client, transport and wallet steps live here. `zakura-pir-receiver`'s `DirectoryError`
  is `receiver::session::Error`.

## [0.0.1-rc2] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use PIR protocol and server crates `0.0.1-rc2` and SQLite `0.1.0-rc9.3`.

## [0.0.1-rc1] - 2026-10-20

### Changed

- Update to the Common `4.0.0-rc3` dependency family and the matching protocol,
  server and wallet release candidates. Optional wallet and SQLite integrations
  use backend and SQLite `0.1.0-rc9.2`.

## [0.0.1-rc0] - 2026-10-19

### Added

- Consolidated Enhance, Status and Transparent clients with explicit product
  features and opt-in wallet, SQLite, recovery and HTTP transport capabilities.
- Native helpers used by receiver PIR without enabling other products.

### Compatibility

- Replace the former product-specific package imports with role-based modules.
  Engine-store schema 7, recovery companion v3 and Transparent shard v12 are
  unchanged. Wallet validation is still required before recovery results affect
  wallet state.

## pir-enhance history

# Changelog

## Changes carried into consolidation

### Added

- `testing` feature (off by default) with `testing::IronwoodOutputFixture`, a
  deterministic synthetic Ironwood output built from fixed public test seeds,
  and byte-level `testing::decrypt_incoming` / `testing::recover_outgoing`
  checks, so services can authenticate PIR-returned records without depending
  on Orchard or note encryption directly.

## [0.0.1-rc4] - 2026-10-16

### Changed

- Require native PIR `0.0.1-rc2`, including the canonical protocol primitives moved into this repository.

### Removed

- `PreparedWork::waiting`, following removal of the randomized first-query delay.
  Suspended work still counts as incomplete.

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

## pir-status history

# Changelog

## Changes carried into consolidation

## [0.0.1-rc2] - 2026-10-16

### Changed

- Require native PIR `0.0.1-rc2`, including the canonical protocol primitives moved into this repository.

## [0.0.1-rc1] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Changed

- Queries upload a selection dithered to 44 bits instead of rounded to nearest
  at 49 bits, so a request body shrinks from 77,876 to 72,756 bytes. The
  protocol `status-pir-v3-native-two-mask-m29`, the `SPN1` magic and the
  session material are unchanged. Requires a server that accepts 44-bit
  requests; earlier servers reject them by length.

- Updated the native PIR dependency to `0.0.1-rc1`.

## [0.0.1-rc0] - 2026-09-27

Initial release candidate for private transaction-status observation.

### Added

- The `status-pir-v3-native-two-mask-m29` row format and transport-neutral
  client.
- Wallet-verified anchor acceptance, bounded clock-skew checks, and exact
  request, session, and response length validation.
- Coverage-aware observations that keep absent records inconclusive without a
  conservative earliest-inclusion bound.

### Security

- Status rows and coverage are server assertions, not inclusion proofs.
  Applications must reconcile observations with wallet-verified chain state.

## transaction-status history

# Changelog

## Changes carried into consolidation

### Added

- A default-enabled `lightwalletd` feature. Disabling default features keeps
  status policy available without the wallet backend or gRPC transport.

## [0.0.1-rc3] - 2026-10-16

### Changed

- Require private Status PIR `0.0.1-rc2`, which carries the updated native PIR dependency.

## [0.0.1-rc2] - 2026-10-14

### Changed

- Update the wallet backend dependency to `0.1.0-rc9`. Status routing and
  observation behavior are unchanged.

## [0.0.1-rc1] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Added

- `lightwalletd::observe_response` accepts a response from an application's
  authorized transport while retaining cancellation, timeout, transaction ID
  and payload validation. It never retries or falls back to another source.

### Changed

- Updated the private status protocol dependency to `0.0.1-rc1` and the wallet
  backend dependency to `0.1.0-rc8`.

## [0.0.1-rc0] - 2026-09-27

Initial release candidate for policy-bound transaction status observation.

### Added

- `StatusReader`, which selects one public or private status source per batch
  without cross-source fallback.
- A lightwalletd source that validates the transaction ID returned by
  `GetTransaction` and discards the transaction payload.
- Typed source-opening, observation, transport, and local-storage errors.

## pir-transparent history

# Changelog

## Changes carried into consolidation

### Fixed

- Retain maps adopted during facade synchronization and consume cached map receipts once. HTTP retries preserve all delivered response bytes, including partial and failed attempts.
- Reject aggregate-value overflow before either engine store changes events, coverage or commit markers, and handle inclusive coverage through the largest height without wrapping. No SQL schema, version or migration changes are required.
- Preserve unsent page-cover queries across query/byte budgets, outages and SQLite reopen. The existing pending-work JSON gains an optional cover obligation; existing schema-7 records remain readable and no SQL schema, version or migration changes are required. Failure holds begin only after the cover queries finish.
- Verify a sealed manifest before promoting provisional coverage, and retain previously bound seal parameters when a publication temporarily omits a geometry.
- Include newly watched scripts in early progress, retain unproductive counts in mixed shards, and charge prefetched filters and manifests when transferred even if their replies are later discarded.
- Reject recovered balances and transaction totals that overflow, including historical prefixes retained after rollback.

### Changed

- Custom engine stores must round-trip `PendingPages::dummy_queries` with their existing pending state. Eager `FilterSource` implementations can override `prefetch_charged` to report transfer costs before replies are consumed.

## [0.0.1-rc2] - 2026-10-16

### Fixed

- Refuse a SQLite engine store whose metadata lacks a schema version, or whose store tables lack the metadata table, before changing its journal mode, tables or rows; admission is repeated under the write lock. Unrelated tables sharing the file still open as a fresh store.
- Hide a script's recovered activity only for a content failure under the same shard revision, so a replacement read in the same sync still reports it to gap-limit discovery; failures under the withdrawn revision stay reported.
- Prune filter and setup caches of revisions the validated map no longer publishes during every engine sync, for both reference stores; cached runs and content failure counts are kept. `WalletStore` gains the required `prune_caches` method.
- Match settled coverage cut short of its shard by a target or rollback against the exact publication it was read from. A same-chain silent replacement is refused as a sealed rewrite, an exact re-cut declaration keeps it, a republication on a fork above the covered part re-derives it, and an endpoint the chain cannot check yet defers the sync.
- Scope content failure holds to the exact shard revision so a re-cut can reuse numeric shard ids without inheriting another shard's failures. Pending-work housekeeping preserves those holds; legacy counters with no proven revision binding do not hold a current revision.
- Complete empty-script recovery at its accepted target while retaining conservative progress when scripts are added or preflight stops early.
- Charge failed and already dispatched private query attempts, including observed refusal bytes, before handling retries or decoding batch responses. Private HTTP setup and query calls make one physical attempt so wallet work limits govern retries; failed setup response bytes consume the private allowance.

- Report retained coverage after reopening, early sync stops, script additions and rollback by recomputing it from saved script ranges.

- Apply the same checked event encoding to unfinished work and cached runs in both reference stores before accepting a commit.

- Refuse contradictory receives or spends within one store commit before writing anything, while accepting identical repeated observations.

- Reject invalid event encodings before changing either wallet store, including unfinished walks and cached page runs.

### Changed

- Refuse unsupported shard-map versions before storing refreshed maps or advancing sync, including an already complete wallet.

- A publication ending below the wallet's target retains its public retry wait
  even when private content, a work budget or a contradiction prevents the pass
  from completing. An overload preserves its longer wait. Coverage and failed-entry
  counts are unchanged, so the content-aware retry and hold policy still apply.

## [0.0.1-rc1] - 2026-10-14

### Added

- `FailedEntries`, `RecoveryBatch::failed_entries` and `PassReport::failed_entries`:
  the directory entries (one watched script in one shard) whose private replies
  failed on content in a pass, counted, and how many of them are at three failures.
- `HoldCause::FailedEntries`: `PassPlan::next` holds an account once one of its
  entries has failed on content three times, after settling the pass.
- `testing::service::ShardSpec::malformed_entries`: scripts whose directory entry the
  test service publishes malformed.

### Removed

- `PassLimits::passes`: a plan runs one counted pass per sync, so it has no pass
  count left to bound.
- `Step::Wait`: retry delays schedule the next sync instead of another pass in
  the current sync. Callers use `Step::Done(Some(Retry::After(delay)))`.

### Changed

- Update the wallet backend and SQLite dependencies to `0.1.0-rc9`.

- `PassPlan::next` ends the sync after every counted pass, including publication
  lag and capacity refusals, with `Step::Done` and its retry. A grown address
  window, changed watched addresses and `Retry::More` no longer start another
  pass at once; they continue at the next sync. A service that forges a receive
  near the end of the window can no longer tell from the wallet's next requests
  whether its directory row was the one forged.
- A restore whose used addresses and their trailing unused-address gaps fit in
  the wallet's restore window (with `zakura-client-sqlite`, 50 external and 25
  internal addresses) completes in one sync instead of one sync per window step. The window is fixed in the wallet and
  never follows replies.
- The recovery example ends its bounded run when a pass reports lag or overload,
  leaving its saved continuation for a later invocation instead of waiting forever.

- A private row whose content fails to decode or check out, or a record that
  contradicts the companion, fails one directory entry instead of the pass: everything else the sync
  read settles, and the account stays uncovered and inactive. A pass with failed
  entries is `Retry::Stalled`, so a failed entry is asked again only at the next
  sync, and the companion stops asking after three failures. A content failure the
  reference client cannot lay at one entry is no longer `PassError::Failure`: what
  the sync committed settles, as `Outcome::Stalled`. `Outcome::Stalled` now also
  covers `IncompleteReason::ContentFailed`. A reply whose length, revision binding
  or parameter epoch does not verify still fails its request, and the pass.
- The companion's reference store is format 7, which counts content failures per
  entry. A format-6 companion upgrades in place: an empty failure-count table
  and the format marker are added atomically, preserving recovery history,
  coverage, unfinished work and catalog evidence. A publication change that
  resets the store keeps the counts.
- Depend on the transparent PIR crates from crates.io at `=0.1.0-rc.4` (tagged
  `transparent-v0.1.0-rc.4` in wallet-pir), which fails one entry rather than the
  sync for bad row content. Previously `=0.1.0-rc.3`.
- Txid lookups read the 4,096-row display tables the `/v2/txid` service now
  publishes; earlier clients refuse them. History recovery is unchanged.
- The `testing` fake txid display publication and the txid end-to-end test use
  `txid-4k8` (4,096 rows, a 180,000-entry recent window), the geometry
  production serves.
- `deferral` maps an HTTP refusal (`TxidError::Refused`) and every
  `TxidError::Protocol` kind except `ProtocolKind::Decode` (a bad init
  document, map, map header, manifest, profile, setup, reply framing, epoch,
  length or unexpected status) to `Unavailable` instead of `Protocol`: the
  service chooses those without knowing the row, so they are not content
  failures and do not count toward the wallet's cap of three.
- `DetailRun::record` defers any public answer under a snapshot without public
  transport as `Unavailable` (a public transaction was `Protocol`, a public
  failure its own outcome): it comes from the caller racing a mode change, not
  from a private reply.

## [0.0.1-rc0] - 2026-10-13

Initial release candidate for transparent PIR discovery, recovery and receipt
lookups. See the [README](README.md) and
[wallet integration guide](../../docs/transparent-pir-wallet-integration.md).

### Packaging

- Include the MIT and Apache license texts in the crate package.

### Added

- Transport-neutral private discovery and `TransparentHistoryRecovery` over
  caller-derived address watch sets. Applications own HTTP routing, timeouts,
  cancellation and body limits through `HttpExchange`.
- `WalletChain` checks publication anchors against locally scanned mainnet
  blocks. Wrong networks and genesis blocks are refused before service setup;
  empty watch sets send no request.
- Bounded recovery passes, stable revision identities, companion stores, opaque
  recovery batches and typed ready/pending/withdrawn outcomes. Missing or lagging
  publication data grants no coverage or financial authority.
- A shared pass driver with explicit retry, refresh, skip and stop decisions.
  Publication changes reset the companion's reference store and retry once;
  catalog lineage remains available to detect conflicting publications.
- SQLite settlement with explicit observed/trusted evidence and a caller-owned
  write gate. Each wallet commit is atomic; acknowledgment follows durable
  application of every commit. Interrupted settlement preserves replay, stale
  commits refresh within bounds, and policy changes stop private recovery.
- Declared re-cut handling that preserves sealed histories and source identities
  across shard renumbering. Undeclared sealed rewrites are withdrawn; exported
  revision identities remain recorded after catalog pruning.
- `CompanionDir` with origin/schema-bound names, per-companion operating system
  locks, pruning and deletion. `forget_private_recovery` removes companions and
  private-only wallet facts under public policy with generation checks.
- Import-time address discovery over publication filters with private confirmation
  of every match. Filters and the map are reused across bounded passes while new
  candidates are confirmed; false positives are not returned.
- A shared `TxidDisplayService`, HTTP adapter and `DetailRun` for bounded private
  receipt lookups, preferred work, display-map refreshes and guarded writes.
  Timed-out attempts back off; explicit run cancellation writes nothing.
- Feature `testing` with synthetic batches, display publications and an in-process
  real shard publisher/server for application integration tests.
- A `recover-activity` example using the SQLite pass driver.

### Protocol and storage

- Supports `transparent-shard-v12` with decoupled directory/page shards and
  recent `decoupled-2k-8k` / archive `decoupled-32k-32k` geometry. The txid
  display client uses the one-query `txid-4k8` layout (and the earlier
  `txid-2k8`) at the 8-bit profile under its own native schema,
  `transparent-txid-display-p8-v1`; it reports a `/v2/txid` served at the
  earlier 16-bit profile as unsupported.
- Checked partial page walks survive restarts and enforce query/byte limits
  between requests. Verified run caches let catch-up stop at cached history.
- Directory, page and archive history queries use the 8-bit one-digit profile
  with 28-bit queries. This profile does not use 44-bit dithering or a 49-bit
  fallback. Published prefix dimensions shorten growing-tail page queries
  without depending on the privately selected row.
- Discovery, history recovery and receipt lookups use the `/v2` HTTP API.
  Applications must supply a service that supports these paths and profiles.
- The reference store is format 6; earlier prototype stores must be recreated.
  Companion names bind the shard schema, so v12 does not reuse v11 companions.
- Git dependencies remain pinned to one wallet-pir revision and now declare
  registry versions. Publication requires those upstream implementations first.

### Removed during development

- Earlier shard schemas and prototype recovery names, mutable batch fields,
  public acknowledgment shortcuts and the ungated settlement wrapper. Use
  `settle_latest` or `apply_and_acknowledge_gated` with `Ungated` as appropriate.
- Built-in production HTTP clients; applications provide the authorized transport.
  `reqwest` remains only for examples and tests.
