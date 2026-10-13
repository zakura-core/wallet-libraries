# Changelog

## [Unreleased]

### Changed

- Depend on the transparent PIR crates from crates.io (`=0.1.0-rc.3`, tagged
  `transparent-v0.1.0-rc.3` in wallet-pir) instead of a git revision.
- Txid lookups read the 4,096-row display tables the `/v2/txid` service now
  publishes; earlier clients refuse them. History recovery is unchanged.
- The `testing` fake txid display publication and the txid end-to-end test use
  `txid-4k8` (4,096 rows, a 180,000-entry recent window), the geometry
  production serves.

## [0.0.1-rc0] - PLANNED

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
- A shared pass driver with explicit retry, wait, refresh, skip and stop decisions.
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
