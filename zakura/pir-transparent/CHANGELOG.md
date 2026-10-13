# Changelog

## [Unreleased]

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

- `PassPlan::next` ends the sync after every counted pass, including publication
  lag and capacity refusals, with `Step::Done` and its retry. A grown address
  window, changed watched addresses and `Retry::More` no longer start another
  pass at once; they continue at the next sync. A service that forges a receive
  near the end of the window can no longer tell from the wallet's next requests
  whether its directory row was the one forged.
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
- Depend on the transparent PIR crates from wallet-pir's `main` at `4bbcb697`
  (`0.1.0-rc.4`, not yet on crates.io), which fails one entry rather than the sync
  for bad row content. Previously `=0.1.0-rc.3` from crates.io.
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
