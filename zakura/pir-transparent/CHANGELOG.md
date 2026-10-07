# Changelog

## [Unreleased]

### Added

- Txid display lookups: re-exports of wallet-pir's `transparent-txid-client`
  (`TxidDisplayClient`, `TxidTransport`, `TxidRequest`, `TxidReply`, `TxidLookup`, `TxidError`,
  `TransparentDisplayRecord` and related types), `display_facts`, which maps a found record to
  the wallet's `TransparentDisplayFacts`, `deferral`, which maps a lookup that found nothing to
  a `TransparentDetailOutcome`, and `map_sha256`, which decodes the client's map digest.

### Changed

- wallet-pir is pinned to `7ed5c87d`; every wallet-pir dependency moves together.

- `SCHEMA` (`transparent-shard-v11`), the only shard schema the adapter reads.
- `RecoveryBatch::retired_revisions()`, exactly the retired provisional
  revisions a `Ready` batch resolves: each was exported by an earlier batch, is
  no longer published, and has a successor for its source at a higher lineage
  among the batch's commits. They are notifications, not authority to withdraw
  wallet evidence, and stay recorded in the companion until acknowledged, or
  until `RecoveryError::PublicationChanged` drops their source, after which no
  successor can resolve them.
- `ReferenceRecovery::acknowledge_reconciled`, the caller's confirmation that
  it applied a `Ready` batch's commits through the wallet's trusted operation
  (`qualify_and_apply_transparent_ledger_commit`), which resolves the batch's
  retired revisions; the adapter cannot verify that wallet transaction.
  `acknowledge_applied` refuses any batch with retirements. Both refuse a
  `Pending` or `Withdrawn` batch and the receipt of an earlier pass. The
  trusted operation requires `PrivateRequired`; without it, a batch with
  retirements is never acknowledged, and each later pass that sees a new
  revision of a retired source lists one more.
- `Progress { covered_through, outcome }` and `Outcome { Complete, Behind,
  More, Overloaded, Stalled }`, the adapter's own report of a pass.
- Re-exports of `ChainView`, `FilterSource`, `ShardTransport`, `ShardRequest`,
  `Table`, `refusal`, `StaleRevision`, `Overloaded` and `BoxError`, so an
  application can implement its transports without naming wallet-pir crates.
- `WalletChain`, a `ChainView` over the blocks a wallet scanned
  (`WalletRead::get_block_hash`) that answers only through the watch set's
  target and is `Unknown` above it or where the wallet holds no block.
- `BatchState { Ready, Pending, Withdrawn(WithdrawnCause) }`,
  `WithdrawnCause { Regression, Equivocation, ChangedSealed, Retired }` and
  `RecoveryBatch::state`. Commits are returned, and a batch can be
  acknowledged, only when the state is `Ready`.
- `RecoveryError::PublicationChanged`, raised only by a check before the sync,
  for a shard map whose set identity no longer continues the one the
  companion's store is bound to. The pass first resets the companion in one
  transaction: every store table is emptied but the schema version, catalog
  rows whose source the map no longer names lose their export mark, forgetting
  any unacknowledged retirements among them, and the catalog is kept, so each
  source keeps its highest lineage. Retry once with the same companion. A map
  under another set ending below the store's anchor, which the chain view
  still accepts, is instead a `Pending` batch with `Outcome::Behind`, and the
  store is kept.
- A completion-only commit for each page the wallet holds under a source the
  map no longer names, once the batch covers the page's range under the map's
  sources.
- An end-to-end test of private recovery against an in-process
  `transparent-shard-server` that records every request; see the README. Its
  shard service is a development dependency only, and the crate leaves the
  `default` development lane: the `transparent-pir` lane runs its tests and
  `zakura-graph` checks its library without features.

### Changed

- `ReferenceRecovery::recover` takes the caller's `FilterSource` and
  `ShardTransport` for each pass. Before any retrieval it checks the target,
  the script limits, that the filter source does not use parent filters, the
  shard limit, and that the service's init names `SCHEMA`.
- `RecoveryConfig::origin` replaces `filter_origin` and `shard_origin`. It is
  an identity label and is never dialed. The companion binding now covers the
  source, account binding, origin and `SCHEMA`, so companions created before
  this change are refused at open and must be recreated.
- `RecoveryBatch::progress` replaces `report`. The companion classifies the
  exported revisions a map no longer publishes itself, and a batch lists only
  those its commits resolve; their export intents stay in the companion until
  trusted reconciliation is acknowledged or a publication change drops their
  source.
- The wallet-pir crates move to `648264bb4801ae8faf7a61f4638ea049edb167cf`,
  whose client accepts maps and manifests that carry txid display fields.
- `recover` refuses, before the service's init, a shard map whose network or
  genesis block is not Zcash mainnet's.
- A pass needs the chain view only from the watch set's floor, its lowest
  required height. Shards ending below it are neither exported nor cataloged,
  and the reference client may roll back below it without a wallet hash, so a
  map that starts at genesis serves a wallet with a later birthday. A watch set
  with no addresses sends no request and completes at its target.
- When the publication ends below the target, a pass syncs to the map's end if
  that end is at or above the floor, the chain view accepts its terminal block,
  and the companion holds no anchor or event above it. Completing there reports
  `Outcome::Behind` with `covered_through` at the map's end, and the commits
  keep the watch set's context. A pass that cannot clamp, as for a wallet born
  above the map's end, also reports `Behind`, including on a companion no
  earlier pass has bound.
- Revision identities are stable across companions. `source` covers the
  companion binding, the set-identity fields that never change while the
  publication continues, the shard's geometry and that geometry's seal
  parameters, the shard id and the shard's start height, so a new geometry tier
  changes no existing source, while reusing an id for a different height range
  gives that range a new source. `revision` covers the manifest digest and seal
  state, and `lineage` is the published revision number plus one instead of a per-companion
  counter, so a recreated companion reproduces the wallet's triples.
- Companions are format `transparent-reference-companion-v2`, with a
  `pir_bridge_catalog` table. Earlier companions are refused at open with
  `companion format v1; recreate`.
- A pass builds its batch from the shard map its sync finished with and fetches
  no second map.
- A lagging unsealed revision (also below a revision seen sealed), a map
  missing a shard, stored facts naming a revision the map no longer names, a
  shard ending on a block the chain view does not hold, or an exported tail
  without a retrieved successor make the batch `Pending` instead of failing
  the pass. So does every `MapDiverged` from the reference client's sync (a
  shard with pending pages withdrawn, or a mid-pass refresh that does not
  continue the first map), with `Outcome::Behind` and no claimed coverage, and
  a pass on a reset store that stops before binding it while the catalog still
  records exported revisions. A sealed regression, an equivocating revision, a
  changed sealed revision or a retired shard make it `Withdrawn`.
- A revision an earlier batch exported is left out of a batch while it opens a
  page the watch set does not hold, since the wallet may already cover that
  range, as after a store reset.
- Each pass prunes the catalog to published, exported and per-source newest
  rows, the store's filter and setup caches to revisions the map names, and
  the store's commit log to its last entry.

### Removed

- `transparent-shard-v10` support.
- `RecoveryConfig::{schema, timeout, response_bytes}`, the `observer`
  argument of `recover`, and the adapter's fixed HTTP user agent.
- `reqwest` from the normal dependency graph. Only the `recover-activity`
  example builds the reference HTTP transports.
- The companion's `lineage` binding key, its `pir_bridge_revisions` table and
  the 65,536-revision catalog limit.
