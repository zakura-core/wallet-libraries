# Changelog

## [Unreleased]

### Added

- Declared re-cuts. A sealed revision the shard map declares a re-cut
  superseded stays current, and facts stored under it are exported under the
  revision triple the wallet already holds; the renumbered shards and tail keep
  their sources, and the renumbered tail is listed as resolving the old one. A
  pass checks the declarations against the map (`Equivocation`, `Regression`)
  and, on the first stored fact under a declared revision, against the catalog
  (`Equivocation`). A ready pass over a re-cut map records its re-cut epoch
  once the store holds a fact under a revision the re-cut superseded, or under
  one the map publishes at or above the re-cut's first height, and a pass over
  a map with a lower epoch is `Pending` with `Outcome::Behind` before any
  retrieval, so a re-cut only rolls forward. The shard limit counts declared
  entries at or above the watch set's floor. Wallet pages under a superseded
  sealed revision are completed once the batch covers their range, in the
  revision's own commit when it has one. An undeclared change of sealed content
  never reaches the wallet.
- `pir_bridge_exports`, a never-pruned record of every revision a batch
  exported. A published or declared revision that differs from one exported at
  its source and lineage, or under its identity, is `Withdrawn(Equivocation)`,
  so a pruned catalog row cannot let a colliding revision reach the wallet.

- Txid display lookups: re-exports of wallet-pir's `transparent-txid-client`
  (`TxidDisplayClient`, `TxidTransport`, `TxidRequest`, `TxidReply`, `TxidLookup`, `TxidError`,
  the fixed-size `DisplayEntry` and related types), `display_facts`, which maps a found entry
  to the wallet's `TransparentDisplayFacts` after checking its tag is the txid's, `deferral`,
  which maps a lookup that found nothing to
  a `TransparentDetailOutcome` (a height above the publication is `NotYetPublished`, retried
  within minutes; below it is `NotCovered`), and `map_sha256`, which decodes the client's map
  digest. `TxidDisplayClient::refresh_map` re-checks coverage when only parked work remains.

- `SCHEMA` (`transparent-shard-v11`), the only shard schema the adapter reads.
- `RecoveryBatch::retired_revisions()`, exactly the retired provisional
  revisions a `Ready` batch resolves: each was exported by an earlier batch, is
  no longer published, and has a successor for its source at a higher lineage
  among the batch's commits. They are notifications, not authority to withdraw
  wallet evidence, and stay recorded in the companion until acknowledged, or
  until `RecoveryError::PublicationChanged` drops their source, after which no
  successor can resolve them.
- Optional `sqlite` integration: `ReferenceRecovery::apply_and_acknowledge`
  consumes an opaque batch and an owned SQLite wallet handle with an explicit
  `Trust` choice. It rejects an enclosing SQL transaction, applies commits
  using the wallet's durable transaction and quarantine rules, and acknowledges
  only after all commits reach wallet storage under the captured policy
  generation. Retirements require trusted reconciliation under
  `PrivateRequired`. `Applied` and `ApplyStats` report progress and the
  committed prefix; `ApplyError` and `ApplyFailure` report typed failures and
  preserve replay. No network request or spending authorization occurs here.
  `acknowledge_applied` remains available for batches without retirements and
  rejects non-ready batches and receipts from earlier passes.
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
  `RecoveryBatch::state()`. Commits are returned, and a batch can be
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

- wallet-pir is pinned to `c4068c10`, whose shard map carries re-cut
  declarations and whose sync keeps a store's history across a declared
  re-cut; every wallet-pir dependency moves together. Its sync refuses a map
  that rewrites sealed history the store holds, over a block the wallet's chain
  still accepts, without declaring a re-cut, as `SyncError::SealedRewrite`,
  which a pass returns as `Withdrawn(ChangedSealed)`, and drops page work
  under an unpublished revision instead of diverging.
- Sources are `transparent-reference-source-v3`: the shard id is no longer
  bound, only the geometry, its seal parameters and the start height, so a
  renumbered shard or tail keeps its source.
- Companions are format `transparent-reference-companion-v3`: the catalog
  records start heights instead of shard ids, and the binding table records the
  re-cut epoch. Opening a v2 companion rebuilds its catalog empty in place and
  keeps its store; the next pass exports the stored facts again under v3
  sources, without retrieving them.
- Stored facts are matched to commits by revision digest, and exported rows the
  map no longer publishes are classified by source and start height instead of
  shard id.
- `ReferenceRecovery::recover` takes the caller's `FilterSource` and
  `ShardTransport` for each pass. Before any retrieval it checks the target,
  the script limits, that the filter source does not use parent filters, the
  shard limit, and that the service's init names `SCHEMA`.
- `RecoveryConfig::origin` replaces `filter_origin` and `shard_origin`. It is
  an identity label and is never dialed. The companion binding now covers the
  source, account binding, origin and `SCHEMA`, so companions created before
  this change are refused at open and must be recreated.
- Recovery batches expose `commits()`, `state()` and `progress()` through
  accessors instead of mutable public fields. `progress()` replaces `report`.
  The companion classifies the
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
  parameters, and the shard's start height, so a new geometry tier changes no
  existing source, while a different height range gets a new source.
  `revision` covers the manifest digest and seal
  state, and `lineage` is the published revision number plus one instead of a per-companion
  counter, so a recreated companion reproduces the wallet's triples.
- Companions record revisions in a `pir_bridge_catalog` table. Companions
  from before stable identities are refused at open with
  `companion format v1; recreate`.
- A pass builds its batch from the shard map its sync finished with and fetches
  no second map.
- A lagging unsealed revision (also below a revision seen sealed), a map
  missing a shard, stored facts naming a revision the map no longer names, a
  shard ending on a block the chain view does not hold, or an exported tail
  without a retrieved successor make the batch `Pending` instead of failing
  the pass. So does every `MapDiverged` from the reference client's sync (a
  mid-pass refresh that does not continue the first map, or an undeclared
  rewrite of sealed history the store holds), with `Outcome::Behind` and no
  claimed coverage, and
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

- Public `acknowledge_reconciled`: callers cannot assert trusted reconciliation
  with a boolean or bypass the SQLite integration's apply/acknowledge ordering.
- `transparent-shard-v10` support.
- `RecoveryConfig::{schema, timeout, response_bytes}`, the `observer`
  argument of `recover`, and the adapter's fixed HTTP user agent.
- `reqwest` from the normal dependency graph. Only the `recover-activity`
  example builds the reference HTTP transports.
- The companion's `lineage` binding key, its `pir_bridge_revisions` table and
  the 65,536-revision catalog limit.
