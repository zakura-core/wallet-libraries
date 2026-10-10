# Changelog

## [Unreleased]

### Changed

- `PassPlan::next` skips the account (`Step::Skip`) after a settlement the
  caller's `WriteGate` interrupted, instead of stopping the run. A gate stops a
  settlement when one account's time budget runs out as well as when the run is
  cancelled; the caller checks its own cancellation before the next pass, so a
  cancelled run still stops. `StopCause::Interrupted` is removed.
- A changed policy generation (`ApplyError::PolicyChanged`) is its own
  `ApplyAction::PolicyChanged` and stops the run with
  `StopCause::PolicyChanged`, instead of refreshing like a stale commit: once
  private queries are turned off mid-run no further private pass may run, and
  the next run captures the policy again. Stale commits still refresh up to
  `PassLimits::stale_refreshes`. Callers matching `ApplyAction` or `StopCause`
  exhaustively add the new variant.
- `DetailAnswer::TimedOut` records a txid detail lookup the caller's run budget
  stopped as an `Unavailable` deferral, so it backs off (30 seconds, doubling up
  to an hour) instead of staying first in every listing and taking every run.
  `DetailAnswer::Cancelled` stays for a caller that is exiting and writes
  nothing.
- A display lookup that failed with `TxidError::Cancelled` is an attempt,
  deferred as `Unavailable` like `DetailAnswer::TimedOut` (`deferral` returns
  it too), instead of writing nothing: the lookup cannot say why it was
  cancelled, and a caller forwarding a budget cancellation unchanged would
  otherwise leave the lookup due and first in every run. Only an explicit
  `DetailAnswer::Cancelled` writes nothing.
- `DetailWrite::Defer` carries the listing's `expected_generation`, and
  applying it fails with the wallet's stale-policy error after a policy
  change, as a store does. A run that started under private queries therefore
  ends at its first write after they are turned off, instead of deferring
  every remaining lookup.

- Rename the account recovery module to `transparent_history_recovery`,
  `ReferenceRecovery` to `TransparentHistoryRecovery`, and `RecoveryConfig` to
  `TransparentHistoryRecoveryConfig`. Callers still supply already-derived
  addresses through a watch set; mnemonic derivation remains outside this crate.

### Added

- `forget_private_recovery` (feature `sqlite`) removes what private recovery
  contributed once the wallet's policy is `Public` on the handle and durably:
  it deletes every companion of a `CompanionDir`, then runs
  `forget_transparent_ledger` through the caller's `WriteGate`. A companion
  still held fails with `ForgetError::CompanionBusy` and forgets nothing; a
  wallet not public fails with `ForgetError::NotPublic` before anything is
  deleted. The forget runs in one wallet transaction with a check of the
  policy generation read before the companions went, so any policy change
  since, even private and back to public, fails with
  `ForgetError::PolicyChanged` and forgets nothing: a companion created
  meanwhile would otherwise outlive the facts it records.
- One recovery pass driver, so wallets stop writing their own loop.
  `TransparentHistoryRecovery::pass` recovers through a fresh `TransparentPirHttp` on
  the caller's `HttpExchange`, retries once after
  `RecoveryError::PublicationChanged` unless the caller is stopping, maps any
  failure during an outage to `PassError::Outage`, and returns a `PassReport`
  while holding a `Ready` batch inside the companion (`take_latest`).
  With feature `sqlite`, `settle_latest` settles the held batch through
  `apply_and_acknowledge_gated`, and `PassPlan` is the pure decision table that
  turns a pass, its settlement and the re-read watch set into the next `Step`:
  pass, refresh, wait, hold (`HoldCause::Withdrawn`, `Unreconciled`), skip,
  stop (`StopCause::NotEnabled`, `PolicyChanged`), fail, or done with the last
  retry, within `PassLimits` (8 passes, 3 stale refreshes by default).
  `recover-activity` now requires feature `sqlite` and runs on the driver, and
  the end-to-end tests drive every pass through it.
- `discover_active_addresses`, `Discovery` and `DiscoveryLimits`: import-time
  discovery of which candidate addresses hold transparent history from a floor
  on, before any wallet exists. It downloads every filter from the floor's
  shard through the publication's end and confirms each match by private
  retrieval over an in-memory store, so filter false positives are never
  reported and nothing is stored.
- `ReferenceRecovery::apply_and_acknowledge_gated` runs each wallet write of a
  settlement (every commit's transaction, then the acknowledgment's) through a
  `WriteGate`. An application that serializes its wallet writes holds that
  serialization for one commit instead of the whole batch, and can stop the
  batch between commits: the gate returns `Interrupted`, the batch fails with
  `ApplyError::Interrupted` (`ApplyAction::Interrupted`), the applied commits
  stay, and the next pass replays the batch. `apply_and_acknowledge` is
  unchanged and runs through `Ungated`.
- Private queries go at 44 dithered bits when the shard service advertises the
  dithered schemes (`directory_scheme_dq44`, `pages_scheme_dq44`) and they
  reproduce locally, and at 49 bits otherwise, so older services keep working.
  A 44-bit query is 27,648 bytes plus `rows × 44 / 8` after the binding, where
  the 49-bit one needs `rows × 49 / 8`; the end-to-end tests check that every
  query they send is the 44-bit length.
- A pages query to a growing tail selects over only the page rows its
  revision's manifest says it holds, rounded up to whole 2,048-row blocks,
  instead of the whole segment (wallet-pir `9d2cbda0`). The count comes only
  from digest-bound manifest fields every wallet shares, never from the row a
  query selects. A `recent-8k` tail's pages query shrinks from 72,712 bytes to
  as little as 38,920. Sealed shards, multi-segment shards and directory
  queries keep the full length, and the service must accept prefix
  selections (wallet-pir `0f89fbe0` or later).
- Declared re-cuts. A sealed revision the shard map declares a re-cut
  superseded stays current, and facts stored under it are exported under the
  revision triple the wallet already holds; the renumbered shards and tail
  keep their sources, and the renumbered tail is listed as resolving the old
  one. A pass checks the declarations against the map (`Equivocation`,
  `Regression`) and, on the first stored fact under a declared revision,
  against the catalog (`Equivocation`). A ready pass over a re-cut map records
  its re-cut epoch once the store holds a fact under a revision any of its
  re-cuts superseded, or under one the map publishes at or above its newest
  re-cut's first height. The epoch never stops a sync: a map the reference
  client refuses as a rewrite of history the store holds is `Pending` with
  `Outcome::Behind` when its epoch is lower (a replica still serving the map
  from before the re-cut) and `Withdrawn(ChangedSealed)` otherwise. The shard
  limit counts declared entries at or above the watch set's floor, and every
  declaration, at any height, counts toward a separate limit of
  `MAX_SUPERSEDED` (65,536), refused before any retrieval as
  `Invalid("publication declaration limit exceeded")`. Wallet pages under a
  superseded sealed revision are completed once the batch covers their range,
  in a completion-only commit after the commits carrying that coverage. An
  undeclared change of sealed content never reaches the wallet.
- A sealed shard changed under its revision number, which the catalog reported
  as `Withdrawn(Equivocation)`, is now refused by the reference client before
  anything is read and reported as `Withdrawn(ChangedSealed)`.
- `pir_bridge_exports`, a never-pruned record of every revision a batch
  exported. A published or declared revision that differs from one exported at
  its source and lineage, or under its identity, is `Withdrawn(Equivocation)`,
  so a pruned catalog row cannot let a colliding revision reach the wallet.
- One raw HTTP exchange for both services: an application implements `HttpExchange`
  (`send(&HttpRequest) -> Result<HttpReply, HttpFailure>`), owning the origin, routing,
  timeouts, cancellation and body limits. `TransparentPirHttp` gives a pass its `FilterSource`
  and `ShardTransport` over it and owns the routes, their log templates and refusal mapping,
  with wallet-pir's own `refusal` and `Overloaded::from_http`; `outage()` reports a failure that
  says the service is unreachable or not serving. `TxidHttp` is the txid display client's
  transport over it, with per-route body limits. Capacity is wallet-pir's definition only: a
  shard-route 429, even with `retry-after`, or a 503 naming no delay fails the pass as an
  outage, not a capacity retry. An application whose own transport retried those as capacity
  now ends its run on them and passes again at its next scheduled run.
- `TxidDisplayService`, the `Send + Sync` txid display client of one origin for a whole
  process: lookups take turns on the client, a waiting lookup stops at cancellation, the map
  digest and the last map check time are read without waiting, and a lookup that finds the
  display unsupported leaves only the derived native profiles, so the next lookup asks again.
  `lookup` returns a `DisplayLookup`: the result with the digest of the map that lookup used,
  read before another lookup or map check can change it.
- `DetailRun`, the wallet's txid detail work protocol for one run, so callers keep only
  transport, scheduling and their write lock: `plan` lists the due lookups (preferred ones
  first) under the service's display map and, when nothing is due but lookups are parked and
  their re-check time has passed, yields one `DetailStep::RefreshMap`, whose `MapCheck` is
  recorded as started before the fetch, so failed and abandoned checks are bounded too;
  `relist` lists again only when the fetched map differs and the policy is unchanged. `record`
  turns a lookup's `DetailAnswer` (a boxed `DisplayLookup`, a public result, or a stopped
  lookup) into a `DetailWrite`: display facts to store under the
  listing's generation, a deferral with the map the lookup used, or a public transaction
  handed back only under public transport. A cancelled lookup writes nothing.
  `DetailWrite::apply` performs a store or deferral and returns the public transaction to the
  caller's own policy-checked ingestion.
- `CompanionDir`, one wallet's companions: `open` names each `{account}-{tag}.sqlite` (the
  tag binds the origin and `SCHEMA`), prunes the account's companions for other origins and
  those of accounts the caller no longer has, and holds an operating system lock on the
  companion's lock file for the returned `Companion`'s life; `remove` deletes an account's
  companions under their locks; `clear` deletes every companion, failing on one still held;
  `retain` sweeps those of deleted accounts. `open` and `retain` both list the companions
  before they read the accounts.
- `RecoveryBatch::retry` and `Progress::retry` (`Retry::{Complete, More, After, Stalled}`,
  waiting `Retry::BEHIND` or `Retry::OVERLOADED`; a `Withdrawn` batch is `Stalled` whatever
  its outcome) and `Progress::behind`; `ApplyFailure::action` (`ApplyAction::{Refresh,
  Reconcile, Skip, NotEnabled, Fail}`), so callers act on the outcome contract without
  re-encoding it. `ApplyError::Rejected`'s message names the rejection's kind.
- Feature `testing`: `testing::batch` builds a batch no companion issued, `testing::apply`
  settles it as `apply_and_acknowledge` does without a companion, policy-generation check
  after the last commit included, and `TxidPublication` and
  `unsupported_txid_init` answer txid display requests as a fake service.

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

- wallet-pir is pinned to its `main` at `a317455e`, whose shard map carries
  re-cut declarations and whose sync keeps a store's history across a
  declared re-cut (valargroup/wallet-pir#138); every wallet-pir dependency
  moves together. It also brings #137's txid display client changes: the
  client follows a fresh display publication, hardens its fresh-publication
  rules, and refuses display maps with no bucket or too many. After rolling back any
  reorg the wallet's chain shows, its sync refuses a map that rewrites sealed
  history the store holds without declaring a re-cut, where the chain accepts
  both the stored and the replacing shard's end blocks, as
  `SyncError::SealedRewrite`, which a pass returns as
  `Withdrawn(ChangedSealed)`, and drops page work under an unpublished
  revision instead of diverging.
- wallet-pir then moves to `06a972db469f302d8c561416d4674e937fdde0cb` for
  dithered queries. From `a317455e`, its only library changes to the crates
  this one uses are the dithered query (wallet-pir's `pir-native` and the
  transparent client and server); the `BelowFloor` call sites were re-checked
  there.
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
- A pass retrieves through a `FilterSource` and a `ShardTransport`, which
  `pass` builds over the caller's `HttpExchange`; the single attempt it makes is
  internal. Before any retrieval it checks the target,
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
- A pass refuses, before the service's init, a shard map whose network or
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
  argument of a pass, and the adapter's fixed HTTP user agent.
- `reqwest` from the normal dependency graph. Only the `recover-activity`
  example builds the reference HTTP transports.
- The companion's `lineage` binding key, its `pir_bridge_revisions` table and
  the 65,536-revision catalog limit.
