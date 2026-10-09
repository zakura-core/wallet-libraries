# Transparent PIR candidate recovery

The `wallet` feature bridges the reference transparent PIR client and a durable
companion SQLite store into normalized wallet-libraries recovery commits.
Applications supply a stable account binding, an origin label, a current watch
set, an independently accepted chain view, and, for every pass, their own
`FilterSource` and `ShardTransport`. No address, txid, parent or outpoint lookup
fallback exists.

The adapter makes no network requests of its own and has no HTTP client in its
normal dependency graph. The caller's transports decide routing, timeouts,
retries and response limits, and must reach the origin bound into the
companion. `RecoveryConfig::origin` is an identity label, never dialed: the
companion's binding covers the source, account binding, origin and `SCHEMA`
(`transparent-shard-v11`), so a companion opened under another account, origin
or schema is refused. The re-exported `Table`, `ShardRequest`, `refusal`,
`StaleRevision`, `Overloaded` and `BoxError` are what a transport implementation
needs to map service refusals.

`recover` checks, in order and before any retrieval: the watch set's target is
accepted by the chain view; the watch set and retained scripts are within the
script limit; the filter source does not use the parent-filter experiment,
whose selective child requests leak coarse activity; the shard map is within
the shard limit, declares at most `MAX_SUPERSEDED` superseded revisions in all,
and names Zcash mainnet's network and genesis block; and the service's init
names `SCHEMA`. A refused check makes no further requests. A
watch set with no addresses needs nothing retrieved: once its target is
accepted, the pass makes no request and completes at the target.

`WalletChain` is the chain view for a wallet: it answers from the blocks the
wallet scanned, only through the watch set's target, and never from a
publication. A pass needs it only from the watch set's floor, the lowest
required height (the account birthday). Shards ending below the floor are
neither exported nor cataloged, and the reference client may roll its own
coverage back to just below a shard that starts under the floor without a
wallet hash; that is the only use it makes of blocks below the floor. When the
publication ends below the target, the pass syncs to the map's end if that end
is at or above the floor, the chain view accepts its terminal block, and the
companion holds nothing above it; completing there still reports `Behind`.
Otherwise it passes the target and reports `Behind` at once. Commits keep the
watch set's context either way.

Every pass has script, publication, query, byte and export bounds. Its
`Progress` reports `covered_through` and an `Outcome`:

| `Outcome` | Meaning |
| --- | --- |
| `Complete` | Every watched script is covered through the target. |
| `Behind` | The publication ends below the target; `covered_through` may reach its end. |
| `More` | A query, byte or pending-page budget stopped the pass; the next pass resumes. |
| `Overloaded` | The service refused for capacity throughout its retry budget. |
| `Stalled` | An unknown chain block, unresolved spends or unbounded script discovery. |

The companion store owns reference page continuation and revision-bound caches;
the wallet store owns candidate evidence, qualification and activation. The
adapter never qualifies a revision, promotes an account or authorizes a spend.

Every commit's `RecoveryRevision` is derived from the publication, never
counted, so a recreated companion reproduces the triples the wallet holds:

- `source` hashes the companion binding with the set-identity fields that never
  change while the publication continues (shard schema, network, genesis block,
  profile, envelope version and start height), the shard's geometry, that
  geometry's seal parameters and the shard's start height, not its shard id. A
  set growing into a new geometry tier changes no existing source. A re-cut
  renumbers later shards and the tail without moving their start heights, so
  they keep their sources; a re-cut range, which starts elsewhere or under
  another geometry, gets new ones.
- `revision` hashes the shard's manifest digest and whether it is sealed.
- `lineage` is the published revision number plus one.

The companion catalogs each source's published revisions and records which
ones a batch exported. Each pass classifies the map its sync finished with,
without fetching another, and returns a `BatchState`. Commits are returned
only when it is `Ready`:

| `BatchState` | Meaning |
| --- | --- |
| `Ready` | The map agrees with the catalog, and every exported revision is still published, declared superseded by a re-cut, or has a successor at a higher lineage in this batch. |
| `Pending` | A lagging replica (an unsealed revision below one already seen, sealed or not), a map ending below an exported revision, stored facts naming a revision the map neither publishes nor declares, a shard ending on a block the chain view does not hold, an exported tail whose successor is not retrieved yet, or a publication that diverged from what the sync read or predates a re-cut the store followed (reported as `Behind`). Nothing to apply; a later pass can be ready. |
| `Withdrawn(cause)` | The publication contradicts the catalog. Nothing to apply. Keep the companion and retry later. |

| `WithdrawnCause` | Meaning |
| --- | --- |
| `Regression` | A sealed shard is published below a revision already seen, or a shard below a revision a re-cut declares superseded in its source. |
| `Equivocation` | One revision number is published or declared with other content, seal state or endpoint. |
| `ChangedSealed` | An exported sealed revision is neither published nor declared superseded, and its source is published at another revision that is not merely an older unsealed one. |
| `Retired` | The heights of an exported revision are published under another source, as after a geometry change or an undeclared re-cut. |

A re-cut rebuilds sealed history from some height up under other boundaries,
renumbering every later shard. A publisher declares it in the map
(`ShardMap::recuts`), listing every entry it superseded exactly as published.
The adapter keeps the wallet's history across a declared re-cut: facts the
store holds under a superseded sealed revision keep being exported under the
triple the wallet holds, that revision stays current and is never withdrawn,
and the renumbered tail resolves the old one in their shared source. A pass
checks the declarations against the map and, on the first stored fact under a
declared revision, against the catalog and every revision ever exported. A
ready pass over a re-cut map records its re-cut epoch once the store holds a
fact under a revision the re-cut superseded, or under one the map publishes at
or above the re-cut's first height. The epoch never stops a sync: a map at a
lower epoch that rewrites nothing the store has finished reading is synced
normally. Only a map the reference client refuses as a rewrite of history the
store holds is classified by it: one with a lower epoch, as from a replica
still serving the map from before the re-cut, is `Pending` and behind rather
than withdrawn. Wallet
pages under a superseded sealed revision are completed once the batch covers
them, in a completion-only commit after the coverage. An undeclared change of sealed content never reaches the wallet: the
reference client, after rolling back any reorg the wallet's chain shows,
refuses a rewrite of history the store holds that contradicts that chain (it
accepts both the stored and the replacing shard's end blocks) before reading
anything, which a pass returns as
`Withdrawn(ChangedSealed)`; one the chain cannot settle yet stalls the pass;
and the catalog withdraws the rest.

`Ready` assumes the trusted operation. A successor withdraws its predecessor's
provisional evidence from the wallet only when the wallet qualifies it and
applies it in one transaction
(`TransparentLedgerWrite::qualify_and_apply_transparent_ledger_commit`).
`batch.retired_revisions()` lists exactly the predecessors a `Ready` batch
resolves: provisional revisions an earlier batch exported, which the map no
longer publishes, and for whose source the batch's commits carry a successor at
a higher lineage. They are notifications, not authority: the adapter withdraws
no wallet evidence, and a `Pending` or `Withdrawn` batch lists none.
A batch is opaque: `commits()`, `progress()`, `state()` and
`retired_revisions()` read it, and nothing edits it. Acknowledge a `Ready`
batch only after every commit applied:

- With feature `sqlite`, `apply_and_acknowledge` consumes the batch, applies
  every commit to a `WalletDb<rusqlite::Connection, ..>` and acknowledges it.
  The caller states the trust explicitly: `Trust::Observed` applies candidate
  evidence only and refuses, before applying anything, a batch listing
  retirements; `Trust::Trusted` qualifies each commit's revision as it applies,
  which reconciles the retirements, and requires `PrivateRequired` on the
  handle and durably. The adapter never infers trust, promotes an account or
  authorizes spending.
- Without it, apply the commits yourself and call `acknowledge_applied`, which
  refuses a batch listing retirements and changes nothing. Such a batch can only
  be settled through `apply_and_acknowledge` with trusted commits.

`apply_and_acknowledge` refuses a wallet connection inside an explicit SQL
transaction (`ApplyError::OuterTransaction`): each commit must commit on its
own, so that an integrity rejection's quarantine is durable when it is
reported, rather than rolled back with a caller's transaction. Commits apply in
order, each in its own wallet transaction; the first one the wallet refuses or
fails stops the batch. The companion is acknowledged, in its own database, only
once every wallet transaction committed. The two databases are not atomic: a
stale or refused commit, a policy change, a failed wallet or companion write,
or a crash leaves the batch unacknowledged, with the committed prefix reported
in `ApplyFailure::stats`. The next pass exports the same revisions and lists
the same retirements again, and replaying commits the wallet already applied
changes nothing. `Applied` and `ApplyFailure` carry the commit counts, whether a
window grew, and the pass `Progress`, for scheduling the next pass. Every
outcome consumes the batch's receipt. Make no network request while holding the
wallet's write serialization; this call makes none.

Both paths refuse a `Pending` or `Withdrawn` batch and the receipt of any pass
but the latest. Export intent is persisted before a batch is returned, and retired
revisions stay recorded until acknowledged, so after a failed reconciliation or
a crash before acknowledgment the next pass reports those notifications again,
with any retirement found since, and replaying the trusted operation changes
nothing. A pass that would forget a possibly applied revision stays `Pending`
until its successor is retrieved. Only a publication change, below, forgets
retirements unacknowledged: those of sources the new map no longer names, which
no successor can resolve.

The trusted operation requires `PrivateRequired`, on the handle and durably, and
qualifies whatever it is given, so call it only for commits from an origin the
caller trusts. A caller that does not trust the origin can never acknowledge a
batch with retirements: until a trusted pass reconciles them, each later pass that sees a new revision of
their source adds one more to `retired_revisions()` and one row to the catalog.
Such a caller should stop passing the account at its first batch with
retirements instead of applying the same commits again.

Before the sync, a pass checks that the store's set identity continues to the
shard map's (the same profile, start height, envelope, and seal for every
geometry in use). When it does not, the pass resets the companion in one
transaction, emptying every store table but the schema version and clearing the
export mark of catalog rows whose source the map no longer names, keeps the
catalog rows, and fails with `RecoveryError::PublicationChanged`. Retry the pass
once with the same companion. The changed fields are part of every affected
source, so the retried pass exports those shards under new sources, while each
unchanged source keeps its catalog history: a publisher that restarted its
revision numbers is caught as `Withdrawn(Regression)`, `Withdrawn(Equivocation)`
or `Pending`, never as a lineage that collides in the wallet. The wallet keeps
the changed sources' old provisional evidence, which nothing supersedes and no
later batch reports as retired revisions, even one an earlier batch listed and
nobody acknowledged. A page the wallet holds under a source the
map no longer names would block its account for good, so once a batch covers the
page's range under the map's sources, the batch also completes the page in a
commit of the page's own revision that carries nothing else.

Until the retried pass binds the store again, a reset companion that still
records exported revisions returns `Pending`. A revision an earlier batch
exported is held back while the store opens a page on it that the wallet does
not hold, as when a reset store retrieves it again: the wallet may already
cover that range, and refuses a page opened over its own coverage.

A map under another set that ends below the store's anchor, while the chain
view still accepts that anchor, is a replica that has not caught up, perhaps
still serving the previous set; the pass keeps the store. That, and every other
divergence the reference client finds, a map refreshed mid-pass that does not
continue the first or one rewriting sealed history the store holds without
declaring a re-cut, makes the batch `Pending` with `Outcome::Behind`, keeping
the companion and catalog; a later pass starts from the publication it then
finds. Page work under a shard a lagging replica's map lacks is dropped, not a
divergence, and read again once a map publishes it.

Never recreate a companion, whether a batch is `Withdrawn` or after
`PublicationChanged`. A publisher that re-cuts a set without declaring it and
restarts revision numbers is reported as `Regression`, `Equivocation` or
`Pending`, and a declaration that misstates a revision as `Equivocation`, but a
recreated companion cannot detect either, and the wallet refuses colliding
revisions as an integrity failure.

The messages of `RecoveryError::Invalid` and `RecoveryError::Failure` may quote
the companion's transparent history or the caller's transport errors. Log the
variant only.

Companions are format `transparent-reference-companion-v3`. Opening a v2
companion, whose sources bound shard ids, rebuilds its catalog empty in place
and keeps its store, so the next pass exports the stored facts again under v3
sources without retrieving them. A v1 companion, whose lineage was a local
counter, is refused with `companion format v1; recreate`. The companion keeps
every revision a batch exported, never pruned, since the wallet keeps every
revision it registered. Each pass prunes catalog rows that are neither
published nor exported, keeping each source's newest row; the store's filter
and setup caches down to revisions the map names; and the store's commit log
down to its last entry. Acknowledgment prunes the catalog again.

This is recovery plumbing; sending, Vizor and public transaction-details fetching
are outside its scope. The headless real-source harness and final qualification
are tracked with the activity metadata implementation plan.

`recover-activity` is a bounded headless harness for real HTTP retrieval into
library SQLite candidate evidence, followed by a durable reopen comparison. It
builds the reference HTTP transports itself (development dependency on
`transparent-wallet` with `reqwest`): a 30 s timeout, a 64 MiB response limit,
one request at a time and up to three attempts for transient failures.

```sh
cargo run --locked -p zakura-pir-transparent --features wallet \
  --example recover-activity -- independent-snapshot.json new-evidence-directory \
  http://127.0.0.1:18192
```

The snapshot supplies `birthday`, `through`, up to 64 public locking `scripts`,
and consecutive independently collected RPC `headers` from birthday minus one
through the target. Each header has `height`, display-order `hash`, `time`, and
`previousblockhash`. Keep the raw RPC responses beside this snapshot. Never derive
accepted headers from a publisher manifest. The origin should be a controlled
capture proxy so every HTTP attempt can be checked for public lookup fallback.

This harness inserts public scripts as controlled fixture watches and uses empty
shielded scan fixtures. It proves transparent metadata delivery and SQLite
persistence, not ownership of those public funds or shielded scan correctness.
It requires nonempty metadata recovery and reader version 7, reopens both stores,
and refuses qualification or account activation. Its output directory must be
new; failed runs and partial stores remain available for diagnosis.

`tests/private_recovery.rs` runs private recovery end to end against a
`transparent-shard-server` in the test process, over loopback HTTP and real
PIR, through the reference HTTP transports and the wallet's trusted operation.
Its fixture publishes real shards for a synthetic chain at mainnet heights,
taking block hashes from the test wallet's own scan, and records every request
the service receives. Each publication gets its own server, while every
companion stays bound to the origin label `https://fixture.test`.
`private_mode_lifecycle_against_an_in_process_shard_service` goes from untrusted
observation through trusted commits and promotion, a moving tail, publication
lag, a reopened and then a lost companion, a publication change retried with
the same companion, and a sealed shard changed under its revision number. It
then checks that every request used a service route with its method, carried no
watched script in bytes or hex in its path, query, headers or body, and named no
shard wholly below the birthday. `young_wallet_rolls_back_below_its_birthday`
follows a wallet born inside the tail through a clamped pass, two
republications and a reorg that rolls the companion back below its birthday.
`a_declared_re_cut_keeps_the_wallets_history` re-cuts two sealed shards into
one wider shard: the next pass requests only the renumbered tail and changes
nothing else in the wallet, and a companion recreated afterwards heals.
`an_undeclared_re_cut_reaches_nothing_in_the_wallet` publishes the same re-cut
undeclared, and `a_lagging_pre_re_cut_map_after_the_re_cut_changes_nothing`
serves the pre-re-cut map again after the wallet followed the re-cut.

```sh
python3 scripts/dev.py test --config transparent-pir
```

The service, with axum 0.7 and tower-http 0.5, is in the test graph only. The
`default` lane excludes this crate: the `transparent-pir` lane runs its tests,
and `zakura-graph` checks all of its targets with every feature and its library
without features. Test builds compile `valar-spiral-rs` without overflow checks
(`.cargo/config.toml`), as wallet-pir does, because its reduction relies on
wrapping arithmetic.
