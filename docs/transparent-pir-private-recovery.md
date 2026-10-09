# Private transparent recovery over transparent PIR

## Status

Planned. This document records the stage that wires the transparent PIR service
into the [transparent ledger](transparent-pir-ledger-architecture.md) as a
private recovery source, behind a development flag. None of it is on `main` yet:
the library half lands as the PRs listed under the stack below, and the Vizor
half as one PR into `roman/tpir` (chainapsis/vizor-wallet#783). The release
gates of the [preparatory refactor](transparent-pir-preparatory-refactor.md)
still apply.

The library's private mode is qualified against fixtures, and the reference
adapter `zakura-pir-transparent` turns transparent PIR results into
`TransparentLedgerCommit`s, but nothing uses it; Vizor's coordinator runs with
`DisabledSource`. Six gaps remain: production cannot qualify a revision, yet the
tail changes every block; the live map starts at height 0, and the adapter asks
for accepted hashes below the wallet birthday, which the wallet cannot supply;
per-companion sources and lineages collide after a second account or a recreated
companion, quarantining every account; the adapter's blocking reqwest client
bypasses Vizor's routing and Tor; the pinned wallet-pir client rejects manifests
carrying `txid_display`; and Vizor has no source, no production policy
transition, an ungated iOS observe ABI, and no way to show restored authority.

## Decisions

| Decision | Choice |
| --- | --- |
| D1. Trust | Trusted indexer. A new atomic library operation qualifies and applies a commit, and Vizor qualifies only commits from its configured origin. This deviates from the architecture's [independent-verifier gate](transparent-pir-ledger-architecture.md#trust-and-privacy-model); PR 2 records the deviation in the design notes. |
| D2. Rollout | Development flag `--dart-define=ZCASH_PRIVATE_TRANSPARENT_RECOVERY=true`, pushed to Rust at bootstrap. With it, "Private queries" on mainnet selects `PrivateRequired`. Default builds keep `Public` and write nothing. No new toggle. |
| D3. Transport | Owned by Vizor. The adapter takes injected `FilterSource` and `ShardTransport` implementations, which Vizor builds over its routed transport: HTTPS only, Tor when enabled, cancellation. No reqwest in the adapter's normal dependency graph. |
| D4. Vizor tree | A separate branch, `claude/tpir-private-pir`, cut from `roman/tpir` and proposed as one PR into it, pinned to the library mega PR head. |

Roman settled these on 2026-10-04. The design also makes reversible assumptions,
open to owner review: Ledger accounts are paused under private mode; transparent
authority may be missing between a new block and the next private pass; #783's
"published release before merge" rule is recorded as a release decision, not
worked around; publishers meet the publisher requirements below; the unused
recovery-work query is deleted; and the wallet schema does not change.

## What private mode means

In a Vizor build with the development flag, on mainnet, turning on Private
queries with a confirmed preference durably applies `PrivateRequired` through
the existing transition fence. Each software account is then recovered from
`https://transparent-pir.valargroup.dev` over Vizor's routed HTTPS transport
(Tor when enabled, cancellable); each commit from that origin is qualified and
applied in one library transaction, candidate accounts are promoted at the tip,
and a re-emitted completion event shows the restored authority.

From then on, transparent authority, balances and spends come from the private
ledger, and no address, script, outpoint or txid goes to lightwalletd. Failure,
outage, a disabled source, missing configuration or an unconfirmed preference
pauses transparent work and never selects `Public`. An account that cannot
progress shows `Stopped` with a reason instead of an indefinite "Unavailable":
`Quarantined`, `Ledger`, `LegacyDiscrepancy` (legacy public rows that nothing
can yet explain), `Withdrawn` (the adapter withdrew a publication), `Stalled`
(three stalled runs) or `NotSelected` (a durably private database in a build
that cannot recover privately).

In default builds nothing changes for a database that never ran with the flag:
the selection stays `Public` and no durable policy is written. Handles adopt a
durable `PrivateRequired` if one is present, so they fail closed; such a wallet
shows `Stopped(NotSelected)` with copy telling the user to turn off Private
queries, which lowers it to `Public` in every build.

The selection is `PrivateRequired` only on mainnet, with the preference on and
the flag set, outside the `ironwood_masquerade` configuration. The stricter
state is persisted first. Startup only raises, and only from a preference that
was actually read; an unreadable one withholds public lookups for that launch
without raising. Only an explicit toggle-off demotes. A failed enable leaves the
setting unchanged; a failed disable restores the private state.

## Library operation

`TransparentLedgerWrite` gains one required method under `transparent-inputs`,
`qualify_and_apply_transparent_ledger_commit`, which takes a
`TransparentLedgerCommit` and returns a `CommitOutcome`. It qualifies
`commit.revision` as trusted and applies the commit, atomically. It requires
`PrivateRequired` on the handle and durably. In one transaction it runs every
check of `apply_transparent_ledger_commit`, qualifies the exact revision,
withdraws older provisional evidence of the same source wallet-wide, and writes
the commit's facts. Any failure changes nothing, except that an integrity
failure quarantines exactly as an ordinary commit does, without qualifying.
Replaying an applied commit changes nothing. Qualification is the caller's trust
decision; the operation does not verify the publication.

Two calls cannot be made safe. Applying first is refused for an active account,
whose commits need a qualified revision. Qualifying first withdraws the
predecessor's provisional coverage, so a stale commit would leave neither. An
outer transaction cannot keep the integrity quarantine, which commits with the
rejection, while discarding the qualification.

In SQLite, `apply_commit` takes a private `CommitTrust { Observed, Qualified }`.
After the existing mode checks, `Qualified` requires `PrivateRequired` on the
handle and in the durable policy, and otherwise returns
`TransparentRecoveryNotEnabled`. Inside the inner savepoint, before the facts,
`qualify_in` registers the revision, inserts it into `tpir_qualified_revisions`,
supersedes older provisional evidence only if that row is new, and requires
`REVISION_READER_VERSION`; the integrity arm then rolls back both and
quarantines. The test hook `qualify_transparent_revision` stays test-only and
reuses `qualify_in`. `WalletDb` is the only implementor.

There is no wallet schema change and no reader-version change. The ledger
migrations are absent from the published `zakura-client-sqlite` 0.1.0-rc7, the
latest release, so the next publish is rc8. The new required method breaks
external implementors of the trait, and the backend changelog says so.

## Adapter

### Injected transports and identity origins

All adapter changes are in `zakura/pir-transparent`, under the `wallet` feature.
`recover(watch, chain, filters, transport)` takes
the caller's `ChainView`, `FilterSource` and `ShardTransport`.
`RecoveryConfig`'s separate filter and shard origins collapse into one `origin`:
an identity label bound into the companion and its sources, which the adapter
never dials. The companion binding covers `source`, `account_binding`, `origin`
and `SCHEMA` (`transparent-shard-v11`). Schema v10, the `HttpObserver` plumbing
and the fixed user agent are deleted. The example builds its own HTTP clients
from a `reqwest` dev-dependency.

Before any shard retrieval, a pass checks that the chain view accepts the
target, that the script limits hold, that the filter source does not use parent
filters, that the shard map is within the shard and declaration limits and for
mainnet, and that the service's schema equals `SCHEMA`.

Progress is adapter-owned, `Progress { covered_through, outcome }`, and the
wallet-pir report types are not re-exported:

| wallet-pir report | `Outcome` |
| --- | --- |
| Complete | `Complete` |
| `QueryBudget`, `ByteBudget`, `PendingLimit` | `More` |
| `PublicationBehind`, or a clamped pass that completes below the target | `Behind` |
| `Overloaded` | `Overloaded` |
| `ChainUnknown`, `UnresolvedSpends`, `DiscoveryUnbounded` | `Stalled` |

Re-exports are limited to what Vizor's transport and the tests use: `ChainView`,
`FilterSource`, `ShardTransport`, `ShardRequest`, `BoxError`, `refusal`,
`Overloaded`, `StaleRevision` and `Table`. The four wallet-pir dependencies move
to `648264bb4801ae8faf7a61f4638ea049edb167cf`, which reads `txid_display` and
adds a `rayon` dependency; the store schema stays at 4.

### Chain view, floor, clamp and mainnet check

`WalletChain` answers `ChainView` from the wallet's own blocks up to a fixed
target. A height above the target is Unknown. At or below it, a hash is Accepted
when it equals the wallet's `get_block_hash`, Rejected when it differs, and
Unknown when the wallet has no block or the read fails. `hash_at` returns the
wallet's hash at or below the target, and `tip()` is the target. Vizor builds it
over a read-only wallet database inside `spawn_blocking`.

The birthday floor is the lowest `required_from` in the watch set, capped at the
target, or 0 without addresses. Normalization exports and catalogs a shard only
when it starts at or below the target and ends at or above the floor, so shards
wholly below the birthday produce no commit or catalog row. The sync's shard
planning visits only shards that intersect `[required_from, target]`, so it
requests no filter for them either. The wallet-pir sync sees a private
`BelowFloor` view: below the floor every hash is Accepted, and `hash_at` answers
only for height 0, with the map's genesis hash. This is sound because of that
planning rule, and because below the floor the sync asks only for rollback
anchors. Every later wallet-pir pin must re-verify both.

Publication lags the wallet's tip. With `t` the end height of the last map
entry, a pass targets `t` and the map's terminal hash instead of the wallet
target only when `t` is below the wallet target, at or above the floor, and at
or above the companion's stored anchor (so a lagging replica cannot cause
`AnchorRegressed`), and the wallet accepts that terminal hash (so a map on a
stale branch is not followed). When `t` is below the wallet target but a
condition fails, the pass uses the wallet target and wallet-pir reports
`PublicationBehind` (`Behind`); when `t` reaches the target, nothing is clamped
and the outcome maps as usual. A clamped pass that completes reports `Behind`
with `covered_through = t`. Commit contexts keep the wallet target, and anchors
stay at the lower of the shard end and the target, so a clamp never claims
coverage the map does not hold.

The mainnet check runs before `init`: the map's `network` and `genesis_hash`
must equal `transparent_filter::profile::NETWORK` and `MAINNET_GENESIS_DISPLAY`.
A map for another network is refused before retrieval.

### Identity, lineage and catalog rules

```text
source   = sha256("transparent-reference-source-v3" || binding
             || lp(shard_schema) || lp(network) || lp(genesis_hash)
             || lp(profile) || envelope_le || start_height_le
             || lp(entry.geometry)
             || lp(canonical_json(map.seal[entry.geometry]))
             || entry_start_height_le)
revision = sha256("transparent-reference-revision-v2" || digest || sealed)
lineage  = entry.revision + 1
```

`binding` is the companion binding hash and `lp` is a length prefix. A source
binds the map-wide identity fields, the entry's geometry, that geometry's seal
tier and the entry's start height, but not its shard id. Under the publisher
requirements, none of them changes for a shard while the store's set identity
continues. A publisher can add a geometry tier without re-binding the store;
that extends the seal map but changes no existing source. A re-cut renumbers
every later shard and the tail without moving their start heights, so their
next revisions stay in the sources the wallet holds, while a re-cut range,
which starts elsewhere or under another geometry, gets new sources. The start
height also gives a range that a seal change moved a source of its own. Lineage
comes from the publication, so a lost or recreated companion reproduces
identical triples. The library raises `Integrity` before `Superseded` on a
lineage collision, so the catalog must keep colliding commits from reaching the
wallet.

The companion format is `transparent-reference-companion-v3`, recorded in
`pir_bridge_binding` beside the account binding and `recut-epoch` (see
[Declared re-cuts](#declared-re-cuts)). Revisions live in
`pir_bridge_catalog`, keyed by `(source, digest, sealed)` with lineage and
revision unique per source, which records the start height, publication height
and terminal hash, and `exported` and `current` flags. `pir_bridge_exports`
keeps every revision a batch exported, as the wallet identifies it, and is
never pruned: the wallet keeps every revision it registered for good, so no
later revision may reach it at the source and lineage, or under the identity,
of one it holds, even after the catalog pruned that row.

Opening a v2 companion, whose sources bound the shard id, rebuilds its catalog
in place: the catalog table is dropped and recreated empty, the format and
epoch are recorded, and the store's tables are kept, so the next pass exports
the stored facts again under v3 sources without retrieving anything. Vizor keys
companion files by origin and schema only, so a v2 file would otherwise fail
every pass. The account binding is checked before the rebuild. A v1 companion
is refused with an instruction to recreate it.

Each pass parses the map the sync finished with, recorded rather than fetched
again, and in one immediate transaction marks current every stored row that a
published entry, or a sealed entry a re-cut declares superseded, names exactly.
It checks the re-cut declarations (see [Declared re-cuts](#declared-re-cuts)),
then classifies each relevant published entry, highest first:

| Map entry | Result |
| --- | --- |
| Stored with the same digest, sealing, height and hash | Current |
| A stored row has its lineage with another digest or sealing, or a revision exported at its source and lineage, or under its identity, differs from it | `Withdrawn(Equivocation)` |
| New, sealed, below the source's highest stored lineage | `Withdrawn(Regression)` |
| New, unsealed, below that lineage (lagging replica or rollback) | `Pending`; nothing inserted, the shard's commit dropped |
| Otherwise | Inserted |

Stored facts are then read by the revision digest the store recorded them
under, never by shard id alone:

| Stored fact's digest | Result |
| --- | --- |
| Published by the map | Placed in that entry's commit, if the entry was classified exportable; the fact's shard id must be the entry's |
| A sealed revision a re-cut declares superseded | Placed in a commit under that revision's own triple, opened on the first such fact; the fact must lie inside the declared range and name the declared shard id, the commit is anchored at the wallet's block at the lower of the declared end and the target, and at the declared end that block must be the declared terminal block |
| Anything else, or a fact failing those checks | Skipped; the batch is `Pending` |

None of these fails the pass. The store's own unfinished page work opens pages
only under revisions the map publishes, and any other page defers the batch:
the store retrieves no page of a superseded revision, so such a page could
never complete. Rows exported earlier and no longer current are classified
last, by the first rule that matches:

| Exported row | Result |
| --- | --- |
| Sealed, its source published unsealed at a lower lineage (a replica behind the seal) | `Pending` |
| Sealed, its source published otherwise | `Withdrawn(ChangedSealed)` |
| Unsealed, with a commit in this batch for its source at a higher lineage | Resolved |
| Unsealed, its source published without such a commit | `Pending` |
| Source not published, and the map ends below the row's start height or reaches it inside an unsealed shard that starts below it (the map is behind) | `Pending` |
| Source not published otherwise: its heights are published under another source | `Withdrawn(Retired)` |

A batch can commit one source at two lineages, a superseded sealed revision
from stored facts and its renumbered successor; the higher one settles the
source.

### Declared re-cuts

A re-cut rebuilds sealed history from some height up under other boundaries,
as when sealed recent shards are merged into archive shards. It renumbers every
later shard and changes its digest, but not the chain, so a wallet that covered
those heights needs nothing new. The publisher declares every re-cut in the
map (wallet-pir's `ShardMap::recuts`): an epoch, the first changed height, and
every entry it superseded exactly as it was published, the old tail included.
A map never re-cut omits the field and keeps its bytes and digest.

The adapter keeps the wallet's history across a declared re-cut. Superseded
sealed revisions stay current and keep being exported under the identity the
wallet already holds; they are never withdrawn or retired.

- Facts the store holds under a sealed revision a re-cut superseded are
  exported under that revision's triple, as the stored-fact table above says.
- The renumbered shards and the tail keep their start heights and geometries,
  so they stay in their sources at higher lineages. The renumbered tail
  resolves the old one, which a `Ready` batch lists in `retired_revisions()`.
  A superseded tail counts neither for currency nor for export.
- Before classifying, a pass checks the declarations against the map: a
  published entry in the source of a declared one must have a higher lineage
  (equal is `Withdrawn(Equivocation)`, lower `Withdrawn(Regression)`), and two
  declarations of one source and lineage that differ are
  `Withdrawn(Equivocation)`. The check needs no catalog history, so a
  recreated companion makes it too. wallet-pir's `check_shape` already refuses
  a map that breaks the first rule, so the pass fails before reaching it.
- The first stored fact under a declared digest admits that revision. It must
  match any row the catalog recorded for it exactly, and any revision exported
  at its source and lineage or under its identity, and its digest must not be
  recorded under another source, since a manifest digest binds its geometry
  and start height; otherwise the batch is `Withdrawn(Equivocation)`. It is
  recorded as current without the regression check, since its source's
  published successor is newer by construction.
- The companion records a map's re-cut epoch only after a `Ready` pass over it
  that found the store followed its re-cuts: a stored fact under a revision
  any of them superseded, or under one the map publishes at or above the
  newest re-cut's first height, which only a map at that re-cut publishes, as
  for a companion recreated after the re-cut or an account born above it. It
  keeps the highest; a publication change clears it with the store. A map whose
  declaration is refused, or whose re-cut the store did not follow, cannot
  raise it. The epoch never stops a sync: a map at a lower epoch that rewrites
  nothing the store has finished reading, such as a lagging replica when the
  store read only the tail above the re-cut, is synced normally, and its old
  tail is `Pending` behind the one the wallet holds. Only a map the sync
  refuses as a rewrite of history the store holds (`SealedRewrite`, below) is
  classified by the epoch:
  one whose epoch is below the recorded one, as a replica still serving the map
  from before a re-cut, is `Pending` with `Outcome::Behind`, and any other is
  `Withdrawn(ChangedSealed)`. The sync refuses before reading anything, so
  either way the catalog is untouched and the store keeps what it held, less
  any reorg the chain shows, which the sync rolls back before judging the
  rewrite. A forged epoch can therefore at most turn a real contradiction into
  `Pending`; it never holds back an honest map, which rewrites nothing the
  store holds. Undoing a re-cut takes another re-cut at a higher epoch.
- The shard limit counts the published entries and the declared ones that end
  at or above the watch set's floor. Declarations are never dropped, and those
  wholly below every watched script's required height cannot name a stored
  fact. They are still checked against the map and each other, and marked
  current where the catalog holds them, since the wallet may hold one from a
  pass whose floor was lower, so every declaration, at any height, counts
  toward a separate limit of `MAX_SUPERSEDED` (65,536), the most the map's own
  shape check accepts. The declaration check indexes them by source and
  lineage, so a pass at that limit stays linearithmic.
- A wallet page under a sealed declared revision completes once the batch's
  commits cover its range, whether or not the map still names the revision's
  source (see [Publication change](#publication-change)). When that revision
  also has a commit of its own, from facts the store saved under it before the
  re-cut while the rest of its range was read again under the shard that now
  covers it, the completion goes into that commit, judged on the whole batch's
  coverage. Any other page whose revision has a commit in the batch is left to
  that commit, so no page completes twice.

`ChangedSealed` and `Retired` now catch only undeclared changes. The sync
refuses most of them first. Its reorg scan, on the wallet's chain alone, first
rolls back any reorg the chain shows, so a map cannot hold one back by changing
history below it. It then judges each settled range the rollback kept that the
map neither publishes nor declares. When the chain accepts both the stored end
block and the end block of the map's sealed shard now covering the range's
start, at or below the target, the publisher contradicts the wallet's own
chain, and the sync refuses it as `SyncError::SealedRewrite` before anything is
read. Anything else, such as a publisher that followed a reorg through a
just-sealed shard before the wallet's chain did, stops the pass as
`ChainUnknown` at the replacement's end height until the chain settles it. The adapter returns `SealedRewrite` as
`Withdrawn(ChangedSealed)` with `Outcome::Behind`, claiming no coverage: a
hold, never a reset of the store or catalog. A stored range with no recorded
endpoint matches a declaration when it ends inside the declared range, or at
its end on the declared block. The sync keeps no re-cut epoch, so a
replica still serving a map from before a re-cut the store followed looks the
same to it; the adapter tells that case apart by the map's lower epoch and
returns `Pending` instead. While a map keeps serving a sealed shard that
contradicts history the store holds, every pass over it is withdrawn: a
publisher undoes a bad sealed publish by declaring the shard superseded in a
re-cut, which wallets that read it then accept.
The catalog withdraws the rest, such as a rewrite of revisions an earlier batch
exported that the store no longer holds: `Withdrawn(ChangedSealed)` when the
row's source is published at another revision, and `Withdrawn(Retired)` when
its heights are published under another source.

The wallet database needs no change. `register_revision` accepts a higher
sealed lineage in a source and replays a lower sealed one unchanged, and
qualifying a successor supersedes only unsealed evidence of its source, which
is exactly the old tail. The wallet-pir sync keeps the companion's store
consistent across a declared re-cut. Sealed coverage stays under the revisions
it was read under, and a stored digest the map declares superseded is not a
reorganization. Unfinished page work under a revision the map no longer
publishes is dropped: for a sealed declared revision whose work was read for a
target the wallet's chain still accepts, what it saved is kept and the
script's gap is read again under the shard that now covers it, with events
kept once per outpoint; otherwise what it saved is rolled back first, from the
lowest height it saved anything at, or the declared start if lower. The old
tail is truncated and read again.

### Batch states and causes

`RecoveryBatch` carries `state: BatchState`: `Ready`, `Pending` or
`Withdrawn(WithdrawnCause)`, where the cause is `Regression`, `Equivocation`,
`ChangedSealed` or `Retired`. The state is the first withdrawal cause found,
else `Pending` if anything is pending, else `Ready`. Commits are returned,
marked exported and given an acknowledgment token only when `Ready`; a
`Pending` or `Withdrawn` batch exports nothing and cannot be acknowledged.

A `Ready` batch also names the retirements it resolves.
`RecoveryBatch::retired_revisions()` returns exactly the Resolved rows above:
retired provisional revisions, each with a successor commit in the batch for
the same source at a higher lineage. They are notifications, not authority; the
adapter withdraws no wallet evidence. The caller resolves them by applying the
batch's commits through the trusted operation, which qualifies each successor
and supersedes the retired provisional evidence in the same wallet transaction.

Acknowledgment refuses a batch that is not `Ready` and a stale token, and
otherwise clears the export mark on resolved rows and prunes; a batch's commits
were marked exported when it was returned. The batch is opaque, so its commits
cannot be edited or dropped before acknowledgment. `acknowledge_applied`
acknowledges only a batch with no retirements. With feature `sqlite`,
`apply_and_acknowledge` consumes the batch, applies every commit to a SQLite
wallet with the caller's explicit trust, and acknowledges it only once every
wallet transaction committed; only trusted commits, which qualify the
successors, acknowledge a batch with retirements. It refuses a wallet
connection inside a caller's SQL transaction, so that an integrity rejection's
quarantine commits with its own transaction before it is reported. A stale,
refused or failed commit, a policy change, a failed acknowledgment or a crash
leaves the batch unacknowledged and reports the committed prefix; the wallet
and companion databases are never treated as atomic. Until acknowledgment the
notifications stay durable, so after a failure or a crash the next pass reports
them again, with any retirement found since, and replaying the applied prefix
changes nothing. Only a publication change forgets them unacknowledged: those
of sources the new map no longer names, which no successor can resolve; the
wallet keeps their provisional evidence.

The trusted operation requires `PrivateRequired` and is used only for the
trusted origin. Without it a batch with retirements is never acknowledged, and
until a `PrivateRequired` pass from the trusted origin reconciles them, each
pass that sees a new revision of a retired source adds one retirement and one
catalog row.

### Publication change

A publisher changes the set identity by changing the profile, start height,
range envelope or a geometry's seal tier. Before the sync, the adapter checks
that the store's set identity `continues` to the map's,
`SetIdentity::of_schema(map, SCHEMA)`; this check alone raises
`RecoveryError::PublicationChanged`. When it fails, the adapter, in one
transaction, empties the wallet-pir store tables except the schema version,
clears the export mark of catalog rows whose source the map no longer names,
forgetting any unacknowledged retirements among them, and keeps the catalog
rows, so each source's highest lineage survives. Vizor retries the pass once,
keeping the companion. A map-wide change gives every shard a new source, and a
seal change gives new sources to the re-sharded geometry's shards. Unchanged
sources keep their catalog history, so a publisher that restarts their revision
numbers is caught as `Withdrawn(Regression)` or `Pending`, as for an undeclared
re-cut, not as an `Integrity` collision in the wallet.

Every pending page blocks its account, and no commit of their own revision
follows for pages the wallet holds under a source the map no longer names, as
after a set, origin or source-format change or a re-cut, or under a sealed
revision a re-cut declared superseded, whose source the map may still name.
Once a batch's commits cover such a page's addresses over its whole range, the
batch also completes it in a commit of the page's own revision that carries
nothing else, anchored at the wallet's block at the lower of the revision's
publication height and the target; at the publication height that block must
be the publication's own, and a page whose anchor the wallet's chain does not
hold waits. A page whose revision has a commit in the batch is left to that
commit, and a named source's provisional revisions are left to their
successor, whose qualification withdraws them.

wallet-pir also raises `SyncError::MapDiverged` when a mid-pass map refresh is
not a continuation, including a refresh to a map with another re-cut epoch or
one that moves a resumed shard id to another start height. The adapter maps
every `MapDiverged` from the sync to a `Pending` batch with outcome `Behind`,
keeping the companion and catalog, so the next pass starts from the publication
it then finds. A rewrite of sealed history the store holds is
`SyncError::SealedRewrite` instead (see [Declared re-cuts](#declared-re-cuts)).
Stored page work under a revision the map no longer publishes, as when a
lagging replica's map lacks the newest shard after a budget-limited pass, is no
divergence: the sync drops it, rolling back what it saved unless a re-cut
declared that sealed revision and the wallet's chain still accepts the target
the work was read for, and reads those heights again once a map publishes
them.

### Cache pruning

Each pass and each acknowledgment prunes. The catalog drops rows that are
neither current nor exported and lie below their source's highest lineage; the
highest row of every source is kept, so regressions stay detectable, also
across a publication change. A sealed revision a re-cut declares superseded
stays current, so its row is kept while the map declares it. The store drops `filter_cache` and `setup_cache`
entries for digests the map no longer names, and every `commits` row but the
last. A compile-time assertion pins the store schema at version 4, so a pin bump
that changes the tables this pruning or the publication-change reset touches
fails.

## Coordinator contract for Vizor

Vizor's `TransparentPirSource` uses `https://transparent-pir.valargroup.dev`,
which `VIZOR_TRANSPARENT_PIR_URL` overrides only in debug builds, with the
source `vizor/transparent-pir/v1` and the account UUID as the binding. Each
account's companion,
`{db}.tpir/{uuid}-{hex16(sha256(origin || 0 || SCHEMA))}.sqlite`, is created
lazily, excluded from backup and locked per path. Opening one deletes the
account's companions for other origins or schemas and those of deleted accounts;
deleting an account removes its companion and sidecars.

A pass runs in `spawn_blocking` over a read-only wallet database and
`WalletChain`, exiting on cancellation or a 90-second deadline, and retries once
on `PublicationChanged`, keeping the companion. The async side always joins it.
Per-pass limits are 10,000 scripts, 1,024 shards (published, plus those declared
superseded at or above the floor), 500,000 events, 256 queries,
96 MiB of private bytes and 8 MiB per response. The source answers
`Ready { next, behind_by }`, keeping the opaque batch, `Pending { next }` or
`Withdrawn(cause)`, or fails with `Unavailable` (the service is unreachable or
not serving, which stops the run), `Failed` or `Cancelled`. A `Ready` batch is
settled through the source, which hands it to `apply_and_acknowledge` under the
wallet write lock with the run's explicit trust. `More` continues with another
pass, `Overloaded` retries after 30 s, and `Behind`, clamped or not, retries
after 10 s while the run's publication wait is under 90 s.

A run raises the policy only under the fence and only from a confirmed
preference. It visits the active account first and the rest from a rotating
cursor, with at most 8 passes and 120 s per account and 180 s per run. Ledger
accounts are skipped under `PrivateRequired`, and held or quarantined accounts
are skipped without PIR traffic. For the rest:

| Result | Coordinator action |
| --- | --- |
| `Ready` | Settle the batch with `apply_and_acknowledge`: `Trust::Trusted` when the source is trusted and the policy is `PrivateRequired` on the handle and durably, `Trust::Observed` otherwise. It acknowledges only once every commit's wallet transaction committed. An observed batch with retirements is refused before anything applies; hold the account for 1 h: only a trusted pass resolves the retirements, and each pass until then adds any newer revision of their sources to them. A failed acknowledgment skips the account; the next pass replays the batch. |
| Stale rejection | Retry from a fresh watch set, up to 3 times, without acknowledgment. |
| Integrity, quarantine, invalid or unqualified rejection | Skip the account. |
| `NotEnabled` | Stop the run. |
| `Pending` | Apply and acknowledge nothing. |
| `Withdrawn(cause)` | Log the cause, acknowledge nothing and hold the account for 1 h. |
| Third stalled run, or promotion blocked by `LegacyDiscrepancy` | Hold the account for 1 h. |

The follow-up runs after the sync marks completion and emits its final event;
unless the run exited or was not enabled, it re-emits a completion event flagged
with new transactions, so the UI re-reads balances. Ledger readiness is bypassed
while public lookups are withheld. The iOS observe ABI takes the wallet path and
network, returns `UNSUPPORTED` without sending under a private policy, and
returns `INCONCLUSIVE` if the wallet cannot open.

## Privacy invariants and accepted leaks

Under `PrivateRequired`:

- No address, script, outpoint or txid reaches lightwalletd, from recovery,
  follow-on work, status, import, preview or the iOS observe ABI.
- Only an explicit toggle-off selects `Public`. Failure, outage, cancellation, a
  deadline, missing configuration, a default build or an unconfirmed preference
  pauses transparent work.
- PIR requests go only to the configured origin, over HTTPS, through Tor when
  enabled, with no User-Agent and no transport retries.
- Requests use only the service's six routes. No path, query or body carries
  script bytes, and shards below the floor are never requested.
- Logs carry route templates, statuses, body lengths, variant and cause names,
  and lag, never ids, digests, addresses, scripts, txids, outpoints or bodies.

The service still sees shard ids, which reveal activity ranges; the filter range
from the floor to the tip; request counts, sizes and timing; and the network
origin when Tor is off. Broadcasting a shield or spend publishes its transparent
outpoints through `SendTransaction`. Turning the setting off re-stamps
`tx_retrieval_queue` and queues the transactions routed to lightwalletd for
public retrieval, so txids learned privately are disclosed publicly at once.

## Accepted limitations

These hold under the development flag; PR 2 mirrors them in the design notes.

| Item | Limitation | Remedy or reason |
| --- | --- | --- |
| Tip gap | Spends and shields can fail between a new block and the next private pass, and during a scan. | The store-time recheck refuses them, so funds are never at risk. |
| Lag | If publication lags sync completion by more than about 90 s, a run ends `Behind`; authority returns only when a run catches the tail. | Lag in blocks and seconds waited is logged. |
| Ledger | Ledger accounts are `Stopped(Ledger)`. | Recovery from the birthday would miss earlier Ledger history. |
| Same seed elsewhere | `UnresolvedSpends` from use of the seed in another wallet is permanent. | After 3 stalled runs the account is held and shows `Stopped(Stalled)`. |
| Quarantine | Nothing clears a quarantine. | Delete and re-import the account, which gives new sources, or turn the setting off. |
| Pre-birthday outputs | Legacy public outputs mined below the birthday give a permanent `LegacyDiscrepancy`. | `Stopped(LegacyDiscrepancy)` with a 1 h hold; turn the setting off. |
| Re-cut | A declared re-cut keeps the wallet's history. An undeclared one stops every account with evidence there: the sync refuses a rewrite of sealed history the store holds that contradicts the wallet's own chain, and the adapter returns `Withdrawn(ChangedSealed)`, while one the chain cannot settle yet stalls the pass as `ChainUnknown`; the catalog withdraws what the sync does not refuse as `Withdrawn(ChangedSealed)` or `Withdrawn(Retired)`. One that restarts revision numbers under an unchanged set identity is `Withdrawn(Regression)`; a restarted tail is `Pending` below the old maximum, and `Withdrawn(Equivocation)` at any lineage an earlier batch exported, which the never-pruned export record catches. A declaration that names a revision otherwise than it was published is `Withdrawn(Equivocation)` for a companion that recorded it, but after companion loss the catalog cannot detect it, and the colliding triple yields `Integrity` and a quarantine, as does a restarted lineage. | Turn the setting off, or delete and re-import. See the publisher requirements. |
| Set-identity change | The adapter resets the store automatically and keeps the catalog, but old provisional evidence of the changed sources is never superseded, even where a batch listed it as retired and nobody acknowledged it. A shard whose source did not change but whose revision number restarted is treated as an undeclared re-cut: a restarted tail that reaches a lineage an earlier batch exported is `Withdrawn(Equivocation)`, not `Pending`. Revisions a re-cut declared are derived under the current set, so a set change that alters their sources orphans them like any changed source. | It is consistent data, and reorgs still rewind it. See the publisher requirements. |
| Geometry move | Heights an exported revision covered that are published under another geometry, under one set identity and without a declared re-cut, make every pass for an account with that evidence `Withdrawn(Retired)`. | As for a re-cut. See the publisher requirements. |
| Source format | Opening a v2 companion rebuilds its catalog, so its next pass exports every stored fact again under v3 sources: a new `tpir_revisions` row for every exported revision, once per account. The v2 catalog's export marks are dropped, so the old provisional tail under its v2 source is never superseded, and retirements nobody acknowledged are forgotten. | One time. It is consistent data, and reorgs still rewind it; Vizor's transparent PIR is unreleased. |
| Re-cut epoch | Once a ready pass shows the store followed a re-cut, a map at a lower epoch that the sync refuses as a rewrite is `Pending` rather than `Withdrawn` for that companion. A map that served a forged high epoch the store followed can thus soften a later real contradiction to `Pending`, retried every pass instead of held; it never holds back a map that rewrites nothing the store holds. | Undo a re-cut with another at a higher epoch. |
| Origin change | A debug override creates new sources; the previous origin's provisional tail evidence is never withdrawn. | Debug builds only. |
| Withdrawn | Every cause holds the account for 1 h, then it retries; holds are in memory, so a restart retries once. | A lagging replica is `Pending`, not `Withdrawn`. No new durable state. |
| Pauses | Hard caps pause recovery, passes fail during a rescan, and a restore under private mode does not find transparent-only accounts. | Fails closed. |
| Service edges | A tail ahead of the wallet is not hash-bound, a server rollback stalls, and rc7 is not a supported rollback target. | — |
| Cost | Filters are downloaded per account, about 0.8–28 MB. About 91 commits are re-applied per account per pass, and about one `tpir_revisions` row is added per block per account. A re-cut does not shrink the commit count: facts stored under superseded revisions keep being exported under them, beside commits for the re-cut shards that later scripts retrieve. Up to 180 s of post-completion work delays the next sync. | No cross-account filter cache, and `tpir_revisions` is not pruned. |
| Test builds | `valar-spiral-rs` runs without overflow checks in every wallet-libraries test build, including Enhance PIR tests. | Mirrors wallet-pir's exemption. |

Not built: a verifier, attestation or trusted-source registry; revision
withdrawal, quarantine clearing or trust epochs; persisted holds; a library
coordinator or async API; reqwest in the adapter's normal graph; v10, txid
display, unsupported ranges or the parent-filter experiment; a freshness
tolerance; a new toggle, remote kill switch, Dart-configurable
endpoint or release-build origin override; a progress FFI, cross-account filter
cache, concurrent batches or transport retries; mempool or txid PIR; Android
native changes; a PIR server in Vizor tests; a Ledger recovery bound; the
publisher side of a re-cut (building the re-cut map, verifying its declaration,
moving its shards and switching the router); or a crates.io release of the
adapter.

## Publisher requirements

The catalog rules assume a publisher that publishes the mainnet map under
`transparent-shard-v11`, never lowers a shard's revision number under an
unchanged set identity (a replica may lag, which the wallet treats as pending),
never publishes two digests or sealing states under one shard revision, and
changes neither a sealed shard's content nor the geometry a height range is
published under, except through a declared re-cut.

A declared re-cut must meet these rules, which wallet-pir's `check_shape`
partly enforces:

- Entries below `from_height` are byte-identical. `from_height` and the end of
  the re-cut span are earlier sealed boundaries with unchanged terminal hashes,
  and the new entries tile exactly the same heights.
- Revisions are numbered per geometry and start height, not per shard id: a new
  entry at the geometry and start height of any earlier entry, the tail
  included, takes a higher revision. The tail keeps its start height and
  geometry.
- The declaration names every changed entry exactly as it was published, the
  tail included. Declarations are kept forever with strictly increasing epochs,
  a superseded digest never reappears, and the seal parameters of every
  geometry a declaration names stay published.
- A re-cut is never withdrawn: undoing one is published as another re-cut at a
  higher epoch. A wallet that followed it treats a lower epoch whose map
  rewrites what it read as a lagging replica, never as the publication.
- Production is not re-cut until every client runs a version that reads
  declarations; an older client rolls its store back or stops. Vizor's
  transparent PIR is unreleased, so this is a release-ordering rule.

A re-cut that restarts revision numbers is not a declared re-cut: it must change
a field every source binds, for example through a profile or schema bump. A
seal-tier change re-shards only
its geometry, so it must keep the revision numbers of shards whose source fields
are unchanged. The live service, probed on 2026-10-05 (`transparent-shard-v11`,
91 shards from height 0, seal tiers `archive-wide` and `recent-4k-8k`), shows
the pattern a fresh publication directory leaves: shards 0–88 sealed at
revision 0 beside shard 89 sealed at 901, and a tail at 666. A freshness target
is also still open; this design waits at most 90 s per run.

## Stack and merge policy

The library half is three independent stacks from `main` at `8897057f0`. They
touch disjoint code and merge cleanly against one another, so they can be
reviewed and merged in any order:

| Stack | PR | Branch | Title |
| --- | --- | --- | --- |
| Docs | #97 | `claude/tpir-pm-1-design` | docs: plan private transparent recovery over transparent PIR |
| Ledger | #98 | `claude/tpir-pm-2-trusted-commit` | feat(sqlite): atomically qualify and apply trusted transparent commits |
| Ledger | #99 | `claude/tpir-pm-3-remove-work-query` | refactor(ledger): remove the unused recovery-work query |
| Adapter | #100 | `claude/tpir-pm-4-injected-transport` | feat(pir-transparent): accept caller transports, narrow the API, repin wallet-pir |
| Adapter | #101 | `claude/tpir-pm-5-wallet-chain` | feat(pir-transparent): wallet chain view, birthday floor, publication-lag clamp, mainnet check |
| Adapter | #102 | `claude/tpir-pm-6-companion` | feat(pir-transparent): stable sources, published lineage, batch states, cache pruning |
| End to end | — | `claude/tpir-pm-7-e2e` | feat(pir-transparent): end-to-end private recovery against an in-process shard service |

Within a stack, each PR targets the one before it. The end-to-end PR needs the
ledger operation and the whole adapter stack, so it targets an integration
branch, `claude/tpir-pm-base`, that only merges the three stack tips; its diff
is the test alone. Once those stacks are on `main`, it is retargeted to `main`.

PR #99 deletes `TransparentLedgerRead::transparent_recovery_work` and its types,
which nothing calls outside tests and rc7 does not contain; the qualification
oracle instead covers each watched address from `required_from` through the
target, plus pending pages, as the adapter does. It is purely subtractive and
can be dropped.

The mega PR, `claude/tpir-private-mode`, points at the end-to-end PR's head, so
it carries every stack and its tree is identical to merging them all. Vizor pins
that 40-character SHA in all four `[patch.crates-io]` entries and the new
`zakura-pir-transparent` git dependency, repins after any restack, and repins to
`main` once everything is merged. Roman reviews and merges the stacks as they
are ready; each PR is reviewable on its own and leaves `main` green.

## Verification

In the library, PR 7 runs the real protocol against an in-process
`transparent-shard-server` that records every request.
`private_mode_lifecycle_against_an_in_process_shard_service` goes from untrusted
recovery through trusted commits and promotion, a tail move, lag, reopen,
companion loss and a sealed change, and asserts that requests match the service
routes, carry no script bytes and never fetch a filter below the floor;
`young_wallet_rolls_back_below_its_birthday` covers a rollback below the
birthday. Each earlier PR carries the focused tests its description names.
`a_declared_re_cut_keeps_the_wallets_history` re-cuts two sealed shards into
one wider shard behind the same origin: the next pass is `Ready`, requests only
the renumbered tail, and leaves the wallet unchanged apart from the tail, and a
companion recreated afterwards heals without quarantine.
`an_undeclared_re_cut_reaches_nothing_in_the_wallet` publishes the same re-cut
without its declaration: no shard is read and nothing in the wallet changes.
`a_lagging_pre_re_cut_map_after_the_re_cut_changes_nothing` serves the map from
before the re-cut again after the wallet followed it: each pass reads only the
old tail and is `Pending`, nothing in the wallet changes, and the re-cut map
served once more is `Ready` with the tail the wallet holds.

Focused runs, then final evidence on the mega head:

```sh
python3 scripts/dev.py test --config transparent -p zakura-client-sqlite transparent_ledger
python3 scripts/dev.py test --config transparent-pir
python3 scripts/dev.py verify
```

The `transparent-pir` CI lane runs the end-to-end tests; their wall time is
measured before merge, and the fixture shrinks past about 5 minutes. PR 7 drops
the crate from the `default` lane, leaving its no-feature build to
`zakura-graph`, and adds axum 0.7 and tower-http 0.5 (beside 0.6) to the test
graph; the graph check does not police duplicates outside vendored crates.

In Vizor: coordinator, policy, status, source, transport and FFI suites; the
ported Phase 6 suite, whose privacy test drives the real source against a
capturing lightwalletd with a positive control; a default build that writes
nothing and sends no PIR request; `db_upgrade` coverage of the ledger
migrations; an empty `cargo tree -i reqwest`; Dart tests for orderings, re-emit,
`Stopped` and cleanup; and an opt-in live test, once with Tor off and once with
Tor on. A manual desktop run checks the applied policy, promotion, the
re-emitted balance, shielding, toggle-off and `Stopped(NotSelected)` in a
default build.

## Release gates

Private authority stays behind the development flag until these close:

- an independent publication verifier and owner acceptance of the
  trusted-indexer model;
- a published library release with a rollback reader, and an exact Vizor and
  library pair with gate results;
- #783's published-release rule, which `zakura-pir-transparent` cannot meet
  while the wallet-pir crates are git-only;
- a freshness tolerance or re-propose, quarantine clearing, a
  `LegacyDiscrepancy` explanation path and pre-birthday Ledger recovery;
- a publisher commitment to the publisher requirements, and a publication
  freshness target;
- mobile and Tor bandwidth measurements, and iOS and Android device runs; and
- Vizor repinned to the merged `main`.
