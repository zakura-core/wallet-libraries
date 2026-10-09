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

All adapter changes are in `zakura/pir-transparent`, under the `wallet` feature;
wallet-pir does not change. `recover(watch, chain, filters, transport)` takes
the caller's `ChainView`, `FilterSource` and `ShardTransport`.
`RecoveryConfig`'s separate filter and shard origins collapse into one `origin`:
an identity label bound into the companion and its sources, which the adapter
never dials. The companion binding covers `source`, `account_binding`, `origin`
and `SCHEMA` (`transparent-shard-v11`). Schema v10, the `HttpObserver` plumbing
and the fixed user agent are deleted. The example builds its own HTTP clients
from a `reqwest` dev-dependency.

Before any shard retrieval, a pass checks that the chain view accepts the
target, that the script limits hold, that the filter source does not use parent
filters, that the shard map is within the shard limit and for mainnet, and that
the service's schema equals `SCHEMA`.

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
source   = sha256("transparent-reference-source-v2" || binding
             || lp(shard_schema) || lp(network) || lp(genesis_hash)
             || lp(profile) || envelope_le || start_height_le
             || lp(entry.geometry)
             || lp(canonical_json(map.seal[entry.geometry]))
             || shard_id_le || entry_start_height_le)
revision = sha256("transparent-reference-revision-v2" || digest || sealed)
lineage  = entry.revision + 1
```

`binding` is the companion binding hash and `lp` is a length prefix. A source
binds the map-wide identity fields, the entry's geometry, that geometry's seal
tier, the shard id and the entry's start height. Under the publisher
requirements, none of them changes for a shard while the store's set identity
continues. A publisher can add a geometry tier without re-binding the store;
that extends the seal map but changes no existing source. Shard ids are one
gapless sequence across geometries, so a seal change that re-shards one
geometry can move later shards to other ids; the start height gives an id
reused for other content a new source. Lineage comes from the publication, so a
lost or recreated companion reproduces identical triples. The library raises
`Integrity` before `Superseded` on a lineage collision, so the catalog must keep
colliding commits from reaching the wallet.

The companion format becomes `transparent-reference-companion-v2`, recorded in
`pir_bridge_binding`; a v1 companion is refused with an instruction to recreate
it. Revisions live in `pir_bridge_catalog`, keyed by `(source, digest, sealed)`
with lineage and revision unique per source, which records the shard id,
publication height and terminal hash, and `exported` and `current` flags.

Each pass parses the map the sync finished with, recorded rather than fetched
again, and in one immediate transaction marks stored entries still in the map
current, then classifies each relevant entry, highest first:

| Map entry | Result |
| --- | --- |
| Stored with the same digest, sealing, height and hash | Current |
| A stored row has its lineage with another digest or sealing | `Withdrawn(Equivocation)` |
| New, sealed, below the source's highest stored lineage | `Withdrawn(Regression)` |
| New, unsealed, below that lineage (lagging replica or rollback) | `Pending`; nothing inserted, the shard's commit dropped |
| Otherwise | Inserted |

Stored facts are then read with checked lookups. A fact naming a stale digest or
a shard missing from the map drops that shard's commit and makes the batch
`Pending`; it never fails the pass. Rows exported earlier and no longer current
are classified last, by the first rule that matches:

| Exported row | Result |
| --- | --- |
| Its shard id is in the map under another source | `Withdrawn(Retired)` |
| Its shard id is beyond the map's last shard (the map is behind) | `Pending` |
| Sealed | `Withdrawn(ChangedSealed)` |
| Unsealed, with a commit in this batch for its source at a higher lineage | Resolved |
| Unsealed without such a commit | `Pending` |

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
numbers is caught as `Withdrawn(Regression)` or `Pending`, as for a re-cut, not
as an `Integrity` collision in the wallet.

wallet-pir also raises `SyncError::MapDiverged` when stored pending pages name a
shard the map no longer lists, and when a mid-pass map refresh is not a
continuation. A lagging replica causes the first: the store commits its anchor
only when a pass completes, so after a budget-limited pass leaves pages on the
newest shard, the next clamp can follow a map without that shard. The adapter
maps every `MapDiverged` from the sync to a `Pending` batch with outcome
`Behind`, keeping the companion and catalog; PR 6 tests that case.

### Cache pruning

Each pass and each acknowledgment prunes. The catalog drops rows that are
neither current nor exported and lie below their source's highest lineage; the
highest row of every source is kept, so regressions stay detectable, also
across a publication change. The store drops `filter_cache` and `setup_cache`
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
Per-pass limits are 10,000 scripts, 1,024 shards, 500,000 events, 256 queries,
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
| Re-cut | A re-cut under an unchanged set identity restarts revision numbers. Sealed shards become `Withdrawn(Regression)`, the tail stays `Pending` until it passes the old maximum, and every account with evidence stops. After companion loss the catalog cannot detect the regression, so a colliding lineage yields `Integrity` and a quarantine. | Turn the setting off, or delete and re-import. See the publisher requirements. |
| Set-identity change | The adapter resets the store automatically and keeps the catalog, but old provisional evidence of the changed sources is never superseded, even where a batch listed it as retired and nobody acknowledged it. A shard whose source did not change but whose revision number restarted is treated as a re-cut. | It is consistent data, and reorgs still rewind it. See the publisher requirements. |
| Geometry move | A shard id that moves to another geometry under one set identity makes every pass for an account with its evidence `Withdrawn(Retired)`. | As for a re-cut. See the publisher requirements. |
| Origin change | A debug override creates new sources; the previous origin's provisional tail evidence is never withdrawn. | Debug builds only. |
| Withdrawn | Every cause holds the account for 1 h, then it retries; holds are in memory, so a restart retries once. | A lagging replica is `Pending`, not `Withdrawn`. No new durable state. |
| Pauses | Hard caps pause recovery, passes fail during a rescan, and a restore under private mode does not find transparent-only accounts. | Fails closed. |
| Service edges | A tail ahead of the wallet is not hash-bound, a server rollback stalls, and rc7 is not a supported rollback target. | — |
| Cost | Filters are downloaded per account, about 0.8–28 MB. About 91 commits are re-applied per account per pass, and about one `tpir_revisions` row is added per block per account. Up to 180 s of post-completion work delays the next sync. | No cross-account filter cache, and `tpir_revisions` is not pruned. |
| Test builds | `valar-spiral-rs` runs without overflow checks in every wallet-libraries test build, including Enhance PIR tests. | Mirrors wallet-pir's exemption. |

Not built: a verifier, attestation or trusted-source registry; revision
withdrawal, quarantine clearing or trust epochs; persisted holds; a library
coordinator or async API; reqwest in the adapter's normal graph; v10, txid
display, unsupported ranges or the parent-filter experiment; a freshness
tolerance; a new toggle, Shadow selection, remote kill switch, Dart-configurable
endpoint or release-build origin override; a progress FFI, cross-account filter
cache, concurrent batches or transport retries; mempool or txid PIR; Android
native changes; a PIR server in Vizor tests; a Ledger recovery bound; any
wallet-pir change; or a crates.io release of the adapter.

## Publisher requirements

The catalog rules assume a publisher that publishes the mainnet map under
`transparent-shard-v11`, never lowers a shard's revision number under an
unchanged set identity (a replica may lag, which the wallet treats as pending),
never publishes two digests or sealing states under one shard revision, never
changes a sealed shard's content, and never moves an existing shard id to
another geometry under one set identity.

A re-cut that restarts revision numbers must change a field every source binds,
for example through a profile or schema bump. A seal-tier change re-shards only
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
`private_mode_lifecycle_against_an_in_process_shard_service` goes from shadow
recovery through trusted commits and promotion, a tail move, lag, reopen,
companion loss and a sealed change, and asserts that requests match the service
routes, carry no script bytes and never fetch a filter below the floor;
`young_wallet_rolls_back_below_its_birthday` covers a rollback below the
birthday. Each earlier PR carries the focused tests its description names.

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
