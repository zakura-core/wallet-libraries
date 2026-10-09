# Preparatory refactor for a transparent PIR ledger

Status: Phase 0 is done, and the wallet-libraries halves of Phases 1–6 are
merged (#60–#62, #64, #68–#71). The Vizor halves of Phases 1–5 are in
`roman/tpir` (chainapsis/vizor-wallet#783, open); its Phase 6 suite is
unmerged, so consumer qualification remains pending. Production transparent
authority stays public during preparation. Real PIR integration, behind a
development flag, is planned in
[private transparent recovery](transparent-pir-private-recovery.md).

## Objective and fixed boundaries

Prepare wallet-libraries and Vizor incrementally for the
[transparent-ledger architecture](transparent-pir-ledger-architecture.md).
That document owns the invariants and API semantics. This plan owns the order
of changes, repository handoffs, intermediate behavior, and acceptance gates.

Keep the existing LRZ wallet core, database, input selectors, transaction
builder, and hardware flows. Wallet-libraries owns durable evidence and financial
authorization; Vizor owns the shared private-queries setting, networking,
scheduling, and presentation. No new user toggle is introduced.

Shielded scanning and transparent recovery remain two logical discovery loops
joined by txid. Enhance and Status have separate work and completion rules.
Follow the architecture's [sync contract](transparent-pir-ledger-architecture.md#shielded-sync-and-shared-transactions)
and [history contract](transparent-pir-ledger-architecture.md#history-completeness-and-storage-contract).

Private activation is exercised only in tests/development during this plan.
Once production activation is introduced in a later stage, the saved shared
setting applies before discovery, public transparent queries stop immediately,
and incomplete accounts cannot consume transparent inputs. Independently
eligible shielded-funded operations, including unshielding, remain available.
Missing display-only payment details do not block otherwise eligible spending.

## Execution order and repository handoffs

Complete Phase 0, then Phases 1–6 in order. Within each phase, implement and test
the wallet-libraries steps first, then integrate that exact revision into Vizor.
A phase can contain several small changes; its acceptance gate must pass before
enabling behavior that depends on it. Tests belong with each change, not only
in the final qualification phase.

| Phase | Wallet-libraries deliverable | Vizor deliverable | Behavior available at phase exit |
| --- | --- | --- | --- |
| 0. Baseline (done) | Contract/call-site inventory and reference fixtures. | Consumer baseline and discovery/handle inventory. | Existing public behavior recorded. |
| 1. Contract and migration (library merged) | Read contract, policy/provenance schema, configured handles. | Dependency upgrade and explicit handle configuration. | Schema upgrades; private transparent input use remains unavailable. |
| 2. Privacy boundaries | Durable policy transitions and guarded follow-on work. | Shared policy, dispatch guards, native/preview coverage. | Required-private fixtures fail closed before any unsupported request. |
| 3. Candidate recovery | Watched scripts, candidate events, coverage, resumable commits. | Disabled/fixture source and bounded coordinator. | Isolated candidate recovery; no production projection changes. |
| 4. Safe activation | Atomic projection, rewind, promotion, and all financial gates. | Balance/operation integration and activation fixtures. | Per-account private activation and spending exercised with fixtures. |
| 5. History integration | Evidence-backed history reads and detail state. | Partial-history classification, FFI, and UI. | Mixed transactions and restored history represented accurately. |
| 6. Qualification | Lifecycle/failure evidence and repair compatibility. | Cross-repository regression and request-capture results. | Preparatory refactor complete; real PIR integration still gated. |

For each handoff:

1. Record the tested wallet-libraries commit and enabled features.
2. Update Vizor's related dependency pins and lockfile consistently; verify the
   resolved graph rather than assuming all packages use the same revision.
3. Run the phase's consumer checks against that revision. Keep dependency or
   consensus changes unrelated to this refactor visible as separate changes.
4. Record the gate result and remaining limitations. Do not enable production
   private authority merely because a pin, schema, or fixture test is present.

For library paths below, `backend/` means
`librustzcash/zcash_client_backend/src/` and `sqlite/` means
`librustzcash/zcash_client_sqlite/src/`. Vizor paths are relative to its repository
root. New modules are marked proposed. Reuse existing transport and database
boundaries; do not create a general sync plugin framework or a second
authoritative database.

## Phase 0 — Establish the implementation baseline (done)

Phase 0 produced the call-site inventory on both sides. The library inventory
shaped Phase 1 below. The Vizor inventory, which later phases depend on, is:

- **Handles.** Every production `WalletDb` comes from the three constructors in
  `rust/src/wallet/db.rs`: `open_wallet_db_with_timeout`,
  `open_wallet_db_for_read_with_timeout`, and
  `open_wallet_db_readonly_with_timeout`. The one exception is the
  borrowed-transaction handle in `record_creation_evidence`
  (`rust/src/wallet/sync/migration.rs`). `open_wallet_raw_conn_with_timeout`
  returns a raw connection, not a `WalletDb`. Tests and examples construct
  their own handles (`rust/src/wallet/addresses/tests.rs`,
  `rust/examples/ledger_zcash_speculos_poc.rs`).
- **Transparent discovery** runs on the per-sync handle: UTXO refresh
  (`store_transparent_outputs` in `rust/src/wallet/sync_engine/mod.rs`),
  Ledger discovery (`rust/src/wallet/sync_engine/ledger_discovery.rs`), and
  transparent history
  (`rust/src/wallet/sync_engine/enhancement/auxiliary/transparent_history.rs`).
- **Pre-DB public requests**, with no `WalletDb`:
  `discover_used_software_accounts` and
  `preview_software_account_transparent_balance` in `rust/src/api/wallet.rs`.
  Phase 2 guards them.
- **Migrations** run seedless through `ensure_db_migrated_once`
  (`rust/src/wallet/keys.rs`) at startup, before the Enhance/Status policy is
  applied. Only creating the first software account passes a seed; hardware and
  observer imports are seedless.
- **Sync.** Vizor runs its own sync engine over `scan_cached_blocks` and does
  not call the backend's `sync::run`.

## Phase 1 — Add the contract, schema, and configured handles

The wallet-libraries half shipped in #60 (contract), #61 (schema and
provenance), and #62 (configured handles). It is narrower than originally
planned in some places and stricter in others; see the deviations below.

**What shipped in wallet-libraries**

1. **Contract.** `backend/data_api/transparent_ledger.rs` provides
   `ChainPoint`, `TransparentLedgerMode` (`Public`, `PrivateRequired`), `TransparentLedgerSnapshot<AccountId>`, and
   `TransparentLedgerRead` (`transparent_ledger_mode`,
   `transparent_ledger_snapshot`). The snapshot carries the authority, the
   authorized balance split into regular and coinbase, the last-known amount
   with `LegacyPublic` or `LegacyPublicAndLocal` provenance, and blockers.
   There is no write trait.
2. **Schema.** The `transparent_ledger_schema` migration is seedless and
   additive. It creates three tables:
   - `tpir_meta`: the durable policy (`applied_mode`, `policy_generation`,
     `min_reader_version`), seeded as public, generation 0, reader version 1;
   - `tpir_output_origins` and `tpir_spend_origins`: provenance, with codes
     0 = legacy public and 1 = local construction; 2 and 3 are reserved.

   It backfills legacy and local origins. From then on every transparent
   output or spend write records its origin in the same transaction, and
   outbox creation evidence adds local origins atomically. Existing remote rows
   are legacy evidence, never private coverage.
3. **Handles.** `WalletDb::set_transparent_ledger_mode` and
   `with_transparent_ledger_mode` set a per-handle mode. It is not persisted;
   `transactionally` inherits it.
4. **Fail-closed rules.**
   - An explicit mode is required for transparent input selection, storing any
     transaction with transparent inputs, `put_received_transparent_utxo`,
     transparent history requests, and the ledger APIs. Unconfigured handles
     fail. An unconfigured handle on a wallet without a private policy can
     still read balances for display.
   - A durable `PrivateRequired` is never weakened: every read resolves a
     weaker configured handle to `PrivateRequired`, including after another
     connection applied it, without writing the policy. Only an explicit
     transition lowers it. Qualification and promotion still require a handle
     configured `PrivateRequired`. A missing policy row or table, or a newer
     reader requirement, fails closed.
   - Transparent authority is unavailable under `PrivateRequired`, while the
     chain tip is unknown, and in builds without `transparent-inputs`. Then
     selectors and stores with transparent inputs fail,
     `get_wallet_summary` omits transparent funds,
     `get_transparent_balances` fails, and `get_received_outputs` reports
     `u32::MAX` confirmations until spendable.
   - Under `PrivateRequired`, public transparent discovery is refused, the
     backend `sync::run` skips UTXO refresh before any request (it now requires
     `TransparentLedgerRead`), and transparent history requests are withheld.
5. **CI** runs an `orchard,transparent-inputs,test-dependencies,unstable` lane.

**Deviations from the original plan**

- **Schema.** Only the policy and provenance tables exist. The recovery tables
  (scripts, event observations, coverage, pending work) move to the Phase 3
  migration.
- **Contract.** Write, commit, promotion, and history-completeness types were
  left out. Phases 3–5 add them with the code that uses them.
- **Existing APIs require configuration.** The plan had only new APIs reject
  unconfigured handles; the existing transparent APIs above do too.
- **Phase 2 gates pulled forward.** Refusing public discovery and withholding
  transparent summary and balances under `PrivateRequired` are already in the
  library. Phase 2 keeps the rest.
- **Release.** No release contains the migration yet, so it can still be
  corrected in place. Once a release includes it, it is frozen and schema
  changes need forward migrations; record it in `PUBLIC_MIGRATION_STATES`
  then.

**Vizor steps**

1. Consume wallet-libraries `main` (at least `0e0d1b128`) through
   `[patch.crates-io]` git entries for `zakura-client-backend` and
   `zakura-client-sqlite`. Other Vizor dependencies such as `zakura-pir-enhance`
   reach the backend through crates.io, so a direct git dependency would
   duplicate it. The pin also brings in the ZIP 318 schema drop (#55).
2. Configure `TransparentLedgerMode::Public` on every handle in the Phase 0
   inventory, from one mode source in
   `rust/src/wallet/sync_engine/enhancement/policy.rs`. It always returns
   `Public` in Phase 1; Phase 2 derives it from the private-queries setting.
   Development fixtures can request stricter modes.
3. Keep the saved user setting intact. Never overwrite a durably applied
   `PrivateRequired` policy with `Public` because a build lacks support; such a
   database stays blocked, and the user sees that it needs a newer build.
4. Check callers that shield or propose before the first chain-tip update,
   which now fail.
5. Extend the upgrade probes: fixtures from a pre-Phase-1 base (and the
   existing `mobile/v0.0.18` base), including a hardware-first scenario
   without a seed and raw-SQL transparent rows (a remote UTXO and a local send
   with a lock).

**Exit gate:** representative databases, including imported-only and
hardware-first ones, upgrade without seeds, changed public balances, or lost
local history. Verified with raw SQL: the `tpir_*` tables exist, `tpir_meta` is
`(0, 0, 1)`, and every transparent output and spend has an origin.
Transactional/reopened handles retain the required configuration;
unconfigured/private-unavailable paths fail explicitly, and a durable
`PrivateRequired` survives startup migration unchanged. Migration interruption
and storage failures fabricate neither coverage nor history completeness.

## Phase 2 — Enforce privacy before adding recovery networking

Phase 1 already refuses public transparent discovery and withholds transparent
history requests, summary funds, and balances under `PrivateRequired`. This
phase owns the rest: queued follow-on work such as parent-transaction retrieval
from `tx_retrieval_queue`, Status routing, durable policy transitions with
generations checked at dispatch, and the Vizor paths.

**Wallet-libraries steps**

1. Implement durable applied policy, generations, and compatibility requirements.
   A transition revokes stale operation contexts; commit checks must reject
   obsolete policy generations even when an older handle remains open.
2. Audit work creation and routing in `backend/data_api/enhance_pir/`,
   `sqlite/wallet/enhance_pir.rs`, and status/transaction-retrieval APIs. Under
   `PrivateRequired`, mixed results such as `has_transparent` or
   `LwdRequired` must yield explicit pending/unsupported private details,
   without deleting financial facts or authorizing a public request.
3. Keep transaction/action/output detail work independent. A recovered memo,
   unsupported payload, or incomplete status response cannot complete another
   obligation or establish ledger coverage. Preserve existing trusted local
   evidence rules for status and expiry.

**Vizor steps**

1. Extend the existing policy in
   `rust/src/wallet/sync_engine/enhancement/policy.rs`,
   `lib/src/providers/enhance_pir_provider.dart`, and
   `lib/src/core/storage/enhance_pir_preference_store.dart`. Extend the paused
   setting-transition flow; reconcile preference and database policy
   conservatively before dispatch and capture one immutable policy per operation.
2. Guard UTXO refresh, Ledger/address-history discovery, software account
   discovery, and previews. Resolve the same policy before pre-DB requests;
   unsupported private previews report unavailable.
3. Guard payload, fee/parent, and status dispatch from either discovery loop,
   including already queued public work and retries. Shielded-first mixed
   discovery must be protected before the transparent ledger sees the txid;
   server shape flags cannot grant disclosure authority.
4. Apply the policy to `rust/src/ffi.rs`, mobile/native preparation adapters,
   and their reopened handles. Preserve foreground handoff where a background
   task cannot establish the required private anchor. Reuse existing route,
   cancellation, and deadline handling.
5. Add request-capture tests for private transitions and unsupported sources
   before the coordinator can issue requests. Production transparent authority
   remains public during preparation; the stricter path is exercised with
   test/development policy, not a new user setting.

**Exit gate:** private fixtures emit no unauthorized address, script, outpoint,
or txid lookup through any inventoried entry point. Test startup, interrupted
setting writes, cancellation, stale queues/handles, mixed shape flags, and
missing configuration. Explicit public behavior remains covered by regression
tests. No real transparent PIR client is needed to pass this gate.

## Phase 3 — Recover an isolated candidate ledger

Phase 3 adds candidate recovery that the library owns and keeps apart from the
wallet's balances. It stores what a source reports about each watched address
and checks every commit against the current policy, account, addresses, and
chain. It never writes the LRZ tables that balances, input selection,
receiving-address allocation, and history read.

**What the wallet-libraries half adds**

1. **Watch set.** `TransparentLedgerRead::transparent_watch_set(account)`
   returns, from one read:
   - every watched address:
     - the account's rows in `addresses` (external, internal, ephemeral, and
       imported standalone keys and scripts);
     - the legacy external address, which may have no row;
     - the candidate window (see step 5);
   - the capture context: the policy generation, and the highest contiguously
     scanned local block as the target;
   - the pages earlier runs left open.

   Every address must be covered from the account birthday.
2. **Commit.** `TransparentLedgerWrite::apply_transparent_ledger_commit`
   applies one pass for one account atomically. A commit carries:
   - receive and spend events;
   - checked ranges, including ranges with no events;
   - ranges the source cannot check;
   - opened and completed pages;
   - the source revision;
   - an anchor: the highest local block the source verified the revision agrees
     with.

   Nothing in a commit may extend past the anchor, and the anchor may not
   extend past the target.
3. **Context checks.** A commit is refused, applying nothing, unless:
   - the policy is still at the captured generation;
   - the policy is `PrivateRequired` both on the handle and durably;
   - the account still exists;
   - the target is still a contiguously scanned local block, and the anchor is
     still a local block;
   - every address the commit names is still watched by the account.

   Rejections are `Stale` (retry from a fresh watch set), `Integrity` (stop
   trusting the session), or `Invalid` (malformed).
4. **Evidence rules.**
   - A receive is identified by its outpoint, and a spend by its txid and input
     index. Content is immutable; a later commit can set only a placement that
     is missing.
   - A spend names the address of the output it consumes. It stays unresolved
     until that output arrives, and is checked against it.
   - Refused as integrity failures: contradictory content, a different
     placement on the local chain, and two mined spends of one output.
   - Each revision that reports an event is recorded as an observation.
   - Within a source, a trusted qualification transition to a higher lineage replaces
     a lower one. Observing a candidate revision cannot invalidate financial evidence.
     Authorizing the transition
     removes the coverage, pages, and event observations of the source's older
     provisional revisions. Events without another active observation are
     removed; sealed revisions are never superseded.
   - Within one revision, supported coverage and an open page cannot overlap
     for the same address, in either order, and no range can be both checked
     and unsupported. Other revisions' pages and coverage
     are independent evidence.
   - All events of one transaction share one placement and one coinbase
     classification, and a coinbase transaction spends nothing. No commit
     anchor may lie above its revision's asserted publication height.
     Unsupported ranges block completeness until another source covers them.
5. **Candidate window.** Mined activity within a gap limit of a derived scope's
   window end extends the window in `tpir_candidate_windows`. The commit then
   reports `window_grew`. Window addresses are derived on read. They are never
   written to `addresses`, so they are never marked used or offered for
   receiving.
6. **Lifecycle.**
   - *Truncation* runs in every build, at the rescan floor: a rewind can keep a
     higher checkpoint but requeues the blocks above the floor. It clears event
     placements above the floor and removes pages opened for a later target.
     Coverage anchored above the floor is clipped to it and re-anchored there:
     the revision agreed with the old chain at its anchor, and that chain equals
     the surviving one up to the floor. Coverage is deleted when the floor block
     is unknown.
   - *Policy transitions* remove open pages.
   - *Re-attributing an imported receiver* to another account forgets the
     previous account's evidence for it.
   - *Deleting an account* removes its candidate state.
   - *Reader version.* The first candidate commit raises
     `tpir_meta.min_reader_version` to 3, so earlier builds, which would leave
     candidate state stale across rewinds, fail closed.
   - *Lowering a birthday* needs no hook: completeness is computed from the
     current birthday, so coverage from the old birthday no longer suffices.
7. **Diagnostics.** `TransparentLedgerRead::transparent_candidate_recovery`
   returns, from one read:
   - continuous coverage from the birthday (vacuous while the target is below
     it), and blockers;
   - counts;
   - the mined receives and spends, and the unspent outputs;
   - their sum, which is unverified: it can be above or below the real balance,
     and is absent when it exceeds `MAX_MONEY`.
8. **Schema.** The seedless, additive `transparent_recovery_schema` migration
   adds nine empty `tpir_*` tables:
   - `tpir_candidate_windows`, `tpir_revisions`, `tpir_coverage`;
   - `tpir_receive_events` and `tpir_spend_events`, each with its observations
     table;
   - `tpir_pending_pages` and `tpir_pending_page_scripts`;
   - indexes for the per-event lookups: coverage by script, events by account,
     and spends by prevout.

**Deviations from the original plan**

- **The bound is the birthday.** The architecture accepts a birthday only when
  it is also a justified transparent-history bound. Phase 3 uses the account
  birthday for every script, trusting a restored wallet's user-supplied
  birthday as shielded scanning does.
- **Addresses are checked one by one; there is no watch-set generation.** Each
  named address must still be watched. Addresses added mid-run are simply
  uncovered, so in-flight work survives. The coordinator repeats while
  `window_grew` is set or the watch set changes.
- **Deferred to Phase 4:**
  - durable integrity quarantine and trust epochs;
  - source qualification;
  - recovered-unverified amounts in `TransparentLedgerSnapshot`;
  - projection, promotion, and the history-completeness contract.

**Vizor steps**

1. Add a proposed `rust/src/wallet/sync_engine/transparent_ledger.rs`
   coordinator and a narrow source boundary returning normalized results.
   Implement disabled and deterministic fixture sources only. Disabled returns
   unavailable; fixtures cannot qualify a production account.
2. Capture a fixed accepted contiguous chain point and operation context,
   enumerate scripts, call the source under query/byte/page/time bounds, and
   commit through the library. Repeat on window growth at the same target.
   Hold no write lock across network/source I/O.
3. Schedule alongside shielded scanning while keeping separate checkpoints,
   queues, retries, and completion. The public projection and `.receive.redb`
   cache never become private evidence.
4. Add local exact-set comparison against fixtures at a common chain point.
   Expose only development diagnostics at this stage, with candidate amounts
   explicitly unverified and potentially above or below the real balance.

**Exit gate:** fixture receives/spends, empty ranges, partial pages, cancellation,
window growth, and restart converge to expected candidate state. Reorg/import
races reject stale commits. Candidate recovery changes no production balances,
selection, locks, address allocation, or history.

## Phase 4 — Activate safely and enforce every financial path

Projection, rewind, promotion, and financial gating form one release boundary.
They may be implemented in smaller changes. Keep successful promotion unavailable
outside focused tests until those library components pass together; only then
let Vizor's fixture coordinator exercise activation.

**What the wallet-libraries half adds**

The half is one PR on top of Phase 3. Every intermediate commit fails
closed: `PrivateRequired` keeps the Phase 1 mode-level "unavailable" until the
gating change lands. Only a test/development hook can qualify a revision, so
production cannot qualify nonempty recovery. An empty required interval can still
promote with zero funds; missing coverage subsequently withholds authority.

1. **Schema.** A seedless, additive `transparent_activation_schema` migration
   adds four empty tables:
   - `tpir_active_accounts`: the account lifecycle. A row makes the account
     *active*; otherwise it is a *candidate*.
   - `tpir_qualified_revisions`: revisions qualified to support authority.
   - `tpir_quarantined_sources` and `tpir_quarantined_accounts`: integrity
     quarantine.

   The first write to any of them raises `min_reader_version` to 5, so a
   build that ignores them or retained-output withdrawal semantics fails closed.
   Withdrawing a previously projected receive also requires 5 when the account
   has been demoted to a candidate. Version 4 admitted all stored outputs under
   public policy and therefore cannot safely read retained withdrawn rows.
   Epochs are left out: nothing can clear
   a quarantine yet, so there is no revalidation race to guard.
2. **Contract.**
   - `TransparentAuthority::Private` and `RecoveryCompletion::Complete`.
   - The snapshot gains `covered_through` and `recovered_unverified`, and
     `LastKnownSource::PrivateLedger` reports a blocked active account. Its
     amount is anchored at `covered_through` only when that is the tip.
   - `RecoveryBlocker` becomes the one blocker enum for the snapshot and
     promotion. It gains `Recovery(CandidateBlocker)`, `NotActivated`,
     `Quarantined`, `UnqualifiedRevision`, `LegacyDiscrepancy` and
     `ChainBehindTip`.
   - `TransparentLedgerWrite::promote_transparent_account(account)`.
   - The watch set and the recovery context carry the account's
     `AccountLifecycle`; a commit captured under another lifecycle is
     `StaleCommit::LifecycleChanged`.
   - `CommitRejection::Refused` covers a quarantined source or account and an
     unqualified revision on an active account.
   - Qualification is a sqlite-only test/development hook, not a trait method.
     It records a new revision exactly as a commit would, so a revision can be
     qualified before its first commit to an active account.
3. **Quarantine.** An integrity rejection rolls back every submitted fact.
   In the same transaction it quarantines the source, the committing account,
   and every account holding that source's evidence, and deletes those
   accounts' pending pages. Quarantine survives restarts and rewinds.
4. **Projection.** Placed events are written into the LRZ tables through the
   existing `put_transparent_output` and `mark_transparent_utxo_spent`, with
   a new projection origin, *ledger event* (code 2). Mixed transactions join on
   the shared `transactions` row, which keeps raw data, fees, local creation
   evidence, notes and locks. A projected coinbase receive records
   `tx_index = 0`, so its classification does not depend on raw bytes. A
   placement or content conflict with the projection is an integrity failure,
   and so is an event the wallet's stored transaction bytes contradict: a
   receive of an output the transaction lacks or holds with another value,
   script or coinbase status, or a spend by an input that spends another
   outpoint or does not exist.
   Legacy-only rows are never deleted, and never authorize a spend.
5. **Promotion.** One transaction:
   1. rechecks the policy (`PrivateRequired` on the handle and durably), the
      account, quarantine, the candidate blockers at the local target, a
      local target equal to the chain tip, qualification of every revision
      that contributed coverage or observations, and legacy discrepancies;
   2. writes the candidate-window addresses, and the legacy external receiver
      when it has no row, into `addresses` (the projection requires an address
      row), then drops the candidate window rows. A window reaching the last
      non-hardened index is `WindowUnderivable`: the address table cannot hold
      that index, so the account stays a candidate;
   3. projects every placed event;
   4. records the account as active.

   A legacy discrepancy is one of:
   - a wallet output, of any origin, whose candidate receive has other content,
     account, or placement;
   - a wallet output, of any origin, mined at or below the target that the
     complete candidate set lacks or no longer places;
   - a legacy spend mined at or below the target that no candidate spend by the
     same transaction confirms.

   Each blocks promotion; there is no way to explain one yet.
   A ledger-only output retained after its receive lost every observation is
   historical wallet state, not independent evidence of a missing receive, and
   does not block reactivation. Content conflicts and independent legacy evidence
   still block; a rewound receive still present in the ledger keeps the existing
   discrepancy rule.
6. **Active commits** follow the candidate path, additionally require qualified
   revisions, and project their events in the same transaction. After
   activation, window growth uses LRZ's gap-limit address generation. When a
   trusted higher lineage supersedes a provisional revision, each event that loses its
   last observation withdraws its authority. Unsupported ledger-only spend links
   and pending spends are removed. A ledger-only output keeps its row and
   historical origin so independent spend links and reservations survive, but
   without a placed receive every selector and balance query excludes it under
   both private and public policy. Replaying the receive updates that same row,
   preserving its spentness and lock ownership. An output with another origin
   keeps that independent evidence and loses its ledger origin.
   Leaving `PrivateRequired` demotes every account in the policy
   transaction.
7. **Rewind.** LRZ un-mining already makes projected rows above the truncation
   unspendable, and the Phase 3 truncation clips coverage to the retained
   block. That block is then the local tip, so authority continues over the
   surviving outputs. Once the wallet learns of a newer tip, authority pauses
   (`ChainBehindTip`) until recovery covers it. A rewound receive keeps its
   projection, but private authority admits an output only while the ledger
   places its receive, so an orphaned receive authorizes nothing even after
   coverage returns. A rewound spend stays a pending spend until its default
   expiry, as LRZ treats a reorged public spend; that only withholds the
   output. Activation, qualification, quarantine, and address exposure survive
   rewinds; re-placed events are re-projected.
8. **Financial gating.** Under `PrivateRequired`, an account is eligible for
   target `T` when it is active and not quarantined, has no candidate blockers,
   and its local target and the chain tip are both `T - 1`. All four selectors
   check eligibility and query in one read snapshot, and admit only
   ledger-origin outputs of eligible accounts whose receive is placed. The account and outpoint lookups
   fail for an ineligible account. The address selectors filter out ineligible
   accounts, and fail only when no owning account is eligible.
   `store_transactions_to_be_sent` rechecks every transparent input at the
   transaction's target height, which covers proposals, PCZTs and hardware
   finalization. The outpoint lookup enforces the same coinbase maturity rule
   as the other selectors, including at this final storage gate. Metadata
   lookups without a spend target can still read immature or withdrawn rows.
   An input created by an earlier transaction of the same batch
   is allowed. Shielded-funded unshielding spends no transparent input, and
   its own transparent output is spendable only once a ledger commit covers it.
9. **Snapshot.** Under `PrivateRequired`, an eligible account reports
   `Private` authority, its ledger-origin balance as authorized, and
   `Complete`. Otherwise authority is unavailable and the blockers explain
   why. `get_wallet_summary` and `get_transparent_balances` keep omitting
   transparent funds under `PrivateRequired`, so clients read the snapshot.

**Deviations from the plan**

- **Coinbase.** A projected coinbase receive records `tx_index = 0`, the
  consensus position of a coinbase transaction, rather than adding a
  ledger-specific coinbase predicate to the balance and selection queries.
  Un-mining clears it together with the placement.
- **Epochs are deferred.** Nothing can clear a quarantine or requalify a source
  before Phase 6's verification, so trust and quarantine epochs would guard
  nothing yet.
- **Rewinds keep authority at the retained tip** (item 7) instead of revoking
  it outright. Coverage through the retained block is valid on the surviving
  chain, and learning of any newer tip pauses authority.
- **Truncation entry points.** The four entry points share
  `truncate_to_height_internal`, which calls the Phase 3 hook, so the tests
  exercise `truncate_to_height`.
- **Quarantine granularity.** Quarantine is per account and per source.
  Revisions of a quarantined source recorded before the failure stay as
  evidence, and the accounts holding them are quarantined with the source.

**Vizor steps**

1. Consume the snapshot in balance/summary and operation availability paths,
   including `rust/src/wallet/wallet_summary_cache.rs`. Show unavailable or
   last-known amounts accurately; invalidate caches on commits, policy,
   promotion, rewind, and account lifecycle changes.
2. Integrate software send/shielding, `rust/src/wallet/sync/send.rs`,
   `rust/src/wallet/sync/pczt.rs`, and Ledger/Keystone completion paths with
   the existing library selectors and revalidation rules. Preserve the current
   signing, outbox, persistence, and broadcast lifecycle; a UI precheck never
   substitutes for authorization.
3. Exercise private activation with fixtures: immediately stop public
   transparent discovery, leave incomplete accounts unavailable, promote ready
   accounts independently, and handle lag or outage without source fallback.
   Reuse candidate state only after revalidating its full activation context.

**Exit gate:** commit/promotion/rewind failpoints and WAL restart leave a
consistent projection and authority. Both discovery orders and payload replay
preserve mixed effects. All transparent selectors and stale proposals reject
incomplete coverage; coinbase, locks, local chains, shielded-funded unshielding,
account isolation, and explicit public behavior have focused regression tests.
Revision withdrawal/replay preserves independently observed and locally
constructed spends and reservations across reopen; withdrawn rows contribute
no public funds and do not block reactivation. Coinbase boundary tests reject
all four selectors and final storage at 99 blocks and admit them at 100.

## Phase 5 — Integrate complete and partial transaction history

**Wallet-libraries steps**

1. Implement the Phase 1 history read contract using existing transaction/output
   views where possible. Read effects and completeness consistently, retaining
   account/scope, local intent, optional metadata, and source provenance.
2. Tie any stored detail-completion markers to evidence and supported
   capabilities. Keep missing recipients, per-output memos, fees, and status
   distinct from missing owned-effect coverage. Empty queues are not proof of
   complete history.
3. Invalidate derived classifications/detail state with affected evidence on
   rewind, promotion, account changes, and later enhancement. Preserve richer
   independently recorded local-send details when partial discoveries arrive.

**Library plan**

Phase 5 adds one read, and no tables or stored markers:
`TransparentLedgerRead::transaction_history_details(account, txids)`. It returns
`TransactionHistoryDetails` for each requested transaction in which the account
has a recorded output or spend, from one read. A spend an active ledger
recovered before its output counts, so a debit is never hidden; a candidate
ledger stays isolated from history. Everything it reports is derived
from facts the wallet already holds: `v_received_outputs` and its spends, the
`transactions` row, the scan queue, the account's ledger coverage, and the
queued follow-on work. So rewinds, promotion, account changes, and later
enhancement change the result as soon as they change those facts, and there is
nothing to invalidate.

- **Owned effects.** A `PoolEffect` for every pool the build supports:
  transparent (with `transparent-inputs`), Sapling, and Orchard and Ironwood
  (with `orchard`). Each carries the known amounts received and spent by the
  account, and an `EffectCompleteness`:
  - `Complete`: no owned effect in the pool can be missing;
    - for a transaction the wallet constructed and stored, while its funding
      account's recorded outputs remain, every pool, except
      a shielded pool with an output the wallet sent to an external address
      without recording a receipt, until the transaction is scanned: local
      construction defers the receipt of a payment to one of the wallet's own
      external shielded addresses. Creation evidence alone, such as an
      outbox's, is not enough;
    - for a shielded pool of an account with a full viewing key, a mined
      transaction at or below the fully scanned height, or an unmined one whose
      full data is stored while the fully scanned height is the chain tip,
      and every known owned nullifier in that payload has a recorded spend
      link. Ingestion links only notes already found; later scanning can find a
      funding note without linking an unmined spender. Until reingestion repairs
      that link, the pool stays incomplete. An account imported
      from an incoming viewing key never detects its spends, so its shielded
      effects stay incomplete;
    - for the transparent pool under `PrivateRequired`, a mined transaction of
      an active, unquarantined account covered through its height, with no
      unresolved spend in that transaction;
  - `PublicDiscovery`: the transparent pool while public discovery holds
    authority (`Public`) and no parent of the transaction's
    unresolved inputs is queued for retrieval. Its completeness is not
    verified;
  - `Incomplete`: anything else. The known amounts are partial, not final.
- **Payment details.** `Complete` when the wallet constructed and stored the
  transaction. Otherwise every effect must be settled, every shielded memo of
  the account's outputs retrieved, and either the account only received, or
  the value it spent equals what it received back, plus its recorded outputs to
  others, plus the recorded fee. Full data alone is not enough: outputs the
  wallet cannot decrypt, such as one sent with its outgoing viewing key
  discarded, are never recorded. One recovered memo does not complete a
  transaction.
- **Fee.** `Known(fee)` when the account spent something and the fee is
  recorded; `NotApplicable` when the account provably spent nothing (every pool
  complete or public, no known spend, and no creation evidence without stored
  details); otherwise `Unknown`. Unknown is never zero.
- **Classification.** `LocalIntent` for a transaction the wallet created;
  `Reconstructed` when every pool is complete or public and either the account
  only received or its spent value is accounted for; otherwise `Provisional`.
  A missing memo alone never makes a transaction provisional.
- **Pending private details.** The `PrivateTransparentDetail`s withheld for this
  transaction under the current policy: a queued parent retrieval for one of
  its inputs, or its own mixed-transaction marker. The queue keeps only the
  latest dependent of a parent, so a transaction's parents are also found
  through its unresolved inputs in `transparent_spend_map`.

Local construction details are kept when discovery arrives in either order,
because projection and payload ingestion upsert the shared `transactions` row;
tests check this through the new read.

**Deviations from the plan**

- **Completeness states.** Effects are `Complete`, `PublicDiscovery`, or
  `Incomplete`, not complete, partial, or unknown. An incomplete effect already
  carries whatever amounts are known, so "partial" and "unknown" add nothing.
  Public discovery gets its own state, because it is authoritative by policy
  but not verified.
- **Memos and recipients per transaction.** Payment-detail completeness is one
  value per transaction. Per-output memo state is already distinct in
  `v_tx_outputs` (`NULL` is not retrieved; `0xF6` is empty), and recipients stay
  in `v_tx_outputs`; the read adds only what those views cannot say.
- **Shielded bound.** Shielded completeness uses the wallet's contiguously
  scanned height, not a per-account bound. That is conservative for an account
  born after the wallet birthday.
- **No stored markers.** Every result is derived, so there are no detail
  markers to tie to evidence or to invalidate.

**Vizor steps**

1. Update `rust/src/wallet/sync/transactions.rs`: make
   `HISTORY_BASES_CTE` classification completeness-aware, remove unknown-fee
   coalescing in `read_history_bases`, and fix `classify_history_tx` so
   missing external outputs cannot hide a known debit with change.
2. Carry recovery state and optional fields through flat Rust API/Flutter
   results. Regenerate bindings with `scripts/generate-rust-bridge.sh` when
   the API changes; adapt providers and activity/details views together.
3. Keep transaction identity stable while details arrive. Represent shielding,
   self-unshielding, mixed payments, and cross-account effects without duplicate
   accounting. A provisional net debit is not a final recipient amount.
4. Show known activity with incomplete details instead of invented zero fees
   or recipients. Preserve local TEX grouping; without sufficient restored
   grouping evidence, retain the individual transactions. Invalidate history
   and summary caches when discovery or enhancement changes these results.

**Exit gate:** Rust and Dart fixtures cover preserved local history and seed
restoration for shielding, self/external unshielding, mixed inputs, and
cross-account transfers. Test both arrival orders, missing external outputs
with change, unknown fees/memos, and later enrichment. Known debits remain
visible, self-transfers are not double-counted, and no history gap triggers
public enrichment.

## Phase 6 — Qualify migration, restart, and cross-repository behavior

**Wallet-libraries steps**

1. Run the independent block-derived oracle over exact receive/spend, UTXO,
   balance, coverage, and projected-effect results. Legacy parity alone does
   not qualify correctness or completeness.
2. Exercise fresh, long-lived, multi-seed, imported-only, and hardware-first
   migration fixtures, including pending sends, reservations, and prior rewinds.
3. Inject commit/promotion/rewind failures, disk-full/storage errors, and restart.
   Cover same-height and sealed/provisional reorgs, re-mining, account deletion,
   earlier bounds, and stale generations.
4. Validate forward repair and the designated privacy-aware rollback release.
   Preserve local evidence and applied private policy; arbitrary historical
   binaries are not supported rollback targets.

**What the wallet-libraries half adds**

Phase 6 is qualification. It adds tests under
`sqlite/wallet/transparent_ledger/tests/recovery/activation/qualification/`,
one production fix they exposed, and no API or table.

1. **Block-derived oracle** (`oracle.rs`). A fixture chain of real transactions
   with transparent bundles, placed at local heights. The oracle walks it block
   by block with only the account's keys, and derives the exact receives,
   spends, unspent outputs, and balances. A fixture source indexes the same
   chain by address, as a server would. A driver delivers it the way a
   coordinator might: in groups, reordered, with spends before their receives,
   through pages, and replayed, repeating while the watch set grows. The chain
   extends both derived windows several times and holds a coinbase output, a
   spend in its receive's block, a spend mixing owned and foreign inputs, and
   foreign-only activity. The candidate diagnostics, the projection, the
   snapshot, and the selectors equal the oracle after candidate recovery,
   promotion, active commits, and a rewind that re-mines transactions at the
   same and at other heights and orphans one payment. Legacy rows take part
   only through the promotion discrepancy check.
2. **Migration fixtures** (`migration.rs`). Wallets created at the migration
   state before the ledger schema, with real keys and addresses, and with
   transparent history written the way older builds wrote it:
   - fresh;
   - long-lived: legacy receives and spends, a coinbase output, a send in
     flight, a reserved output, and a transaction un-mined by an earlier
     rewind;
   - multi-seed, with a cross-account transfer;
   - imported-only;
   - hardware-first, without a spending key.

   Each upgrades without a seed, with every existing row unchanged, then is
   recovered, qualified, and promoted. The send in flight, the reservation, and
   the local details survive, and only outputs the ledger authorizes are
   spendable.
3. **Failure injection** (`failpoints.rs`, `lifecycle.rs`).
   - A full disk fails a candidate commit, a promotion, and an active commit;
     aborted writes fail a rewind and a demotion. Each leaves every table
     unchanged, and a retry reaches the oracle's state.
   - WAL copies before and after commit recover the prior and committed state
     for candidate commits, promotion, active commits, rewind, and demotion.
     Promotion is held open explicitly; the other operations use a SQLite
     commit hook to copy before their internally owned transaction commits.
   - A reorg clips sealed and provisional coverage alike and makes older work
     stale. Deleting an active account removes its ledger and keeps another
     account's shared transaction and authority. Lowering an active account's
     birthday pauses its authority until recovery covers the new bound. A
     policy round trip makes captured work stale and demotes the account.
4. **Repair and rollback** (`repair.rs`).
   - A projection whose ledger provenance and spends are lost fails closed, and
     demoting and promoting again rebuilds it exactly from durable evidence.
   - Applying a policy needs no newer reader, and nothing lowers
     `min_reader_version`.
   - A wallet requiring a newer reader is refused by ledger reads and writes,
     rewinds, re-attribution, account deletion, outbox creation evidence, and
     transparent output/spend ingestion, including low-level writes. Each
     rejected operation keeps every table and the applied private policy unchanged.
5. **Fix: lifecycle and provenance writes respect the reader version.**
   Truncation, re-attributing an imported receiver, qualification, account
   deletion, outbox creation evidence, and transparent output/spend ingestion
   check the durable policy before writing, inside the caller's transaction.
   Before, these paths could change recovery state or provenance that a newer
   reader might maintain differently.

**Deviations from the plan**

- **Rollback targets.** The schema migrator does not refuse a database that
  carries migrations it does not know, so `min_reader_version` is the only
  guard between an older build and newer ledger state. A supported rollback
  target is a build that contains the fix above and whose reader version
  meets the wallet's requirement. Earlier builds, including every build before
  this phase, rewind without checking it, so they are not supported rollback
  targets once a wallet holds recovery state.
- **Disk full.** Rewinds and demotions only delete or update rows, so a size
  cap cannot fail them; aborted writes cover them instead. The crash
  simulation covers all five operations above. A commit hook observes the
  internally owned transactions without adding a production failpoint. These
  are WAL recovery simulations, not power-loss or filesystem fault tests.
- **Lowered birthday.** No API lowers a birthday within the scanned range; the
  test edits the account row, as a restore with an earlier birthday would
  leave it.
- **Privileged verification and epochs** are not added. Clearing a
  quarantine, requalifying a source, and explaining a legacy discrepancy need
  real source verification, which belongs to the next stage.

**Pinned library revisions and release gates**

| Repository | Phase | PR | Reviewed source revision |
| --- | --- | --- | --- |
| wallet-libraries | 3 | #68 (merged) | `89ba66297202a9b9f3efa50733615ad715f67111` |
| wallet-libraries | 4 | #69 (merged) | `8dab5c8ff34b5ed3ee6e7fa0f4572207335ef958` |
| wallet-libraries | 5 | #70 (merged) | `0c7adf4f245107363a92f0facabb0e65ddc33b34` |
| wallet-libraries | 6 historical version-5 rollback candidate | #71 | `3ea93c4e9912d5721dcda8b8014bb77c048af259` |
| Vizor | 3 | chainapsis/vizor-wallet#787 | Consumer release qualification outstanding |
| Vizor | 4 | chainapsis/vizor-wallet#790 | Consumer release qualification outstanding |
| Vizor | 5–6 | Consumer qualification stage | Exact release revision and results required |

The pinned Phase 6 commit contains the compatibility fix and regression tests.
It is a historical version-5 source rollback candidate, not a published or deployed
rollback release. It cannot read the version-6 state written by the hardening below.
The final qualification head is the head of #71, including the commit-hook tests.
Production release remains blocked until the release process records:

1. The exact released library artifact built from this fix (or a descendant),
   its build features, and seedless open/read/write/rewind results on a copy of
   the release's wallet fixture. Test requirements above the rollback reader's
   version must refuse without changes; supported requirements must retain
   balances, local evidence, reservations, and private policy. A release whose
   new state requires an older reader to interpret unknown semantics cannot
   designate that reader as its rollback target.
2. The exact Vizor consumer revision and library revision, with the cross-repository
   exit-gate results below. The library fixtures alone do not qualify Vizor.
3. Real-source verification and the privileged qualification operation. The
   current `qualify_transparent_revision` hook exists only under `test` or
   `test-dependencies`. Production qualifies a fresh source only through a
   trusted commit, a development-flag deviation that verifies nothing (see the
   [design notes](transparent-pir-ledger-design-notes.md#trusted-indexer-qualification-deviation)).
   Release builds must not enable `test-dependencies` to bypass this gate. Quarantine
   clearing, requalification, and trust epochs remain owned by the source-
   verification stage; incomplete recovery never authorizes public fallback.

**Vizor steps**

1. Run the fixture coordinator through the integrated Rust/Flutter interfaces:
   public-to-private, initial private recovery, qualified candidate reuse,
   per-account promotion, interrupted activation, lag, outage, and restart.
2. Capture requests across sync, import, preview, startup, fee/payload/status
   work, and native boundaries. Include setting races, shielded-first mixed
   discovery, stale queued public work, and server shape flags.
3. Verify that balances, visible history, operation availability, and caches agree
   after both discovery orders, payload replay, account changes, and rewinds.
   Preserve local sends and hardware-flow state throughout.
4. Record exact library/application revisions, feature configuration, fixture
   provenance, gate outcomes, and remaining unsupported details. Keep sensitive
   comparisons local and export only redacted aggregate diagnostics.

**Exit gate:** no unexplained qualifying discrepancies, candidate financial side
effects, unauthorized public requests, duplicate accounting, or lost local
history. Restart/repair behavior and the supported rollback release have direct
evidence. This completes preparation, not remote-service or production-private
qualification.

## Validation and completion boundary

Run focused backend/SQLite tests with transparent support and applicable
existing balance, selection, migration, status, and enhancement regressions.
For each consumer handoff, validate the actual dependency graph and run the
relevant Vizor Rust and Dart tests. Use FVM for Flutter; run mobile-tagged tests
with the repository's mobile form-factor define when changing mobile UI.
Heavy regtest/device runs require a separately scheduled explicit request and
remain release gates; unit/fixture success does not imply they passed.

Preparation is complete when Phases 1–6 pass against an identified pair of
library/consumer revisions: deterministic recovery can resume, promote, project,
authorize or block inputs, reconstruct honest history, and rewind through the
intended APIs while shared-policy transitions cover all disclosure paths.

The next stage adds real filters, manifests, shards, PIR retrieval, publication
verification, protocol known-answer/malformed-input tests, real-source candidate
qualification, a controlled private cohort, and measured mobile/network-route
behavior. No phase here removes the public source or enables production private
authority.

Full private reconstruction of external transparent recipients requires an
additional payload/summary capability with identity binding, supported-pool
coverage, and explicit fee evidence. It has its own
[capability gate](transparent-pir-ledger-architecture.md#capability-and-rollout-boundary).
This plan requires honest partial history and blocks unauthorized fallback;
it does not claim full seed-restored recipient/memo/fee parity, cryptographic
completeness proofs, or support for privacy-unaware rollback binaries.

### Follow-up API and authority hardening

Revision observation and trusted replacement are separate operations. Candidate commits
register identities and retain evidence; observing a higher lineage does not revoke another
account's evidence or make a lower qualified lineage stale. Only trusted qualification
atomically withdraws older provisional coverage, pages and observations across the wallet.
Sealed and independent evidence retains its existing semantics. Production source verification
is still required before exposing that privileged operation.

These revision writes require reader version 6 through the existing durable reader fence.
Version-5 binaries, including the earlier #71 source rollback candidate, are not suitable
rollback readers for version-6 wallets. There is no new table or automatic release designation;
a published version-6-aware rollback artifact still requires the release evidence above.

Consumers can compose `get_wallet_summary` and `transparent_ledger_snapshot` inside
`WalletDb::transactionally`; both reuse that database snapshot. Required-private summary
amounts still withhold transparent funds; the authority snapshot supplies only eligible
transparent amounts. Do not combine separate reads across a promotion, rewind or mixed spend.

Use `WalletHandleModes` with `with_handle_modes` when opening handles, including exceptional
and background paths. It explicitly configures status, transparent discovery and (with
Orchard) enhancement together. It does not persist policy, capture a generation, cancel
requests or establish a dispatch fence. The application must cancel and join public work,
apply the durable policy transition, replace handle configuration and discard stale queued
work. Existing setters remain available for compatibility.


### Overlapping receiver ownership

An existing production owner retains a receiver during candidate recovery. Deriving that
receiver in another account's candidate window does not transfer it or authorize duplicate
financial events. Activity observed by the existing owner still informs the deriving key's
gap expansion. Standalone imports invalidate competing candidate facts and entire pending
page requests atomically; queued work for a removed receiver is stale, not source corruption.
Explicit production address generation can reattribute an imported receiver under the existing
rules. Its new owner must recover fresh coverage. Promotion rechecks completeness after
generating addresses and rolls the entire transition back if that would introduce uncovered
receivers; perform the explicit production transfer and recover before retrying promotion.


## Published-wallet upgrades and recovery boundary repairs

Fresh wallets and upgrades from published `zakura-client-sqlite` rc5/rc7 retain
`transactions.zip318_kind INTEGER NOT NULL DEFAULT 0` and its matching
`v_transactions` field in place. Existing
classification values survive the upgrade. The unused pool-migration tables
and engine remain removed. Databases that applied the earlier development
revision which dropped the column are outside the supported upgrade path.
This change does not qualify older builds writing to wallets after a
private-ledger upgrade and adds no downgrade reconciliation machinery.

`python3 scripts/check-published-wallet-upgrades.py` creates disposable databases
using actual published rc5 and rc7 crates, ingests wallet-owned transactions and
a UTXO before upgrading, and checks that the current library preserves accounts,
transaction bytes, classification values and outputs. The existing ledger migration
classifies pre-upgrade outputs as legacy provenance without private coverage.
Repeated current initialization preserves the migration journal. This is an
upgrade probe, not whole-wallet sync qualification.

Recovery reads derive the effective discovery window from all recorded mined
candidate activity, including receivers owned by another account. Recovery retains
skipped derivation indices in `tpir_shared_derivations` when addresses
are materialized. These indices survive promotion, rewind and reopen, grant no
ownership or coverage, and are deleted with the deriving account. Their writes require
reader version 8; earlier readers must refuse those wallets. The seedless additive
migration creates an empty table without changing policy or authority. Active commits
materialize newly discovered addresses before projecting events, retaining other
accounts' ownership and withholding private authority until the new ranges are covered.

The expanded
window exposes missing coverage immediately without an extra commit. Ownership
filtering still excludes the other account's receiver. Promotion generates only
unowned window receivers and rechecks coverage before activation; any ownership
change during normal wallet gap generation withdraws authority until the newly
scheduled recovery completes.
