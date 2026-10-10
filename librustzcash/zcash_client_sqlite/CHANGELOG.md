# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

<<<<<<< HEAD
- `WalletDb` implements `TransparentLedgerWrite::forget_transparent_ledger`. Under `Public`
  on the handle and durably, it removes in one transaction every spend link, pending spend,
  output and transaction that only the transparent ledger supports, the ledger origin of rows
  another origin also supports, and recovered events, coverage, pending pages and transaction
  metadata. Outputs that lost a spend are queued for spend detection again. A ledger-only
  output that is locked, or that a spend from another origin refers to, stays without value or
  authority and raises `tpir_meta.min_reader_version` to 5. Revisions, qualification,
  quarantine, candidate windows and shared derivations stay. A wallet without ledger facts is
  only read. `PrivateRequired` on either side fails with
  `PublicTransparentDiscoveryForbidden`. There is no schema change.

- Transparent ledger reads resolve a configured handle under the durable policy: a durably
  applied `PrivateRequired` policy governs every read, including one applied by another
  connection after the handle was configured, instead of failing it with
  `TransparentLedgerPolicyConflict`, which is removed. Reads never write the policy, and an
  explicitly lowered policy again resolves to the handle's configured mode. An unconfigured
  handle, a missing or corrupt policy row, or a newer reader requirement still fails closed.
  Qualifying a revision or promoting an account still requires a handle configured
  `PrivateRequired`, and a handle configured `Public` records no recovery evidence.
- `WalletDb::is_autocommit` reports whether the handle's connection is outside an explicit
  SQL transaction.

- Transparent receipt ownership now requires current, qualified, non-quarantined private
  spend evidence or an independently recorded public/local spend. Candidate and withdrawn
  recovery records cannot suppress funding omissions. Raw sender ownership also requires an
  outpoint actually spent by the transaction. Conservative contradiction checks are unchanged.

- Transparent txid enhancement (prototype): `WalletDb` implements `TransparentDetailRead` and
  `TransparentDetailWrite`. The additive `transparent_txid_enhancement` migration adds
  `transparent_detail_work`, `transparent_tx_display` (one display entry: fee, counts, sender
  and omission flags) and `transparent_tx_display_outputs` (outputs 0 and 1), and
  queues work for existing mined route-2 transactions and ledger-origin transactions without raw
  bytes. Ledger projection, the route-2 marker, and mining a route-2 transaction queue work for
  mined transactions without stored facts; each first deletes stored facts that the wallet now
  contradicts. Storing raw bytes clears work and any display facts. Parked work is due again
  after seven days without a display map change; under public authority nothing is parked, and
  held work is due at its ordinary retry. Failed lookups and contradictions only
  change retry state while the looked-up height still matches the transaction's mined height;
  a change of outcome class restarts the backoff. The view shows work as pending only while the
  listing would return it.
  Facts are validated against the coinbase
  position, owned outputs that financial queries count, recovered metadata, the stored fee,
  known shielded components, and known spends (input indexes and the number of distinct spent
  outpoints, including public spend links); a contradiction stores nothing.
- Recovered outgoing Activity assumes account funding and the whole fee unless recovered evidence
  identifies conflicting funding. The transparent-spend veto now requires an active account's
  qualified, non-quarantined observation at the accepted transaction height; candidate recovery
  cannot suppress the estimate. This display convention does not establish payment or fee attribution.
- Private recovery of mixed transparent/Ironwood transactions under `PrivateRequired` keeps
  the details that do not depend on transparent data. A has-transparent Enhance PIR record (or
  a compact scan with explicit non-Ironwood fields) still takes the sticky route-2
  (`PrivateDetailsUnsupported`) marker, but the transaction keeps private memo work for its
  received Ironwood notes. Each memo is authenticated by note decryption, and the whole-transaction
  fee is filled only when it agrees with every known fee, expiry, and displayed expiry; a
  disagreeing response is rejected without effect. Memo work is dispatched only while public
  authority is absent and is dropped when a policy transition restores it (route 1).
  The additive `ironwood_unsupported_memo_retry` migration requeues the unknown memos of
  route-2 transactions in existing wallets, without resetting notes, spend links, or routes.
- History reconstructs a mixed transaction without full data, as
  `HistoryClassification::NetReconstructed`, only as a transparent-to-shielded self-transfer: every owned effect complete, qualified metadata counting exactly the account's
  published transparent inputs, its exact whole-transaction fee agreeing with the stored one
  when present, recovered evidence that no transparent outputs exist, only
  transparent spends and shielded receipts, and the spent value equal to the receipts plus that
  fee. Otherwise it stays provisional. A net reconstruction does not prove the debit was the
  fee: another party's shielded spend paying an equal output at a padding action has the same
  evidence. The stored fee of such a transaction is the whole
  transaction's: `FeeState` stays `Unknown` and the aggregate payment is not inferred.

- Mixed net-shielding reconstruction can use the qualified transparent PIR whole-transaction
  fee when Enhance PIR omits it, without filling `transactions.fee` or attributing the fee.
  The additive `ironwood_transparent_output_shape` migration retains the nullable output-presence
  assertion and privately requeues its recovery for existing memo-complete route-2 wallets.
  Unknown or conflicting shape, incomplete/unqualified effects, and failed accounting remain
  provisional.

- A stored transaction that spends a wallet transparent output recorded after it, and so has no
  sent outputs, is stored again from its raw data once that output is recorded through
  `put_received_transparent_utxo` or a retrieved parent transaction. Its sent outputs are
  attributed only when one wallet account funded it and every transparent input spends a wallet
  output; jointly funded transactions stay unattributed. Fixes fresh restores whose sends stayed
  provisional with no recipient or payment. Ledger projection is not covered. No migration
  re-derives sends already stored this way; recording their spent output again does.

- Transparent spend discovery retains work for unmined local spenders and resumes after they
  expire. Address and per-outpoint completion advance past expired-spender links, using expiry
  at the current tip; an address range advances only the outputs whose search frontier it covers.

- Fixed `v_transactions.account_balance_delta`, `total_spent` and `total_received` being
  multiplied for a send whose sent notes include an output a wallet account received
  (transparent change, or a transfer to another account): `sent_note_counts` grouped by the
  receiving rather than the sending account. The `v_transactions_sender_grouping` migration
  recreates the view.
- Rewinds now preserve historical inclusion receipts for transactions compact scanning cannot
  rediscover through wallet shielded notes or spends. Accepted rescanning of the same block restores
  mined height and an available transaction index locally, without an automatic status query.
  A changed block or missing receipt uses the existing routed status recovery. The additive
  `transaction_reconfirmation_receipts` migration starts empty; it cannot reconstruct erased hashes.
- Reconfirmation status obligations are backfilled by `unmined_status_obligations` and flagged by
  `status_reconfirmation`. The `reconfirm_mined` flag exempts fallback work from expiry dormancy
  until one completed observation. Incomplete private coverage preserves recovery; it never permits
  a public fallback or proves absence. Delayed changed-block recovery beyond Status PIR retention
  can remain unresolved. See `docs/transaction_status_work.md` for the coverage contract.

- Shared derivation origins survive promotion and reopen without transferring receiver ownership.
  Activity at those receivers schedules new gaps and withholds private authority until coverage
  completes. Active recovery materializes its discovered addresses before projecting receipts.
  The additive `transparent_shared_derivations` migration creates empty bookkeeping; recording
  a shared origin requires reader version 8 and excludes public legacy-writer handover.

- Candidate windows respect existing receiver ownership; imports discard competing candidate
  facts atomically, and promotion refuses a transfer that introduces missing coverage.

### Added
- `WalletDb::transaction_history_summaries` returns typed account-scoped transaction
  metadata and monetary effects without reading raw transaction payloads. It shares
  the corrected accounting definition of `v_transactions`, filters account inputs
  before aggregation, and reuses caller-owned read snapshots. The existing view
  retains its columns and behavior. A seedless `v_transactions_legacy_projection`
  migration restores its retained `zip318_kind` field after sender grouping;
  transaction values and historical migration SQL are unchanged.
- `SqlTransaction::new` lets consumers run guarded wallet operations and application cleanup in one caller-owned transaction.
- `WalletDb::check_transparent_transaction_inputs` authorizes finalized submissions and exact-byte retries without permitting competing spends or weakening transparent authority.
- The unreleased `drop_zip318_pool_migration` retains `transactions.zip318_kind` and its
  `v_transactions` field in place, preserving classification values on upgrades from published
  rc5/rc7 schemas. The obsolete explicit rollback preparation API is removed. Development
  databases that already dropped the column are outside the supported upgrade path. Writable
  downgrades after a private-ledger upgrade are not qualified by this schema change.
- Initialization refuses unknown migration IDs before schema interpretation and restores foreign
  key enforcement on error. ZIP 318 removal names dependent application views/triggers.
- Shared-receiver activity expands effective recovery windows on read, exposing work immediately.
  Promotion materializes only unowned receivers; public reads do not inspect private provenance,
  and per-account balance reads share one SQLite snapshot.
- `WalletHandleModes`, `set_handle_modes`, and `with_handle_modes` configure every supported disclosure lane together without persisting policy.
- Revision observations no longer supersede wallet-wide evidence. Only a trusted qualification transition (a trusted commit, or the test/development hook) withdraws older provisional evidence. New revision writes require reader version 6; version-5 binaries cannot safely operate those wallets.
- `get_wallet_summary` reuses existing transactions, allowing summary and transparent authority reads in one snapshot. Per-account transparent balances use an account-scoped query.

- The seedless `transparent_ledger_schema` migration. It adds `tpir_meta`, the
  durable transparent policy recorded as public, and the `tpir_output_origins`
  and `tpir_spend_origins` provenance tables. It classifies every existing
  transparent output and spend as legacy evidence, and marks records whose
  transaction has local creation evidence as local construction too. Neither
  origin is coverage. Existing wallet tables are unchanged.
- The additive `transparent_policy_generation` migration. It adds
  `tx_retrieval_queue.policy_generation` (default 0) and extends
  `ironwood_enhance_routing.route` to allow `2` (`PRIVATE_DETAILS_UNSUPPORTED`).
- The seedless, additive `transparent_recovery_schema` migration. It adds empty
  candidate recovery tables: `tpir_candidate_windows`, `tpir_revisions`,
  `tpir_receive_events`, `tpir_receive_observations`, `tpir_spend_events`,
  `tpir_spend_observations`, `tpir_coverage`, `tpir_pending_pages`, and
  `tpir_pending_page_scripts`, with indexes for coverage by script, events by
  account, and spends by prevout.
- Candidate recovery: `WalletDb` implements `transparent_watch_set`,
  `apply_transparent_ledger_commit`, and `transparent_candidate_recovery`.
  - A commit requires a `PrivateRequired` policy, both on the handle and durably
    applied, at the captured generation. The account must
    still exist, the target and anchor must still be local blocks, and every
    named address must still be watched by the account.
  - Events are idempotent: contradictory content or placement is refused.
    Superseding a provisional revision retracts its observations and removes
    events that no other active revision observed.
    Within one revision, supported coverage and an open page cannot overlap,
    and no range can be reported both checked and unsupported.
  - The first candidate commit raises `tpir_meta.min_reader_version` to 3, the
    minimum recovery reader version, so builds without the recovery lifecycle fail
    closed on that wallet.
  - A commit extends the candidate window of a derived scope when mined
    activity reaches within a gap limit of its end. Window addresses are
    derived on read and are never written to `addresses`.
  - Truncation clips candidate coverage to the rescan floor and re-anchors it
    there, clears event placements above it, and removes pages opened for a
    later target. This runs in every build.
  - A spend mined below the output it consumes is refused, as are events of one
    transaction that disagree on its placement or coinbase classification.
  - A policy transition removes open pages.
  - Re-attributing an imported receiver to another account forgets the previous
    account's candidate evidence for it.
  - Deleting an account removes its candidate state.
- `SqliteClientError::TransparentRecoveryNotEnabled` and, behind
  `transparent-inputs`, `SqliteClientError::TransparentLedgerCommitRejected`.
- The seedless, additive `transparent_activation_schema` migration. It adds
  empty `tpir_active_accounts`, `tpir_qualified_revisions`,
  `tpir_quarantined_sources`, and `tpir_quarantined_accounts` tables.
- Private transparent activation, behind `transparent-inputs`:
  - `promote_transparent_account` requires `PrivateRequired` on the handle and
    durably. In one transaction it rechecks quarantine, the candidate blockers
    at a local target equal to the chain tip, qualification of every
    contributing revision, and agreement with the wallet's legacy evidence;
    adds the candidate window's addresses; projects every placed event with a
    new ledger-event origin (2); and records the account as active.
  - Projection joins the shared transaction row and keeps raw data, fees, local
    creation evidence, notes, locks, and other origins. A projected coinbase
    receive records `tx_index = 0`. A placement, coinbase, or content conflict
    with the wallet is an integrity failure.
  - Withdrawing the last observation of a receive retains its ledger-only output
    row, historical origin, independently supported spends, and reservations.
    Without a placed receive it contributes no balance and authorizes no input,
    including after demotion to public policy. Replaying the receive preserves
    spend links and lock ownership. Independent output origins remain evidence.
  - An active account's commits require a qualified revision and project their
    events in the same transaction. Window growth then uses the wallet's own
    gap-limit address generation.
  - An integrity rejection applies none of the commit's facts but quarantines
    the source, the account, and every account holding the source's evidence,
    and removes their pending pages. Quarantined sources and accounts refuse
    later commits. Quarantine survives rewinds; nothing clears it yet.
  - Leaving `PrivateRequired` demotes every active account.
  - Activation, qualification, and quarantine writes raise
    `tpir_meta.min_reader_version` to 5. Withdrawal of a previously projected
    receive also requires 5, including on a demoted candidate account, so a
    version 4 reader cannot mistake retained rows for current public funds.
  - `WalletDb::qualify_transparent_revision`, a test and development hook
    behind `test-dependencies`. Production builds qualify a revision only
    through a trusted commit.
  - `qualify_and_apply_transparent_ledger_commit` requires `PrivateRequired` on
    the handle and durably. In one transaction it makes every check of an
    ordinary commit, qualifies the exact revision, withdraws older provisional
    evidence of its source across the wallet, and applies the commit's facts.
    An integrity failure quarantines as an ordinary commit does, without
    qualifying; any other failure changes nothing. There is no schema or
    reader-version change.
- `SqliteClientError::TransparentPromotionBlocked`, behind `transparent-inputs`.
- Projection origins for new transparent records. Public discovery records a
  legacy-public origin, and local construction, including creation evidence
  recorded by an outbox, records a local origin. Each is written in the same
  transaction as the record it describes.
- `WalletDb::set_transparent_ledger_mode` and `with_transparent_ledger_mode`,
  and implementations of `TransparentLedgerRead` and `TransparentLedgerWrite`.
  The mode is not persisted, and transactional handles inherit it. The snapshot
  reports `Unavailable` authority, never a fabricated or public balance, when:
  - private authority is required;
  - the chain tip is unknown; or
  - the build cannot read transparent state.
- Durable policy transitions via `apply_transparent_policy`. A mode change
  increments `policy_generation` by one in the same SQLite transaction and
  restamps outstanding `tx_retrieval_queue` rows to that generation so
  still-required work remains dispatchable under modes that retain public
  authority; same-mode reapplication does not. Restoring public authority also converts unresolved
  sticky `route = 2` (mixed) markers to the public LWD route so those
  transactions become ordinary enhancement work again.
  `check_transparent_policy_generation` is the commit check an older open handle
  must fail. Pending withheld follow-on details are exposed by
  `pending_private_transparent_details`. Mixed (`route = 2`) details are reported
  only while the transaction has no stored raw payload.
- `SqliteClientError` variants:
  - `TransparentLedgerModeNotConfigured`;
  - `TransparentAuthorityUnavailable`;
  - `PublicTransparentDiscoveryForbidden`;
  - `TransparentLedgerIncompatible`: the wallet requires a newer ledger reader;
  - `StaleTransparentPolicy`: a captured generation no longer matches the
    wallet after a concurrent transition.

  A `tpir_meta` table without its policy row, or a missing `tpir_meta` after the
  migration has run, is reported as corrupted data.
- `WalletDb` implements `transaction_history_details`. Every result is derived
  from stored facts in one read (the transaction row, the account's outputs and
  spends, the scan queue, ledger coverage, and queued follow-on work); no
  completion marker is stored.

### Changed
- `TransparentDetailRead::transparent_display_view` returns `None` for an account that takes
  no part in the transaction's transparent side: no transparent output or spend of its own,
  scanned or recovered, and no shielded part (a received, spent or sent note) in a
  transaction the wallet records as having one, by its raw bytes or, without them, by detail
  work, stored display facts or the route-2 marker. It used to return a view whose outputs
  the account did not own.
- Unmined shielded history remains incomplete when scanning discovers a funding
  note whose spend was not linked at payload ingestion. A scanned chain tip and
  stored raw data certify completeness only once all known owned nullifiers
  have their spend links, preventing a debit's change from being classified as
  a complete receive with no applicable fee.
- Transparent outpoint lookup with a spend target now enforces coinbase
  maturity, matching the other selectors. The final private transaction storage
  gate therefore rejects an immature coinbase input, including externally
  finalized transactions. Lookups without a spend target retain metadata access.
- The following now require an explicitly configured transparent ledger mode;
  they never default to public authority:
  - transparent input selection;
  - storing any transaction with transparent inputs, in every build;
  - `put_received_transparent_utxo`;
  - the transparent spend-detection and address-history requests of
    `transaction_data_requests`;
  - `transaction_status_work` and `transaction_status_work_for`.
- Under `PrivateRequired`, set on the handle or durably applied, public
  transparent discovery stops. Public enhancement and status dispatch require
  a matching `policy_generation` and a mode that retains public authority.
  Parent-transaction retrieval and mixed Enhance results are withheld from
  public requests and reported as pending private details while they remain
  unresolved (mixed `route = 2` rows with stored raw are omitted; public LWD
  `route = 1` rows are included); financial rows are not deleted. Status
  obligations become `TransactionStatusWork::Private`.
- Transparent authority is unavailable under `PrivateRequired`, while the chain
  tip is unknown, and in builds without `transparent-inputs`. While it is
  unavailable:
  - transparent input selection and storing transactions with transparent
    inputs fail;
  - `get_wallet_summary` omits transparent funds;
  - `get_transparent_balances` fails;
  - `get_received_outputs` reports transparent outputs as not spendable
    (`u32::MAX`).

  Shielded-funded spends, including unshielding, are unaffected.
- Under `PrivateRequired`, transparent authority is per account. An account is
  eligible for a transaction targeting `T` when it is active and not
  quarantined, its ledger has no blockers, and its covered local target and the
  chain tip are both `T - 1`. Then:
  - every transparent selector admits only ledger-projected outputs of eligible
    accounts, within one read snapshot. The account selector and the outpoint
    lookup fail for an ineligible account; the address selectors filter out
    ineligible accounts and fail only when no owning account is eligible;
  - storing a transaction rechecks each transparent input at its target height,
    except inputs created by an earlier transaction of the same batch;
  - the snapshot reports `Private` authority and the ledger-projected balance.
    Otherwise its blockers explain why authority is unavailable.
  `get_wallet_summary` and `get_transparent_balances` still omit transparent
  funds under `PrivateRequired`.
- A transparent output report whose script or value conflicts with the stored
  output is refused.
- Retrieval-queue inserts stamp the current policy generation and do not
  refresh it on conflict. Internal commit paths check the captured generation
  before inserting a public request.
- Transparent address-history request enumeration reads public authority, the
  chain tip, and request rows from one SQLite snapshot, so a concurrent policy
  transition cannot expose private-era rows under stale public authority.
- A wallet whose `tpir_meta.min_reader_version` exceeds this build's reader
  version now also refuses rewinds (every `truncate_to_height`,
  `truncate_to_chain_state`, and `rewind_to_chain_state`), the re-attribution of
  an imported receiver, account deletion, creation-evidence bookkeeping,
  transparent output and spend writes (including low-level writes), and
  `qualify_transparent_revision`, with
  `TransparentLedgerIncompatible`, changing nothing. Previously a rewind clipped
  recovery state that a newer reader might maintain differently.

### Removed
- The ZIP 318 pool-migration schema. A new `drop_zip318_pool_migration`
  migration drops the `orchard_ironwood_migration*` tables and their indexes,
  which nothing read or wrote. The migrations that created them stay
  registered, so existing databases still migrate. The `zip318_kind` column of
  `transactions` and `v_transactions` stays for published rc5/rc7 writers.
- The implementations of the removed backend APIs
  (`put_zip318_classification`, `select_single_spendable_note`,
  `anchor_computable` and `WalletRead::anchor_retention_interval`).
  `WalletDb` reports its configured grid through
  `InputSource::anchor_retention_interval` instead.
- `set_durable_policy_for_testing`; tests use `apply_transparent_policy`.

## [0.1.0-rc7] - 2026-09-27

Breaking storage release for independently routed transaction status and
payload enhancement work.

### Fixed
- History payment details recognize a recovered received memo for the exact same
  owned sent output (account, transaction, pool, and output index), including an
  empty memo. Private Ironwood recovery no longer leaves details incomplete solely
  because the duplicate sent record's memo is unknown. Missing received or external
  sent memos, unsettled effects, and incomplete accounting still prevent completeness.
- Retire undecryptable Ironwood outgoing candidates once the wallet's value
  accounting proves no account it holds funded them: the wallet has a linked
  spend, no discovery work remains, every other output is recovered, the fee is
  known, and linked spends equal recovered outputs plus fee. In the wallet's own
  sends these are dummy padding outputs; otherwise they were funded by another
  party or by an account since deleted, whose sent history is deleted with it.
  They no longer remain as permanent `OutgoingNotRecoverable` suspensions that
  also keep the transaction's retrieval request open. Account deletion
  re-evaluates suspended transactions, since removing a funder can balance
  them. Rows suspended before this change are not migrated; a rescan requeues
  and retires them.
  Undecryptable real zero-value outputs are indistinguishable from dummies and
  are retired with them.
- Make finite-expiry status obligations dormant after contiguous local scanning
  reaches expiry plus the reorg safety depth, retaining queue rows for rewind
  reactivation without treating incomplete private coverage as proof of absence.
  Zero-expiry transactions remain eligible.

### Breaking changes
- Replace legacy transaction status requests with explicitly routed public/private
  `TransactionStatusWork` and a dedicated `TransactionStatusRead` interface.
  SQLite requires an explicit status mode and derives inclusion evidence from
  existing local-creation fields, with rewind handling at the actual rescan floor,
  a data-only legacy migration, and a transactional outbox evidence writer.
  No new columns are added.
  Sent-transaction storage requires a known chain tip to clamp creation evidence.
  See `docs/transaction_status_work.md` for consumer migration instructions.

### Added
- Implement `EnhancePirRead::transaction_enhancement_work` with one SQL statement
  over the ordinary and private queues, partitioned by transaction-wide route.
  No schema migration is required. `EnhancePirRead` is implemented with or without
  Orchard support; without it, every payload request is public work.

### Changed
- Enhance PIR storage and routing are now part of Orchard support; the separate
  `zakura-pir-enhance` feature has been removed.
- `WalletRead::transaction_data_requests` no longer returns payload work and no
  longer requires an enhancement mode to be configured.
- Status observations preserve every enhancement request, including ordinary
  requests and requests whose raw bytes are already stored. Expiry and rewind
  behavior for status requests is unchanged.
- Implement `WalletWrite::notify_transaction_enhancement_not_found` atomically:
  retire ordinary enhancement only, retaining status and outstanding
  PIR-routed recovery.
- Successful payload ingestion continues to complete enhancement independently.
  No schema migration is required. Downstream payload-not-found handlers must
  adopt the new API; status-only handlers continue to use `set_transaction_status`.
- The `ironwood_enhance` migration now adds the Ironwood compact encryption
  columns itself; the separate `ironwood_compact_encryption` migration and
  `migrations::ids::IRONWOOD_COMPACT_ENCRYPTION` are removed. The Enhance PIR
  schema is treated as undeployed, so pre-release databases that already carry
  those columns are no longer tolerated.
- `WalletMigrator::init_or_migrate` no longer repairs orphaned Ironwood
  enhancement work on every full initialization; account deletion already
  suspends it atomically.
- `ironwood_enhance_metadata_queue` records a compact binding with a single
  `compact_bound` flag instead of unused `ephemeral_key` and
  `compact_ciphertext` copies.

## [0.1.0-rc6] - 2026-09-24

PIR storage integration release using `zakura-client-backend 0.1.0-rc6`.

### Added
- Add durable SQLite routing and work queues for private Ironwood-only enhancement,
  including incoming memos, outgoing recovery, candidate accounts, rediscovery, and
  transaction metadata.
- Populate fee through a metadata queue independent of memo and outgoing
  recovery. Metadata comparison, enhancement writes, routing changes, and queue
  retirement are atomic.
- Reconcile private enhancement work across rescans, rewinds, account
  deletion, late or cross-account funding discovery, and full-transaction arrival.
- Create all six Ironwood Enhance PIR tables and expose a history-only PIR expiry
  through `v_transactions` in one consolidated migration.

### Fixed
- Upgrade existing rc5 wallets with a forward migration for Ironwood compact
  encryption fields, preserving notes, spends, and locks. Older notes retain
  nullable context until their compact blocks are rescanned.

### Changed
- Require each PIR-enabled wallet handle to configure `EnhancementMode` before
  enumerating transaction or PIR requests. An unconfigured handle returns
  `EnhancementModeNotConfigured`; wallet constructor signatures remain unchanged.
- Keep PIR-supplied expiry separate from authoritative transaction expiry. History
  displays it only for privately routed transactions; spendability and expiry
  status continue to use authenticated transaction data. Conflicting PIR expiry
  assertions are rejected. Metadata retrieval depends only on a missing fee.

## [0.1.0-rc5] - 2026-09-09

### Changed
- Updated the Zakura wallet and protocol dependencies to the stable 1.2
  release family, including `zakura-client-backend 0.1.0-rc5` and
  `zakura-pczt 0.1.0-rc3`.

## [0.1.0-rc4] - 2026-08-28

### Changed
- Updated the Zakura wallet and protocol dependencies to the RC5 cryptography
  family and raised the MSRV to Rust 1.91.

## [0.1.0-rc3] - 2026-08-25

### Changed
- `WalletRead::suggest_scan_ranges` now reports the `Historic` scan-queue coverage
  at or above the NU6.3 activation height under
  `ScanPriority::LatestPoolActivation`, so that a wallet whose birthday precedes
  the Ironwood pool scans the Ironwood era before backfilling its older history.
  Once no pre-activation `Historic` coverage remains, the backfill proceeds
  normally.

  The priority is derived when answering the query; `scan_queue` still stores that
  coverage as `Historic`, so no new priority code is written to the database and a
  wallet database remains readable by earlier releases. The policy applies only on
  networks with an assigned NU6.3 activation height, and only when the `orchard`
  feature is enabled -- without it the wallet has no Ironwood viewing keys and
  cannot detect Ironwood notes at all.

  Note that `WalletSummary::is_synced` remains `false` until the pre-activation
  backfill completes, because `fully_scanned_height` requires contiguous coverage
  from the wallet birthday. Consumers that want to surface a recovered balance
  early should use the account balances and the scan-progress ratio rather than
  `is_synced`.

## [0.1.0-rc2] - 2026-08-21

### Changed
- Updated the backend, PCZT, and Zakura protocol dependencies to their
  RC3-compatible release line.

## [0.1.0-rc1] - 2026-08-19

### Added
- A store-backed implementation of
  `InputSource::select_spendable_notes_for_consolidation` that selects necessary
  funding notes largest first, then returns the smallest eligible notes from
  the same preferred lock tier as optional consolidation candidates.

## [0.1.0-rc0] - 2026-08-19

- Forked from upstream `zcash_client_sqlite` and renamed to `zakura-client-sqlite`;
  this changelog starts fresh for the Zakura fork's initial release.
- Restarted the version lineage at 0.1.0, leaving behind the inherited upstream
  version (0.22.0-rc.7); the initial Zakura release will be preceded by `0.1.0-rc`
  release candidates.

## [0.22.0-rc.7] - 2026-08-03
=======
## [0.23.0-pre.1] - 2026-10-06
>>>>>>> 9753b8d9b00f160dee2ed0b8aa7c977bf3c2b772

### Added
- `zcash_client_sqlite::error::SqliteClientError::UnifiedEncoding`

### Changed
- Migrated to `pczt 0.10.0-pre.1`, `zcash_address 0.14.0-pre.1`,
  `zcash_client_backend 0.25.0-pre.1`, `zcash_keys 0.17.0-pre.1`,
  `zcash_pool_migration 0.2.0-pre.1`, `zcash_primitives 0.31.0-pre.1`, and
  `zcash_transparent 0.11.0-pre.1`.
- Unified addresses and viewing keys written to the wallet database are encoded
  at ZIP 316 Revision 0 when Revision 0 can represent them, and at Revision 2
  otherwise. Previously they were always encoded at Revision 2. Rows written
  earlier are not re-encoded.

### Fixed
- The `full_account_ids` migration no longer rejects a wallet whose stored UFVK
  is encoded at a different ZIP 316 revision from the one the migration derives.

## [0.23.0-pre.0] - 2026-10-02

### Added
- `WalletDb` implements the storage-trait methods newly added to
  `zcash_client_backend`: `WalletWrite::queue_rescan` and, behind
  `transparent-inputs`, `WalletRead::{get_unspent_transparent_outpoints,
  get_transparent_receiver_accounts}` and
  `ll::LowLevelWalletWrite::track_block_transparent_spends`.
- `WalletSnapshot` and `WalletDb::get_wallet_snapshot`.
- `zewif::ZewifImportReport::transactions_deferred_no_chain_tip`

### Changed
- Migrated to `bip32 0.6`, `group 0.14`, `incrementalmerkletree 0.9`,
  `jubjub 0.11`, `orchard 0.16`, `pczt 0.10.0-pre.0`, `rand_core 0.10`,
  `sapling-crypto 0.9`, `secp256k1 0.33`, `shardtree 0.8`,
  `zcash_address 0.14.0-pre.0`, `zcash_client_backend 0.25.0-pre.0`,
  `zcash_keys 0.17.0-pre.0`, `zcash_pool_migration 0.2.0-pre.0`,
  `zcash_primitives 0.31.0-pre.0`, `zcash_proofs 0.31.0-pre.0`,
  `zcash_protocol 0.11.0-pre.0`, `zcash_script 0.6`,
  `zcash_transparent 0.11.0-pre.0`, and `zip32 0.3`.
- `SqliteClientError` has a new variant `DivergedCheckpoints { pool, height }`.
  When a pool's note commitment tree has checkpoints above and below the
  truncation height but none at it, truncating or rewinding the wallet now
  fails with this variant instead of `SqliteClientError::CorruptedData`.
- `zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations::take_transaction_for_broadcast`
  takes an additional `rng` first argument that implements `rand_core::{Rng, CryptoRng}`.
- The `R` parameter of `WalletDb` must now implement `rand_core::Rng` in place
  of `rand_core::RngCore` wherever it previously required the latter.
- The types in `zcash_client_sqlite::util` (`Clock`, `SystemClock`, and
  `util::testing::FixedClock`) are now re-exports of the same-named types in
  `zcash_client_backend::util`.
- `WalletWrite::import_account_ufvk` accepts a transparent-only unified full
  viewing key; it previously failed with
  `AddressGenerationError::NoSatisfiableReceiver`. The resulting account's
  default address is a transparent-only ZIP 316 Revision 2 (`tu`) Unified
  Address.
- `WalletDb::put_blocks` records the transparent outputs that pay a wallet
  account and the spends of the wallet's transparent outputs, for blocks
  scanned from both compact and full block data. A spend observed before the
  output it spends has been discovered is resolved when that output is
  discovered.
- `zewif::ZewifImportReport::transactions_without_wallet_relevance` no longer
  counts transactions deferred to the post-import rescan for lack of a chain
  tip; these are counted by `transactions_deferred_no_chain_tip`.

### Fixed
- Upgrading a wallet database whose `support_zcashd_wallet_import` migration
  ran before 2025-09-16 no longer fails with `NOT NULL constraint failed:
  accounts_new.zcashd_legacy_address_index`.
- Reading back a stored unmined transaction with a zero expiry height (such as
  a coinbase transaction imported from a zcashd wallet before any chain scan)
  no longer fails with a "Consensus branch ID not known" error when the wallet
  has a view of the chain tip.
- `zewif::import_wallet` now establishes the wallet's view of the chain tip
  from the document (the maximum of its export height and its transactions'
  mined heights, clamped to the wallet birthday) whenever at least one account
  was imported and account import itself did not establish one. A document
  whose accounts all had birthdays at or below Sapling activation previously
  had every transaction deferred to the post-import rescan.
- The `v_tx_outputs` view now includes its documented `diversifier_index_be`
  column; queries naming it previously failed with "no such column".
- The `v_transactions` and `v_transactions_with_pending_migrations` views no
  longer multiply a sending account's row by the number of distinct groups the
  transaction's outputs were received into, where a group is an account of the
  wallet and the outputs no account of the wallet received form one further
  group. `account_balance_delta`, `total_spent`, `total_received`,
  `received_note_count`, `spent_note_count`, and the received-note contribution
  to `memo_count` were each scaled by that count; `sent_note_count` reported
  the notes of the largest single group instead of all of them.
- `wallet::init::init_wallet_db` and `wallet::init::WalletMigrator::init_or_migrate`
  no longer fail on wallets containing accounts imported by UIVK.
- `WalletDb`'s implementation of
  `zcash_client_backend::data_api::ll::LowLevelWalletRead::get_unknown_fee_spenders_of`
  now returns only transactions that spend a transparent output of the given
  transaction. It previously returned every transaction with an unknown fee
  that spends any transparent output received by the wallet.

## [0.22.0] - 2026-08-18

### Added
- `zcash_client_sqlite`:
  - `WalletDb::transactionally_with_extension`, which performs wallet
    operations and writes to application-owned `ext_`-prefixed tables (created
    via `WalletMigrator::with_external_migrations`) atomically in one database
    transaction, and `ExtensionTransaction`, the restricted statement executor
    it provides to the closure. `ExtensionTransaction::{execute, query_row}`
    run under a SQLite authorizer that permits reads of any table, permits
    `INSERT`/`UPDATE`/`DELETE` only against `ext_`-prefixed tables, and denies
    everything else, including DDL, `PRAGMA`, `ATTACH`/`DETACH`, and
    transaction control.
  - `WalletDb::{with_anchor_retention_interval, set_anchor_retention_interval}`,
    which configure the interval on which note commitment tree checkpoints are
    retained as durable anchors. The setting governs the grid the next pool
    migration is planned against; the grid an in-flight migration was committed
    under is recorded with it and keeps being retained.
  - `WalletDb::{get_unspent_ironwood_notes_at_historical_height,
    generate_ironwood_witnesses_at_historical_height}`
  - `WalletDb` implements the storage-trait methods `zcash_client_backend
    0.24.0` adds, including `WalletRead::get_wallet_recover_until`,
    `WalletWrite::{prune_scan_queue_below, reserve_next_n_internal_addresses,
    import_standalone_transparent_pubkeys}`, the `OutputLockStore` methods, and
    `WalletCommitmentTrees::{get_sapling_subtree_root, get_orchard_subtree_root,
    get_ironwood_subtree_root, with_ironwood_tree_mut}`.
- `zcash_client_sqlite::error`:
  - `SqliteClientError::{PutBlocksCommitmentTree, TruncateCommitmentTree,
    FeeRuleError, BackendError}` and the `BackendError` the last wraps. The
    first two record the shielded pool and, respectively, the block range being
    added or the height being truncated to when a note commitment tree error
    occurs; both cases previously surfaced as the generic `CommitmentTree`
    variant.
- `zcash_client_sqlite::pool_migration`, which implements `zcash_pool_migration`'s
  `PoolMigrationRead` / `PoolMigrationWrite` store traits over tables in the
  wallet database, persisting each account's in-progress Orchard -> Ironwood
  (ZIP 318) migration. Requires the `orchard` feature.
  - `orchard_ironwood::PoolMigrations`, constructed by
    `PoolMigrations::for_account(params, clock, conn, account)`, with
    `migration_lock_owners`, `take_transaction_for_broadcast`,
    `cancel_migration`, `latest_migration`, `list_migrations`, and
    `get_migration_by_id`.
  - `orchard_ironwood::{Error, FinalizeError}`
  - `{MigrationUuid, MigrationSummary, CancelOutcome}`
- `zcash_client_sqlite::wallet::init::migrations`:
  - Release-state constants for every published version whose migration-graph
    state had none: `V_0_7_0`, `V_0_8_0_RC1`, `V_0_8_0_RC4`, `V_0_8_0_RC5`,
    `V_0_8_1`, `V_0_20_0`, `V_0_22_0_RC1`, `V_0_22_0_RC2`, `V_0_22_0_RC5`, and
    `V_0_22_0_RC6`.
  - `ids` module, behind the `unstable` feature, exposing the identifier of
    each individual internal migration, so that an external migration can be
    anchored against unreleased schema. These identifiers are unstable; move
    the anchor to the release constant that covers it once that release exists.
- `zcash_client_sqlite::zewif`, behind the new `zewif` feature, for importing
  wallets from the Zcash Wallet Interchange Format. `import_wallet` ingests a
  ZeWIF document into an initialized `WalletDb` in a single transaction,
  delivering encountered spending-key material to a caller-supplied
  `SecretSink` (`DiscardSecrets` drops it) and returning a `ZewifImportReport`
  (including `addresses_never_exposed`); failures are reported as
  `ZewifImportError`. The report is detailed by `ImportedAccount`,
  `SkippedAccount`, `AccountSkipReason`, `SkippedTransparentKey`,
  `TransparentKeySkipReason`, and `BirthdayBasis`.
- Schema and views:
  - Persistence of the Ironwood value pool, behind the `orchard` feature.
    Migrations add the `ironwood_received_notes` and
    `ironwood_received_note_spends` tables, the Ironwood note commitment tree
    tables and views, the `ironwood_commitment_tree_size` and
    `ironwood_action_count` columns on `blocks`, and a `note_version` column on
    `orchard_received_notes` (existing rows backfilled as version 2); the
    `v_received_outputs` and `v_received_output_spends` views carry Ironwood
    notes under pool code 4, so they appear in `v_transactions`,
    `v_tx_outputs`, and the balances derived from them. Scan-range planning
    extends suggested ranges to complete Ironwood subtrees from NU6.3.
  - Support for `WalletWrite::import_standalone_transparent_address` (under the
    `transparent-key-import` feature): a watch-only transparent address is
    stored as a `key_scope = -1` row of the `addresses` table with neither
    imported-material column set, admitted by a migration that relaxes the
    table's constraint. Importing the corresponding pubkey or redeem script
    with `WalletWrite::import_standalone_transparent_pubkey` /
    `import_standalone_transparent_script` upgrades such a row in place.
    Outputs received by an address imported without key material contribute to
    the account balance but are excluded from spendable-output selection.
  - A `zip318_kind` column on the `transactions` table and on `v_transactions`,
    recording how each transaction classifies against ZIP 318 so that a wallet
    can label a pool-migration transaction without a migration plan. Both the
    pool-migration store and `WalletWrite::store_transactions_to_be_sent`
    classify a transaction as they store it, and enhancement classifies it once
    it has mined. The column defaults to the code for NOT CLASSIFIED, which a
    client must render as "no label yet" rather than as "not a migration
    transaction": rows written before the column existed keep the default and
    need the transaction rescanned.
  - A `pool_crossing_value` column on `v_transactions`, non-`NULL` exactly for
    a wholly-shielded wallet-internal transaction that moved the account's own
    funds into a pool it spent nothing from, carrying the amount that crossed.
    Use `pool_crossing_value IS NOT NULL` as the classification predicate, and
    present that value as the migrated amount: `account_balance_delta` for such
    a transaction is just the negated fee, and `total_spent` / `total_received`
    overstate the crossing whenever the transaction also returns change to a
    pool it spent from.
  - The `v_migration_transactions` view: one row per scheduled pool-migration
    transaction, with its identity, kind, lifecycle state, scheduled and expiry
    heights, values, and ZIP 318 classification code.
  - The `v_transactions_with_pending_migrations` view: `v_transactions` plus
    the scheduled migration transactions projected into the same column shape.
    `v_transactions` itself is unchanged.
  - A migration adding `lock_expiry_height` and `lock_owner` columns to the
    `sapling_received_notes`, `orchard_received_notes`,
    `ironwood_received_notes`, and `transparent_received_outputs` tables,
    backing the note locking that `zcash_client_backend`'s proposal-creation
    functions perform.
  - A `UNIQUE` index on `addresses.cached_transparent_receiver_address`, making
    account-by-transparent-address lookups index-backed and enforcing that each
    transparent receiver belongs to at most one address record. The migration
    that adds it resolves pre-existing duplicates in place — within one account
    by keeping a canonical record and repointing received outputs to it, across
    accounts by derivation from each account's viewing key — and aborts on a
    cross-account duplicate that no unique record can be verified for.
- The additive `ignore-expensive-tests` feature, which compiles expensive tests
  but marks them ignored for broad `--all-features` runs.
- `zcash_client_sqlite::testing`:
  - `db::TestDbFactory::file_backed`, and `db::TestDb::{conn, conn_mut}` for
    tests that open a sibling store over the wallet database's own connection.

### Changed
- MSRV is now 1.88
- Migrated to `zcash_protocol 0.10.5`, `zcash_address 0.13.0`,
  `zcash_transparent 0.10.0`, `zip321 0.9.0`, `zcash_keys 0.16.1`,
  `zcash_primitives 0.30.1`, `zcash_proofs 0.30.0`, `orchard 0.15`,
  `shardtree 0.7`, `zcash_client_backend 0.24.0`, `zcash_pool_migration 0.1.0`.
- The `orchard` feature is now enabled by default. Consumers that require a
  smaller feature set should disable default features and enable only the
  features they need.
- Every public error enum in this crate is now `#[non_exhaustive]`; a `match`
  over any of them must include a wildcard arm: `error::SqliteClientError`,
  `FsBlockDbError`, `pool_migration::orchard_ironwood::Error`,
  `wallet::commitment_tree::Error`, `wallet::init::WalletMigrationError`, and
  `zewif::ZewifImportError`.
- `zcash_client_sqlite`:
  - `WalletWrite::store_transactions_to_be_sent` upserts each transaction's
    sent-output records, so storing a transaction the wallet has already
    recorded replaces that record instead of failing.
  - `WalletWrite::truncate_to_height` and `rewind_to_chain_state` accept a
    target that a pool's note commitment tree checkpoints do not cover,
    whenever the truncation leaves that pool's tree in a consistent state: an
    empty or lagging tree is left untouched, and a tree whose checkpoints all
    postdate the target is reset to the roots of subtrees completed at or below
    it. A rewind that would destroy witness data the rescan will not re-create
    is refused as `RequestedRewindInvalid`, and a pool with checkpoints both
    above and below the target but none at it is still reported as corruption.
    Callers that relied on `RequestedRewindInvalid` for an uncovered height
    should note that the truncation now succeeds. Truncation additionally rolls
    every stored pool migration back to the height truncated to, in the same
    database transaction, so an application calling
    `MigrationState::truncate_to_height` from a reorg hook should stop.
  - Behind the `spend-index` feature,
    `WalletRead::transaction_data_requests` emits
    `TransactionDataRequest::GetSpendingTx` for transparent spend detection
    instead of `TransactionsInvolvingAddress`. The latter is still emitted for
    ephemeral-address discovery, and for spend detection when `spend-index` is
    disabled.
  - `testing::db::TestDbFactory::default` and `testing::BlockCache::default`
    use isolated in-memory SQLite databases.
- The `zip-233` feature also enables `zcash_client_backend/zip-233`, and the
  `pczt-tests` feature also enables this crate's `orchard` and
  `transparent-inputs` features.

### Fixed
- `zcash_client_sqlite`:
  - Note selection draws the oldest eligible notes first, ordering by note
    commitment tree position. Notes were previously drawn in scan-discovery
    order, which for a restored wallet prefers its most recently discovered —
    typically newest — notes.
  - Transaction status requests are generated from explicit, durable
    observation intent. A sent transaction is queried by txid only when this
    wallet cannot observe one of its shielded spends or outputs; intent remains
    dormant while a transaction is mined and becomes active again after a chain
    rewind. Redundant requests previously synthesized for wallet-observable
    shielded transactions are no longer produced.
  - Value in immature transparent coinbase outputs is reported as pending
    spendability in wallet-summary account balances, rather than counted as
    spendable before the output reaches coinbase maturity.
- `zcash_client_sqlite::wallet::init::migrations`:
  - `V_0_8_0` held the leaf state of the 0.8.1 release rather than 0.8.0's. The
    constant now records the true 0.8.0 state, and the 0.8.1 state it
    previously held is the new `V_0_8_1`. An external migration anchored on
    `V_0_8_0` now anchors one migration earlier in the graph, which cannot
    invalidate its ordering.
- Schema and views:
  - The `to_address` column of `v_tx_outputs` reports a transparent output
    received by the wallet at the transparent receiver address itself rather
    than at a unified address containing that receiver, and for an output the
    wallet created, the recipient address recorded at construction time takes
    precedence over the receiving address.

## [0.21.1] - 2026-06-19

### Fixed
- Fixed a bug in `WalletDb::delete_account` that caused it to fail with
  `rusqlite::Error::InvalidParameterName(":address")` when the account being
  deleted was referenced by a `sent_notes` row via its `to_account_id` column
  (for example, after an internal transfer to an address belonging to the
  account being deleted). The `sent_notes` update statement bound a parameter
  named `:address` while the SQL expected `:to_address`.

## [0.21.0] - 2026-06-02

### Changed
- Migrated to `zcash_protocol 0.9.0`, `zcash_address 0.12.0`, `zcash_transparent 0.8.0`, `zip321 0.8.0`, `zcash_keys 0.14.0`, `zcash_primitives 0.28.0`, `zcash_proofs 0.28.0`.

### Fixed
- Updated to crate versions that fix an Orchard soundness vulnerability
  (GHSA-ww9q-8r59-xv46) and Orchard non-canonical proof size issue
  (GHSA-2x4w-pxqw-58v9).

## [0.20.2] - 2026-05-07

### Fixed
- Scan-progress accounting (`subtree_scan_progress`) no longer counts outputs
  from blocks whose enclosing scan-queue range has been re-queued for
  scanning. Previously, a wallet that had scanned blocks and then re-queued
  the corresponding range (for example as a consequence of adding a new
  account whose birthday lies within already-scanned territory) would
  over-report scan progress, because the re-queued blocks remained in the
  `blocks` table and were still counted as scanned.

## [0.20.1] - 2026-05-06

### Fixed
- This release fixes a bug in progress estimation that can occur when rewinding
  to a height prior to any existing wallet birthday as a consequence of adding
  an account.

## [0.20.0] - 2026-04-27

### Added
- The following columns have been added to the exposed `v_tx_outputs` view:
  - `transaction_id`
  - `tx_mined_height`
  - `tx_trust_status`
  - `recipient_key_scope`
- `zcash_client_sqlite::TxRef`
- `impl<'a> Borrow<rusqlite::Transaction<'a>> for zcash_client_sqlite::SqlTransaction<'a>`
- `impl zcash_client_backend::data_api::ll::LowLevelWalletRead for WalletDb`
- `impl zcash_client_backend::data_api::ll::LowLevelWalletWrite for WalletDb`
- `impl Hash for zcash_client_sqlite::{ReceivedNoteId, UtxoId, TxRef}`
- `impl {PartialOrd, Ord} for zcash_client_sqlite::UtxoId`
- `impl zcash_keys::keys::transparent::gap_limits::AddressStore for WalletDb`
  (behind the `transparent-inputs` feature flag)
- `zcash_client_sqlite::AccountRef` is now public.
- `impl<'conn, P, CL, R> WalletWrite for WalletDb<SqlTransaction<'conn>, P, CL, R>` to
  enable calling `WalletWrite` methods inside `WalletDb::transactionally` (amortizing the
  database transaction overhead).
- `WalletDb::get_unspent_orchard_notes_at_historical_height` returns all Orchard
  notes that existed and were unspent at a given height.
- `WalletDb::generate_orchard_witnesses_at_historical_height` generates Merkle
  witnesses at a historical height using an ephemeral in-memory
  `shardtree::store::memory::MemoryShardStore`.
- Two new `orchard`-gated variants have been added to
  `zcash_client_sqlite::error::SqliteClientError` to surface the failure modes
  of `WalletDb::generate_orchard_witnesses_at_historical_height`:
  - `HistoricalFrontierInvalid(shardtree::error::InsertionError)` —
    the caller-supplied frontier is inconsistent with the shard data
    reconstructed from the wallet at the requested height.
  - `HistoricalWitnessUnavailable { position, height }` — no witness can be
    produced for the specified position at the specified height (the wallet
    most likely has not synced through that height).
  Shard-read failures continue to surface via the existing
  `SqliteClientError::CommitmentTree` variant.

### Changed
- Migrated to `sapling-crypto 0.7`, `orchard 0.13`, `zcash_encoding 0.4`,
  `zcash_protocol 0.8`, `zcash_address 0.11`, `zip321 0.7`, `zcash_transparent 0.7`,
  `zcash_primitives 0.27`, `zcash_proofs 0.27`, `zcash_keys 0.13`, `pczt 0.6`,
  `zcash_client_backend 0.22`
- The `accounts` table now stores IVK item caches instead of FVK item caches for
  collision detection. A new `p2sh_ivk_item_cache` column is reserved for future
  ZIP 316 Revision 2 P2SH support.
- Account collision detection now uses IVK-based matching, which catches collisions
  between FVK-imported and IVK-imported accounts. Importing an FVK over an existing
  IVK-only account is treated as a capability upgrade if the existing IVK items are
  a subset of those derivable from the new FVK.
- The `InputSource::get_spendable_transparent_outputs` implementation now
  accepts an `output_filter: TransparentOutputFilter` parameter. When set to
  `CoinbaseOnly`, the SQL query restricts results to outputs from coinbase
  transactions (identified by `tx_index = 0`).
- Migrated to `orchard 0.13`, `sapling-crypto 0.7`.
- Renamed `zcash_client_sqlite::error::PubkeyImportConflict` to
  `zcash_client_sqlite::error::StandaloneImportConflict`
- P2SH UTXOs returned by `get_spendable_transparent_outputs` now include a
  precomputed input size for accurate ZIP 317 fee estimation.
- Added a `witness_stabilized` column to the `sapling_received_notes` and
  `orchard_received_notes` tables. The column is set to 1 at the end of each
  scan batch (and once as a backfill by the `witness_stabilized_notes`
  migration) for notes whose containing shard is fully Scanned and whose
  `subtree_end_height` has received at least `PRUNING_DEPTH` confirmations.

### Removed
- `zcash_client_sqlite::GapLimits` use `zcash_keys::keys::transparent::GapLimits` instead.
- `zcash_client_sqlite::UtxoId` contents are now private.
- The inadvertently-exposed `zcash_client_sqlite::chain::migrations::blockmeta::init`
  module has been removed from the public API.

### Fixed
- `get_transparent_balances` no longer fails for standalone transparent addresses
  that have no `TransparentKeyScope`. Previously, it would error when encountering
  a `KeyScope` that could not be converted to a `TransparentKeyScope`.
- Notes are now consistently treated as having "uneconomic value" if their value is less
  than **or equal to** the marginal fee. Previously, some call sites only considered
  note uneconomic if their value was less than the marginal fee.

## [0.19.5] - 2026-03-10

### Fixed
- The following APIs no longer crash in certain regtest mode configurations with
  fewer NUs active:
  - `WalletDb::{create_account, import_account_hd, import_account_ufvk}`
  - `WalletDb::get_wallet_summary`
  - `WalletDb::truncate_to_height`

## [0.18.12, 0.19.4] - 2026-02-26

### Fixed
- Updated to `shardtree 0.6.2` to fix a note commitment tree corruption bug.

## [0.19.3] - 2026-02-19

### Fixed
- Migration no longer crashes in regtest mode.

## [0.18.11, 0.19.2] - 2026-01-30

### Fixed
- Migration no longer fails for wallets last written with certain older versions
  of the crate.

## [0.18.10, 0.19.1] - 2025-11-25

### Fixed
- Fixes a SQL bug that causes unspent note metadata queries to fail.

## [0.19.0] - 2025-11-05

### Added
- `zcash_client_sqlite::wallet::init::migrations::V_0_19_0`

### Changed
- MSRV is now 1.85.1.
- Migrated to `zcash_protocol 0.7`, `zcash_address 0.10`, `zip321 0.6`,
  `zcash_transparent 0.6`, `zcash_primitives 0.26`, `zcash_proofs 0.26`,
  `prost 0.14`, `rusqlite 0.37`.
- The implementation of `zcash_client_backend::WalletWrite` for `WalletDb` has
  additional type constraints. The `R` type parameter is now constrained to
  types that implement `RngCore`.
- The default gap limit for ephemeral address generation has been changed from
  5 addresses to 10. Now that ephemeral addresses are being used for more
  single-use-address use cases than just transactions sending to TEX addresses,
  the case that there will be a series of unused addresses (for example, for
  swap refunds) becomes more common.

### Fixed
- A bug was fixed in `WalletDb::get_transaction` that could cause transaction
  retrieval to return an error instead of `None` for transactions for which the
  raw transaction data was not available.

## [0.18.9] - 2025-10-22

### Fixed
- Fixes a problem whereby dust-valued transparent outputs in the wallet could
  disrupt shielding operations.
- Fixes a bug wherein `WalletDb::get_transparent_balances` was returning
  balance for ephemeral addresses, contradicting its documented requirements.

## [0.18.8] - YANKED

## [0.18.7] - 2025-10-16

### Fixed
- Fixes a data persistence error that could result in a violation of the
  `transactions.min_observed_consistency` constraint.

## [0.18.6] - 2025-10-16

### Fixed
- Fulfilled transaction enhancement requests are now deleted once it is
  determined that there is no wallet involvement with the transaction.

## [0.18.5] - 2025-10-14

### Changed
- This release regularizes our approach to determining when outputs belonging
  to the wallet are unspent. We now track the block height at which we first
  observe a transaction; for transactions discovered by scanning the mempool
  and transactions generated by the wallet, this is equivalent to the mempool
  "height".
- This release introduces a more robust approach to the management of
  transaction status requests. It ensures that we continue to query for
  transaction status for a given transaction until we have positive
  confirmation that either:
    - the transaction has definitely expired, or
    - if expiry information is unavailable, that the transaction has not been
      mined for at least 140 blocks since the block height at which we first
      observed the transaction.

## [0.18.4] - 2025-10-08

### Fixed
- This modifies balance calculation to explicitly ignore balance held in
  ephemeral addresses. This will be altered in a future release; at present,
  the only use of ephemeral addresses is as interstitial addresses in TEX
  address transfers, and so it is safe to ignore these funds. Funds would only
  appear in the case of a partial TEX transfer failure or funds being returned
  to a TEX address, which would not be detected by normal scanning but which
  could be detected by the new mempool detection logic implemented by Zashi.

## [0.18.3] - 2025-09-30

### Changed
- The `zcash_client_sqlite` implementation of `WalletWrite::update_chain_tip`
  now ensures that a transaction status request is queued for any transactions
  for which we do not have mined-height information and which are known to be
  unexpired.
- Transaction status requests are no longer deleted until the transaction in
  question is positively known to be expired.

## [0.18.2] - 2025-09-28

### Changed
- The `zcash_client_sqlite` implementation of `InputSource::get_unspent_transparent_output`
  now correctly selects transparent UTXOs with zero confirmations.

## [0.18.1] - 2025-09-25

### Fixed
- This fixes a bug in zcash_client_sqlite-0.18.0 that could result in
  underreporting of wallet balance.

## [0.18.0] - YANKED

### Added
- A `zcashd-compat` feature flag has been added in service of being able to
  import data from the zcashd `wallet.dat` format. For additional information
  refer to the `zcash_client_backend 0.20.0` release notes.
- `zcash_client_sqlite::wallet::init::migrations::V_0_18_0`

### Changed
- Migrated to `zcash_protocol 0.6`, `zcash_address 0.9`, `zip321 0.5`,
  `zcash_transparent 0.5`, `zcash_primitives 0.25`, `zcash_proofs 0.25`,
  `zcash_keys 0.11`, `zcash_client_backend 0.20`.
- Added dependency `secp256k1` when the `transparent-inputs` feature flag
  is enabled.
- `zcash_client_sqlite::error::SqliteClientError`:
  - An `IneligibleNotes` variant has been added. It is produced when
    `spendable_notes` is called with `TargetValue::MaxSpendable`
    and there are funds that haven't been confirmed and all spendable notes
    can't be selected.
  - A `PubkeyImportConflict` variant has been added. It is produced when
    a call to `WalletWrite::import_standalone_transparent_pubkey` attempts
    to import a transparent pubkey to an account when that pubkey is already
    managed by a different account.
- The `v_tx_outputs` view now includes an additional `diversifier_index_be`
  column, containing the diversifier index (or transparent change-level BIP 44
  index) of the receiving address as a BLOB in big-endian order for received
  outputs. In addition, the `to_address` field is now populated both for sent
  and received outputs; for received outputs, it corresponds to the wallet
  address at which the output was received. For wallet-internal outputs,
  `to_address` and `diversifier_index_be` will be `NULL`.
- `WalletDb::get_tx_height` will now return heights for transactions detected
  via UTXOs, before their corresponding block has been scanned for shielded
  details.

## [0.17.3] - 2025-08-29

### Fixed
- This release fixes possible false positive in the way that the
  `expired_unmined` column of the `v_transactions` view is computed. It now
  checks against the `mined_height` field of the UTXO, instead of joining
  against the `blocks` table to determine whether the UTXO has expired unmined;
  after this change, the corresponding block need not have been scanned in
  order to correctly determine whether the UTXO actually expired.

## [0.16.4, 0.17.2] - 2025-08-19

### Fixed
- `TransactionDataRequest::GetStatus` requests for txids that do not
  correspond to unexpired transactions in the transactions table are now
  deleted from the status check queue when `set_transaction_status` is
  called with a status of either `TxidNotRecognized` or `NotInMainChain`.
- This release fixes a bug that caused transparent UTXO value to be
  double_counted in the wallet summary, contributing to both spendable and
  pending balance, when queried with `min_confirmations == 0`.
- Transaction fees are now restored when possible by calls to
  `WalletDb::store_decrypted_tx`.

## [0.16.3, 0.17.1] - 2025-06-17

### Fixed
- `TransactionDataRequest`s will no longer be generated for coinbase inputs
  (which are represented as having the all-zeros txid).

## [0.17.0] - 2025-05-30

### Added
- `zcash_client_sqlite::wallet::init::WalletMigrator`
- `zcash_client_sqlite::wallet::init::migrations`
- `zcash_client_sqlite::WalletDb::params`

### Changed
- Migrated to `zcash_address 0.8`, `zip321 0.4`, `zcash_transparent 0.3`,
  `zcash_primitives 0.23`, `zcash_proofs 0.23`, `zcash_keys 0.9`, `pczt 0.3`,
  `zcash_client_backend 0.19`
- `zcash_client_sqlite::wallet::init::WalletMigrationError::`
  - Variants `WalletMigrationError::CommitmentTree` and
    `WalletMigrationError::Other` now `Box` their contents.

## [0.16.2] - 2025-04-02

### Fixed
- This release fixes a migration error that could cause some wallets
  to crash on startup due to an attempt to associate a received transparent
  output with an address that does not exist in the wallet's `addresses`
  table.

## [0.16.1] - 2025-03-26

### Fixed
- This release fixes a migration error that could cause some wallets
  to crash on startup due to an attempt to derive a unified address with
  a Sapling receiver at an index for which no Sapling receiver can exist.

## [0.16.0] - 2025-03-19

### Added
- `zcash_client_sqlite::WalletDb::with_gap_limits`
- `zcash_client_sqlite::GapLimits`
- `zcash_client_sqlite::util`
- `zcash_client_sqlite::schedule_ephemeral_address_checks` has been added under
  the `transparent-inputs` feature flag.
- `zcash_client_sqlite::wallet::transparent::SchedulingError`

### Changed
- Updated to `zcash_keys 0.8`, `zcash_client_backend 0.18`
- `zcash_client_sqlite::WalletDb` has added fields and type parameters:
    - a `clock` field and corresponding type parameter. Tests that make use of
      `WalletDb` now use a `zcash_client_sqlite::util::FixedClock` for this
      field value.
    - an `rng` field and corresponding type parameter. Tests that make use of
      `WalletDb` now use a `ChaChaRng` value initialized with the all-zeros
      seed for this field value.
    - the following methods have been changed to accept additional parameters
      as a result of these changes:
      - `WalletDb::for_path`
      - `WalletDb::from_connection`
      - `wallet::init::init_wallet_db` has additional type constraints
- `zcash_client_sqlite::WalletDb::get_address_for_index` now returns some of
  its failure modes via `Err(SqliteClientError::AddressGeneration)` instead of
  `Ok(None)`.
- `zcash_client_sqlite::error::SqliteClientError` variants have changed:
  - The `EphemeralAddressReuse` variant has been removed and replaced
    by a new generalized `AddressReuse` error variant.
  - The `ReachedGapLimit` variant no longer includes the account UUID
    for the account that reached the limit in its payload. In addition
    to the transparent address index, it also contains the key scope
    involved when the error was encountered.
  - A new `DiversifierIndexReuse` variant has been added.
  - A new `Scheduling` variant has been added.
- Each row returned from the `v_received_outputs` view now exposes an
  internal identifier for the address that received that output. This should
  be ignored by external consumers of this view.

## [0.15.0] - 2025-02-21

### Added
- `zcash_client_sqlite::WalletDb::from_connection`
- `zcash_client_sqlite::WalletDb::check_witnesses`
- `zcash_client_sqlite::WalletDb::queue_rescans`

### Changed
- MSRV is now 1.81.0.
- Migrated to `bip32 =0.6.0-pre.1`, `nonempty 0.11`.`incrementalmerkletree 0.8`,
  `shardtree 0.6`, `orchard 0.11`, `sapling-crypto 0.5`, `zcash_encoding 0.3`,
  `zcash_protocol 0.5`, `zcash_address 0.7`, `zcash_transparent 0.2`,
  `zcash_primitives 0.22`, `zcash_keys 0.7`, `zcash_client_backend 0.17`.
- `zcash_client_sqlite::wallet::init::init_wallet_db` now has an additional
  generic parameter, enabling it to be used with wallets constructed via
  `WalletDb::from_connection`.
- The `v_transactions` view has added columns `total_spent` and `total_received`.

## [0.14.0] - 2024-12-16

### Added
- `zcash_client_sqlite::AccountUuid`

### Changed
- Migrated to `sapling-crypto 0.4`, `zcash_keys 0.6`, `zcash_primitives 0.21`,
  `zcash_proofs 0.21`, `zcash_client_backend 0.16`
- The `v_transactions` view has been modified:
  - The `account_id` column has been replaced with `account_uuid`.
- The `v_tx_outputs` view has been modified:
  - The `from_account_id` column has been replaced with `from_account_uuid`.
  - The `to_account_id` column has been replaced with `to_account_uuid`.
- The `WalletRead` and `InputSource` impls for `WalletDb` now set the `AccountId`
  associated type to `AccountUuid`.
- Variants of `SqliteClientError` have changed:
  - The `AccountCollision` and `ReachedGapLimit` now carry `AccountUuid` values
    instead of `AccountId`s.
  - `SqliteClientError::AccountIdDiscontinuity` has been removed as it is now
    unused.
  - `SqliteClientError::AccountIdOutOfRange` has been renamed to
    `Zip32AccountIndexOutOfRange`.

### Removed
- `zcash_client_sqlite::AccountId` (use `AccountUuid` instead).

## [0.13.0] - 2024-11-14

### Added
- Exposed `AccountId::from_u32` and `AccountId::as_u32` conversions under the
  `unstable` feature flag.

### Changed
- MSRV is now 1.77.0.
- Migrated to `zcash_primitives 0.20`, `zcash_keys 0.5`,
  `zcash_client_backend 0.15`.
- Migrated from `schemer` to our fork `schemerz`.
- Migrated to `rusqlite 0.32`.
- `error::SqliteClientError` has additional variant `NoteFilterInvalid`

### Fixed
- `zcash_client_sqlite::WalletDb`'s implementation of
  `zcash_client_backend::data_api::WalletRead::get_wallet_summary` has been
  fixed to take account of `min_confirmations` for transparent balances.
  (Previously, it would treat transparent balances as though
  `min_confirmations` were `1` even if it was set to a higher value.)
  Note that this implementation treats `min_confirmations == 0` the same
  as `min_confirmations == 1` for both shielded and transparent TXOs.
  It also does not currently distinguish between pending change and
  non-change; the pending value is all counted as non-change (issue
  [#1592](https://github.com/zcash/librustzcash/issues/1592)).

## [0.12.2] - 2024-10-21

### Fixed
- Fixes an error in determining the minimum checkpoint height to which it's
  possible to rewind in the case of a reorg, when no other truncation height
  information is available.

## [0.12.1] - 2024-10-10

### Fixed
- An error in scan progress computation was fixed. As part of this fix, wallet
  summary information is now only returned in the case that some note
  commitment tree size information can be determined, either from subtree root
  download or from downloaded block data. NOTE: The recovery progress ratio may
  be present as `0:0` in the case that the recovery range contains no notes;
  this was not adequately documented in the previous release.

## [0.12.0] - 2024-10-04

### Added
- `impl WalletTest for WalletDb` is now available under the `test-dependencies`
  feature flag.

### Changed
- Migrated to `zcash_client_backend 0.14`, `orchard 0.10`,
  `sapling-crypto 0.3`, `shardtree 0.5`, `zcash_address 0.6`,
  `zcash_primitives 0.19`, `zcash_proofs 0.19`, `zcash_protocol 0.4`.
- `zcash_client_sqlite::error::SqliteClientError::RequestedRewindInvalid`
  is now a structured variant.

## [0.11.2] - 2024-08-21

### Changed
- The `v_tx_outputs` view was modified slightly to support older versions of
  `sqlite`. Queries to the exposed `v_tx_outputs` and `v_transactions` views
  are supported for SQLite versions back to `3.19.x`.
- `zcash_client_sqlite::wallet::init::WalletMigrationError` has an additional
  variant, `DatabaseNotSupported`. The `init_wallet_db` function now checks
  that the sqlite version in use is compatible with the features required by
  the wallet and returns this error if not. SQLite version `3.35` or higher
  is required for use with `zcash_client_sqlite`.

## [0.11.1] - 2024-08-21

### Fixed
- The dependencies of the `tx_retrieval_queue` migration have been fixed to
  enable migrating wallets containing certain kinds of transactions.

## [0.11.0] - 2024-08-20

`zcash_client_sqlite` now provides capabilities for the management of ephemeral
transparent addresses in support of the creation of ZIP 320 transaction pairs.

In addition, `zcash_client_sqlite` now provides improved tracking of transparent
wallet history in support of the API changes in `zcash_client_backend 0.13`,
and the `v_transactions` view has been modified to provide additional metadata
about the relationship of each transaction to the wallet, in particular whether
or not the transaction represents a wallet-internal shielding operation.

### Changed
- MSRV is now 1.70.0.
- Updated dependencies:
  - `zcash_address 0.4`
  - `zcash_client_backend 0.13`
  - `zcash_encoding 0.2.1`
  - `zcash_keys 0.3`
  - `zcash_primitives 0.16`
  - `zcash_protocol 0.2`
- `zcash_client_sqlite::error::SqliteClientError` has a new `ReachedGapLimit` and
  `EphemeralAddressReuse` variants when the "transparent-inputs" feature is enabled.
- `zcash_client_sqlite::error::SqliteClientError` has changed variants:
  - Removed `HdwalletError`.
  - Added `AccountCollision`.
  - Added `TransparentDerivation`.
- The `v_transactions` view has been modified:
  - The `block` column has been renamed to `mined_height`.
  - A `spent_note_count` column has been added.
  - An `is_shielding` column has been added, which is true for transactions where the
    spends from the wallet are all transparent, and the outputs to the wallet are all
    shielded.
- The `v_tx_outputs` view has been modified:
  - The result can now include transparent outputs with unknown height.

### Fixed
- The `to_address` column of the `v_tx_outputs` view is now `NULL` for
  transparent outputs received by the wallet. This column is only intended to
  contain addresses for outputs sent to external recipients. The fix aligns
  received transparent outputs with received shielded outputs (which have always
  returned `NULL`).

## [0.10.3] - 2024-04-08

### Added
- Added a migration to ensure that the default address for existing wallets is
  upgraded to include an Orchard receiver.

### Fixed
- A bug in the SQL query for `WalletDb::get_account_birthday` was fixed.

## [0.10.2] - 2024-03-27

### Fixed
- A bug in the SQL query for `WalletDb::get_unspent_transparent_output` was fixed.

## [0.10.1] - 2024-03-25

### Fixed
- The `sent_notes` table's `received_note` constraint was excessively restrictive
 after zcash/librustzcash#1306. Any databases that have migrations from
 zcash_client_sqlite 0.10.0 applied should be wiped and restored from seed.
 In order to ensure that the incorrect migration is not used, the migration
 id for the `full_account_ids` migration has been changed from
 `0x1b104345_f27e_42da_a9e3_1de22694da43` to `0x6d02ec76_8720_4cc6_b646_c4e2ce69221c`

## [0.10.0] - 2024-03-25

This version was yanked, use 0.10.1 instead.

### Added
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependendencies.
- `zcash_client_sqlite::AccountId`
- `zcash_client_sqlite::wallet::Account`
- `impl From<zcash_keys::keys::AddressGenerationError> for SqliteClientError`

### Changed
- Many places that `AccountId` appeared in the API changed from
  using `zcash_primitives::zip32::AccountId` to using an opaque `zcash_client_sqlite::AccountId`
  type.
  - The enum variant `zcash_client_sqlite::error::SqliteClientError::AccountUnknown`
    no longer has a `zcash_primitives::zip32::AccountId` data value.
  - Changes to the implementation of the `WalletWrite` trait:
    - `create_account` function returns a unique identifier for the new account (as before),
      except that this ID no longer happens to match the ZIP-32 account index.
      To get the ZIP-32 account index, use the new `WalletRead::get_account` function.
  - Two columns in the `transactions` view were renamed. They refer to the primary key field in the `accounts` table, which no longer equates to a ZIP-32 account index.
    - `to_account` -> `to_account_id`
    - `from_account` -> `from_account_id`
- `zcash_client_sqlite::error::SqliteClientError` has changed variants:
  - Added `AddressGeneration`
  - Added `UnknownZip32Derivation`
  - Added `BadAccountData`
  - Removed `DiversifierIndexOutOfRange`
  - Removed `InvalidNoteId`
- `zcash_client_sqlite::wallet`:
  - `init::WalletMigrationError` has added variants:
    - `WalletMigrationError::AddressGeneration`
    - `WalletMigrationError::CannotRevert`
    - `WalletMigrationError::SeedNotRelevant`
- The `v_transactions` and `v_tx_outputs` views now include Orchard notes.

## [0.9.1] - 2024-03-09

### Fixed
- Documentation now correctly builds with all feature flags.

## [0.9.0] - 2024-03-01

### Changed
- Migrated to `orchard 0.7`, `zcash_primitives 0.14`, `zcash_client_backend 0.11`.
- `zcash_client_sqlite::error::SqliteClientError` has new error variants:
  - `SqliteClientError::UnsupportedPoolType`
  - `SqliteClientError::BalanceError`
  - The `Bech32DecodeError` variant has been replaced with a more general
    `DecodingError` type.

## [0.8.1] - 2023-10-18

### Fixed
- Fixed a bug in `v_transactions` that was omitting value from identically-valued notes

## [0.8.0] - 2023-09-25

### Notable Changes
- The `v_transactions` and `v_tx_outputs` views have changed in terms of what
  columns are returned, and which result columns may be null. Please see the
  `Changed` section below for additional details.

### Added
- `zcash_client_sqlite::commitment_tree` Types related to management of note
  commitment trees using the `shardtree` crate.
- A new default-enabled feature flag `multicore`. This allows users to disable
  multicore support by setting `default_features = false` on their
  `zcash_primitives`, `zcash_proofs`, and `zcash_client_sqlite` dependencies.
- `zcash_client_sqlite::ReceivedNoteId`
- `zcash_client_sqlite::wallet::commitment_tree` A new module containing a
  sqlite-backed implementation of `shardtree::store::ShardStore`.
- `impl zcash_client_backend::data_api::WalletCommitmentTrees for WalletDb`

### Changed
- MSRV is now 1.65.0.
- Bumped dependencies to `hdwallet 0.4`, `incrementalmerkletree 0.5`, `bs58 0.5`,
  `prost 0.12`, `rusqlite 0.29`, `schemer-rusqlite 0.2.2`, `time 0.3.22`,
  `tempfile 3.5`, `zcash_address 0.3`, `zcash_note_encryption 0.4`,
  `zcash_primitives 0.13`, `zcash_client_backend 0.10`.
- Added dependencies on `shardtree 0.0`, `zcash_encoding 0.2`, `byteorder 1`
- A `CommitmentTree` variant has been added to `zcash_client_sqlite::wallet::init::WalletMigrationError`
- `min_confirmations` parameter values are now more strongly enforced. Previously,
  a note could be spent with fewer than `min_confirmations` confirmations if the
  wallet did not contain enough observed blocks to satisfy the `min_confirmations`
  value specified; this situation is now treated as an error.
- `zcash_client_sqlite::error::SqliteClientError` has new error variants:
  - `SqliteClientError::AccountUnknown`
  - `SqliteClientError::BlockConflict`
  - `SqliteClientError::CacheMiss`
  - `SqliteClientError::ChainHeightUnknown`
  - `SqliteClientError::CommitmentTree`
  - `SqliteClientError::NonSequentialBlocks`
- `zcash_client_backend::FsBlockDbError` has a new error variant:
  - `FsBlockDbError::CacheMiss`
- `zcash_client_sqlite::FsBlockDb::write_block_metadata` now overwrites any
  existing metadata entries that have the same height as a new entry.
- The `v_transactions` and `v_tx_outputs` views no longer return the
  internal database identifier for the transaction. The `txid` column should
  be used instead. The `tx_index`, `expiry_height`, `raw`, `fee_paid`, and
  `expired_unmined` columns will be null for received transparent
  transactions, in addition to the other columns that were previously
  permitted to be null.

### Removed
- The empty `wallet::transact` module has been removed.
- `zcash_client_sqlite::NoteId` has been replaced with `zcash_client_sqlite::ReceivedNoteId`
  as the `SentNoteId` variant is now unused following changes to
  `zcash_client_backend::data_api::WalletRead`.
- `zcash_client_sqlite::wallet::init::{init_blocks_table, init_accounts_table}`
  have been removed. `zcash_client_backend::data_api::WalletWrite::create_account`
  should be used instead; the initialization of the note commitment tree
  previously performed by `init_blocks_table` is now handled by passing an
  `AccountBirthday` containing the note commitment tree frontier as of the
  end of the birthday height block to `create_account` instead.
- `zcash_client_sqlite::DataConnStmtCache` has been removed in favor of using
  `rusqlite` caching for prepared statements.
- `zcash_client_sqlite::prepared` has been entirely removed.

### Fixed
- Fixed an off-by-one error in the `BlockSource` implementation for the SQLite-backed
 `BlockDb` block database which could result in blocks being skipped at the start of
 scan ranges.
- `zcash_client_sqlite::{BlockDb, FsBlockDb}::with_blocks` now return an error
  if `from_height` is set to a block height that does not exist in the cache.
- `WalletDb::get_transaction` no longer returns an error when called on a transaction
  that has not yet been mined, unless the transaction's consensus branch ID cannot be
  determined by other means.
- Fixed an error in `v_transactions` wherein received transparent outputs did not
  result in a transaction entry appearing in the transaction history.

## [0.7.1] - 2023-05-17

### Fixed
- Fixes a potential crash that could occur when attempting to read a memo from
  sqlite when the memo value is `NULL`. At present, we return the empty memo
  in this case; in the future, the `get_memo` API will be updated to reflect
  the potential absence of memo data.

## [0.7.0] - 2023-04-28
### Changed
- Bumped dependencies to `zcash_client_backend 0.9`.

### Removed
- The following deprecated types and methods have been removed from the public API:
  - `wallet::ShieldedOutput`
  - `wallet::block_height_extrema`
  - `wallet::get_address`
  - `wallet::get_all_nullifiers`
  - `wallet::get_balance`
  - `wallet::get_balance_at`
  - `wallet::get_block_hash`
  - `wallet::get_commitment_tree`
  - `wallet::get_nullifiers`
  - `wallet::get_received_memo`
  - `wallet::get_rewind_height`
  - `wallet::get_sent_memo`
  - `wallet::get_spendable_sapling_notes`
  - `wallet::get_transaction`
  - `wallet::get_tx_height`
  - `wallet::get_unified_full_viewing_keys`
  - `wallet::get_witnesses`
  - `wallet::insert_block`
  - `wallet::insert_witnesses`
  - `wallet::is_valid_account_extfvk`
  - `wallet::mark_sapling_note_spent`
  - `wallet::put_tx_data`
  - `wallet::put_tx_meta`
  - `wallet::prune_witnesses`
  - `wallet::select_spendable_sapling_notes`
  - `wallet::update_expired_notes`
  - `wallet::transact::get_spendable_sapling_notes`
  - `wallet::transact::select_spendable_sapling_notes`

## [0.6.0] - 2023-04-15
### Added
- SQLite view `v_tx_outputs`, exposing the history of transaction outputs sent
  from and received by the wallet. See `zcash_client_sqlite::wallet` for view
  documentation.

### Fixed
- In a previous crate release, `WalletDb` was modified to start tracking Sapling
  change notes in both the `sent_notes` and `received_notes` tables, as a form
  of double-entry accounting. This broke assumptions in the `v_transactions`
  SQLite view, and also left the `sent_notes` table in an inconsistent state. A
  migration has been added to this release which fixes the `sent_notes` table to
  consistently store Sapling change notes.
- The SQLite view `v_transactions` had several bugs independently from the above
  issue, and has been rewritten. See `zcash_client_sqlite::wallet` for view
  documentation.

### Changed
- Bumped dependencies to `group 0.13`, `jubjub 0.10`, `zcash_primitives 0.11`,
  `zcash_client_backend 0.8`.
- The dependency on `zcash_primitives` no longer enables the `multicore` feature
  by default in order to support compilation under `wasm32-wasi`. Users of other
  platforms may need to include an explicit dependency on `zcash_primitives`
  without `default-features = false` or otherwise explicitly enable the
  `zcash_primitives/multicore` feature if they did not already depend
  upon `zcash_primitives` with default features enabled.

### Removed
- SQLite views `v_tx_received` and `v_tx_sent` (use `v_tx_outputs` instead).

## [0.5.0] - 2023-02-01
### Added
- `zcash_client_sqlite::FsBlockDb::rewind_to_height` rewinds the BlockMeta Db
 to the specified height following the same logic as homonymous functions on
 `WalletDb`. This function does not delete the files referenced by the rows
 that might be present and are deleted by this function call.
- `zcash_client_sqlite::FsBlockDb::find_block`
- `zcash_client_sqlite::chain`:
  - `impl {Clone, Copy, Debug, PartialEq, Eq} for BlockMeta`

### Changed
- MSRV is now 1.60.0.
- Bumped dependencies to `zcash_primitives 0.10`, `zcash_client_backend 0.7`.
- `zcash_client_backend::FsBlockDbError`:
  - Renamed `FsBlockDbError::{DbError, FsError}` to `FsBlockDbError::{Db, Fs}`.
  - Added `FsBlockDbError::MissingBlockPath`.
  - `impl fmt::Display for FsBlockDbError`

## [0.4.2] - 2022-12-13
### Fixed
- `zcash_client_sqlite::WalletDb::get_transparent_balances` no longer returns an
  error if the wallet has no UTXOs.

## [0.4.1] - 2022-12-06
### Added
- `zcash_client_sqlite::DataConnStmtCache::advance_by_block` now generates a
  `tracing` span, which can be used for profiling.

## [0.4.0] - 2022-11-12
### Added
- Implementations of `zcash_client_backend::data_api::WalletReadTransparent`
  and `WalletWriteTransparent` have been added. These implementations
  are available only when the `transparent-inputs` feature flag is
  enabled.
- New error variants:
  - `SqliteClientError::TransparentAddress`, to support handling of errors in
    transparent address decoding.
  - `SqliteClientError::RequestedRewindInvalid`, to report when requested
    rewinds exceed supported bounds.
  - `SqliteClientError::DiversifierIndexOutOfRange`, to report when the space
    of available diversifier indices has been exhausted.
  - `SqliteClientError::AccountIdDiscontinuity`, to report when a user attempts
    to initialize the accounts table with a noncontiguous set of account identifiers.
  - `SqliteClientError::AccountIdOutOfRange`, to report when the maximum account
    identifier has been reached.
  - `SqliteClientError::Protobuf`, to support handling of errors in serialized
    protobuf data decoding.
- An `unstable` feature flag; this is added to parts of the API that may change
  in any release. It enables `zcash_client_backend`'s `unstable` feature flag.
- New summary views that may be directly accessed in the sqlite database.
  The structure of these views should be considered unstable; they may
  be replaced by accessors provided by the data access API at some point
  in the future:
  - `v_transactions`
  - `v_tx_received`
  - `v_tx_sent`
- `zcash_client_sqlite::wallet::init::WalletMigrationError`
- A filesystem-backed `BlockSource` implementation
  `zcash_client_sqlite::FsBlockDb`. This block source expects blocks to be
  stored on disk in individual files named following the pattern
  `<blockmeta_root>/blocks/<blockheight>-<blockhash>-compactblock`. A SQLite
  database stored at `<blockmeta_root>/blockmeta.sqlite`stores metadata for
  this block source.
  - `zcash_client_sqlite::chain::init::init_blockmeta_db` creates the required
    metadata cache database.
- Implementations of `PartialEq`, `Eq`, `PartialOrd`, and `Ord` for `NoteId`

### Changed
- Various **BREAKING CHANGES** have been made to the database tables. These will
  require migrations, which may need to be performed in multiple steps. Migrations
  will now be automatically performed for any user using
  `zcash_client_sqlite::wallet::init_wallet_db` and it is recommended to use this
  method to maintain the state of the database going forward.
  - The `extfvk` column in the `accounts` table has been replaced by a `ufvk`
    column. Values for this column should be derived from the wallet's seed and
    the account number; the Sapling component of the resulting Unified Full
    Viewing Key should match the old value in the `extfvk` column.
  - The `address` and `transparent_address` columns of the `accounts` table have
    been removed.
    - A new `addresses` table stores Unified Addresses, keyed on their `account`
      and `diversifier_index`, to enable storing diversifed Unified Addresses.
    - Transparent addresses for an account should be obtained by extracting the
      transparent receiver of a Unified Address for the account.
  - A new non-null column, `output_pool` has been added to the `sent_notes`
    table to enable distinguishing between Sapling and transparent outputs
    (and in the future, outputs to other pools). Values for this column should
    be assigned by inference from the address type in the stored data.
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `jubjub 0.9`,
  `zcash_primitives 0.9`, `zcash_client_backend 0.6`.
- Renamed the following to use lower-case abbreviations (matching Rust
  naming conventions):
  - `zcash_client_sqlite::BlockDB` to `BlockDb`
  - `zcash_client_sqlite::WalletDB` to `WalletDb`
  - `zcash_client_sqlite::error::SqliteClientError::IncorrectHRPExtFVK` to
    `IncorrectHrpExtFvk`.
- The SQLite implementations of `zcash_client_backend::data_api::WalletRead`
  and `WalletWrite` have been updated to reflect the changes to those
  traits.
- `zcash_client_sqlite::wallet`:
  - `get_spendable_notes` has been renamed to `get_spendable_sapling_notes`.
  - `select_spendable_notes` has been renamed to `select_spendable_sapling_notes`.
  - `get_spendable_sapling_notes` and `select_spendable_sapling_notes` have also
    been changed to take a parameter that permits the caller to specify a set of
    notes to exclude from consideration.
  - `init_wallet_db` has been modified to take the wallet seed as an argument so
    that it can correctly perform migrations that require re-deriving key
    material. In particular for this upgrade, the seed is used to derive UFVKs
    to replace the currently stored Sapling ExtFVKs (without losing information)
    as part of the migration process.

### Removed
- The following functions have been removed from the public interface of
  `zcash_client_sqlite::wallet`. Prefer methods defined on
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` instead.
  - `get_extended_full_viewing_keys` (use `WalletRead::get_unified_full_viewing_keys` instead).
  - `insert_sent_note` (use `WalletWrite::store_sent_tx` instead).
  - `insert_sent_utxo` (use `WalletWrite::store_sent_tx` instead).
  - `put_sent_note` (use `WalletWrite::store_decrypted_tx` instead).
  - `put_sent_utxo` (use `WalletWrite::store_decrypted_tx` instead).
  - `delete_utxos_above` (use `WalletWrite::rewind_to_height` instead).
- `zcash_client_sqlite::with_blocks` (use
  `zcash_client_backend::data_api::BlockSource::with_blocks` instead).
- `zcash_client_sqlite::error::SqliteClientError` variants:
  - `SqliteClientError::IncorrectHrpExtFvk`
  - `SqliteClientError::Base58`
  - `SqliteClientError::BackendError`

### Fixed
- The `zcash_client_backend::data_api::WalletRead::get_address` implementation
  for `zcash_client_sqlite::WalletDb` now correctly returns `Ok(None)` if the
  account identifier does not correspond to a known account.

### Deprecated
- A number of public API methods that are used internally to support the
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` interfaces have
  been deprecated, and will be removed from the public API in a future release.
  Users should depend upon the versions of these methods exposed via the
  `zcash_client_backend::data_api` traits mentioned above instead.
  - Deprecated in `zcash_client_sqlite::wallet`:
    - `get_address`
    - `is_valid_account_extfvk`
    - `get_balance`
    - `get_balance_at`
    - `get_sent_memo`
    - `block_height_extrema`
    - `get_tx_height`
    - `get_block_hash`
    - `get_rewind_height`
    - `get_commitment_tree`
    - `get_witnesses`
    - `get_nullifiers`
    - `insert_block`
    - `put_tx_meta`
    - `put_tx_data`
    - `mark_sapling_note_spent`
    - `put_receiverd_note`
    - `insert_witness`
    - `prune_witnesses`
    - `update_expired_notes`
    - `get_address`
  - Deprecated in `zcash_client_sqlite::wallet::transact`:
    - `get_spendable_sapling_notes`
    - `select_spendable_sapling_notes`

## [0.3.0] - 2021-03-26
This release contains a major refactor of the APIs to leverage the new Data
Access API in the `zcash_client_backend` crate. API names are almost all the
same as before, but have been reorganized.

### Added
- `zcash_client_sqlite::BlockDB`, a read-only wrapper for the SQLite connection
  to the block cache database.
- `zcash_client_sqlite::WalletDB`, a read-only wrapper for the SQLite connection
  to the wallet database.
- `zcash_client_sqlite::DataConnStmtCache`, a read-write wrapper for the SQLite
  connection to the wallet database. Returned by `WalletDB::get_update_ops`.
- `zcash_client_sqlite::NoteId`

### Changed
- MSRV is now 1.47.0.
- APIs now take `&BlockDB` and `&WalletDB<P>` arguments, instead of paths to the
  block cache and wallet databases.
- The library no longer uses the `mainnet` feature flag to specify the network
  type. APIs now take a `P: zcash_primitives::consensus::Parameters` variable.

### Removed
- `zcash_client_sqlite::address` module (moved to `zcash_client_backend`).

### Fixed
- Shielded transactions created by the wallet that have no change output (fully
  spending their input notes) are now correctly detected as mined when scanning
  compact blocks.
- Unshielding transactions created by the wallet (with a transparent recipient
  address) that have no change output no longer cause a panic.

## [0.2.1] - 2020-10-24
### Fixed
- `transact::create_to_address` now correctly reconstructs notes from the data
  DB after Canopy activation (zcash/librustzcash#311). This is critcal to correct
  operation of spends after Canopy.

## [0.2.0] - 2020-09-09
### Changed
- MSRV is now 1.44.1.
- Bumped dependencies to `ff 0.8`, `group 0.8`, `jubjub 0.5.1`, `protobuf 2.15`,
  `rusqlite 0.24`, `zcash_primitives 0.4`, `zcash_client_backend 0.4`.

## [0.1.0] - 2020-08-24
Initial release.
