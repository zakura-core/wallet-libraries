# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<<<<<<< HEAD
### Added

- Migration `transactions_mined_height_index` adds an index on
  `transactions.mined_height`.
- Migration `transparent_spend_map_prevout_index` indexes `transparent_spend_map`
  by `(prevout_txid, prevout_output_index)`.

### Changed

- Generating the crate's feature table now requires the optional
  `document-features` feature. Ordinary builds omit the documentation macro;
  docs.rs continues to include the table.

- Use `schemerz` 0.3 and `schemerz-rusqlite` 0.371 for wallet migrations,
  sharing the dependency family required by the LRZ facade. Applications naming
  migration errors or implementing external migrations must use these versions
  for `MigratorError` and `RusqliteMigration` respectively. Migration UUIDs and
  the database schema are unchanged.

- Storing a scanned block uses the new index to attach transactions first learned
  from a transparent UTXO query, avoiding a scan of the whole transactions table.
- Storing a received transparent output no longer scans `transparent_spend_map`
  to learn whether a wallet transaction already spends it.
- An account's first `begin_one_time_recovery` reads its untouched receive
  bootstrap lookups only through the publication's end and places the filter
  marker there, even without `complete`. Turning one-time recovery on no longer
  makes the first receive address wait for the Receiver publication to reach
  the wallet's tip. Every other lookup target is unchanged.
- `WalletDb::prepare_receive_reservation` takes a `tip: BlockHeight` argument,
  the caller's live chain tip, as `reserve_refund_key` does. A new receive
  address needs the account's filter marker within 10 blocks of the newer of
  that tip and the saved chain tip, so a wallet no longer has to save the live
  tip with `update_chain_tip` first. Resuming a live draft now needs the same
  fresh marker, so a draft isn't quoted again while another device's payment to
  it may sit in blocks filters haven't read.
- `WalletDb::recheck_one_time_history_for` replaces
  `WalletDb::check_one_time_history_for`. Each account's new history check
  first forgets its history results, as `reset_one_time_history` does, in the
  same transaction that starts the batch, so an account refusing the
  publication rolls back every reset too. An account whose check is unfinished
  resumes it with the history it kept. An account named more than once in the
  batch is checked once, so a repeat can't restart a check the first occurrence
  just finished and forget its pending payments.
- `WalletDb::reserve_refund_key` allocates a refund key only once the wallet is
  fully scanned to within 1 block of the chain tip, the newer of `tip` and the
  saved chain tip, rather than 10. Funding memos arrive through ordinary block
  scanning, so this narrows the unread blocks in which another device's memo
  for the same index can hide. Wallets such as Vizor now wait for ordinary sync
  to reach within 1 block of the tip before quoting a refund, and get
  `ReservationPolicy::FundingHistory` until then.
- Consolidation's additional Ironwood candidates stop rebuilding one-time-key
  notes once they hold their half of the limit, so a proposal costs about its
  limit rather than every unspent one-time-key note. The selection is unchanged.

## [0.1.0-rc9.6] - 2026-10-30

### Added

- `WalletDb` implements `WalletWrite::get_addresses_for_index_range`, looking up the account, deriving its incoming viewing key and reading the chain tip once for the whole range. Exposing a deep window of addresses (a transparent recovery window on restore) is about seven times faster than one index at a time.

### Changed

- `WalletDb::record_one_time_lookup` stores each new candidate with its witness payload and admits it in the same transaction, and refuses a lookup captured under another birthday. The `one_time_reset` migration renames the candidate columns for directory sessions. `WalletDb::{record_one_time_witness, refresh_one_time_witness}` are removed.

- Refund memos are read on demand, as before this change, with no queue. Storing blocks accepts the refund memos stored on the wallet transactions those blocks mine, which covers a memo stored before its block and one a reorg's replacement chain mines again. Storing a decrypted, sent or privately enhanced transaction accepts that transaction's memo, so a memo retrieved after the last block batch registers its key at once. Enabling, each round's start and refund issuance read every memo of the account, which accepts a memo the 100-index gap deferred once the gap closes. A mined memo that decodes enables recovery for its account, enabled or not, and one that doesn't decode is ignored.
- `WalletDb::prepare_receive_reservation` hands out a new receive address only once the account's filter marker is within 10 blocks of the chain tip, as well as after the address's own lookup completed. Otherwise it returns `ReservationPolicy::ReceiveHistory`, and `RecoveryStatus::round_due` asks for the round that catches the marker up.
- A refund key known only from its funding memo stays watched until the account's filter marker reaches 90 days of chain time after its canonical funding height, instead of seven days of account progress. With no marker it stays watched. A reorg above the funding height clears it until the replacement chain mines the funding again.
- One-time IVK filters are only a trigger, and each account keeps one marker, the block through which filters were read. `WalletDb::record_one_time_filter_span` commits a sparse filter range only when it starts just past the marker with the marker's hash as its parent (or at Ironwood activation with no marker) and ends at a fully scanned block with the same hash, and returns a `FilterOutcome`; any other start is an error. Each hit queues a lookup from its key's history start through the hit. `WalletDb::one_time_receivers` returns the watched receivers alone. Every key that starts being watched gets one bootstrap lookup from its history start through the processed frontier, so a fresh account's seed walk takes its four receive lookups. A new migration, `one_time_reset`, resets one-time progress: it drops payment candidates and clears lookups, cursors, the seed walk and the marker. It doesn't rebuild use markers, receive windows or bootstrap lookups, so a development wallet with one-time data should be recreated. A development database that ran an earlier build of this change no longer opens and must be recreated.
- `WalletDb::begin_one_time_recovery` takes `complete` instead of `direct`: a complete check reads every monitored key, paid ones included, from its last PIR check through the publication's end, so it finds repeat payments, and moves the marker there, capped at the fully scanned block. Direct catch-up, which skipped completed paid keys, is gone.
- Corrections and earlier birthdays clear the filter marker, and reorgs move it back to the fork. A correction no longer reads every monitored key by PIR: the next round's complete check does, and only pending lookups and open reservations are read again directly.

- Each account keeps a one-time use marker, reported as `RecoveryStatus::used`. Handing out a receive address or refund key, recording the wallet's own refund funding, storing a payment candidate at or after the birthday, or accepting a refund memo sets it in the same transaction, whether or not recovery is enabled. Nothing clears it.
- One-time recovery ignores payments before the account birthday. A lookup passes over such a record before storing a candidate, so it is neither credited nor counted as use, and no longer marks its key paid or extends the seed walk. The `one_time_reset` migration drops `ironwood_one_time_keys.prebirthday_height`.
- `WalletDb::check_one_time_history_for` starts the history check of several accounts in one transaction. If any account refuses, none start and the call returns that account.
- `WalletDb::reset_one_time_history` forgets an account's one-time history results as a history correction does, so the next round reads every watched address again from its history start. A wallet calls it after switching to another receiver service.
- Starting a history check makes the account's backed-off lookups due at once, so a check after an outage doesn't wait out the outage's backoff.
- A rewind or history correction no longer reopens a finished history check. The next `WalletDb::check_one_time_history` starts fresh at the new publication's end instead of resuming under the old frontier, so it finds a repeat payment mined after that frontier.
- `WalletDb::one_time_recovery` takes the captured inventory's end. The four listed lookups are then ones that inventory can answer, so lookups waiting for a later publication no longer hide a runnable one. Its `round_due` tells the app when to run a round for the account (see `RecoveryStatus::round_due`).

- `WalletDb::enable_one_time_recovery` replaces `WalletDb::set_one_time_recovery_enabled`. One-time recovery can no longer be paused: an enabled account stays enabled. An account that isn't enabled exposes no work, including the repair-only work a paused account used to run, and re-enabling no longer resets lookup progress.

### Removed

- `WalletDb::record_one_time_filters`, its per-block identities and 256-block cap, and `WalletDb::one_time_direct_query_count`.
- `testing::db::TestDb` implements the wallet traits by forwarding every method, including those with default bodies, to its `WalletDb` by hand rather than through `ambassador`, which the `test-dependencies` feature no longer depends on. Its behavior is unchanged.

## [0.1.0-rc9.5] - 2026-10-26

### Changed

- Use backend `0.1.0-rc9.5`, which skips accounts born after the scanned range, and retain regression coverage for both shielded pools.

## [0.1.0-rc9.4] - 2026-10-23

### Changed

- Read transaction history outputs and received/spent amounts in batches to avoid repeatedly scanning the entire wallet for each transaction.

- Replace one-time-key discovery passes and scan watches with a durable PIR recovery queue. Seed recovery stops after four complete empty receive histories, receive issuance recycles unpaid holes in a four-index window that extends once a payment is mined and hands out an index only after its own history lookup completes (`ReservationPolicy::ReceiveHistory` until then), and refunds use authenticated funding evidence. Manual history checks support cancellation, restart and an explicit receive bound.
- Remove provider seen gates, broad one-time-key decryption, scan hints, replay state and their old APIs. Ordinary sync never waits for receiver discovery. Retain targeted payment authentication, chain proofs, spend-journal checks and existing note ownership. Rewinds and earlier birthdays requeue affected history even while discovery is disabled.
- Receiver lookups follow sealed shard inventories. A request keeps its required history start and the height checked through, so a replacement inventory resumes after whole checked shards and rereads any shard straddling that point, while a cursor is only resumed under the inventory it came from. Seed receive discovery covers history from activation, and four empties count only with that coverage. Corrections clear progress between shards and send active requests back to activation, reorgs clamp progress to the fork, enabling discovery drops repair-only progress, and a payment rejected after its pages were read sends its key back to that payment's shard.
- `WalletDb::record_one_time_witness` takes a companion witness answer instead of a full path, and `WalletDb::refresh_one_time_witness` re-reads a payment whose session can no longer serve its witness. A provisional witness is checked against the wallet's own tree at exactly its construction block; a final one (its Ironwood shard full) at the scanned tip. The accepted root is read before any returned node is used, and an unusable or missing witness leaves the payment pending and reads it again, never completing an empty address.
- `WalletDb::require_one_time_upgrade` records that a step returned `Unsupported`. Recovery then exposes no work and keeps every pending lookup, candidate and obligation, instead of backing off forever, until `begin_one_time_recovery` accepts a publication this client captured.
- A provider's promised receipt settles only through a recovered note in a transaction the provider reported for that operation, recorded from `Observation::receipts`. Without one, the address stays in direct catch-up.
- Rebaseline the unlaunched one-time-key schema. The cutover drops abandoned discovery progress while preserving accounts, note ownership and unrelated wallet data. Recovery starts disabled.
- One-time IVK issuance no longer reads a provider seen set. `WalletDb::prepare_receive_reservation`, `WalletDb::begin_receive_operation` and `WalletDb::reserve_refund_key` drop their `seen` argument, and keys no longer stop being watched `COMPLETION_LIMIT_SECS` after their last deadline. `ReservationPolicy` gains `Disabled`, `FundingHistory` and `ReceiveHistory`.
- A build without `orchard` that stores a transaction holding a private one-time receipt keeps that receipt's private enhancement work and leaves its raw-transaction check to an Orchard build, which runs it when it next stores blocks.
- Storing scanned blocks looks for those deferred raw-transaction checks from their queue, so a wallet with no one-time state no longer walks its whole transaction table on every scan batch.
- No one-time call creates recovery state for an account that never enabled it, so scanning does no per-account recovery work for it. `WalletDb::one_time_recovery`, `WalletDb::one_time_receivers` and `WalletDb::one_time_direct_query_count` are pure reads, `WalletDb::set_one_time_recovery_enabled(.., false)`, `WalletDb::require_one_time_upgrade` and `WalletDb::check_one_time_history` change nothing, `WalletDb::begin_one_time_recovery` returns `false` unless the account already holds receipts needing repair, and the swap calls answer `ReservationPolicy::Disabled` or their disabled error. The reads and these calls also report disabled for an account without an Orchard full viewing key instead of failing. Enabling recovery and issuing keys still refuse such an account. Pausing an account that is not enabled, or reporting an upgrade it already waits for, only reads, so it works on a read-only connection and never waits on another writer.
- Storing scanned blocks no longer decodes the viewing key of each account with one-time recovery enabled several times per batch. Its bookkeeping looks up only the account's row, decodes the key only to register a new one-time key, and skips admission's monitoring reads when no payment awaits admission.
- `WalletDb::get_wallet_summary` computes scan and recovery progress without looking up
  each scanned block in the scan queue, which made it slow on wallets with millions of
  scanned blocks. The reported progress is unchanged.
- Use backend `0.1.0-rc9.4` and one-time IVK `0.0.1-rc4`.

### Removed

- `WalletDb::get_one_time_key_for_receiver`, which only tests used, and its receiver index.
- `SqliteClientError::OneTimeIvksNotUsed`, which only the removed one-time scanning APIs returned.
- `ReservationPolicy::Coverage`, `ReservationPolicy::SeenUnavailable`, `ProviderSeen`, `ISSUANCE_TIP_LAG`, `RECEIVE_GAP_LIMIT`, `RECEIVE_RECLAIM_SECONDS` and `SEEN_SLACK_SECONDS`.
- `WalletDb::close_finished_one_time_keys`, `WalletDb::mark_one_time_account_fresh` and `WalletDb::recheck_one_time_key_history`. `WalletDb::check_one_time_history` replaces the recheck.
- The unused `now` argument of `WalletDb::set_one_time_recovery_enabled`, `WalletDb::begin_one_time_recovery`, `WalletDb::check_one_time_history` and `WalletDb::reserve_refund_key`, and the write-only `registered_at` key column.

### Fixed

- Refund recovery trusts a refund memo on any of the account's internal Ironwood notes, without requiring the funding transaction to spend a note the wallet knows. A second device or a restore that has not recovered the one-time notes a swap spent, or whose birthday falls after them, now registers the funded refund key instead of ignoring the memo and issuing the same refund index again. `WalletDb::reserve_refund_key` waits only while an internal note's memo has not been retrieved. Since a viewing key can also pay internal addresses, a memo registers its index only within 100 of the highest refund index the account knows, or when its transaction spends a note the account owns, so a forged memo cannot exhaust the index space. A memo beyond the gap without that spend is recovered only once the gap closes.
- A refund key with no local operation, such as one recovered from its funding memo, leaves automatic monitoring once filters have checked seven days of chain time past its funding block, instead of being looked up on every catch-up forever. A key recovered after that still has its history read once, an explicit history check still covers it, and its index is never issued again.
- A one-time receipt that a reorg displaced no longer keeps its key in repair, and so in automatic monitoring, forever. Once the key's history has been read past its transaction's expiry height, and filters have passed the pruning depth (100 blocks) beyond it, the current chain does not hold it and no reorg the wallet follows can mine it again, so the key can retire, for example after a replacement transaction paid the same refund. A paused account keeps repairing.
- A reorg shortly after a wallet starts scanning no longer leaves it unable to rewind. `WalletDb::truncate_to_height` can now rewind to the tree state the wallet started scanning from, at `birthday - 1`, which is also the safe rewind height it reports. Before, a rewind past every scanned block with a shielded output was refused, and so was the retry at the reported safe height.
- A started incoming quote that never gets a fresh conclusive provider status no longer holds its receive slot forever. If its address is unpaid with no payment pending, the slot is released 24 hours after the quote's deadline, measured by the earlier of the device clock and the latest block time, so a fast device clock cannot release it early. A paid address still needs a fresh status, since a reorg can make it unpaid again. A quote seen funded, or whose last status was active, still keeps its slot. The released address stays monitored, so a late payment to it is still recovered.

## [0.1.0-rc9.3] - 2026-10-20

### Changed

- Use the stable Common `4.0.0` dependency family, with compatible requirements
  for downstream consumers.
- Use backend `0.1.0-rc9.3` and one-time IVK `0.0.1-rc3`.

## [0.1.0-rc9.2] - 2026-10-20

### Changed

- Use backend `0.1.0-rc9.2`, PCZT `0.1.0-rc8` and one-time IVK `0.0.1-rc2`,
  with the compatible Common `4.0.0-rc3` dependency family.
- Transaction expiry, input locks, status work and one-time-key closure follow
  the network's NU7 expiry rules, including transactions whose expiry is not yet
  known. Mined transaction evidence is preserved independently of expiry.
- `WalletDb::check_witnesses` now requires its network parameter type to implement
  `consensus::Parameters` so it can apply the network's NU7 rules.

### Fixed

- Select shielded anchors at the required depth behind the chain tip and report
  notes as spendable only when they are covered by the selected anchor.
- Apply the same expiry and competing-spend rules to transparent balances,
  spendability and recovery-ledger snapshots.

## [0.1.0-rc9.1] - 2026-10-19

### Added

- One-time IVK discovery (with `orchard`): `WalletDb` implements the backend's discovery
  methods and `get_one_time_scanning_keys_for_range`. A restored account's payments appear
  as its restore scan covers them, and one found after the scan passed it once the scan
  covers every later block. Issuance waits until a restored account's discovery has
  registered every index its publication marks used, and a fresh account waits for none.
- `wallet::init::migrations::ids::ONE_TIME_IVK_DISCOVERY`, the migration for discovery and
  the spend journal.
- A spend journal (with `orchard`): every block scan keeps every Ironwood nullifier each
  recognized transaction reveals, matched to a wallet note or not, and records which blocks
  it covered for each account. A rewind drops the entries and coverage
  above its rescan floor.
- `TransparentPirSession`, with `WalletDb::with_transparent_pir_session`,
  `WalletDb::set_transparent_pir_session` and `WalletDb::transparent_pir_session`: the transparent work an open wallet holds
  back until the next chain tip, shared by the wallet's database handles like
  `EnhancePirSession`. It is kept in memory only, with no new table or migration.

### Changed

- Use the published Zakura Common `4.0.0-rc2` dependency family.

- One-time IVK issuance fails closed without a fresh provider seen set.
  `WalletDb::prepare_receive_reservation`, `WalletDb::reserve_refund_key` (which now
  takes the caller's `now`) and a reservation's first `WalletDb::begin_receive_operation`
  (which now takes `seen`) return the new `ReservationPolicy::SeenUnavailable` unless the
  set's last read began within 15 minutes before, and at most a minute after, the
  caller's clock. A reservation never quoted that the set holds is retired, and its key
  scans until `COMPLETION_LIMIT_SECS` after, in case another device's swap pays it. An
  incoming swap attempt keeps its address across quotes: the draft is resumed until its
  latest request's deadline passes, and `begin_receive_operation` then refuses the
  reservation as `ReservationPolicy::Stale`. A reissued address's earlier requests do not
  count, and a reservation made before `ONE_TIME_IVK_DISCOVERY` counts every request on
  its key.
- One-time IVK restore no longer retains Ironwood nullifiers: restore sweeps, their
  retention floors, coverage marks, replays and stepped release are gone, and the nullifier
  map prunes Ironwood nullifiers like the other pools'. The migration drops the
  `ironwood_one_time_sweeps`, `ironwood_nullifier_scan_blocks` and
  `ironwood_one_time_spend_retention` tables, which released wallets hold empty.
- Blocks scanned without one-time keys judge discovery's publications and turn the hints
  they skip into late candidates. Builds without `orchard`, which cannot, also refuse blocks
  while discovery waits for the scan or a payment candidate is pending.
- `WalletDb::recheck_one_time_key_history` returns nothing. It ends the account's discovery
  pass, so the next one checks every key against the directory's current filters and reads
  each paid key's history again. Once discovery is complete, only this starts a pass. On a
  fresh account, new swap addresses then wait for that pass.
- A rewind repairs one-time IVK state in every build, not only with `orchard`: discovery
  redoes what the rescan may change, and lowering an account's birthday reopens its
  discovery. A key closed without scanning scans again from its first payment above the
  rewind until that payment is confirmed again. An open key that started above the rewind
  scans from the first rescanned block.

- Operations that can queue transparent lookups now reject caller-owned SQL transactions
  without a wallet-owned session journal with `TransparentSessionTransactionRequired`.
  Use `WalletDb::transactionally` or `transactionally_with_extension` so a rollback cannot
  release an existing lookup's privacy hold.

- A txid lookup newly queued at the current chain tip (by a recovery, Enhance,
  status or receiver PIR reply, a policy change or the scan) is not listed by
  `TransparentDetailRead::transparent_detail_work` until the chain tip changes,
  whether it rose or a reorg lowered it, even when the caller prefers its txid.
  The display service therefore never sees a reply from another service turn
  into a lookup at the same tip. Adding a reason to a queued lookup does not hold
  it back. The record lives in the handle's `TransparentPirSession` and changes
  with the wallet transaction that queued the work; a fresh session, as after a
  restart, lists the work at once.

- Newly queued Ironwood Enhance positions no longer wait a random time before
  their first private query. The shared session still tracks content failures.
  `EnhancePirRead` for `WalletDb` no longer requires `CL: Clock`.

### Removed

- `WalletDb::set_enhance_pir_max_delay` and the session's in-memory query deadlines.
  No database migration is required.

### Fixed

- Deleting an account removes spend-journal entries for transactions owned only
  by that account, while retaining transactions shared with another account.
- Block scans skip spend-journal entries for transactions without Ironwood
  nullifiers while still recording that the block was scanned.

## [0.1.0-rc9] - 2026-10-14

### Added

- One-time IVKs (with `orchard`): per-swap Ironwood refund and incoming addresses derived
  with `zakura-one-time-ivk` and recoverable from the seed. `wallet::one_time_ivk` holds the
  key registry, scanning, spending and restore sweeps, and its rustdoc lists the calls a
  wallet makes; `wallet::one_time_ivk::swap` holds issuance, provider operations, refund
  funding and closing. `WalletDb` implements the backend's `OneTimeIvkRead`,
  `OneTimeIvkWrite`, `OneTimeIvkRestoreRead` and `OneTimeIvkRestoreWrite`. New errors are
  `SqliteClientError::OneTimeIvksNotUsed` and `SqliteClientError::InvalidOneTimeIvkInput`.
  ZeWIF import also decrypts with the wallet's one-time keys. With
  `NoteSelection::PreferConsolidation`, one-time-key notes are spent first where that adds
  no actions or fee.
- `wallet::init::migrations::ids::ONE_TIME_IVK`, the one-time IVK migration, which runs in
  every build. Builds without `orchard` refuse blocks and transactions with
  `SqliteClientError::OneTimeIvksNotUsed` while a one-time key is open.

### Changed

- Updated the public cryptography and note-encryption types to Zakura Common
  3.0.0 and raised the minimum supported Rust version to 1.97.

- Each newly queued Ironwood Enhance position waits a delay drawn uniformly
  from 0 to 75 seconds (37.5 seconds on average) with the wallet's random source
  before its first private query, and is listed as `EnhancePirWork::Waiting`
  until then. The time is kept in the `EnhancePirSession`, with no new table or
  migration. A rescan in the session keeps it; completing the position or a
  rewind that removes it forgets it, so a requeue draws a new one. A fresh
  session schedules queued positions at its first wallet write (`update_chain_tip`
  among them); a position read before any write instead waits the full 75 seconds
  from its first read. Later writes preserve that existing deadline. Read-only snapshots retain that deadline;
  rolled-back writes do not publish tentative deadlines. Batch work reads and
  scheduling snapshot session state once, rather than cloning it per position.
  `EnhancePirRead` for `WalletDb` now requires `CL: Clock`.
- `WalletDb::set_enhance_pir_max_delay` (test dependencies only) bounds that
  delay; the test database sets it to zero.

- While an account's transparent recovery is a candidate, its watch set holds a
  fixed restore window: every external index below 50 and internal index below 25,
  past the gap limits. Ephemeral addresses keep their gap limit. The window is
  fixed in code and does not follow replies, so a restore whose used addresses
  and their trailing address gaps lie inside it completes in one pass. Activation makes only the gap-limit
  window the wallet's own, so an active account's watch set follows the gap limits as before.
  An account that becomes a candidate again, as after a public policy round trip,
  watches the restore window again and needs a pass covering it before it
  activates. No migration.
- `CommitOutcome::window_grew` reports whether the watched addresses grew. Growth
  inside the restore window does not count, and an active account's growth past
  an unused run as long as the gap limit now does.

- Transparent receipt lookups retry every content outcome (`Absent`, `Protocol`
  and `Contradiction`) on one schedule: an hour, doubling to a day, plus up to
  25% jitter. `Contradiction` no longer waits for a changed display map.
- Retry jitter is drawn from the wallet's random source instead of being
  derived from the txid, so `TransparentDetailWrite` for `WalletDb` now
  requires `R: rand_core::Rng`.
- Without public authority, the third content failure at one mined height
  gives a receipt lookup up: it is neither due nor parked, and the receipt
  reads as `TransparentDisplayView::GaveUp`. Request failures (`Unavailable`) do not count; mining
  the transaction at another height re-arms it. Under public authority nothing
  counts, and work given up earlier is listed again. A new additive migration
  adds `transparent_detail_work.content_failures`.
- `CURRENT_LEAF_MIGRATIONS` has two leaves, `transparent_detail_content_failures` and
  `one_time_ivk`. An older build, such as 0.1.0-rc8, refuses a database this version has
  migrated, as it does any unknown migration.
- Ironwood memo retrieval skips notes received with a one-time key
  (`one_time_key_id IS NULL`) in every build; an ordinary wallet has none. The
  `ironwood_transparent_output_shape` migration now requeues memos itself, without that
  filter, since it can run before the column exists.

### Added

- Enhance PIR replies rejected or unreadable three times suspend that request for the
  open-wallet session. Counts are in memory, with no new table or migration. A fresh
  session restores the allowance; rescans, different metadata positions and rewinds
  re-arm existing work only after their database operation commits.
- `EnhancePirSession` can be shared by serialized database handles for one wallet.
  Keep it alive across syncs and temporary connections; transaction handles inherit
  it automatically. Independently opened handles otherwise start a fresh session.
  The three-failure cap holds per session, so callers keep one session per wallet
  for the app's lifetime; an app restart starts a new session and a full allowance.
- Enhancement work reads in caller-owned SQL transactions preserve session counts
  until committed work is read, so a rolled-back removal cannot re-arm a suspension.
- `WalletDb` implements `EnhancePirWrite::record_ironwood_enhance_unreadable`.
  Request failures do not consume the allowance. Late results recheck their complete
  request identity so a reused position never inherits another transaction's failure.

## [0.1.0-rc8] - 2026-10-13

### Packaging

- Include the MIT and Apache license texts in the crate package.

Breaking storage release for explicit transparent policy, privately recovered
funds, and account-scoped history. See the
[wallet integration guide](../../docs/transparent-pir-wallet-integration.md)
and [status recovery contract](../../docs/transaction_status_work.md).

### Added

- Durable transparent policy and generation tracking, output/spend provenance,
  candidate events and coverage, trusted revision qualification, private-ledger
  activation and recovery suspension. Existing outputs and spends are marked
  legacy evidence; this grants no private coverage. New recovery tables start
  empty and do not automatically activate private policy.
- Atomic recovery commits bound to the account, watched addresses, policy
  generation, locally scanned target and anchor. Contradictory trusted recovery
  suspends its source and affected accounts without applying contradictory facts.
  Observations alone cannot replace wallet-wide evidence.
- Per-account private spending authority once qualified recovery covers the
  chain tip without blockers and agrees with legacy evidence. Final transaction
  storage checks the inputs again, including coinbase maturity and reservations.
- Shared derivation bookkeeping that preserves receiver ownership across
  activation and reopen, expands recovery windows on activity, and materializes
  only unowned receivers. Imports and ownership changes invalidate competing
  candidate evidence atomically.
- `transaction_history_summaries`, history Activity and receipt reads using one
  account-scoped snapshot. They keep financial evidence separate from display
  facts and report unattributed fees and incomplete effects explicitly.
- Transparent txid display storage and queued lookups with policy/placement
  checks, contradiction rejection, bounded output slots, omissions, backoff and
  periodic map rechecks. Raw payload ingestion clears display work and facts.
- Private mixed-transaction memo retries and output-presence recovery. Balanced
  net shielding can use a qualified transparent PIR whole fee without storing
  or attributing it; unknown or conflicting evidence stays provisional.
- Historical inclusion receipts and reconfirmation obligations. Rescanning an
  accepted unchanged block can restore inclusion locally; changed blocks use
  the configured status source. Incomplete private coverage never permits a
  public fallback. Old erased block hashes cannot be reconstructed.
- `WalletHandleModes`, `WalletDb::is_autocommit`, `SqlTransaction::new`, and
  `check_transparent_transaction_inputs` for guarded application integration.
- Atomic forgetting of private-only ledger contributions under public policy.
  Independently supported data and reservations survive; retained ledger-only
  locked rows grant no value or authority.

### Changed

- Transparent selection, ingestion, discovery, status and enhancement require
  explicit handle configuration. A durable private policy governs reads on
  older open handles too; missing, corrupt or unreadable policy fails closed.
- Public requests carry a policy generation. Private policy blocks public
  transparent discovery and routes status privately; restoring public policy
  demotes active ledgers and rebuilds unresolved public detail work.
- Private authority is account-specific and checked within the read snapshot.
  Legacy balance APIs still omit private transparent funds; the ledger snapshot
  reports the available private balance and its blockers.
- Pending recovery and definitive input refusals are distinct typed results.
  An unplaced recovered receive remains pending while recovery catches up and
  can become spendable again when re-placed; withdrawn evidence stays refused.
- Reader-version guards cover reads, rewinds, ownership changes, deletion and
  transparent writes. Shared derivations require reader version 8; older
  writable wallet handover is not qualified by retaining legacy columns.
- Updated backend and PCZT dependencies to `0.1.0-rc8` and `0.1.0-rc5`,
  respectively.

### Fixed

- Repeated account imports and rewinds use a pruning floor measured from the
  chain tip. Rewinds tolerate a checkpoint naturally straddled by independently
  pruned pools while still reporting a missing checkpoint inside a pool's window.
- Sent-note grouping no longer multiplies account totals for change or transfers
  between wallet accounts. The retained transaction view keeps its legacy fields.
- Restoring an output after its spending transaction re-derives the send from
  stored raw data. Attribution requires one wallet funder and all transparent
  inputs owned; shared funding stays unattributed. Ledger projection and old
  sends without a newly recorded parent output are outside this repair.
- Transparent spend discovery retains unmined local-spender work and resumes
  after expiry without advancing unrelated output search frontiers.
- Unmined shielded history stays incomplete until known owned nullifiers are
  linked to their spends. Private receipt ownership requires current qualified
  evidence or independent public/local evidence, and an actually spent outpoint.
- Unknown migrations are refused before schema interpretation, and foreign key
  enforcement is restored after initialization errors.

### Removed

- Obsolete ZIP 318 pool-migration tables and APIs. Historical migration IDs and
  `transactions.zip318_kind` / its transaction-view field remain for supported
  upgrades from published rc5/rc7 writers. Development databases that already
  dropped the column are outside that upgrade path; writable downgrades after
  private recovery are not qualified.
- Prototype rollback preparation and `set_durable_policy_for_testing` APIs;
  policy transitions use `apply_transparent_policy`.

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

### Added
- A `zip318_kind` column on the `transactions` table, recording how each transaction
  classifies against ZIP 318 so that a wallet can label a pool-migration transaction
  in its history without a migration plan, which does not survive a seed restore.
  The column defaults to the code for NOT CLASSIFIED. The migration deliberately
  does not classify existing rows: those keep the default and need the transaction
  rescanned. A client must render the default as no label, never as "not a
  migration".
- A `zip318_kind` column on `v_transactions`, carrying that value through to the
  view clients read their transaction history from. The mobile SDKs build their
  history types from this view with their own SQL, so the column reaches them
  with no change to any foreign function interface.
- `pool_migration::orchard_ironwood::Error::ChainStateUnavailable`, returned
  when a satisfiability check has no fully-scanned height to observe from.
- `pool_migration::orchard_ironwood::FinalizeError`, and new
  `pool_migration::orchard_ironwood::Error` variants `UnknownTransaction`,
  `NotProved`, `ViewingKeyUnavailable`, `Finalize`, and `Wallet`, reporting
  failures of the store's new proved-transaction finalization.
- `zcash_client_sqlite::testing::db::TestDb::conn` and `TestDb::conn_mut`, for
  tests that open a sibling store (a `pool_migration` `PoolMigrations`, say)
  over the wallet database's own connection.
=======
## [0.23.0-pre.2] - 2026-10-13
>>>>>>> 75a187f2638827515d5d0a1c4894a28a57db6b8b

### Changed
- Migrated to `pczt 0.10.0-pre.2`, `zcash_address 0.14.0-pre.2`,
  `zcash_client_backend 0.25.0-pre.2`, `zcash_keys 0.17.0-pre.2`,
  `zcash_pool_migration 0.2.0-pre.2`, `zcash_primitives 0.31.0-pre.2`,
  `zcash_protocol 0.11.0-pre.1`, and `zcash_transparent 0.11.0-pre.2`.
- `WalletRead::list_addresses` now also returns the transparent receiver that
  the wallet tracks at the index of an exposed unified address that omits it,
  as an `Address::Transparent` entry with that diversifier index.

### Fixed
- Unified addresses that the wallet generates to fill its transparent gap limit
  are stored with their transparent receiver, so `WalletRead::list_addresses`
  returns that receiver. A migration restores the transparent receiver to such
  addresses that `zcash_client_sqlite 0.23.0-pre.1` stored without it, if the
  wallet has not exposed them.

## [0.23.0-pre.1] - 2026-10-06

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
<<<<<<< HEAD
  value-pool migration (ZIP 318) independently. The store is constructed via
  `PoolMigrations::for_account`, scoped to the account whose migration it
  tracks; the underlying `orchard_ironwood_migrations` table enforces at most
  one migration per account.
- `zcash_client_sqlite::pool_migration::PoolMigrations::migration_lock_owners`
  returns the set of `LockOwner`s under which an account's in-progress pool
  migration has reserved notes. A proposal can pass this set to a
  `LockedInputPolicy` override (`SpendPolicy::with_locked_input_policy`) so it
  may draw on the migration's own locked notes without disturbing any other
  flow's locks.
- A database migration adds `lock_expiry_height` and `lock_owner` columns to the
  `sapling_received_notes`, `orchard_received_notes`, `ironwood_received_notes`,
  and `transparent_received_outputs` tables to support explicit note locking
  during concurrent proposal creation: `lock_expiry_height` bounds how long a
  lock lasts, and `lock_owner` records the flow that acquired it.
- `zcash_client_sqlite::WalletDb::with_anchor_retention_interval` configures the
  interval on which the wallet retains note commitment tree checkpoints as
  durable anchors, for use on test networks where waiting out the ZIP 318
  144-block interval makes exercising a pool migration impractical. The setting
  governs what grid the next migration is planned against; the grid an in-flight
  migration was committed under is recorded with it and keeps being retained
  regardless, so reopening the wallet without reapplying the setting cannot
  strand a migration.
- `zcash_client_sqlite::WalletDb::set_anchor_retention_interval`, the
  by-reference form of `with_anchor_retention_interval`.

### Changed
- Migrated to `zcash_primitives 0.30.0`, `zcash_transparent 0.10.0`,
  `zcash_proofs 0.30.0`, `zcash_keys 0.16.0`, `zcash_client_backend 0.24.0-rc.2`.
- The `zip-233` feature flag now also enables `zcash_client_backend/zip-233`,
  keeping the two crates' feature-gated `zcash_primitives` call signatures in
  agreement when this crate is built with ZIP 233 support.
- `WalletWrite::truncate_to_height` now accepts a truncation height that a
  pool's note commitment tree checkpoints do not cover whenever the truncation
  leaves that pool's tree in a consistent state — the same per-pool tolerances
  applied by `rewind_to_chain_state` (see under "Fixed" above). Callers that
  relied on `RequestedRewindInvalid` being returned for such heights should
  note that the truncation now succeeds, resetting any tree whose scanned
  contents lie entirely above the truncation height to only the roots of
  subtrees completed at or below it.

### Fixed
- The coinbase branch of the transparent account-balance tally now classifies
  locked value into `Balance::locked_value`: previously a mature coinbase UTXO
  locked by an in-flight shielding proposal was still reported as spendable,
  even though note selection (correctly) refused to select it.
- The `zewif` importer no longer marks transparent addresses that have no
  recorded exposure height (`zewif::Address::exposed_at_height() == None`, e.g.
  zcashd keypool reserves) as exposed unconditionally. Previously every such
  address was marked exposed at the account birthday, which could exhaust the
  transparent gap limit (in particular the small internal/change gap) and
  permanently block change-address reservation after a zcashd migration. Such an
  address is now treated as exposed only if the wallet already considers it so
  (which, since the document's transactions are imported first, covers every
  address those transactions show to have been used on-chain, change addresses
  included), or if the document exposes an address at a higher child index under
  the same account and key scope, since transparent addresses are handed out in
  index order.
- `WalletWrite::rewind_to_chain_state` no longer reports `CorruptedData` for a
  shielded pool whose note commitment tree checkpoints do not cover the rewind
  target, provided the truncation leaves that pool's tree in a consistent
  state. On an upgraded wallet, the `orchard_shardtree` or `ironwood_shardtree`
  migration creates the pool's tree tables empty and requeues a rescan; until
  that rescan catches up, the pool's checkpoints may be absent entirely, may
  all lag the rewind target (a backfill in progress), or may all lie above it
  (a rescan that has so far only reached tip-priority blocks near the chain
  tip). All of these states are now tolerated: an empty or lagging tree is left
  untouched, while a tree whose checkpoints all postdate the target is reset to
  only the roots of subtrees completed at or below the target (preserving
  subtree roots downloaded during fast sync, which are required to construct
  witnesses spanning those subtrees), with the rescan re-creating the rest — in
  either case without destroying any note witness that the rescan would not
  re-create. This previously caused
  account creation and import (which rewind via this method) to fail
  deterministically on an upgraded, already-scanned wallet until its NU6.3
  rescan had caught up. A rewind that cannot be executed because it would
  destroy witness data that the rescan would not re-create is refused as
  `RequestedRewindInvalid` (it reflects valid wallet state, not corruption); a
  pool whose checkpoints lie both above and below the truncation height
  without one at it is still reported as corruption.
- Value in immature transparent coinbase outputs is now reported as pending
  spendability (in the `value_pending_spendability` field of the coinbase
  bucket) in wallet-summary account balances. Previously it was incorrectly
  counted as spendable before the coinbase output reached maturity, even
  though it could not be selected for shielding.

## [0.22.0-rc.1] - 2026-07-12

### Added
- `WalletDb` implements the new
  `WalletWrite::import_standalone_transparent_pubkeys` batch method (behind the
  `transparent-key-import` feature flag), resolving the target account a single
  time for the whole batch.
- `WalletDb` now implements the new
  `WalletWrite::reserve_next_n_internal_addresses` method (behind the
  `transparent-inputs` feature flag), reserving internal-scope (change)
  transparent addresses subject to the internal-scope gap limit. This is used
  to allocate recipient addresses for non-ephemeral transparent change
  outputs when a change strategy is configured with
  `zcash_client_backend::fees::TransparentChangePolicy::TransparentChangeAllowed`.
  No new migration is required: internal-scope gap addresses are already
  generated at account creation, and received transparent change outputs are
  recorded via the existing `Recipient::InternalTransparent` handling.
- A new migration adds a `note_version` column to `orchard_received_notes`,
  recording the note plaintext version from which each received note was
  obtained. The Orchard note encryption domain accepts only version 2 note
  plaintexts, so existing rows are backfilled as version 2.
- A new migration adds the `ironwood_received_notes` and
  `ironwood_received_note_spends` tables, mirroring the corresponding Orchard
  tables. Received notes obtained from version 3 (Ironwood) note plaintexts
  are recorded in `ironwood_received_notes`; Ironwood notes are stored
  separately from Orchard notes because the two pools have distinct note
  commitment trees, and because an Orchard action and an Ironwood action in
  the same transaction may share an action index.
- A new migration recreates the `v_received_outputs` and
  `v_received_output_spends` views to include received Ironwood notes and their
  spends, tagged with the Ironwood pool code (4). Ironwood notes now appear in
  `v_transactions`, `v_tx_outputs`, and the balances derived from them.
- The wallet database now persists Ironwood note commitment tree data. A new
  migration adds the `ironwood_tree_shards`, `ironwood_tree_cap`,
  `ironwood_tree_checkpoints`, and `ironwood_tree_checkpoint_marks_removed`
  tables (mirroring the Orchard shard-tree tables), the
  `ironwood_commitment_tree_size` and `ironwood_action_count` columns on
  `blocks`, and the `v_ironwood_shard_scan_ranges`,
  `v_ironwood_shard_unscanned_ranges`, and `v_ironwood_shards_scan_state` views.
  The `WalletCommitmentTrees::with_ironwood_tree_mut` implementation now provides
  the persisted Ironwood tree (Ironwood note commitments are Orchard-shaped, so
  the tree reuses the Orchard shard store under a separate table prefix).
- Block scan-range planning now extends suggested scan ranges to complete
  Ironwood note commitment tree subtrees when Ironwood notes are detected,
  mirroring the existing Sapling and Orchard behavior. The extension activates at
  NU6.3.
- A new database migration adds `sapling_tree_retained_checkpoints` and
  `orchard_tree_retained_checkpoints` tables that back explicit retention of
  note commitment tree checkpoints as durable "anchors". `SqliteShardStore`
  now implements the `shardtree` retained-checkpoint store methods, and once
  the NU6.3 activation height is reached scanning retains roughly four anchors
  per day (see the `zcash_client_backend` changelog).
- `zcash_client_sqlite::error::SqliteClientError::PutBlocksCommitmentTree`, a
  new variant that records the shielded pool and the range of block heights
  being added to the wallet when a note commitment tree error occurs during a
  `put_blocks` operation. Previously such errors (for example a `shardtree`
  `InsertionError::Conflict` raised by `insert_frontier`) surfaced as the
  generic `CommitmentTree` variant, which only reported the conflicting tree
  node address and not the affected pool or block range.
- `zcash_client_sqlite::error::SqliteClientError::TruncateCommitmentTree`, a
  new variant that records the shielded pool and the block height that the
  wallet was being truncated to when a note commitment tree error occurs
  during a truncation operation (`truncate_to_height` or
  `truncate_to_chain_state`). Previously such errors surfaced as the generic
  `CommitmentTree` variant without the affected pool or target height.
- The `InputSource::get_spendable_transparent_outputs` implementation now
  accepts `CoinbaseFilter::NonCoinbaseOnly`, restricting the SQL query to
  outputs that are not from coinbase transactions. Outputs with an unknown
  `tx_index` are treated as non-coinbase.
- Added an implementation of `InputSource::select_spendable_transparent_outputs`
  (behind the `transparent-inputs` feature flag). The query orders eligible
  outputs by descending value (backed by a new
  `idx_transparent_received_outputs_value_zat` index) and accumulates them,
  recomputing the cumulative ZIP 317 marginal fee cost of the gathered
  inputs via the supplied `fee_rule: &StandardFeeRule` at each step, stopping
  once the post-fee accumulated value meets the requested `TargetValue` or
  the supplied `max_inputs` cap is reached, whichever happens first. This
  bounds the work done to the prefix of the table needed to satisfy the
  request, so a wallet with many small transparent UTXOs does not have to
  materialize its full UTXO set to build a small transfer. When an
  `address_allow_list` is supplied, the restriction to the given addresses is
  applied within the SQL query, so that ineligible outputs do not consume
  the value bound.
- `zcash_client_sqlite::error::SqliteClientError::FeeRuleError`, a new variant
  (behind the `transparent-inputs` feature flag) that wraps an error produced
  by a `FeeRule` during transparent input selection.
- `WalletDb::generate_ironwood_witnesses_at_historical_height`, which mirrors
  the existing Orchard historical witness helper over the wallet's Ironwood
  commitment tree shard tables.
- A new `zewif` feature flag adds the `zcash_client_sqlite::zewif` module for
  importing wallets from the Zcash Wallet Interchange Format (ZeWIF).
  `zewif::import_wallet` ingests a ZeWIF document into an already-initialized
  `WalletDb` within a single transaction, delivering any encountered spending-key
  material to a caller-supplied `zewif::SecretSink` (use `zewif::DiscardSecrets`
  to drop it, e.g. for a view-only import) and returning a
  `zewif::ZewifImportReport` describing the imported and skipped items. Import
  failures are reported via `zewif::ZewifImportError`.
=======
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
>>>>>>> 75a187f2638827515d5d0a1c4894a28a57db6b8b

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
