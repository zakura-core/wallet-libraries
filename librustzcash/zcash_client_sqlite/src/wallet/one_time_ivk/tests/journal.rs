use std::cell::Cell;

use zcash_client_backend::data_api::{
    chain::{
        LinearScanGuarantee, TransparentHistory, TrialDecryptionPolicy, scan_cached_blocks,
        scan_cached_blocks_with_policy,
    },
    scanning::ScanPriority,
    wallet::ConfirmationsPolicy,
};

use super::{scanning::DuringScan, *};
use crate::wallet::one_time_ivk::restore::tests::discovery::{
    history, key8, one_time_notes, pay_candidate, publication_at, whole_at, work_of,
};

/// The journal's entries as `(height, tx_index, txid)`.
fn entries(st: &State) -> Vec<(u32, u16, Vec<u8>)> {
    rows(
        &st.wallet().db().conn,
        "SELECT block_height, tx_index, txid
         FROM ironwood_spend_journal ORDER BY block_height, tx_index",
        [],
    )
}

/// The nullifiers journaled for the transaction at `height`, in action order.
fn journaled_nullifiers(st: &State, height: BlockHeight) -> Vec<[u8; 32]> {
    column(
        &st.wallet().db().conn,
        "SELECT nf FROM ironwood_spend_journal_nullifiers
         WHERE block_height = ?1 ORDER BY tx_index, action_index",
        [u32::from(height)],
    )
}

/// The test account's covered ranges (see [`account_coverage`]).
fn coverage(st: &State) -> Vec<(u32, u32)> {
    account_coverage(st, st.test_account().unwrap().id())
}

/// The covered ranges of `account` as `(start, end)`, end exclusive.
fn account_coverage(st: &State, account: AccountUuid) -> Vec<(u32, u32)> {
    rows(
        &st.wallet().db().conn,
        "SELECT c.start_height, c.end_height FROM ironwood_journal_coverage c
         JOIN accounts a ON a.id = c.account_id
         WHERE a.uuid = ?1 ORDER BY c.start_height",
        [account.expose_uuid()],
    )
}

/// Mines a transaction that reveals a nullifier the wallet doesn't know and pays change
/// back to the test account, then returns its height and that nullifier. The wallet
/// recognizes it only by its change output.
fn spend_unknown_note(st: &mut State) -> (BlockHeight, [u8; 32]) {
    let stranger = IronwoodFvk(derive(st, KeyId::new(Purpose::Refund, 9_999)));
    let value = Zatoshis::const_from_u64(50_000);
    let (_, _, nf) = st.generate_next_block(&stranger, AddressType::DefaultExternal, value);
    let ordinary = IronwoodFvk(parent(st));
    let paid = Zatoshis::const_from_u64(20_000);
    let to = unified(foreign_receiver());
    let (height, _) = st.generate_next_block_spending(&ordinary, (nf, value), to, paid);
    (height, nf.to_bytes())
}

/// An account with no one-time state journals each transaction its plain scan
/// recognizes, with every Ironwood nullifier, including one it can't match to a note.
#[test]
fn a_recognized_transaction_is_journaled_with_every_nullifier() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    let (height, nf) = spend_unknown_note(&mut st);
    st.scan_cached_blocks(start, 2);

    let journaled = entries(&st);
    assert_eq!(journaled.len(), 1);
    assert_eq!(journaled[0].0, u32::from(height));
    assert_eq!(journaled_nullifiers(&st, height)[0], nf);
    assert_eq!(coverage(&st), [(u32::from(start), u32::from(height) + 1)]);
}

/// A transaction the wallet doesn't recognize isn't journaled, but its block is covered.
#[test]
fn unrelated_transactions_are_covered_but_not_journaled() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    let stranger = IronwoodFvk(derive(&st, KeyId::new(Purpose::Refund, 9_999)));
    let value = Zatoshis::const_from_u64(50_000);
    st.generate_next_block(&stranger, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(start, 1);
    assert!(entries(&st).is_empty());
    assert_eq!(coverage(&st), [(u32::from(start), u32::from(start) + 1)]);
}

/// A recognized transaction with no Ironwood nullifiers, such as a Sapling payment, can't
/// spend a one-time note, so it isn't journaled, but its block is covered.
#[test]
fn a_transaction_without_ironwood_nullifiers_is_covered_but_not_journaled() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    let sapling = st
        .test_account()
        .unwrap()
        .usk()
        .sapling()
        .to_diversifiable_full_viewing_key();
    let value = Zatoshis::const_from_u64(50_000);
    st.generate_next_block(&sapling, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(start, 1);
    let account = st.test_account().unwrap().id();
    assert_eq!(st.get_total_balance(account), value);
    assert!(entries(&st).is_empty());
    assert_eq!(coverage(&st), [(u32::from(start), u32::from(start) + 1)]);
}

/// Batches scanned out of order merge into one covered range once they meet, and a
/// block scanned twice keeps one entry.
#[test]
fn coverage_merges_and_rescans_replace_entries() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    let (height, _) = spend_unknown_note(&mut st);
    st.generate_empty_block();
    st.scan_cached_blocks(height + 1, 1);
    st.scan_cached_blocks(height, 1);
    let actions = journaled_nullifiers(&st, height).len();
    assert_eq!(coverage(&st), [(u32::from(height), u32::from(height) + 2)]);
    st.scan_cached_blocks(start, 2);
    assert_eq!(coverage(&st), [(u32::from(start), u32::from(height) + 2)]);
    assert_eq!(entries(&st).len(), 1);
    assert_eq!(journaled_nullifiers(&st, height).len(), actions);
}

/// A rewind removes the entries and coverage above its floor, and survives a reopen.
#[test]
fn a_rewind_removes_entries_and_coverage_above_its_floor() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    let (first, _) = spend_unknown_note(&mut st);
    let (second, _) = spend_unknown_note(&mut st);
    st.scan_cached_blocks(start, 4);
    assert_eq!(entries(&st).len(), 2);

    st.truncate_to_height(second - 1);
    reopen(&mut st);
    let kept = entries(&st);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].0, u32::from(first));
    assert!(journaled_nullifiers(&st, second).is_empty());
    assert_eq!(coverage(&st), [(u32::from(start), u32::from(second))]);
}

/// An account added after blocks were scanned isn't covered for them, and deleting an
/// account drops its coverage. (An account born below scanned blocks rewinds them, which
/// clears their coverage for every account.)
#[test]
fn coverage_is_per_account() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    st.generate_empty_block();
    st.scan_cached_blocks(start, 1);

    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    // Born after the scanned block, so adding it rewinds nothing.
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(prior, None);
    let (added, _) = st
        .wallet_mut()
        .db_mut()
        .create_account("added", &seed, &birthday, None)
        .unwrap();
    st.generate_empty_block();
    st.scan_cached_blocks(start + 1, 1);

    let next = u32::from(start) + 1;
    assert_eq!(account_coverage(&st, added), [(next, next + 1)]);
    assert_eq!(coverage(&st), [(u32::from(start), next + 1)]);

    st.wallet_mut().db_mut().delete_account(added).unwrap();
    let left: i64 = value(
        &st.wallet().db().conn,
        "SELECT COUNT(*) FROM ironwood_journal_coverage",
        [],
    );
    assert_eq!(left, 1);
}

/// Deleting an account drops the journal entries of the transactions only it took part
/// in, with their nullifiers, and keeps those another account shares.
#[test]
fn deleting_an_account_drops_its_exclusive_journal_entries() {
    let mut st = ironwood_wallet();
    let start = st.sapling_activation_height();
    st.generate_empty_block();
    st.scan_cached_blocks(start, 1);

    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_parts(prior, None);
    let (added, usk) = st
        .wallet_mut()
        .db_mut()
        .create_account("added", &seed, &birthday, None)
        .unwrap();
    // A payment only the added account receives, then its spend with change to the test
    // account, which both accounts take part in.
    let value = Zatoshis::const_from_u64(50_000);
    let receiver = IronwoodFvk(FullViewingKey::from(usk.orchard()));
    let (exclusive, _, nf) = st.generate_next_block(&receiver, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(exclusive, 1);
    let ordinary = IronwoodFvk(parent(&st));
    let to = unified(foreign_receiver());
    let paid = Zatoshis::const_from_u64(20_000);
    let (shared, _) = st.generate_next_block_spending(&ordinary, (nf, value), to, paid);
    st.scan_cached_blocks(shared, 1);
    let heights = |st: &State| entries(st).into_iter().map(|e| e.0).collect::<Vec<_>>();
    assert_eq!(heights(&st), [u32::from(exclusive), u32::from(shared)]);

    st.wallet_mut().db_mut().delete_account(added).unwrap();
    assert_eq!(heights(&st), [u32::from(shared)]);
    assert!(journaled_nullifiers(&st, exclusive).is_empty());
    assert!(!journaled_nullifiers(&st, shared).is_empty());
}

/// A late payment admitted while a batch that spends it is scanning, after the scanner
/// loaded the wallet's nullifiers, is marked spent when the batch is stored.
#[test]
fn a_note_admitted_during_a_batch_is_spent_by_it() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(&st, key8());
    let records = history(work.work.receiver, &[&candidate]);
    let page = whole_at(&st, publication, records, publication.end);
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let note = candidate
        .encrypted_note
        .decrypt(&parent(&st), key8())
        .unwrap();
    let spender = IronwoodFvk(parent(&st));
    let (height, _) = st.generate_next_block_spending(
        &spender,
        (*note.nullifier(), Zatoshis::const_from_u64(100_000)),
        unified(foreign_receiver()),
        Zatoshis::const_from_u64(20_000),
    );
    let network = *st.network();
    let path_to_db = st.wallet().data_file_path();
    let mut scanning_db =
        WalletDb::for_path(path_to_db, network, test_clock(), test_rng()).unwrap();
    let source = DuringScan {
        inner: st.cache(),
        at: 1,
        reads: Cell::new(0),
        run: || {
            let mut db = WalletDb::for_path(path_to_db, network, test_clock(), test_rng()).unwrap();
            assert!(
                db.record_one_time_lookup(account, &work, &page, clock_now())
                    .unwrap()
            );
        },
    };
    scan_cached_blocks(&network, &source, &mut scanning_db, height, &prior, 1).unwrap();
    assert_eq!(source.reads.get(), 2);
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
}

/// Under `ExternalWhenLinear`, a note admitted after `Nullifiers::unspent` whose spend lands in
/// the current batch is linked immediately so it never displays unspent, and `[hit, batch_end + 1)`
/// is queued for an all-scopes rescan that recovers chained internal change (`N -> C2 -> C3`).
#[test]
fn a_note_admitted_during_an_external_only_batch_is_spent_and_queued_for_rescan() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(&st, key8());
    let records = history(work.work.receiver, &[&candidate]);
    let page = whole_at(&st, publication, records, publication.end);
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let note = candidate
        .encrypted_note
        .decrypt(&parent(&st), key8())
        .unwrap();
    let spender = IronwoodFvk(parent(&st));
    let (h_spend, _, c2_nf) = st.generate_next_block_spending_to_internal(
        &spender,
        (*note.nullifier(), Zatoshis::const_from_u64(100_000)),
        &spender,
        Zatoshis::const_from_u64(80_000),
    );
    let (h_next, _, _) = st.generate_next_block_spending_to_internal(
        &spender,
        (c2_nf, Zatoshis::const_from_u64(80_000)),
        &spender,
        Zatoshis::const_from_u64(60_000),
    );

    let network = *st.network();
    let path_to_db = st.wallet().data_file_path();
    let mut scanning_db =
        WalletDb::for_path(path_to_db, network, test_clock(), test_rng()).unwrap();
    let source = DuringScan {
        inner: st.cache(),
        at: 1,
        reads: Cell::new(0),
        run: || {
            let mut db = WalletDb::for_path(path_to_db, network, test_clock(), test_rng()).unwrap();
            assert!(
                db.record_one_time_lookup(account, &work, &page, clock_now())
                    .unwrap()
            );
        },
    };
    let policy = TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(h_next),
    ));
    scan_cached_blocks_with_policy(
        &network,
        &source,
        &mut scanning_db,
        h_spend,
        &prior,
        2,
        policy,
    )
    .unwrap();
    assert_eq!(source.reads.get(), 2);

    // The guard linked the spend immediately so the admitted note never appears unspent.
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
    // Mode canary: the initial batch ran external-only Ironwood, so coverage stopped before
    // `h_spend` and the internal change chain (`C2`, `C3`) was not decrypted yet.
    assert!(
        coverage(&st)
            .iter()
            .all(|&(_, end)| end <= u32::from(h_spend))
    );
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);

    // The guard queued `[h_spend, h_next + 1)` as `Historic`.
    let queued = st.wallet().suggest_scan_ranges().unwrap();
    assert!(
        queued.iter().any(|r| {
            r.priority() == ScanPriority::Historic
                && r.block_range().start <= h_spend
                && r.block_range().end > h_next
        }),
        "expected Historic rescan covering {}..{}, got {queued:?}",
        h_spend,
        h_next + 1
    );

    // Scanning the queued range under the same policy vetoes external-only (Rule 2) and recovers
    // the full change chain `N -> C2 -> C3`.
    scanning_db.update_chain_tip(h_next).unwrap();
    scan_cached_blocks_with_policy(
        &network,
        st.cache(),
        &mut scanning_db,
        h_spend,
        &prior,
        2,
        policy,
    )
    .unwrap();
    assert_eq!(one_time_notes(&st), [(100_000, true)]);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(60_000)
    );
    assert!(
        coverage(&st)
            .iter()
            .any(|&(start, end)| start <= u32::from(h_spend) && end > u32::from(h_next))
    );
    // Mine one confirmation block past `h_next` so `C3` is also spendable at `MIN` confirmations.
    let h_confirm = st.generate_and_scan_empty_blocks(1);
    assert_eq!(
        st.get_spendable_balance(account, ConfirmationsPolicy::MIN),
        Zatoshis::const_from_u64(60_000)
    );
    assert_eq!(notes(&st, h_confirm).len(), 1);
}

/// A failure midway through the concurrent-admission guard rolls back the entire `put_blocks`
/// transaction atomically, leaving blocks, transaction metadata, spend links, and the scan queue
/// unchanged.
#[test]
fn concurrent_admission_guard_rolls_back_atomically_on_failure() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);
    let publication = publication_at(&st, tip(&st).height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(&st, key8());
    let records = history(work.work.receiver, &[&candidate]);
    let page = whole_at(&st, publication, records, publication.end);
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let note = candidate
        .encrypted_note
        .decrypt(&parent(&st), key8())
        .unwrap();
    let spender = IronwoodFvk(parent(&st));
    let (h_spend, _, _) = st.generate_next_block_spending_to_internal(
        &spender,
        (*note.nullifier(), Zatoshis::const_from_u64(100_000)),
        &spender,
        Zatoshis::const_from_u64(80_000),
    );

    let network = *st.network();
    let path_to_db = st.wallet().data_file_path();
    let mut scanning_db =
        WalletDb::for_path(path_to_db, network, test_clock(), test_rng()).unwrap();
    // Fail only when `queue_rescan` writes `ScanPriority::Historic` (20), after `put_blocks`,
    // `put_tx_meta_by_id`, and `mark_ironwood_note_spent` have all run in the same transaction.
    scanning_db
        .conn
        .execute_batch(
            "CREATE TEMP TRIGGER fail_historic_queue
             BEFORE INSERT ON scan_queue
             WHEN NEW.priority = 20
             BEGIN
                 SELECT RAISE(ABORT, 'injected scan_queue failure');
             END;",
        )
        .unwrap();

    let source = DuringScan {
        inner: st.cache(),
        at: 1,
        reads: Cell::new(0),
        run: || {
            let mut db = WalletDb::for_path(path_to_db, network, test_clock(), test_rng()).unwrap();
            assert!(
                db.record_one_time_lookup(account, &work, &page, clock_now())
                    .unwrap()
            );
        },
    };
    let policy = TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(h_spend),
    ));
    assert!(
        scan_cached_blocks_with_policy(
            &network,
            &source,
            &mut scanning_db,
            h_spend,
            &prior,
            1,
            policy,
        )
        .is_err()
    );

    // Nothing from the aborted batch committed: the block is absent, no spending tx exists at
    // `h_spend`, the admitted note remains unspent, and no Historic rescan was queued.
    let block_stored: bool = value(
        &st.wallet().db().conn,
        "SELECT EXISTS(SELECT 1 FROM blocks WHERE height = ?1)",
        [u32::from(h_spend)],
    );
    assert!(!block_stored);
    let tx_stored: bool = value(
        &st.wallet().db().conn,
        "SELECT EXISTS(SELECT 1 FROM transactions WHERE mined_height = ?1)",
        [u32::from(h_spend)],
    );
    assert!(!tx_stored);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .all(|r| r.priority() != ScanPriority::Historic)
    );
}

/// On a live-synced wallet scanning under `ExternalWhenLinear`, a one-time payment discovered by
/// PIR past external-only blocks hits `Uncovered` and queues a single rescan; scanning that range
/// under the same policy vetoes external-only via Rule 2, writes coverage, and admits the payment
/// with no remaining rescans.
#[test]
fn live_external_only_one_time_payment_admits_after_single_rule2_rescan() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    recover(st.wallet_mut().db_mut(), account, key8(), candidate.height);

    // Advance live sync past the payment under `ExternalWhenLinear` (external-only Ironwood).
    let (h_after, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(h_after).unwrap();
    let policy = TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(h_after),
    ));
    st.scan_cached_blocks_with_policy(h_after, 1, policy);

    // Mode canary: external-only left `h_after` uncovered in the Ironwood journal.
    assert!(
        coverage(&st)
            .iter()
            .all(|&(_, end)| end <= u32::from(h_after))
    );

    // PIR returns the payment at tip `h_after`: admission defers (`Uncovered`) and queues a
    // `Historic` rescan covering `h_after`.
    let publication = publication_at(&st, h_after);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, false)
            .unwrap()
    );
    let work = work_of(&st, key8());
    let records = history(work.work.receiver, &[&candidate]);
    let page = whole_at(&st, publication, records, publication.end);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &work, &page, clock_now())
            .unwrap()
    );
    assert!(one_time_notes(&st).is_empty());
    let rescan = st
        .wallet()
        .suggest_scan_ranges()
        .unwrap()
        .into_iter()
        .find(|r| r.priority() == ScanPriority::Historic)
        .expect("uncovered one-time payment should queue a Historic rescan");
    assert!(rescan.block_range().contains(&h_after));

    // Scanning the queued range under the same `ExternalWhenLinear` policy vetoes external-only
    // (Rule 2), writes coverage, admits the payment, and clears the rescan queue in one pass.
    let range = rescan.block_range();
    let len = usize::try_from(u32::from(range.end) - u32::from(range.start)).unwrap();
    st.scan_cached_blocks_with_policy(range.start, len, policy);

    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    assert_eq!(
        st.get_total_balance(account),
        Zatoshis::const_from_u64(100_000)
    );
    assert!(
        coverage(&st)
            .iter()
            .any(|&(start, end)| start <= u32::from(candidate.height) && end > u32::from(h_after))
    );
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .all(|r| r.priority() != ScanPriority::Historic)
    );
}
