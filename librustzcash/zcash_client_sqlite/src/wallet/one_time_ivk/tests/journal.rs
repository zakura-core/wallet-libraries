use std::cell::Cell;

use zcash_client_backend::data_api::chain::scan_cached_blocks;

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
