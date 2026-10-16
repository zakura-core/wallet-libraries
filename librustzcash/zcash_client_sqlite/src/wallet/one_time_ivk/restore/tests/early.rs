use super::apply::witness_at;
use super::*;
use std::num::NonZeroU32;

use zcash_client_backend::data_api::{
    AccountBirthday,
    one_time_ivk::restore::{EarlyRestoreKey, PublicationEnd},
    wallet::ConfirmationsPolicy,
};

/// Receive key `index`.
fn receive(index: u64) -> KeyId {
    KeyId::new(Purpose::Receive, index)
}

/// What the filters say about receive keys 0 to 8, of which `paid` is paid.
fn filtered(paid: u64) -> Vec<EarlyRestoreKey> {
    (0..=8)
        .map(|index| EarlyRestoreKey {
            key: receive(index),
            seen: false,
            paid: index == paid,
            recent: false,
        })
        .collect()
}

/// The publication end at cached block `height`, as its manifest declares it.
fn end_at(st: &State, height: BlockHeight) -> PublicationEnd {
    let sql = "SELECT data FROM compactblocks WHERE height = ?1";
    let data: Vec<u8> = value(&st.cache().0, sql, [u32::from(height)]);
    let block = CompactBlock::decode(data.as_slice()).unwrap();
    PublicationEnd {
        height,
        hash: block.hash().0,
        tree_size: block
            .chain_metadata
            .unwrap()
            .ironwood_commitment_tree_size
            .into(),
    }
}

/// Retains spend history in a new [`ironwood_wallet`], then mines a block paying receive
/// key 8 and two empty blocks, scanning none of them but knowing the last as the chain
/// tip. Returns the wallet, the payment as
/// a candidate, and the first and last heights.
fn unscanned_restore() -> (State, PendingPayment, BlockHeight, BlockHeight) {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let fvk = derive(&st, receive(8));
    let recipient = IronwoodFvk(fvk.clone());
    let value = Zatoshis::const_from_u64(100_000);
    let (paid, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    st.generate_empty_block();
    let (last, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(last).unwrap();
    let candidate = candidate_at(&st, paid, &fvk);
    (st, candidate, paid, last)
}

/// Begins `account`'s early restore at cached block `last` with [`filtered`] keys, receive
/// key 8 paid.
fn begin(st: &mut State, account: AccountUuid, last: BlockHeight) {
    let end = end_at(st, last);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_early_restore(account, end, &filtered(8))
            .unwrap()
    );
}

/// The sibling hashes of the Ironwood leaf at `position` at the cached tip, as a
/// publication ending there serves them.
fn siblings(st: &State, position: u32) -> [[u8; 32]; 32] {
    witness_at(st, position)
        .auth_path()
        .map(|hash| hash.to_bytes())
}

/// Records the early lookup of `account`'s receive key 8 finding `candidate`, with its
/// witness at the cached tip if `witness`.
fn lookup(st: &mut State, account: AccountUuid, candidate: &PendingPayment, witness: bool) {
    let siblings = witness.then(|| siblings(st, candidate.position));
    let answer = [directory_answer(candidate)];
    let db = st.wallet_mut().db_mut();
    db.record_one_time_early_lookup(account, receive(8), &answer, |_, _| siblings)
        .unwrap();
}

/// `account`'s early restore state.
fn state_of(st: &State, account: AccountUuid) -> u8 {
    let sql = "SELECT r.state FROM ironwood_one_time_restores r
               JOIN accounts a ON a.id = r.account_id WHERE a.uuid = ?1";
    value(st.wallet().conn(), sql, [account.0])
}

/// Whether `account` still has restore sweeps or queued payments through `through`.
fn history_pending(st: &State, account: AccountUuid, through: BlockHeight) -> bool {
    let db = st.wallet().db();
    db.one_time_history_pending(account, through).unwrap()
}

/// How many receive keys wait for an ordinary restore sweep.
fn receive_sweeps(st: &State) -> u32 {
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_keys k
               JOIN ironwood_one_time_sweeps s ON s.one_time_key_id = k.id
               WHERE k.purpose = 1 AND s.done_height IS NULL AND s.provisional = 0";
    value(st.wallet().conn(), sql, [])
}

/// Key `key`'s sweep row: its finished height and whether it is provisional.
fn sweep_row(st: &State, key: KeyId) -> (Option<u32>, bool) {
    let sql = "SELECT s.done_height, s.provisional FROM ironwood_one_time_sweeps s
               JOIN ironwood_one_time_keys k ON k.id = s.one_time_key_id
               WHERE k.purpose = ?1 AND k.key_index = ?2";
    let purpose = u8::from(key.purpose() == Purpose::Receive);
    row(
        st.wallet().conn(),
        sql,
        rusqlite::params![purpose, key.index().to_be_bytes()],
    )
}

/// Whether key `key` is closed.
fn closed(st: &State, key: KeyId) -> bool {
    let sql = "SELECT closed_at IS NOT NULL FROM ironwood_one_time_keys
               WHERE purpose = 1 AND key_index = ?1";
    value(st.wallet().conn(), sql, [key.index().to_be_bytes()])
}

/// The queued early payments: their heights and whether each is a scan hint.
fn queued(st: &State) -> Vec<(u32, bool)> {
    let sql = "SELECT height, scan_hint FROM ironwood_one_time_payment_recovery ORDER BY height";
    rows(st.wallet().conn(), sql, [])
}

/// Keys the scanner tries on a batch covering `range`.
fn keys_for(st: &State, range: std::ops::Range<BlockHeight>) -> Vec<KeyId> {
    let keys = st
        .wallet()
        .get_one_time_scanning_keys_for_range(range)
        .unwrap();
    keys.iter().map(|k| k.key_id()).collect()
}

/// A payment in a block the scan has yet to reach is a scan hint: only that batch tries
/// its key, the scan finds the note there, and the key's restore finishes at the anchor
/// and closes once the scan accepts the publication.
#[test]
fn a_hinted_payment_is_found_by_the_scan_and_settles_its_key() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    let db = st.wallet().db();
    assert_eq!(
        db.one_time_early_restore_start(account).unwrap(),
        Some(paid)
    );
    begin(&mut st, account, last);
    lookup(&mut st, account, &candidate, false);
    assert_eq!(queued(&st), [(u32::from(paid), true)]);
    // Only the batch holding the payment tries the key.
    assert_eq!(keys_for(&st, paid..paid + 1), [receive(8)]);
    assert!(keys_for(&st, paid + 1..last + 1).is_empty());
    assert!(scanning_keys(&st).is_empty());

    st.scan_cached_blocks_with_one_time_ivks(paid, 1);
    assert_eq!(unspent_keys(&st, paid), [Some(receive(8))]);
    assert!(queued(&st).is_empty());
    // Done at the anchor, but provisional until the scan stores it.
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), true));
    assert!(!closed(&st, receive(8)));

    st.scan_cached_blocks_with_one_time_ivks(paid + 1, 2);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(closed(&st, receive(8)) && closed(&st, receive(0)));
    assert_eq!(unspent_keys(&st, last), [Some(receive(8))]);
    let db = st.wallet().db();
    assert_eq!(db.one_time_early_restore_start(account).unwrap(), None);
    assert!(!history_pending(&st, account, last));
}

/// A payment in a block the scan already passed is queued with its witness and inserted
/// once the publication is accepted and every block from the payment on carries spend
/// evidence.
#[test]
fn a_payment_in_a_scanned_block_is_inserted_with_its_witness() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    // The scan passes the payment before its lookup comes in.
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert!(unspent_keys(&st, last).is_empty());
    assert_eq!(state_of(&st, account), 1);

    lookup(&mut st, account, &candidate, true);
    assert_eq!(unspent_keys(&st, last), [Some(receive(8))]);
    assert!(queued(&st).is_empty());
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(closed(&st, receive(8)));
}

/// A hint at the wrong block finds nothing there, so the key falls back to a restore
/// sweep, which finds the payment once the scan is done.
#[test]
fn a_hint_that_finds_nothing_falls_back_to_a_sweep() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    let end = end_at(&st, last);
    let mut misplaced = directory_answer(&candidate);
    misplaced.height = u32::from(last);
    misplaced.block_hash = end.hash;
    begin(&mut st, account, last);
    let db = st.wallet_mut().db_mut();
    db.record_one_time_early_lookup(account, receive(8), &[misplaced], |_, _| None)
        .unwrap();
    for height in [paid, paid + 1, last] {
        st.scan_cached_blocks_with_one_time_ivks(height, 1);
    }
    assert!(unspent_keys(&st, last).is_empty());
    assert!(queued(&st).is_empty());
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    assert!(history_pending(&st, account, last));
}

/// A publication whose last block differs from the wallet's is rejected: keys it
/// registered without a payment go, the rest fall back to restore sweeps, and the
/// incoming lookahead restarts from index zero. A late lookup of a key it deleted does
/// nothing.
#[test]
fn a_mismatched_publication_falls_back_to_sweeps() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    let mut end = end_at(&st, last);
    end.tree_size += 1;
    let beyond = receive(RECEIVE_GAP_LIMIT + 1);
    let (seen, paid_beyond) = (
        receive(RECEIVE_GAP_LIMIT + 2),
        receive(RECEIVE_GAP_LIMIT + 3),
    );
    let mut keys = filtered(8);
    keys.extend([
        EarlyRestoreKey {
            key: beyond,
            ..keys[0]
        },
        EarlyRestoreKey {
            key: seen,
            seen: true,
            ..keys[0]
        },
        EarlyRestoreKey {
            key: paid_beyond,
            ..keys[8]
        },
    ]);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_early_restore(account, end, &keys)
            .unwrap()
    );
    lookup(&mut st, account, &candidate, false);
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 2);
    // The hint found the note before the anchor was judged, so its key stays.
    assert_eq!(unspent_keys(&st, last), [Some(receive(8))]);
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    // Keys the filters marked seen or paid stay and are swept, even past the gap.
    assert_eq!(sweep_row(&st, seen), (None, false));
    assert_eq!(sweep_row(&st, paid_beyond), (None, false));
    assert_eq!(receive_sweeps(&st), RECEIVE_GAP_LIMIT as u32 + 2);
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.one_time_early_restore_start(account).unwrap(), None);
    db.record_one_time_early_lookup(account, beyond, &[], |_, _| None)
        .unwrap();
}

/// A hint is satisfied only by its own note: a directory that pairs one payment's
/// ciphertext with another payment's position to the same key gets a scan that finds the
/// other payment there, and the key falls back to a sweep instead of closing.
#[test]
fn a_hint_at_another_payments_position_falls_back_to_a_sweep() {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let fvk = derive(&st, receive(8));
    let recipient = IronwoodFvk(fvk.clone());
    let value = Zatoshis::const_from_u64(100_000);
    let (first, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    let (second, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    let (last, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(last).unwrap();
    let (genuine, other) = (
        candidate_at(&st, first, &fvk),
        candidate_at(&st, second, &fvk),
    );
    let mut misplaced = directory_answer(&genuine);
    misplaced.height = u32::from(other.height);
    misplaced.block_hash = other.block_hash.0;
    misplaced.tx_index = other.tx_index.into();
    misplaced.position = other.position.into();
    begin(&mut st, account, last);
    let db = st.wallet_mut().db_mut();
    db.record_one_time_early_lookup(account, receive(8), &[misplaced], |_, _| None)
        .unwrap();
    assert_eq!(queued(&st), [(u32::from(second), true)]);

    st.scan_cached_blocks_with_one_time_ivks(first, 3);
    assert!(queued(&st).is_empty());
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    assert!(!closed(&st, receive(8)));
    let db = st.wallet().db();
    assert!(db.one_time_history_pending(account, last).unwrap());
}

/// An early restore needs a restored account none of whose history is scanned, with an
/// anchor at or above its restore start.
#[test]
fn an_early_restore_needs_unscanned_history() {
    let (mut st, _, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    let end = end_at(&st, last);
    let below = PublicationEnd {
        height: paid - 1,
        ..end
    };
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.begin_one_time_early_restore(account, below, &[])
            .unwrap()
    );
    assert_eq!(
        db.one_time_early_restore_start(account).unwrap(),
        Some(paid)
    );
    st.scan_cached_blocks_with_one_time_ivks(paid, 1);
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.one_time_early_restore_start(account).unwrap(), None);
    assert!(!db.begin_one_time_early_restore(account, end, &[]).unwrap());

    let mut fresh = ironwood_wallet();
    let account = fresh.test_account().unwrap().id();
    let db = fresh.wallet_mut().db_mut();
    db.mark_one_time_account_fresh(account).unwrap();
    assert_eq!(db.one_time_early_restore_start(account).unwrap(), None);
}

/// An anchor the scan might never store is refused without writing anything: one above
/// the wallet's chain tip, or any while no tip is known.
#[test]
fn an_anchor_above_the_chain_tip_is_refused() {
    let (mut st, _, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    let above = PublicationEnd {
        height: last + 1,
        ..end_at(&st, last)
    };
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.begin_one_time_early_restore(account, above, &filtered(8))
            .unwrap()
    );
    assert_eq!(
        db.one_time_early_restore_start(account).unwrap(),
        Some(paid)
    );
    let sql = "SELECT (SELECT COUNT(*) FROM ironwood_one_time_restores)
                    + (SELECT COUNT(*) FROM ironwood_one_time_keys)";
    assert_eq!(value::<u32>(st.wallet().conn(), sql, []), 0);

    let mut untipped = ironwood_wallet();
    let account = untipped.test_account().unwrap().id();
    let (height, _) = untipped.generate_empty_block();
    let end = end_at(&untipped, height);
    let db = untipped.wallet_mut().db_mut();
    assert!(
        !db.begin_one_time_early_restore(account, end, &filtered(8))
            .unwrap()
    );
    assert_eq!(
        db.one_time_early_restore_start(account).unwrap(),
        Some(height)
    );
}

/// A recent key scans from the block after the anchor, never the history before it, and
/// is not closed when the publication is accepted.
#[test]
fn a_recent_key_scans_only_after_the_anchor() {
    let (mut st, _, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    let end = end_at(&st, last);
    let mut keys = filtered(u64::MAX);
    keys[2].recent = true;
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_early_restore(account, end, &keys)
            .unwrap()
    );
    assert!(keys_for(&st, paid..last + 1).is_empty());
    assert_eq!(keys_for(&st, paid..last + 2), [receive(2)]);
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 1);
    assert!(!closed(&st, receive(2)) && closed(&st, receive(3)));
}

/// A hint whose batch the scanner stored without trying its key, because the lookup came
/// in after the scanner took its keys, becomes a payment to insert rather than a miss.
#[test]
fn a_late_hint_becomes_a_payment_to_insert() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    lookup(&mut st, account, &candidate, true);
    assert_eq!(queued(&st), [(u32::from(paid), true)]);
    // The batch's key snapshot predates the lookup: the hint is out of the scanner's sight
    // while the batch scans, and the store then sees it with that empty snapshot.
    let moved = "UPDATE ironwood_one_time_payment_recovery SET height = height + ?1";
    exec(st.wallet().conn(), moved, [1000]);
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    exec(st.wallet().conn(), moved, [-1000]);
    let db = st.wallet_mut().db_mut();
    db.transactionally(|db| {
        store::restore::early::after_blocks_stored(
            db.conn.0,
            db.params,
            db.transparent_ledger_mode,
            &db.enhance_pir_session,
            &db.transparent_pir_session,
            &[],
            paid..last + 1,
        )
    })
    .unwrap();
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(unspent_keys(&st, last), [Some(receive(8))]);
    assert!(queued(&st).is_empty());
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
}

/// While an early restore waits for the scan, blocks scanned without one-time keys are
/// refused, since storing them would skip judging its publication and trying its hints.
#[test]
fn an_early_restore_refuses_scans_without_one_time_keys() {
    let (mut st, _, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    assert!(matches!(
        st.try_scan_cached_blocks(paid, 1),
        Err(zcash_client_backend::data_api::chain::error::Error::Wallet(
            SqliteClientError::OneTimeIvksNotUsed
        ))
    ));
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 1);
}

/// A rewind below an accepted publication's anchor makes it provisional again, so a paid
/// key whose lookup arrives afterwards, here empty, finishes only when the rescan judges
/// the anchor again, and closes then instead of against the removed block.
#[test]
fn a_rewind_below_an_accepted_anchor_judges_it_again() {
    let (mut st, _, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(sweep_row(&st, receive(8)), (None, true));

    st.truncate_to_height_retaining_cache(paid);
    assert_eq!(state_of(&st, account), 0);
    let db = st.wallet_mut().db_mut();
    db.record_one_time_early_lookup(account, receive(8), &[], |_, _| None)
        .unwrap();
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), true));
    assert!(!closed(&st, receive(8)));

    st.scan_cached_blocks_with_one_time_ivks(paid + 1, 2);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(closed(&st, receive(8)));
}

/// Adds the test seed's second account at `birthday`, which rewinds the wallet to the
/// block before it.
fn add_account(st: &mut State, birthday: &AccountBirthday) -> AccountUuid {
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let db = st.wallet_mut().db_mut();
    db.create_account("added", &seed, birthday, None).unwrap().0
}

/// [`add_account`] with the test account's birthday.
fn add_account_at_birthday(st: &mut State) -> AccountUuid {
    let birthday = st.test_account().unwrap().birthday().clone();
    add_account(st, &birthday)
}

/// Key `key` of the test seed's second account, which [`add_account`] adds.
fn second_key(st: &State, key: KeyId) -> FullViewingKey {
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        st.network(),
        st.test_seed().unwrap().expose_secret(),
        zip32::AccountId::try_from(1).unwrap(),
    )
    .unwrap();
    key.derive(&FullViewingKey::from(usk.orchard())).unwrap()
}

/// Adding an account while another account's early restore waits for its anchor keeps
/// that restore: a payment queued for insertion becomes a hint again, keys done at the
/// anchor stay done, and the rescan finds the payment and accepts the publication.
#[test]
fn adding_an_account_keeps_an_early_restore_in_progress() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    // The scan passes the payment before its lookup comes in, short of the anchor.
    st.scan_cached_blocks_with_one_time_ivks(paid, 2);
    lookup(&mut st, account, &candidate, true);
    assert_eq!(queued(&st), [(u32::from(paid), false)]);

    add_account_at_birthday(&mut st);
    assert_eq!(state_of(&st, account), 0);
    assert_eq!(queued(&st), [(u32::from(paid), true)]);
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), true));
    assert_eq!(keys_for(&st, paid..paid + 1), [receive(8)]);

    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(unspent_keys(&st, last), [Some(receive(8))]);
    assert!(queued(&st).is_empty());
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(closed(&st, receive(8)) && closed(&st, receive(0)));
    assert!(!history_pending(&st, account, last));
}

/// A key whose hint already found its note, closed without scanning, would not find it
/// again after a rewind un-mines it, so that key alone falls back to a restore sweep.
#[test]
fn a_rewind_hands_a_found_payment_to_a_sweep() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    lookup(&mut st, account, &candidate, false);
    st.scan_cached_blocks_with_one_time_ivks(paid, 1);
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), true));

    add_account_at_birthday(&mut st);
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), true));
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 1);
    assert!(closed(&st, receive(0)));
    assert!(history_pending(&st, account, last));
}

/// An account added to a wallet that already scanned its history restores early too.
/// Adding it requeues every block from its birthday, so a block the wallet keeps a row
/// for still counts as unscanned for it, and its payment there is found by a hint.
#[test]
fn an_added_account_restores_early_over_requeued_history() {
    let mut st = ironwood_wallet();
    let first = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), first);
    let fvk = second_key(&st, receive(8));
    let amount = Zatoshis::const_from_u64(100_000);
    let recipient = IronwoodFvk(fvk.clone());
    let (paid, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, amount);
    // Enough later blocks that adding the account keeps the payment's block row.
    let mut last = paid;
    for _ in 0..crate::PRUNING_DEPTH + 10 {
        last = st.generate_empty_block().0;
    }
    let blocks = (u32::from(last) - u32::from(paid) + 1) as usize;
    st.scan_cached_blocks_with_one_time_ivks(paid, blocks);
    let candidate = candidate_at(&st, paid, &fvk);
    let added = add_account_at_birthday(&mut st);
    let sql = "SELECT EXISTS(SELECT 1 FROM blocks WHERE height = ?1)";
    assert!(value::<bool>(st.wallet().conn(), sql, [u32::from(paid)]));

    let db = st.wallet_mut().db_mut();
    retain(db, added);
    assert_eq!(db.one_time_early_restore_start(added).unwrap(), Some(paid));
    begin(&mut st, added, last);
    lookup(&mut st, added, &candidate, false);
    assert_eq!(queued(&st), [(u32::from(paid), true)]);
    st.scan_cached_blocks_with_one_time_ivks(paid, blocks);
    assert_eq!(state_of(&st, added), 1);
    assert_eq!(one_time_notes(&st, added), (1, 1));
    assert!(queued(&st).is_empty());
}

/// Unscanned blocks for two accounts' early restores: a block paying a foreign key, which
/// gives the wallet a checkpoint to truncate to, a block paying the test account's
/// receive key 8, one paying the second account's (see [`second_key`]), and two empty
/// blocks. The test account retains its spend history.
struct Grid {
    st: State,
    /// The test account's payment, then the second account's.
    paid: [PendingPayment; 2],
    first: BlockHeight,
    last: BlockHeight,
    /// The birthday at the second account's payment.
    late_birthday: AccountBirthday,
}

/// Mines the [`Grid`] blocks.
fn grid() -> Grid {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let value = Zatoshis::const_from_u64(100_000);
    let key = orchard::keys::SpendingKey::from_bytes([0xf5; 32]).unwrap();
    let foreign = IronwoodFvk(FullViewingKey::from(&key));
    let (first, _, _) = st.generate_next_block(&foreign, AddressType::DefaultExternal, value);
    let ours = derive(&st, receive(8));
    let recipient = IronwoodFvk(ours.clone());
    let (h1, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    let prior = st.latest_cached_block().unwrap().chain_state().clone();
    let late_birthday = AccountBirthday::from_parts(prior, None);
    let theirs = second_key(&st, receive(8));
    let recipient = IronwoodFvk(theirs.clone());
    let (h2, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    st.generate_empty_block();
    let (last, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(last).unwrap();
    let paid = [candidate_at(&st, h1, &ours), candidate_at(&st, h2, &theirs)];
    Grid {
        st,
        paid,
        first,
        last,
        late_birthday,
    }
}

/// How many one-time-key notes `account` holds, and how many of those are mined.
fn one_time_notes(st: &State, account: AccountUuid) -> (u32, u32) {
    let sql = "SELECT COUNT(*), COUNT(t.mined_height) FROM ironwood_received_notes n
               JOIN accounts a ON a.id = n.account_id
               JOIN transactions t ON t.id_tx = n.transaction_id
               WHERE a.uuid = ?1 AND n.one_time_key_id IS NOT NULL";
    row(st.wallet().conn(), sql, [account.0])
}

/// Keys that neither scan, wait for a sweep, nor are closed, so nothing would ever find
/// a later payment to them.
fn stranded(st: &State) -> u32 {
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_keys k
               WHERE k.closed_at IS NULL AND k.active_from IS NULL
                 AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_sweeps s
                     WHERE s.one_time_key_id = k.id AND s.done_height IS NULL)";
    value(st.wallet().conn(), sql, [])
}

/// Runs each of `account`'s due restore sweeps once at the wallet's tip, the directory
/// answering receive key 8 with `paid` and every other key with nothing, and expects
/// each to finish.
fn sweep_all(st: &mut State, account: AccountUuid, paid: &PendingPayment) {
    let through = tip(st);
    let siblings = siblings(st, paid.position);
    let answer = [directory_answer(paid)];
    let (now, limit) = (clock_now(), NonZeroU32::new(256).unwrap());
    let db = st.wallet_mut().db_mut();
    let work = db.prepare_one_time_sweeps(account, through, now, limit);
    for item in work.unwrap().unwrap() {
        let answer: &[DirectoryPayment] = if item.key == receive(8) { &answer } else { &[] };
        db.begin_one_time_sweep_attempt(account, item.key, now, false)
            .unwrap();
        let queued = db.queue_directory_lookup(account, item.key, through, answer);
        assert_eq!(queued.unwrap(), Ok(()));
        let applied =
            db.apply_one_time_sweep(account, item.key, through, through, false, |_, _| {
                Some(siblings)
            });
        assert_eq!(applied.unwrap(), Ok(PaymentApplication::Applied));
    }
}

/// An account added below a provisional early restore's queued hint rewinds that
/// restore's history but keeps it, and the added account restores early beside it: one
/// scan finds both payments by their hints and accepts both publications.
#[test]
fn an_account_added_below_a_provisional_restore_restores_early_beside_it() {
    let Grid {
        mut st,
        paid,
        first,
        last,
        ..
    } = grid();
    let ours = st.test_account().unwrap().id();
    begin(&mut st, ours, last);
    lookup(&mut st, ours, &paid[0], false);
    st.scan_cached_blocks_with_one_time_ivks(first, 1);
    assert_eq!(queued(&st), [(u32::from(paid[0].height), true)]);

    let theirs = add_account_at_birthday(&mut st);
    assert_eq!(state_of(&st, ours), 0);
    assert_eq!(queued(&st), [(u32::from(paid[0].height), true)]);
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), true));
    retain(st.wallet_mut().db_mut(), theirs);
    let db = st.wallet().db();
    assert_eq!(
        db.one_time_early_restore_start(theirs).unwrap(),
        Some(first)
    );
    begin(&mut st, theirs, last);
    lookup(&mut st, theirs, &paid[1], false);

    st.scan_cached_blocks_with_one_time_ivks(first, 5);
    for account in [ours, theirs] {
        assert_eq!(state_of(&st, account), 1);
        assert_eq!(one_time_notes(&st, account), (1, 1));
        assert!(!history_pending(&st, account, last));
    }
    assert!(queued(&st).is_empty());
    assert_eq!(stranded(&st), 0);
}

/// An account added below an accepted early restore's history rewinds the same chain, so
/// the restore's sweeps stay finished and nothing is looked up again. The paid key, which
/// the restore closed, scans from its payment so the rescan finds that note again, while
/// the added account restores early. Each payment is credited once and stays spendable.
#[test]
fn an_account_added_below_an_accepted_restore_keeps_its_sweeps() {
    let Grid {
        mut st,
        paid,
        first,
        last,
        ..
    } = grid();
    let ours = st.test_account().unwrap().id();
    begin(&mut st, ours, last);
    lookup(&mut st, ours, &paid[0], false);
    st.scan_cached_blocks_with_one_time_ivks(first, 5);
    assert_eq!(state_of(&st, ours), 1);
    assert_eq!(one_time_notes(&st, ours), (1, 1));
    assert!(!history_pending(&st, ours, last));
    assert!(closed(&st, receive(8)));

    let theirs = add_account_at_birthday(&mut st);
    // The rewind removed the anchor, so the rescan judges the publication again.
    assert_eq!(state_of(&st, ours), 0);
    assert_eq!(one_time_notes(&st, ours), (1, 0));
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), false));
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(!closed(&st, receive(8)) && closed(&st, receive(0)));
    assert!(!history_pending(&st, ours, last));
    retain(st.wallet_mut().db_mut(), theirs);
    begin(&mut st, theirs, last);
    lookup(&mut st, theirs, &paid[1], false);

    st.scan_cached_blocks_with_one_time_ivks(first, 5);
    for account in [ours, theirs] {
        assert_eq!(state_of(&st, account), 1);
        assert_eq!(one_time_notes(&st, account), (1, 1));
        assert!(!history_pending(&st, account, last));
    }
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let due = db.prepare_one_time_sweeps(ours, through, clock_now(), NonZeroU32::new(256).unwrap());
    assert!(due.unwrap().unwrap().is_empty());
    assert!(queued(&st).is_empty());
    assert_eq!(stranded(&st), 0);
    // The re-found note is spendable: its leaf is marked again.
    for _ in 0..10 {
        st.generate_empty_block();
    }
    st.scan_cached_blocks_with_one_time_ivks(last + 1, 10);
    // It closes again once its receipt is confirmed and its restore watch has passed.
    let tip = tip(&st).height;
    let later = clock_now() + 2 * zakura_one_time_ivk::swap::RESTORE_WATCH_SECS;
    let db = st.wallet_mut().db_mut();
    let sql = "UPDATE blocks SET time = ?2 WHERE height = ?1";
    exec(&db.conn, sql, rusqlite::params![u32::from(tip), later]);
    db.close_finished_one_time_keys(ours, later, tip).unwrap();
    assert!(closed(&st, receive(8)));
    spend_to_foreign(&mut st, 50_000);
}

/// An account added with a birthday above everything an early restore has scanned
/// rewinds none of that history: the payment its hint already found stays settled, and
/// the added account restores early from its birthday in the same scan.
#[test]
fn an_account_added_above_a_restore_leaves_its_history_alone() {
    let Grid {
        mut st,
        paid,
        first,
        last,
        late_birthday,
    } = grid();
    let ours = st.test_account().unwrap().id();
    begin(&mut st, ours, last);
    lookup(&mut st, ours, &paid[0], false);
    st.scan_cached_blocks_with_one_time_ivks(first, 2);
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), true));

    let theirs = add_account(&mut st, &late_birthday);
    assert_eq!(state_of(&st, ours), 0);
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), true));
    assert_eq!(one_time_notes(&st, ours), (1, 1));
    retain(st.wallet_mut().db_mut(), theirs);
    let db = st.wallet().db();
    let start = db.one_time_early_restore_start(theirs).unwrap();
    assert_eq!(start, Some(paid[1].height));
    begin(&mut st, theirs, last);
    lookup(&mut st, theirs, &paid[1], false);

    st.scan_cached_blocks_with_one_time_ivks(paid[1].height, 3);
    for account in [ours, theirs] {
        assert_eq!(state_of(&st, account), 1);
        assert_eq!(one_time_notes(&st, account), (1, 1));
        assert!(!history_pending(&st, account, last));
    }
    assert!(queued(&st).is_empty());
    assert_eq!(stranded(&st), 0);
}

/// Mines, without scanning, a block paying receive key 8, a block spending that note to a
/// foreign receiver, and two empty blocks, retaining spend history. Returns the wallet,
/// the payment as a candidate, its nullifier, and the first and last heights.
fn spent_restore() -> (
    State,
    PendingPayment,
    orchard::note::Nullifier,
    BlockHeight,
    BlockHeight,
) {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let fvk = derive(&st, receive(8));
    let recipient = IronwoodFvk(fvk.clone());
    let value = Zatoshis::const_from_u64(100_000);
    let (paid, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    let candidate = candidate_at(&st, paid, &fvk);
    let recovered = candidate.encrypted_note.decrypt(&parent(&st), receive(8));
    let nf = *recovered.unwrap().nullifier();
    st.generate_next_block_spending(
        &recipient,
        (nf, value),
        unified(foreign_receiver()),
        Zatoshis::const_from_u64(20_000),
    );
    st.generate_empty_block();
    let (last, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(last).unwrap();
    (st, candidate, nf, paid, last)
}

/// A payment spent before the restore finds it is stored with its spend, whether the scan
/// finds it by a hint or it is inserted after the scan passed it, so it never counts
/// toward the balance, and its key's restore still finishes.
#[test]
fn a_spent_payment_found_early_is_stored_spent() {
    for hinted in [false, true] {
        let (mut st, candidate, nf, paid, last) = spent_restore();
        let account = st.test_account().unwrap().id();
        begin(&mut st, account, last);
        if hinted {
            lookup(&mut st, account, &candidate, false);
            for height in u32::from(paid)..=u32::from(last) {
                st.scan_cached_blocks_with_one_time_ivks(height.into(), 1);
            }
        } else {
            st.scan_cached_blocks_with_one_time_ivks(paid, 4);
            lookup(&mut st, account, &candidate, true);
        }
        assert_eq!(state_of(&st, account), 1, "hinted={hinted}");
        let sql = "SELECT COUNT(*) FROM ironwood_received_notes n
                   JOIN ironwood_received_note_spends s ON s.ironwood_received_note_id = n.id
                   WHERE n.nf = ?1 AND n.one_time_key_id IS NOT NULL";
        let spends: u32 = value(st.wallet().conn(), sql, [nf.to_bytes()]);
        assert_eq!(spends, 1, "hinted={hinted}");
        assert!(unspent_keys(&st, last).is_empty(), "hinted={hinted}");
        let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN).unwrap();
        let balance = summary.account_balances().get(&account).unwrap();
        assert_eq!(balance.ironwood_balance().total(), Zatoshis::ZERO);
        assert!(queued(&st).is_empty());
        assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
        assert!(closed(&st, receive(8)));
        assert!(!history_pending(&st, account, last));
    }
}

/// A paid key whose early lookup never arrives, even across a reopen, keeps waiting once
/// the scan accepts the publication, and its history stays pending. An ordinary restore
/// sweep then finds its payment and credits it once.
#[test]
fn a_lookup_that_never_arrives_leaves_the_key_to_a_sweep() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    reopen(&mut st);
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(sweep_row(&st, receive(8)), (None, true));
    assert!(!closed(&st, receive(8)) && closed(&st, receive(0)));
    assert!(history_pending(&st, account, last));

    sweep_all(&mut st, account, &candidate);
    assert_eq!(one_time_notes(&st, account), (1, 1));
    assert!(queued(&st).is_empty());
    assert!(!history_pending(&st, account, last));
    assert_eq!(sweep_row(&st, receive(8)).0, Some(u32::from(last)));
    assert!(closed(&st, receive(8)));
    assert_eq!(stranded(&st), 0);
}

/// A rewind below a provisional restore's queued payment keeps the payment, as a hint
/// now that its block is unscanned again, and keeps unpaid keys done at the anchor.
/// Rescanning the same chain finds the payment there and accepts the publication.
#[test]
fn a_rewind_below_a_queued_payment_keeps_it_as_a_hint() {
    let Grid {
        mut st,
        paid,
        first,
        last,
        ..
    } = grid();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    // The scan passes the payment before its lookup comes in, short of the anchor.
    st.scan_cached_blocks_with_one_time_ivks(first, 3);
    lookup(&mut st, account, &paid[0], true);
    assert_eq!(queued(&st), [(u32::from(paid[0].height), false)]);

    st.truncate_to_height_retaining_cache(first);
    assert_eq!(state_of(&st, account), 0);
    assert_eq!(queued(&st), [(u32::from(paid[0].height), true)]);
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), true));
    assert_eq!(sweep_row(&st, receive(8)), (None, true));

    st.scan_cached_blocks_with_one_time_ivks(first + 1, 4);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(one_time_notes(&st, account), (1, 1));
    assert!(queued(&st).is_empty());
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(!history_pending(&st, account, last));
    assert_eq!(stranded(&st), 0);
}

/// The row ID of the test account's receive key `index`.
fn key_row(st: &State, index: u64) -> i64 {
    let sql = "SELECT id FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1";
    value(st.wallet().conn(), sql, [index.to_be_bytes()])
}

/// A reorg that replaces the anchor block rejects the provisional publication when the
/// scan stores the new block: keys it registered without a note are deleted and the
/// incoming lookahead restarts as ordinary sweeps, while the key whose hint already found
/// its note keeps it. The sweeps then credit that payment once.
#[test]
fn a_reorg_replacing_the_anchor_rejects_the_publication() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    lookup(&mut st, account, &candidate, false);
    st.scan_cached_blocks_with_one_time_ivks(paid, 2);
    assert_eq!(state_of(&st, account), 0);
    let (unpaid, anchor) = (key_row(&st, 0), end_at(&st, last));

    st.truncate_to_height(paid);
    st.generate_empty_block();
    let (replaced, _) = st.generate_empty_block();
    assert_eq!(replaced, last);
    assert_ne!(end_at(&st, last).hash, anchor.hash);
    st.scan_cached_blocks_with_one_time_ivks(paid + 1, 2);
    assert_eq!(state_of(&st, account), 2);
    assert_ne!(key_row(&st, 0), unpaid);
    assert_eq!(unspent_keys(&st, last), [Some(receive(8))]);
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    assert_eq!(receive_sweeps(&st), RECEIVE_GAP_LIMIT as u32);

    sweep_all(&mut st, account, &candidate);
    assert_eq!(one_time_notes(&st, account), (1, 1));
    assert!(!history_pending(&st, account, last));
    assert_eq!(stranded(&st), 0);
}

/// A rewind below an accepted restore's anchor, on the same chain, keeps every sweep the
/// restore finished. The paid key reopens from its payment, so the rescan finds the note
/// it un-mined again, once, and nothing is due.
#[test]
fn a_rewind_below_an_accepted_anchor_keeps_the_restore_sweeps() {
    let Grid {
        mut st,
        paid,
        first,
        last,
        ..
    } = grid();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    st.scan_cached_blocks_with_one_time_ivks(first, 5);
    lookup(&mut st, account, &paid[0], true);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(one_time_notes(&st, account), (1, 1));

    st.truncate_to_height_retaining_cache(first);
    assert_eq!(one_time_notes(&st, account), (1, 0));
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), false));
    assert_eq!(sweep_row(&st, receive(8)), (Some(u32::from(last)), false));
    assert!(!closed(&st, receive(8)));
    st.scan_cached_blocks_with_one_time_ivks(first + 1, 4);
    assert_eq!(state_of(&st, account), 1);
    assert_eq!(one_time_notes(&st, account), (1, 1));
    assert!(!history_pending(&st, account, last));
    assert_eq!(stranded(&st), 0);
}

/// A reorg that replaces the block a finished sweep finished at reruns that sweep.
#[test]
fn a_reorg_replacing_a_finished_sweeps_block_reruns_it() {
    let Grid {
        mut st,
        paid,
        first,
        last,
        ..
    } = grid();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    st.scan_cached_blocks_with_one_time_ivks(first, 5);
    lookup(&mut st, account, &paid[0], true);
    assert_eq!(one_time_notes(&st, account), (1, 1));

    st.truncate_to_height(last - 1);
    let (replaced, _) = st.generate_empty_block();
    assert_eq!(replaced, last);
    assert_eq!(sweep_row(&st, receive(0)), (Some(u32::from(last)), false));
    st.scan_cached_blocks_with_one_time_ivks(last, 1);
    assert_eq!(sweep_row(&st, receive(0)), (None, false));
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    assert!(history_pending(&st, account, last));
    assert_eq!(one_time_notes(&st, account), (1, 1));
}

/// A paid key whose early lookup never arrived, and which an ordinary sweep then
/// finished, reruns that sweep after a rewind below its lookup, like any finished sweep,
/// so a payment to it in a replacement block is found.
#[test]
fn a_waiting_key_finished_by_a_sweep_reruns_it_after_a_rewind() {
    let (mut st, candidate, paid, last) = unscanned_restore();
    let account = st.test_account().unwrap().id();
    begin(&mut st, account, last);
    st.scan_cached_blocks_with_one_time_ivks(paid, 3);
    sweep_all(&mut st, account, &candidate);
    assert_eq!(sweep_row(&st, receive(8)).0, Some(u32::from(last)));

    // A reorg replaces the blocks after the payment with one paying the key again.
    st.truncate_to_height(paid);
    let recipient = IronwoodFvk(derive(&st, receive(8)));
    let value = Zatoshis::const_from_u64(50_000);
    st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    st.generate_empty_block();
    st.scan_cached_blocks_with_one_time_ivks(paid + 1, 2);
    assert_eq!(sweep_row(&st, receive(0)), (None, false));
    assert_eq!(sweep_row(&st, receive(8)), (None, false));
    assert!(history_pending(&st, account, last));
}
