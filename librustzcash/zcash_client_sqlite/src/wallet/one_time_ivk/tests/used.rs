//! The use marker: which events set it, and that nothing clears it.
use super::*;
use crate::wallet::one_time_ivk::restore::tests::discovery::{
    drain, key8, one_time_notes, pay_candidate, publication_at, queue_late, send_witness, status,
    work_of,
};

/// Whether `account`'s use marker is set.
fn used(st: &State, account: AccountUuid) -> bool {
    status(st.wallet().db(), account).used
}

/// Clears every account's use marker, so a test can watch one event set it again.
fn clear(st: &State) {
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_recovery SET used = 0",
        [],
    );
}

/// Preparing both keys is not use. Handing out the receive address is, and so is resuming
/// that live reservation.
#[test]
fn a_receive_hand_out_sets_the_marker_and_preparing_does_not() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    for _ in 0..4 {
        let tip = tip(&st).height;
        let (receive, _) = st
            .wallet_mut()
            .db_mut()
            .prepare_one_time_keys(account, tip, clock_now())
            .unwrap();
        if receive.is_ok() {
            break;
        }
        let publication = publication_at(&st, tip);
        drain(&mut st, account, publication);
    }
    assert!(!used(&st, account), "preparation is not use");
    let db = st.wallet_mut().db_mut();
    let key = db
        .prepare_receive_reservation(account, clock_now())
        .unwrap();
    assert!(key.is_ok() && used(&st, account));
    clear(&st);
    let db = st.wallet_mut().db_mut();
    let again = db
        .prepare_receive_reservation(account, clock_now())
        .unwrap();
    assert_eq!(again.unwrap().key_id(), key.unwrap().key_id());
    assert!(used(&st, account), "resuming the live reservation is use");
}

/// Handing out a refund key sets the marker.
#[test]
fn a_refund_hand_out_sets_the_marker() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let tip = tip(&st).height;
    assert!(!used(&st, account));
    reserve_refund(st.wallet_mut().db_mut(), account, tip)
        .unwrap()
        .unwrap();
    assert!(used(&st, account));
}

/// Storing a payment candidate at or after the birthday sets the marker, and a reorg that
/// drops the candidate leaves it set. One before the birthday sets nothing.
#[test]
fn a_payment_candidate_sets_the_marker_and_a_reorg_keeps_it() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    assert!(!used(&st, account));
    queue_late(&mut st, key8(), &candidate);
    assert!(used(&st, account));
    st.truncate_to_height(candidate.height - 1);
    assert!(used(&st, account), "a reorg leaves the marker set");

    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    exec(
        st.wallet().conn(),
        "UPDATE accounts SET birthday_height = ?1",
        [u32::from(candidate.height) + 1],
    );
    queue_late(&mut st, key8(), &candidate);
    assert!(
        !used(&st, account),
        "a payment before the birthday is not use"
    );
}

/// The marker's first set raises the new-work counter, and setting it again doesn't.
#[test]
fn the_markers_first_set_raises_the_counter_and_a_second_does_not() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let work = |st: &State| st.wallet().db().one_time_new_work().unwrap();
    let mark = |st: &mut State| {
        tx(st.wallet_mut().db_mut(), |c, _| {
            let owner = crate::wallet::get_account_ref(c, account)?;
            store::restore::queue::mark_used(c, owner.0)
        })
        .unwrap()
    };
    let before = work(&st);
    mark(&mut st);
    assert_eq!(work(&st), before + 1);
    mark(&mut st);
    assert_eq!(work(&st), before + 1);
    assert!(used(&st, account));
}

/// Runs the `one_time_activation` upgrade again over the wallet's current one-time state, as
/// on a wallet that predates it.
fn upgrade(st: &mut State) {
    forget(st);
    migrate(st);
}

/// Returns the wallet to the schema before `one_time_activation`.
fn forget(st: &State) {
    crate::wallet::init::migrations::forget_one_time_activation(st.wallet().conn());
}

/// Applies pending migrations.
fn migrate(st: &mut State) {
    crate::wallet::init::WalletMigrator::new()
        .init_or_migrate(st.wallet_mut().db_mut())
        .unwrap();
}

/// Pauses every account, as a wallet that turned recovery off could have.
fn pause(st: &State) {
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_recovery SET enabled = 0",
        [],
    );
}

/// The registry ID of receive index `index`.
fn receive_id(st: &State, index: u64) -> i64 {
    value(
        st.wallet().conn(),
        "SELECT id FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [index.to_be_bytes()],
    )
}

/// The upgrade marks an enabled account, and a paused one with any evidence of use: a
/// reservation, an operation, a payment candidate or a funded refund key. A paused account
/// whose keys were only prepared stays unmarked.
#[test]
fn the_upgrade_marks_each_kind_of_evidence_and_not_preparations() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    upgrade(&mut st);
    assert!(used(&st, account), "an enabled account stays monitored");

    let evidence: [fn(&mut State, AccountUuid); 4] = [
        |st, _| {
            let id = receive_id(st, 0);
            exec(
                st.wallet().conn(),
                "UPDATE ironwood_one_time_keys SET reserved_at = 1 WHERE id = ?1",
                [id],
            );
        },
        |st, _| {
            let id = receive_id(st, 0);
            exec(
                st.wallet().conn(),
                "INSERT INTO ironwood_one_time_operations (one_time_key_id, reference,
                     deadline, begun_at) VALUES (?1, 'quote', 1, 1)",
                [id],
            );
        },
        |st, _| {
            let candidate = pay_candidate(st, key8());
            queue_late(st, key8(), &candidate);
        },
        |st, account| {
            let height = tip(st).height;
            recover(
                st.wallet_mut().db_mut(),
                account,
                KeyId::new(Purpose::Refund, 0),
                height,
            );
        },
    ];
    for (i, add) in evidence.into_iter().enumerate() {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        add(&mut st, account);
        pause(&st);
        upgrade(&mut st);
        assert!(used(&st, account), "evidence {i} marks the account");
    }

    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let tip = tip(&st).height;
    let db = st.wallet_mut().db_mut();
    let _ = db.prepare_one_time_keys(account, tip, clock_now()).unwrap();
    pause(&st);
    upgrade(&mut st);
    assert!(!used(&st, account), "prepared keys are not use");
}

/// A paused account whose only evidence is a payment candidate before its birthday loses
/// the candidate and stays unmarked.
#[test]
fn the_upgrade_ignores_a_candidate_before_the_birthday() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    queue_late(&mut st, key8(), &candidate);
    exec(
        st.wallet().conn(),
        "UPDATE accounts SET birthday_height = ?1",
        [u32::from(candidate.height) + 1],
    );
    pause(&st);
    upgrade(&mut st);
    assert!(!used(&st, account));
    let candidates: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_payment_recovery",
        [],
    );
    assert_eq!(candidates, 0);
}

/// A wallet from a published schema can hold a reservation of I4 with no progress row. The
/// upgrade creates the row with a receive window past I4 and marks the account, so I4 stays
/// monitored once recovery runs.
#[test]
fn the_upgrade_keeps_a_published_wallets_reservation_monitored() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let height = tip(&st).height;
    for index in 0..5 {
        let key = KeyId::new(Purpose::Receive, index);
        recover(st.wallet_mut().db_mut(), account, key, height);
    }
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET reserved_at = 1 WHERE id = ?1",
        [receive_id(&st, 4)],
    );
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_one_time_recovery",
        [],
    );
    upgrade(&mut st);
    assert!(used(&st, account));
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(
        receivers
            .iter()
            .any(|r| r.key == KeyId::new(Purpose::Receive, 4))
    );
}

/// A paused account's repair read that passed a payment without keeping it, stopped between
/// shards after a completed prefix, resumes right after that prefix once enabled, and finds
/// the payment.
#[test]
fn the_upgrade_resumes_a_paused_repair_after_its_completed_prefix() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let prefix = tip(&st).height;
    let publication = publication_at(&st, prefix);
    drain(&mut st, account, publication);
    pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    st.generate_and_scan_empty_blocks(2);
    let id = receive_id(&st, 0);
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET target_height = ?2, reasons = 1,
             start_height = ?3, checked_height = ?2, inventory = zeroblob(32), shard = 2,
             segment = 0, read_complete = 0 WHERE one_time_key_id = ?1",
        rusqlite::params![id, u32::from(tip(&st).height), u32::from(prefix) + 1],
    );
    pause(&st);
    upgrade(&mut st);
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    assert_eq!(
        work_of(&st, KeyId::new(Purpose::Receive, 0)).from,
        prefix + 1
    );
    let publication = publication_at(&st, tip(&st).height);
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A paused account's completed repair read records no completed history, so after the
/// upgrade drops the candidate before the birthday that held it open, the lookup is read
/// again and finds the later payment the repair read passed over.
#[test]
fn the_upgrade_rereads_a_paused_repair_held_by_an_old_candidate() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let publication = publication_at(&st, tip(&st).height);
    drain(&mut st, account, publication);
    let early = pay_candidate(&mut st, key8());
    let late = pay_candidate(&mut st, key8());
    queue_late(&mut st, key8(), &early);
    let id = value::<i64>(
        st.wallet().conn(),
        "SELECT id FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [key8().index().to_be_bytes()],
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET read_complete = 1, done_height = NULL,
             done_from = NULL, checked_height = target_height WHERE one_time_key_id = ?1",
        [id],
    );
    exec(
        st.wallet().conn(),
        "UPDATE accounts SET birthday_height = ?1",
        [u32::from(late.height)],
    );
    pause(&st);
    upgrade(&mut st);
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A legacy account whose only evidence is a one-time note and that has no progress row
/// gets one, marked, with a receive window that covers the paid index.
#[test]
fn the_upgrade_keeps_a_note_only_account_monitored() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let candidate = pay_candidate(&mut st, key8());
    let publication = queue_late(&mut st, key8(), &candidate);
    send_witness(&mut st, key8(), &candidate);
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_one_time_recovery",
        [],
    );
    upgrade(&mut st);
    assert!(used(&st, account));
    st.wallet_mut()
        .db_mut()
        .enable_one_time_recovery(account)
        .unwrap();
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().any(|r| r.key == key8()));
}

/// An existing progress row whose receive window stops short of an outstanding I4
/// reservation is widened to cover I4. I4 was paid before the old processed frontier and its
/// coverage already passed that payment, so only the bootstrap lookup the upgrade queues can
/// find it, from before the payment through the frontier.
#[test]
fn the_upgrade_widens_a_short_window_over_an_outstanding_reservation() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key4 = KeyId::new(Purpose::Receive, 4);
    let paid = pay_candidate(&mut st, key4);
    st.generate_and_scan_empty_blocks(2);
    let frontier = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, key4, frontier);
    let id = receive_id(&st, 4);
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET reserved_at = 1, covered_height = ?2 WHERE id = ?1",
        rusqlite::params![id, u32::from(frontier)],
    );
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    upgrade(&mut st);
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(receivers.iter().any(|r| r.key == key4));
    let bootstrap = work_of(&st, key4);
    assert!(bootstrap.from <= paid.height && bootstrap.through >= frontier);
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false)]);
}

/// A key the old admission marked paid only by a payment before the birthday is unmarked,
/// so issuance hands I0 out again within the window instead of skipping past it.
#[test]
fn the_upgrade_reissues_indexes_paid_only_before_the_birthday() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    forget(&st);
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET used = 1, prebirthday_height = 1 WHERE purpose = 1",
        [],
    );
    migrate(&mut st);
    let mut key = None;
    for _ in 0..4 {
        match st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, clock_now())
            .unwrap()
        {
            Ok(k) => {
                key = Some(k.key_id());
                break;
            }
            Err(_) => {
                let publication = publication_at(&st, tip(&st).height);
                drain(&mut st, account, publication);
            }
        }
    }
    assert_eq!(key, Some(KeyId::new(Purpose::Receive, 0)));
}

/// A wallet paused just before the old filter re-check of I4, which the window opened after
/// filters passed I4's payment, finds that payment through the complete check the upgrade
/// owes by clearing the frontier. The account stays marked, so it keeps being queried.
#[test]
fn the_upgrade_finds_a_pending_recheck_through_the_complete_check() {
    use crate::wallet::one_time_ivk::restore::tests::discovery::{blocks_above, record_span};
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let paid0 = pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    pay_candidate(&mut st, KeyId::new(Purpose::Receive, 4));
    queue_late(&mut st, KeyId::new(Purpose::Receive, 0), &paid0);
    send_witness(&mut st, KeyId::new(Purpose::Receive, 0), &paid0);
    let token = status(st.wallet().db(), account).token;
    let blocks = blocks_above(&st, tip(&st).height - 3);
    assert!(record_span(
        st.wallet_mut().db_mut(),
        account,
        token,
        &blocks,
        &[]
    ));
    // I4 as the old rule left it: behind the frontier with no lookup, waiting for filters.
    let id = receive_id(&st, 4);
    exec(
        st.wallet().conn(),
        "DELETE FROM ironwood_one_time_lookups WHERE one_time_key_id = ?1",
        [id],
    );
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET covered_height = NULL WHERE id = ?1",
        [id],
    );
    upgrade(&mut st);
    let state = status(st.wallet().db(), account);
    assert!(state.used && state.filter_frontier.is_none());
    let publication = publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    drain(&mut st, account, publication);
    assert_eq!(one_time_notes(&st), [(100_000, false), (100_000, false)]);
}
