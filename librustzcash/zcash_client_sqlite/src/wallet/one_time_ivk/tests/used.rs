//! The use marker: which events set it, and that nothing clears it.
use super::*;
use crate::wallet::one_time_ivk::restore::tests::discovery::{
    drain, key8, pay_candidate, publication_at, queue_late, status,
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
    crate::wallet::init::migrations::forget_one_time_activation(st.wallet().conn());
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
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(
        receivers
            .iter()
            .any(|r| r.key == KeyId::new(Purpose::Receive, 4))
    );
}

/// A paused account's partial repair progress is dropped by the upgrade, since a paused
/// account read only repairs, so the lookup reads its history again once enabled.
#[test]
fn the_upgrade_resets_a_paused_accounts_partial_progress() {
    let mut st = scanned_wallet();
    let id = receive_id(&st, 0);
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_lookups SET checked_height = start_height,
             inventory = zeroblob(32), shard = 0, segment = 0 WHERE one_time_key_id = ?1",
        [id],
    );
    pause(&st);
    upgrade(&mut st);
    let progress: (Option<u32>, Option<Vec<u8>>) = row(
        st.wallet().conn(),
        "SELECT checked_height, inventory FROM ironwood_one_time_lookups
         WHERE one_time_key_id = ?1",
        [id],
    );
    assert_eq!(progress, (None, None));
}

/// A key the old admission marked paid only by a payment before the birthday is unmarked,
/// so issuance hands I0 out again within the window instead of skipping past it.
#[test]
fn the_upgrade_reissues_indexes_paid_only_before_the_birthday() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET used = 1, prebirthday_height = 1 WHERE purpose = 1",
        [],
    );
    upgrade(&mut st);
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
    use crate::wallet::one_time_ivk::restore::tests::discovery::{
        blocks_above, one_time_notes, record_span, send_witness,
    };
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
