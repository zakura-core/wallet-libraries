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
