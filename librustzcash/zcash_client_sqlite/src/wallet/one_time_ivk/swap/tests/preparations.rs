use super::*;
use crate::wallet::one_time_ivk::restore::tests::discovery::{
    drain, pay_candidate, publication_at, status,
};

/// Receive index `index`.
fn receive(index: u64) -> KeyId {
    KeyId::new(Purpose::Receive, index)
}

/// Refund index `index`.
fn refund(index: u64) -> KeyId {
    KeyId::new(Purpose::Refund, index)
}

/// Prepares both keys, returning each prepared key, or the policy it waits on.
fn prepare(
    st: &mut State,
) -> (
    Result<KeyId, ReservationPolicy>,
    Result<KeyId, ReservationPolicy>,
) {
    let account = st.test_account().unwrap().id();
    let tip = tip(st).height;
    let (receive, refund) = st
        .wallet_mut()
        .db_mut()
        .prepare_one_time_keys(account, tip, clock_now())
        .unwrap();
    (receive.map(|k| k.key_id()), refund.map(|k| k.key_id()))
}

/// Answers every due lookup and witness at a publication ending at the tip.
fn run(st: &mut State) {
    let account = st.test_account().unwrap().id();
    let publication = publication_at(st, tip(st).height);
    drain(st, account, publication);
}

/// The due lookups of the account.
fn due(st: &State) -> Vec<KeyId> {
    let account = st.test_account().unwrap().id();
    status(st.wallet().db(), account)
        .lookups
        .iter()
        .map(|w| w.work.key)
        .collect()
}

/// The prepared rows, as `(purpose, key ID)`.
fn rows_prepared(st: &State) -> Vec<(u8, i64)> {
    rows(
        st.wallet().conn(),
        "SELECT purpose, one_time_key_id FROM ironwood_one_time_preparations ORDER BY purpose",
        [],
    )
}

/// Each key waits for its own lookup. Repeated calls and a restart keep the same
/// candidates and lookups; once they are read both are ready, and handing each out
/// consumes its preparation, so the next refund preparation takes the next index.
#[test]
fn preparations_survive_duplicate_calls_and_restart() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let waiting = (
        Err(ReservationPolicy::ReceiveHistory),
        Err(ReservationPolicy::RefundHistory),
    );
    assert_eq!(prepare(&mut st), waiting);
    let prepared = rows_prepared(&st);
    let lookups = due(&st);
    assert_eq!(lookups, [receive(0), refund(0)]);
    assert_eq!(prepare(&mut st), waiting);
    reopen(&mut st);
    assert_eq!(prepare(&mut st), waiting);
    assert_eq!((rows_prepared(&st), due(&st)), (prepared, lookups));
    run(&mut st);
    assert_eq!(prepare(&mut st), (Ok(receive(0)), Ok(refund(0))));
    assert!(due(&st).is_empty());

    let db = st.wallet_mut().db_mut();
    let handed = db
        .prepare_receive_reservation(account, clock_now())
        .unwrap();
    assert_eq!(handed.unwrap().key_id(), receive(0));
    let tip = tip(&st).height;
    let handed = st.wallet_mut().db_mut().reserve_refund_key(account, tip);
    assert_eq!(handed.unwrap().unwrap().key_id(), refund(0));
    assert!(rows_prepared(&st).is_empty());
    let (_, next) = prepare(&mut st);
    assert_eq!(next, Err(ReservationPolicy::RefundHistory));
    assert_eq!(due(&st), [refund(1)]);
}

/// Cancelling drops the preparations. The receive address is still the lowest hole, and
/// the cancelled refund index, registered but never handed out, is passed over.
#[test]
fn a_cancelled_preparation_starts_again() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let _ = prepare(&mut st);
    st.wallet_mut()
        .db_mut()
        .cancel_one_time_preparations(account)
        .unwrap();
    assert!(rows_prepared(&st).is_empty());
    run(&mut st);
    assert_eq!(
        prepare(&mut st),
        (Ok(receive(0)), Err(ReservationPolicy::RefundHistory))
    );
    run(&mut st);
    assert_eq!(prepare(&mut st), (Ok(receive(0)), Ok(refund(1))));
}

/// Another device pays the prepared receive address while its lookup waits. The lookup
/// finds the payment, so the preparation moves to the next hole with a fresh lookup.
#[test]
fn a_receive_candidate_paid_mid_wait_moves_on() {
    let mut st = scanned_wallet();
    assert_eq!(prepare(&mut st).0, Err(ReservationPolicy::ReceiveHistory));
    pay_candidate(&mut st, receive(0));
    run(&mut st);
    assert_eq!(prepare(&mut st).0, Err(ReservationPolicy::ReceiveHistory));
    assert!(due(&st).contains(&receive(1)));
    run(&mut st);
    assert_eq!(prepare(&mut st).0, Ok(receive(1)));
}

/// A funding memo or a refund payment from another device makes the prepared refund index
/// ineligible, so the preparation moves to the next index with a fresh lookup.
#[test]
fn a_refund_candidate_funded_or_paid_mid_wait_moves_on() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    assert_eq!(prepare(&mut st).1, Err(ReservationPolicy::RefundHistory));
    let height = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, refund(0), height);
    assert_eq!(prepare(&mut st).1, Err(ReservationPolicy::RefundHistory));
    assert!(due(&st).contains(&refund(1)));
    pay_candidate(&mut st, refund(1));
    run(&mut st);
    assert_eq!(prepare(&mut st).1, Err(ReservationPolicy::RefundHistory));
    run(&mut st);
    assert_eq!(prepare(&mut st).1, Ok(refund(2)));
}

/// A prepared address checked against a publication older than the account's latest filter
/// coverage is read again through the newer tip before it is handed out.
#[test]
fn a_candidate_behind_filter_coverage_is_read_again() {
    use crate::wallet::one_time_ivk::restore::tests::discovery::{blocks_above, record_span};
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let _ = prepare(&mut st);
    run(&mut st);
    assert_eq!(prepare(&mut st).0, Ok(receive(0)));
    st.generate_and_scan_empty_blocks(1);
    let token = status(st.wallet().db(), account).token;
    let blocks = blocks_above(&st, activation_height(&st) - 1);
    assert!(record_span(
        st.wallet_mut().db_mut(),
        account,
        token,
        &blocks,
        &[]
    ));
    let handed = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now())
        .unwrap();
    assert!(matches!(handed, Err(ReservationPolicy::ReceiveHistory)));
    assert!(due(&st).contains(&receive(0)));
    run(&mut st);
    let handed = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, clock_now());
    assert_eq!(handed.unwrap().unwrap().key_id(), receive(0));
}

/// Ironwood activation on the test network.
fn activation_height(st: &State) -> BlockHeight {
    BlockHeight::from(crate::wallet::one_time_ivk::restore::queue::activation(
        st.network(),
    ))
}
