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

/// Filters run two blocks ahead of every PIR publication. The preparation's target stays
/// where it was prepared, so the next round's publication reaches it, and one lookup makes
/// the address ready instead of chasing the moving filter frontier.
#[test]
fn a_lagging_publication_readies_the_preparation_after_one_lookup() {
    use crate::wallet::one_time_ivk::restore::tests::discovery::{blocks_above, record_span};
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let filter_to_tip = |st: &mut State| {
        let state = status(st.wallet().db(), account);
        let from = state
            .filter_frontier
            .map_or(activation_height(st), |f| f.height + 1);
        let blocks = blocks_above(st, from - 1);
        assert!(record_span(
            st.wallet_mut().db_mut(),
            account,
            state.token,
            &blocks,
            &[]
        ));
    };
    st.generate_and_scan_empty_blocks(2);
    filter_to_tip(&mut st);
    assert_eq!(prepare(&mut st).0, Err(ReservationPolicy::ReceiveHistory));
    let prepared = tip(&st).height;
    st.generate_and_scan_empty_blocks(2);
    filter_to_tip(&mut st);
    assert_eq!(due(&st), [receive(0), refund(0)]);
    // This round's publication ends where the previous round's scan did.
    let lagging = publication_at(&st, prepared);
    drain(&mut st, account, lagging);
    assert_eq!(prepare(&mut st).0, Ok(receive(0)));
    assert!(due(&st).is_empty());
}

/// Another device pays the ready receive address after its target. The filter hit queues a
/// lookup that holds the address back, and once that lookup finds the payment the
/// preparation moves to the next hole.
#[test]
fn a_watched_candidate_paid_after_its_target_moves_on() {
    use crate::wallet::one_time_ivk::restore::tests::discovery::{blocks_above, span_over};
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let _ = prepare(&mut st);
    run(&mut st);
    assert_eq!(prepare(&mut st).0, Ok(receive(0)));
    let paid = pay_candidate(&mut st, receive(0));
    let token = status(st.wallet().db(), account).token;
    let span = span_over(
        st.wallet().db(),
        0,
        &blocks_above(&st, activation_height(&st) - 1),
    );
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filter_span(account, token, &span, &[(paid.height, receive(0))])
            .unwrap(),
        zcash_client_backend::data_api::one_time_ivk::restore::FilterOutcome::Committed
    );
    assert_eq!(prepare(&mut st).0, Err(ReservationPolicy::ReceiveHistory));
    run(&mut st);
    assert_eq!(prepare(&mut st).0, Err(ReservationPolicy::ReceiveHistory));
    run(&mut st);
    assert_eq!(prepare(&mut st).0, Ok(receive(1)));
}

/// Ironwood activation on the test network.
fn activation_height(st: &State) -> BlockHeight {
    BlockHeight::from(crate::wallet::one_time_ivk::restore::queue::activation(
        st.network(),
    ))
}

/// A memo funds the prepared refund index, and a reorg then removes that funding before
/// the next call. The index stays allocated, so the preparation moves to the next one.
#[test]
fn a_funded_candidate_stays_retired_after_a_reorg_clears_its_funding() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(3);
    let account = st.test_account().unwrap().id();
    assert_eq!(prepare(&mut st).1, Err(ReservationPolicy::RefundHistory));
    let funded = tip(&st).height;
    recover(st.wallet_mut().db_mut(), account, refund(0), funded);
    st.truncate_to_height(funded - 1);
    st.generate_and_scan_empty_blocks(2);
    assert_eq!(prepare(&mut st).1, Err(ReservationPolicy::RefundHistory));
    run(&mut st);
    assert_eq!(prepare(&mut st).1, Ok(refund(1)));
}
