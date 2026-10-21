//! Local request ownership and the four payment-backed receive slots.
use super::*;
use zakura_one_time_ivk::swap::{
    OperationStatus::{Active, Terminal},
    ReceiptExpectation,
};
use zcash_protocol::TxId;

/// Starts a quote on the currently lowest eligible slot.
fn quote(st: &mut State, now: i64, deposit: &str, start: bool) -> (KeyId, String) {
    let account = st.test_account().unwrap().id();
    chain_agrees(st.wallet().db(), now);
    let key = match st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now)
        .unwrap()
    {
        Err(ReservationPolicy::ReceiveHistory) => {
            check_window(st);
            st.wallet_mut()
                .db_mut()
                .prepare_receive_reservation(account, now)
                .unwrap()
                .unwrap()
        }
        issued => issued.unwrap(),
    };
    let db = st.wallet_mut().db_mut();
    let request = db
        .begin_receive_operation(account, key.key_id().index(), now + 60, now)
        .unwrap()
        .unwrap();
    db.finish_receive_operation(account, &request, &accepted(deposit, None, now + 60))
        .unwrap();
    if start {
        db.start_receive_operation(account, &request, now)
            .unwrap()
            .unwrap();
    }
    (key.key_id(), request)
}

/// Runs recovery at the tip until every due lookup and witness is answered, so the window's
/// histories are complete.
fn check_window(st: &mut State) {
    let account = st.test_account().unwrap().id();
    let publication = store::restore::tests::discovery::publication_at(st, tip(st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    store::restore::tests::discovery::drain(st, account, publication);
}

/// Quotes and provider responses cannot create a fifth receive slot.
#[test]
fn four_slot_quotes_do_not_widen_the_window() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    for index in 0..4 {
        let (key, _) = quote(&mut st, now, &format!("slot-{index}"), true);
        assert_eq!(key.index(), index);
    }
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap(),
        Err(ReservationPolicy::Limit)
    ));
}

/// Accepted unfunded quotes recycle at expiry, with no extra grace or fresh network check.
#[test]
fn four_slot_expiry_recycles_without_advancing() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    for round in 0..8 {
        let at = now + round * 60;
        let (key, _) = quote(&mut st, at, &format!("round-{round}"), false);
        assert_eq!(key.index(), 0);
        chain_agrees(st.wallet().db(), at + 60);
        let key = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, at + 60)
            .unwrap()
            .unwrap();
        assert_eq!(key.key_id().index(), 0);
    }
}

/// A late accepted response cannot start after its reservation was recycled.
#[test]
fn four_slot_recycling_fences_late_quote_responses() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (_, old) = quote(&mut st, now, "old", false);
    let (_, new) = quote(&mut st, now + 60, "new", false);
    let db = st.wallet_mut().db_mut();
    assert!(matches!(
        db.start_receive_operation(account, &old, now + 60).unwrap(),
        Err(ReservationPolicy::Stale)
    ));
    assert_eq!(
        db.start_receive_operation(account, &new, now + 60)
            .unwrap()
            .unwrap()
            .address,
        "new"
    );
}

/// Active provider processing retains ownership even after the accepted deposit deadline.
#[test]
fn four_slot_processing_keeps_ownership() {
    for (started, funded) in [(false, false), (true, true)] {
        let mut st = scanned_wallet();
        let now = clock_now();
        let account = st.test_account().unwrap().id();
        let (key, _) = quote(&mut st, now, "processing", started);
        st.wallet_mut()
            .db_mut()
            .record_operation_status(
                account,
                "processing",
                None,
                Observation {
                    status: Active,
                    funded,
                    receipts: vec![],
                },
                now + 1,
            )
            .unwrap();
        chain_agrees(st.wallet().db(), now + 60);
        let next = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now + 60)
            .unwrap()
            .unwrap();
        assert_eq!(key.index(), 0);
        assert_eq!(next.key_id().index(), 1);
    }
}

/// A fast device clock cannot expire a quote before chain time reaches its deadline.
#[test]
fn expiry_uses_the_earlier_clock() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (_, request) = quote(&mut st, now, "pending", false);
    let db = st.wallet_mut().db_mut();
    let key = db
        .prepare_receive_reservation(account, now + 3600)
        .unwrap()
        .unwrap();
    assert_eq!(key.key_id().index(), 0);
    assert_eq!(
        db.start_receive_operation(account, &request, now + 3600)
            .unwrap()
            .unwrap()
            .address,
        "pending"
    );
}

/// Deposit ownership is immutable and a second accepted request cannot take a started quote.
#[test]
fn outcomes_and_started_request_ownership_are_stable() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (key, request) = quote(&mut st, now, "first", false);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.finish_receive_operation(account, &request, &accepted("other", None, now + 60))
            .is_err()
    );
    assert!(
        db.finish_receive_operation(account, &request, &OperationOutcome::Rejected)
            .is_err()
    );
    let second = db
        .begin_receive_operation(account, key.index(), now + 60, now)
        .unwrap()
        .unwrap();
    db.finish_receive_operation(account, &second, &accepted("second", None, now + 60))
        .unwrap();
    db.start_receive_operation(account, &request, now)
        .unwrap()
        .unwrap();
    assert!(matches!(
        db.start_receive_operation(account, &second, now).unwrap(),
        Err(ReservationPolicy::Stale)
    ));
}

/// Disabling the feature prevents new addresses and start instructions without deleting requests.
#[test]
fn disabled_feature_refuses_issuance() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (key, request) = quote(&mut st, now, "pending", false);
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    assert!(matches!(
        db.prepare_receive_reservation(account, now).unwrap(),
        Err(ReservationPolicy::Disabled)
    ));
    assert!(matches!(
        db.begin_receive_operation(account, key.index(), now + 60, now)
            .unwrap(),
        Err(ReservationPolicy::Disabled)
    ));
    assert!(matches!(
        db.start_receive_operation(account, &request, now).unwrap(),
        Err(ReservationPolicy::Disabled)
    ));
}

/// A success without a reported refund cannot complete an empty funded refund address.
#[test]
fn success_without_refund_keeps_an_unpaid_funded_key_unfinished() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let height = tip(&st).height;
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, height);
    observe(
        st.wallet_mut().db_mut(),
        account,
        key.key_id(),
        "swap",
        Terminal(ReceiptExpectation::None),
        now,
    )
    .unwrap();
    let publication = store::restore::tests::discovery::publication_at(&st, height);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    store::restore::tests::discovery::drain(&mut st, account, publication);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let status = st.wallet().db().one_time_recovery(account, now).unwrap();
    // A newer frontier is what makes the next direct check necessary.
    assert!(status.lookups.is_empty());
    st.generate_and_scan_empty_blocks(1);
    let newer = store::restore::tests::discovery::publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, newer, true)
            .unwrap()
    );
    // The four-request batch can put lookahead keys ahead of this refund.
    let pending: bool = st
        .wallet()
        .conn()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
         JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
         WHERE k.purpose = 0 AND k.key_index = ?1 AND l.target_height = ?2
           AND l.read_complete = 0)",
            rusqlite::params![
                key.key_id().index().to_be_bytes(),
                u32::from(newer.end.height)
            ],
            |r| r.get(0),
        )
        .unwrap();
    assert!(pending);
}

/// Stamps block `height` with time `at`, as its miner would.
fn mined_at(st: &State, height: BlockHeight, at: i64) {
    let sql = "UPDATE blocks SET time = ?2 WHERE height = ?1";
    exec(
        st.wallet().conn(),
        sql,
        rusqlite::params![u32::from(height), at],
    );
}

/// Reports that the provider finished `deposit`'s swap with a 100,000-zatoshi payout in
/// `receipts`.
fn promise_payout(st: &mut State, deposit: &str, receipts: &[TxId], at: i64) {
    let account = st.test_account().unwrap().id();
    let payout = Some(Zatoshis::const_from_u64(100_000));
    let observation = Observation {
        status: Terminal(ReceiptExpectation::Positive(payout)),
        funded: true,
        receipts: receipts.to_vec(),
    };
    st.wallet_mut()
        .db_mut()
        .record_operation_status(account, deposit, None, observation, at)
        .unwrap();
}

/// Runs direct catch-up through a new block and returns the receive indexes it queued.
fn catch_up(st: &mut State) -> Vec<u64> {
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(1);
    let publication = store::restore::tests::discovery::publication_at(st, tip(st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let queued: Vec<Vec<u8>> = column(
        st.wallet().conn(),
        "SELECT k.key_index FROM ironwood_one_time_lookups l
         JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
         WHERE k.purpose = 1 AND l.target_height = ?1 AND l.read_complete = 0
         ORDER BY k.key_index",
        [u32::from(publication.end.height)],
    );
    store::restore::tests::discovery::drain(st, account, publication);
    queued
        .into_iter()
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
        .collect()
}

/// A payment in the transaction the provider reported as the quote's payout settles it.
#[test]
fn a_reported_payout_transaction_settles_its_quote() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let (key, _) = quote(&mut st, now, "quote", true);
    let paid = store::restore::tests::discovery::pay_candidate(&mut st, key);
    promise_payout(&mut st, "quote", &[paid.txid], now + 120);
    assert!(catch_up(&mut st).contains(&0));
    assert!(!catch_up(&mut st).contains(&0));
}

/// An expired quote's late payment to its recycled address cannot settle the newer quote's
/// promised payout. The newer quote's own reported payout does, even with the old quote open.
#[test]
fn a_late_payment_to_a_recycled_address_does_not_settle_the_new_quote() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let (old, _) = quote(&mut st, now, "old", false);
    let (new, _) = quote(&mut st, now + 60, "new", true);
    assert_eq!(old, new);
    store::restore::tests::discovery::pay_candidate(&mut st, old);
    promise_payout(&mut st, "new", &[], now + 180);
    assert!(catch_up(&mut st).contains(&0));
    assert!(catch_up(&mut st).contains(&0));
    let payout = store::restore::tests::discovery::pay_candidate(&mut st, new);
    promise_payout(&mut st, "new", &[payout.txid], now + 240);
    assert!(catch_up(&mut st).contains(&0));
    assert!(!catch_up(&mut st).contains(&0));
}

/// Another device's quote paid the shared address after this quote began. Without the
/// provider naming that transaction for this quote, the promised payout stays pending.
#[test]
fn another_devices_later_payment_does_not_settle_a_reused_address() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let (key, _) = quote(&mut st, now, "quote", true);
    let theirs = store::restore::tests::discovery::pay_candidate(&mut st, key);
    mined_at(&st, theirs.height, now + 60);
    let unrelated = TxId::from_bytes([9; 32]);
    promise_payout(&mut st, "quote", &[unrelated], now + 120);
    assert!(catch_up(&mut st).contains(&0));
    assert!(catch_up(&mut st).contains(&0));
}

/// An earlier payment whose block timestamp runs ahead of the device clock looks newer than
/// the quote, but cannot settle it. The quote's own reported payout does.
#[test]
fn a_block_timestamp_ahead_of_the_device_clock_does_not_settle_a_quote() {
    let mut st = scanned_wallet();
    let now = clock_now();
    // The payment lands after index 0's history was read, so issuance cannot know it.
    check_window(&mut st);
    let earlier =
        store::restore::tests::discovery::pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    let (key, _) = quote(&mut st, now, "quote", true);
    assert_eq!(key.index(), 0);
    mined_at(&st, earlier.height, now + 600);
    promise_payout(&mut st, "quote", &[], now + 120);
    assert!(catch_up(&mut st).contains(&0));
    assert!(catch_up(&mut st).contains(&0));
    let payout = store::restore::tests::discovery::pay_candidate(&mut st, key);
    promise_payout(&mut st, "quote", &[payout.txid], now + 180);
    assert!(catch_up(&mut st).contains(&0));
    assert!(!catch_up(&mut st).contains(&0));
}

/// A payout widens the window from the block that mines it. With slots 0 to 2 held by
/// quotes, a payout to 3 that is mined but not yet confirmed makes 4 to 7 issuable at
/// once. A reorg that drops the payout shrinks the window back to 0 to 3.
#[test]
fn a_mined_payout_opens_the_next_indexes_until_a_reorg_drops_it() {
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    let floor = tip(&st).height;
    let end = |st: &State| {
        let owner: i64 = value(
            st.wallet().conn(),
            "SELECT id FROM accounts WHERE uuid = ?1",
            [account.0],
        );
        crate::wallet::one_time_ivk::swap::reservations::recovery_end(st.wallet().conn(), owner)
            .unwrap()
    };
    for index in 0..3 {
        assert_eq!(
            quote(&mut st, now, &format!("slot-{index}"), true)
                .0
                .index(),
            index
        );
    }
    let paid =
        store::restore::tests::discovery::pay_candidate(&mut st, KeyId::new(Purpose::Receive, 3));
    catch_up(&mut st);
    assert_eq!(
        store::restore::tests::discovery::one_time_notes(&st),
        [(100_000, false)]
    );
    let depth = u32::from(tip(&st).height) - u32::from(paid.height) + 1;
    assert!(depth < ConfirmationsPolicy::default().untrusted().get());
    assert_eq!(end(&st), 8);
    for index in 4..8 {
        assert_eq!(
            quote(&mut st, now, &format!("slot-{index}"), true)
                .0
                .index(),
            index
        );
    }
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap(),
        Err(ReservationPolicy::Limit)
    ));

    st.truncate_to_height(floor);
    assert_eq!(end(&st), 4);
    if let Ok(key) = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now)
        .unwrap()
    {
        assert!(key.key_id().index() < 4);
    }
}

/// A restored seed already paid index 0. Enabling recovery must not hand that address to a
/// provider before its history is read: issuance waits, then skips the paid index.
#[test]
fn a_restored_seeds_paid_index_is_not_issued_before_its_history() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    store::restore::tests::discovery::pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap(),
        Err(ReservationPolicy::ReceiveHistory)
    ));
    check_window(&mut st);
    let key = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now)
        .unwrap()
        .unwrap();
    assert_eq!(key.key_id().index(), 1);
}

/// A new account issues index 0 as soon as that index's own history lookup completes, while
/// the rest of the window is still unread.
#[test]
fn a_new_account_issues_once_the_index_history_completes() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    assert!(matches!(
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap(),
        Err(ReservationPolicy::ReceiveHistory)
    ));
    let publication = store::restore::tests::discovery::publication_at(&st, tip(&st).height);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    let state = st.wallet().db().one_time_recovery(account, now).unwrap();
    let first = state
        .lookups
        .iter()
        .find(|w| w.work.key == KeyId::new(Purpose::Receive, 0))
        .expect("index 0 is queued")
        .clone();
    assert!(state.lookups.len() > 1, "the rest of the window is unread");
    let empty = zcash_client_backend::data_api::one_time_ivk::restore::LookupPage {
        publication,
        previous: None,
        records: vec![],
        complete: true,
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_lookup(account, &first, &empty, now)
            .unwrap()
    );
    let key = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now)
        .unwrap()
        .unwrap();
    assert_eq!(key.key_id().index(), 0);
}

/// A quote's payout arrived and its provider reported the operation ended, either with a
/// promised receipt or inconclusively after funding. Its reservation was released while the
/// payment kept the address used and index 1 was drafted. A reorg then orphans that payout and
/// the replacement history is empty. The receipt the operation may still owe is outstanding,
/// so the address must not be issued again.
#[test]
fn an_orphaned_promised_payout_keeps_its_address_out_of_reuse() {
    for positive in [true, false] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let now = clock_now();
        let (key, _) = quote(&mut st, now, "quote", true);
        assert_eq!(key.index(), 0);
        let floor = tip(&st).height;
        let paid = store::restore::tests::discovery::pay_candidate(&mut st, key);
        if positive {
            promise_payout(&mut st, "quote", &[paid.txid], now + 120);
        } else {
            let observation = Observation {
                status: Terminal(ReceiptExpectation::Unknown),
                funded: true,
                receipts: vec![],
            };
            st.wallet_mut()
                .db_mut()
                .record_operation_status(account, "quote", None, observation, now + 120)
                .unwrap();
        }
        catch_up(&mut st);
        assert_eq!(
            store::restore::tests::discovery::one_time_notes(&st),
            [(100_000, false)]
        );
        // Past the quote's deadline the reservation is released, and the payment alone
        // keeps index 0 from being issued.
        mined_at(&st, tip(&st).height, now + 600);
        chain_agrees(st.wallet().db(), now + 180);
        let next = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now + 180)
            .unwrap()
            .unwrap();
        assert_eq!(next.key_id().index(), 1);

        st.truncate_to_height(floor);
        st.generate_and_scan_empty_blocks(3);
        check_window(&mut st);
        chain_agrees(st.wallet().db(), now + 180);
        let next = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now + 180)
            .unwrap()
            .unwrap();
        assert_ne!(next.key_id().index(), 0, "positive {positive}");
    }
}

/// Records a positive filter hint for receive index `index` over a new block.
fn hint(st: &mut State, index: u64) {
    let account = st.test_account().unwrap().id();
    let frontier = st
        .wallet()
        .db()
        .one_time_recovery(account, clock_now())
        .unwrap()
        .filter_frontier
        .unwrap()
        .height;
    st.generate_and_scan_empty_blocks(1);
    let (token, _) = st.wallet().db().one_time_receivers(account).unwrap();
    let blocks = store::restore::tests::discovery::blocks_above(st, frontier);
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_one_time_filters(
                account,
                token,
                0,
                &blocks,
                &[KeyId::new(Purpose::Receive, index)]
            )
            .unwrap()
    );
}

/// A positive filter hint recorded after index 0 was reserved may mean another device paid
/// it. Resuming the reservation, beginning a quote on it and starting an accepted quote each
/// wait with `ReceiveHistory` until the hinted lookup settles, then proceed. Routine catch-up
/// raising the key's target does not hold the reservation.
#[test]
fn a_positive_hint_after_reservation_holds_its_receiver() {
    for step in ["resume", "begin", "start"] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let now = clock_now();
        check_window(&mut st);
        let key = st
            .wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap()
            .unwrap();
        assert_eq!(key.key_id().index(), 0);
        // Routine catch-up reads the unused key again without holding it.
        st.generate_and_scan_empty_blocks(1);
        let publication = store::restore::tests::discovery::publication_at(&st, tip(&st).height);
        assert!(
            st.wallet_mut()
                .db_mut()
                .begin_one_time_recovery(account, publication, true)
                .unwrap()
        );
        assert_eq!(
            st.wallet_mut()
                .db_mut()
                .prepare_receive_reservation(account, now)
                .unwrap()
                .unwrap()
                .key_id()
                .index(),
            0
        );
        let request = (step == "start").then(|| {
            let db = st.wallet_mut().db_mut();
            let request = db
                .begin_receive_operation(account, 0, now + 60, now)
                .unwrap()
                .unwrap();
            db.finish_receive_operation(account, &request, &accepted("deposit", None, now + 60))
                .unwrap();
            request
        });
        hint(&mut st, 0);
        let attempt = |st: &mut State| -> Result<(), ReservationPolicy> {
            let db = st.wallet_mut().db_mut();
            match step {
                "resume" => db
                    .prepare_receive_reservation(account, now)
                    .unwrap()
                    .map(|key| assert_eq!(key.key_id().index(), 0)),
                "begin" => db
                    .begin_receive_operation(account, 0, now + 60, now)
                    .unwrap()
                    .map(drop),
                _ => db
                    .start_receive_operation(account, request.as_ref().unwrap(), now)
                    .unwrap()
                    .map(drop),
            }
        };
        assert_eq!(
            attempt(&mut st),
            Err(ReservationPolicy::ReceiveHistory),
            "{step}"
        );
        check_window(&mut st);
        assert_eq!(attempt(&mut st), Ok(()), "{step}");
    }
}
