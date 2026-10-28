//! Local request ownership and the four payment-backed receive slots.
use super::*;
use zakura_one_time_ivk::swap::{
    OperationStatus::{Active, Terminal},
    ReceiptExpectation,
};
use zcash_protocol::TxId;

/// Reserves the currently lowest eligible slot at `now`, with the chain's time at `now`,
/// first completing the window's histories if issuance waits for them.
fn reserve_receive(st: &mut State, now: i64) -> OneTimeKey {
    let account = st.test_account().unwrap().id();
    chain_agrees(st.wallet().db(), now);
    match st
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
    }
}

/// Starts a quote on the currently lowest eligible slot.
fn quote(st: &mut State, now: i64, deposit: &str, start: bool) -> (KeyId, String) {
    let account = st.test_account().unwrap().id();
    let key = reserve_receive(st, now);
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

/// A swap the provider reports as finished with no refund retires its funded refund key:
/// a newer frontier no longer queues its history, though no refund ever reached it.
#[test]
fn success_without_refund_retires_an_unpaid_funded_key() {
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
    assert!(!pending);
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

/// Runs a complete check through a new block and returns the receive indexes that still
/// owed a promised payout when it started (see `restore::queue::UNSETTLED`).
fn catch_up(st: &mut State) -> Vec<u64> {
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks(1);
    let publication = store::restore::tests::discovery::publication_at(st, tip(st).height);
    let queued: Vec<Vec<u8>> = column(
        st.wallet().conn(),
        &format!(
            "SELECT k.key_index FROM ironwood_one_time_keys k
             WHERE k.purpose = 1 AND {} ORDER BY k.key_index",
            store::restore::queue::UNSETTLED
        ),
        [],
    );
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
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
    let empty = store::restore::tests::discovery::whole(publication, vec![]);
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
    filter(st, &[KeyId::new(Purpose::Receive, index)]);
}

/// Commits filter progress over a new block with `hits`, from the current frontier.
fn filter(st: &mut State, hits: &[KeyId]) {
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
    assert!(store::restore::tests::discovery::record_span(
        st.wallet_mut().db_mut(),
        account,
        token,
        &blocks,
        hits
    ));
}
/// Runs recovery at the tip under the account's current correction generation until every
/// due lookup and witness is answered, so invalidated histories settle again.
fn settle(st: &mut State) {
    let account = st.test_account().unwrap().id();
    let revision = st
        .wallet()
        .db()
        .one_time_recovery(account, clock_now())
        .unwrap()
        .token
        .history_revision;
    let publication = zcash_client_backend::data_api::one_time_ivk::restore::RecoveryPublication {
        history_revision: revision,
        ..store::restore::tests::discovery::publication_at(st, tip(st).height)
    };
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_one_time_recovery(account, publication, true)
            .unwrap()
    );
    store::restore::tests::discovery::drain(st, account, publication);
}

/// An event that invalidates index 0's settled history after it was reserved, a positive
/// filter hint, a history correction or a rewind below the height it was checked through,
/// may hide a payment another device received there. Resuming the reservation, beginning a
/// quote on it and starting an accepted quote each wait with `ReceiveHistory` until the
/// re-check settles, then proceed. Routine catch-up raising the key's target never holds it.
#[test]
fn an_invalidating_event_after_reservation_holds_its_receiver() {
    for event in ["hint", "correction", "rewind"] {
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
            let publication =
                store::restore::tests::discovery::publication_at(&st, tip(&st).height);
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
            settle(&mut st);
            let request = (step == "start").then(|| {
                let db = st.wallet_mut().db_mut();
                let request = db
                    .begin_receive_operation(account, 0, now + 60, now)
                    .unwrap()
                    .unwrap();
                db.finish_receive_operation(
                    account,
                    &request,
                    &accepted("deposit", None, now + 60),
                )
                .unwrap();
                request
            });
            match event {
                "hint" => hint(&mut st, 0),
                "correction" => {
                    let corrected =
                        zcash_client_backend::data_api::one_time_ivk::restore::RecoveryPublication {
                            history_revision: 1,
                            ..store::restore::tests::discovery::publication_at(
                                &st,
                                tip(&st).height,
                            )
                        };
                    assert!(
                        st.wallet_mut()
                            .db_mut()
                            .begin_one_time_recovery(account, corrected, true)
                            .unwrap()
                    );
                }
                _ => {
                    let floor = tip(&st).height - 1;
                    st.truncate_to_height(floor);
                    st.generate_and_scan_empty_blocks(2);
                }
            }
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
                "{event} {step}"
            );
            settle(&mut st);
            assert_eq!(attempt(&mut st), Ok(()), "{event} {step}");
        }
    }
}

/// After seed recovery completes, index 0 is reserved and a rewind drops the block its
/// history was checked through. Rolling filters then see no hit, so only the recheck the
/// rewind queued can release the hold: it is runnable at once, and once it settles the
/// reservation resumes. With discovery off, reservations are refused outright, and the
/// queued recheck runs when discovery is enabled again.
#[test]
fn a_rewound_reservation_is_released_by_its_queued_recheck() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks(5);
    let account = st.test_account().unwrap().id();
    let now = clock_now();
    check_window(&mut st);
    assert!(
        st.wallet()
            .db()
            .one_time_recovery(account, now)
            .unwrap()
            .restore_complete
    );
    let prepare = |st: &mut State| {
        st.wallet_mut()
            .db_mut()
            .prepare_receive_reservation(account, now)
            .unwrap()
            .map(|key| key.key_id().index())
    };
    assert_eq!(prepare(&mut st), Ok(0));

    let floor = tip(&st).height - 1;
    st.truncate_to_height(floor);
    st.generate_and_scan_empty_blocks(2);
    filter(&mut st, &[]);
    assert_eq!(prepare(&mut st), Err(ReservationPolicy::ReceiveHistory));
    let queued = store::restore::tests::discovery::status(st.wallet().db(), account);
    assert!(
        queued
            .lookups
            .iter()
            .any(|w| w.work.key == KeyId::new(Purpose::Receive, 0)),
        "the rewind queued a runnable recheck"
    );

    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    assert_eq!(prepare(&mut st), Err(ReservationPolicy::Disabled));
    st.wallet_mut()
        .db_mut()
        .set_one_time_recovery_enabled(account, true)
        .unwrap();
    settle(&mut st);
    assert_eq!(prepare(&mut st), Ok(0));
}

/// Every key that entered automatic monitoring since `before` was read, with the filter
/// frontier then at `frontier`, has history settled through that frontier, a runnable
/// lookup reaching it, coverage behind it for a filter re-check, or a funding height past
/// it, since filters never watched it there. Returns the monitored keys
/// and frontier for the next check.
fn assert_entered_with_history(
    st: &State,
    before: &[KeyId],
    frontier: Option<BlockHeight>,
) -> (Vec<KeyId>, Option<BlockHeight>) {
    let account = st.test_account().unwrap().id();
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    let after: Vec<KeyId> = receivers.iter().map(|w| w.work.key).collect();
    for key in after.iter().filter(|k| !before.contains(k)) {
        let Some(frontier) = frontier else { break };
        let covered: bool = value(
            st.wallet().conn(),
            "SELECT EXISTS(SELECT 1 FROM ironwood_one_time_keys k
                 JOIN accounts a ON a.id = k.account_id
                 LEFT JOIN ironwood_one_time_lookups l ON l.one_time_key_id = k.id
                 WHERE a.uuid = ?1 AND k.purpose = ?2 AND k.key_index = ?3
                   AND (l.done_height >= ?4 OR k.covered_height < ?4 OR k.funding_height > ?4
                     OR (l.target_height >= ?4 AND l.reasons & 3 != 0 AND l.read_complete = 0)
                     OR EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                         WHERE p.one_time_key_id = k.id)))",
            rusqlite::params![
                account.0,
                u8::from(key.purpose() == Purpose::Receive),
                key.index().to_be_bytes(),
                u32::from(frontier)
            ],
        );
        assert!(
            covered,
            "{key:?} entered monitoring with no history through the filter frontier"
        );
    }
    let frontier = st
        .wallet()
        .db()
        .one_time_recovery(account, clock_now())
        .unwrap()
        .filter_frontier
        .map(|f| f.height);
    (after, frontier)
}

/// Seeded sequences of payments, reservations, positive hints, empty filter batches,
/// rewinds, corrections, catch-up, toggles, and refund keys being paid and retired or
/// returned to monitoring by statuses. Every status read checks the no-stall invariant,
/// including that a held reservation always has runnable work (see
/// `restore::tests::discovery::assert_no_stall`). After each step, every key that entered
/// monitoring has its history queued (see [`assert_entered_with_history`]), and settling
/// at the end releases every hold.
#[test]
fn seeded_reservation_sequences_never_hold_without_work() {
    use store::restore::tests::discovery::status;
    for seed in 0..16u64 {
        let mut rng = seed;
        let mut below = |bound: u64| {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (rng >> 33) % bound
        };
        let mut st = scanned_wallet();
        st.generate_and_scan_empty_blocks(5);
        let account = st.test_account().unwrap().id();
        let now = clock_now();
        check_window(&mut st);
        let (mut monitored, mut frontier) = assert_entered_with_history(&st, &[], None);
        let mut observed = now;
        for _ in 0..20 {
            let has_frontier = st
                .wallet()
                .db()
                .one_time_recovery(account, now)
                .unwrap()
                .filter_frontier
                .is_some();
            match below(10) {
                0 => {
                    let index = below(4);
                    store::restore::tests::discovery::pay_candidate(
                        &mut st,
                        KeyId::new(Purpose::Receive, index),
                    );
                }
                1 => {
                    let _ = st
                        .wallet_mut()
                        .db_mut()
                        .prepare_receive_reservation(account, now)
                        .unwrap();
                }
                2 if has_frontier => hint(&mut st, below(4)),
                3 if has_frontier => filter(&mut st, &[]),
                4 => {
                    let floor = tip(&st).height - 1 - below(2) as u32;
                    st.truncate_to_height(floor);
                    st.generate_and_scan_empty_blocks(2);
                }
                5 => {
                    let revision = status(st.wallet().db(), account).token.history_revision;
                    let corrected =
                        zcash_client_backend::data_api::one_time_ivk::restore::RecoveryPublication {
                            history_revision: revision + 1,
                            ..store::restore::tests::discovery::publication_at(
                                &st,
                                tip(&st).height,
                            )
                        };
                    assert!(
                        st.wallet_mut()
                            .db_mut()
                            .begin_one_time_recovery(account, corrected, true)
                            .unwrap()
                    );
                }
                6 => {
                    let db = st.wallet_mut().db_mut();
                    db.set_one_time_recovery_enabled(account, false).unwrap();
                    status(db, account);
                    db.set_one_time_recovery_enabled(account, true).unwrap();
                }
                7 => {
                    store::restore::tests::discovery::pay_candidate(
                        &mut st,
                        KeyId::new(Purpose::Refund, below(2)),
                    );
                }
                8 => {
                    // A funded refund key's swap is active, ends with no refund, or
                    // reports one, retiring the key or returning it to monitoring.
                    let index = below(2);
                    let key = KeyId::new(Purpose::Refund, index);
                    let height = tip(&st).height;
                    recover(st.wallet_mut().db_mut(), account, key, height);
                    let status = match below(3) {
                        0 => Active,
                        1 => Terminal(ReceiptExpectation::None),
                        _ => Terminal(ReceiptExpectation::Positive(Some(
                            Zatoshis::const_from_u64(100_000),
                        ))),
                    };
                    observed += 60;
                    let observation = zakura_one_time_ivk::swap::Observation {
                        status,
                        funded: true,
                        receipts: vec![],
                    };
                    let operation = (format!("refund-{index}"), now + 3_600);
                    observe_with(
                        st.wallet_mut().db_mut(),
                        account,
                        key,
                        (&operation.0, operation.1),
                        observation,
                        observed,
                    )
                    .unwrap();
                }
                _ => settle(&mut st),
            }
            status(st.wallet().db(), account);
            (monitored, frontier) = assert_entered_with_history(&st, &monitored, frontier);
        }
        settle(&mut st);
        settle(&mut st);
        let held: u32 = value(
            st.wallet().conn(),
            "SELECT COUNT(*) FROM ironwood_one_time_keys k WHERE k.purpose = 1 AND k.used = 0
               AND k.reserved_at IS NOT NULL AND k.released_at IS NULL
               AND EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                   WHERE l.one_time_key_id = k.id AND l.reasons & 4 != 0)",
            [],
        );
        assert_eq!(held, 0, "seed {seed}: settling releases every hold");
    }
}

/// Whether receive index `index` is reserved and not released.
fn held(st: &State, index: u64) -> bool {
    value(
        st.wallet().conn(),
        "SELECT reserved_at IS NOT NULL AND released_at IS NULL FROM ironwood_one_time_keys
         WHERE purpose = 1 AND key_index = ?1",
        [index.to_be_bytes()],
    )
}

/// Receive index `index`'s `reserved_at` and `reservation_floor`.
fn reservation(st: &State, index: u64) -> (Option<i64>, Option<i64>) {
    row(
        st.wallet().conn(),
        "SELECT reserved_at, reservation_floor FROM ironwood_one_time_keys
         WHERE purpose = 1 AND key_index = ?1",
        [index.to_be_bytes()],
    )
}

/// The number of stored provider operations.
fn operations(st: &State) -> u32 {
    value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_operations",
        [],
    )
}

/// Records the provider's `status` for `deposit` and `memo` at `at`, returning whether an
/// operation matched.
fn report(
    st: &mut State,
    (deposit, memo): (&str, Option<&str>),
    status: zakura_one_time_ivk::swap::OperationStatus,
    funded: bool,
    at: i64,
) -> bool {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .record_operation_status(
            account,
            deposit,
            memo,
            Observation {
                status,
                funded,
                receipts: vec![],
            },
            at,
        )
        .unwrap()
}

/// A draft is reusable, after a restart too, until the deadline of its latest request: the
/// requested one when the provider rejected the quote or never answered, else the accepted
/// one, which can only lower it. Until then the same address and reservation resume and
/// take another request. From then `begin` refuses it as stale without storing anything,
/// and the next reservation reissues the unpaid address under a new floor.
#[test]
fn a_draft_is_reusable_until_its_latest_request_expires() {
    for outcome in ["rejected", "unanswered", "accepted"] {
        let mut st = scanned_wallet();
        let now = clock_now();
        let account = st.test_account().unwrap().id();
        assert_eq!(reserve_receive(&mut st, now).key_id().index(), 0);
        let db = st.wallet_mut().db_mut();
        let request = db
            .begin_receive_operation(account, 0, now + 120, now)
            .unwrap()
            .unwrap();
        let expiry = match outcome {
            "rejected" => {
                db.finish_receive_operation(account, &request, &OperationOutcome::Rejected)
                    .unwrap();
                now + 120
            }
            "unanswered" => now + 120,
            _ => {
                db.finish_receive_operation(account, &request, &accepted("draft", None, now + 60))
                    .unwrap();
                now + 60
            }
        };
        let (reserved_at, floor) = reservation(&st, 0);
        // Reopening reseeds the fixture's request generator, so it gets another seed.
        let path = st.wallet().data_file_path().to_owned();
        *st.wallet_mut().db_mut() = WalletDb::for_path(
            path,
            *st.network(),
            crate::testing::db::test_clock(),
            zcash_client_backend::data_api::testing::TestRng::seed_from_u64(1),
        )
        .unwrap();

        chain_agrees(st.wallet().db(), expiry - 1);
        let db = st.wallet_mut().db_mut();
        let resumed = db
            .prepare_receive_reservation(account, expiry - 1)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.key_id().index(), 0, "{outcome}");
        assert_eq!(reservation(&st, 0), (reserved_at, floor), "{outcome}");
        let db = st.wallet_mut().db_mut();
        db.begin_receive_operation(account, 0, expiry, expiry - 1)
            .unwrap()
            .unwrap();

        chain_agrees(st.wallet().db(), expiry);
        let before = operations(&st);
        let db = st.wallet_mut().db_mut();
        assert_eq!(
            db.begin_receive_operation(account, 0, expiry + 600, expiry)
                .unwrap(),
            Err(ReservationPolicy::Stale),
            "{outcome}"
        );
        assert_eq!(operations(&st), before);
        let db = st.wallet_mut().db_mut();
        let reissued = db
            .prepare_receive_reservation(account, expiry)
            .unwrap()
            .unwrap();
        assert_eq!(reissued.key_id().index(), 0, "{outcome}");
        assert_eq!(
            reservation(&st, 0),
            (Some(expiry), Some(i64::from(before))),
            "{outcome}"
        );
        let db = st.wallet_mut().db_mut();
        db.begin_receive_operation(account, 0, expiry + 600, expiry)
            .unwrap()
            .unwrap();
    }
}

/// A device clock days ahead of the chain cannot reclaim a started reservation while its
/// deadline has not passed by block time, since the provider may still take a deposit, and
/// its quote still starts. Once the chain catches up, a fresh unfunded status reclaims it.
#[test]
fn a_fast_clock_cannot_reclaim_a_started_reservation_before_the_deadline_by_block_time() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (_, request) = quote(&mut st, now, "fast", true);
    let fast = now + 5 * 86_400;
    let awaiting = zakura_one_time_ivk::swap::OperationStatus::AwaitingDeposit;
    assert!(report(&mut st, ("fast", None), awaiting, false, fast - 10));
    assert!(held(&st, 0));
    st.wallet_mut()
        .db_mut()
        .start_receive_operation(account, &request, fast)
        .unwrap()
        .unwrap();
    chain_agrees(st.wallet().db(), fast);
    assert!(report(&mut st, ("fast", None), awaiting, false, fast));
    assert!(!held(&st, 0));
}

/// A request finishes one way only: rejecting it again is harmless, but a rejected quote
/// can be neither accepted nor started.
#[test]
fn a_rejected_request_keeps_its_outcome() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    let request = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    for _ in 0..2 {
        db.finish_receive_operation(account, &request, &OperationOutcome::Rejected)
            .unwrap();
    }
    assert!(matches!(
        db.finish_receive_operation(account, &request, &accepted("late", None, now + 60)),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(
        db.start_receive_operation(account, &request, now).unwrap(),
        Err(ReservationPolicy::Stale)
    );
}

/// A reservation without an operation floor, as one made before the floor existed, counts
/// every request on its key, even one begun before `reserved_at` after the clock was set
/// back. While that request is live the draft resumes. Once it has expired, `begin` refuses
/// the reservation as stale without storing another request.
#[test]
fn a_reservation_without_a_floor_counts_every_request() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    db.begin_receive_operation(account, 0, now + 120, now)
        .unwrap()
        .unwrap();
    exec(
        st.wallet().conn(),
        "UPDATE ironwood_one_time_keys SET reservation_floor = NULL, reserved_at = ?1
         WHERE purpose = 1 AND key_index = X'0000000000000000'",
        [now + 10],
    );
    let db = st.wallet_mut().db_mut();
    let resumed = db
        .prepare_receive_reservation(account, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(resumed.key_id().index(), 0);
    db.begin_receive_operation(account, 0, now + 120, now + 60)
        .unwrap()
        .unwrap();

    chain_agrees(st.wallet().db(), now + 120);
    let before = operations(&st);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .begin_receive_operation(account, 0, now + 600, now + 120)
            .unwrap(),
        Err(ReservationPolicy::Stale)
    );
    assert_eq!(operations(&st), before);
}

/// A started reservation is reclaimed only on a fresh conclusive status. A funded swap's
/// is a final status without a refund, not an inconclusive one. An unfunded swap's status
/// must have arrived within the last two minutes, and a stale one arriving late never
/// replaces a newer one. Deposit evidence an older status carried sticks, so a later fresh
/// unfunded status cannot reclaim the address.
#[test]
fn a_started_reservation_needs_a_fresh_conclusive_status() {
    let awaiting = zakura_one_time_ivk::swap::OperationStatus::AwaitingDeposit;
    let account_of = |st: &State| st.test_account().unwrap().id();

    // A funded swap ends inconclusively, then without a refund.
    let mut st = scanned_wallet();
    let now = clock_now();
    quote(&mut st, now, "funded", true);
    chain_agrees(st.wallet().db(), now + 120);
    let unknown = Terminal(ReceiptExpectation::Unknown);
    assert!(report(&mut st, ("funded", None), unknown, true, now + 120));
    assert!(held(&st, 0), "an inconclusive end may still owe a refund");
    let none = Terminal(ReceiptExpectation::None);
    assert!(report(&mut st, ("funded", None), none, true, now + 121));
    assert!(!held(&st, 0));

    // An unfunded swap's status goes stale, then a late older one cannot refresh it.
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = account_of(&st);
    quote(&mut st, now, "unfunded", true);
    assert!(report(
        &mut st,
        ("unfunded", None),
        awaiting,
        false,
        now + 59
    ));
    chain_agrees(st.wallet().db(), now + 300);
    let _ = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now + 300)
        .unwrap();
    assert!(held(&st, 0), "a stale status reclaims nothing");
    assert!(report(
        &mut st,
        ("unfunded", None),
        Active,
        false,
        now + 301
    ));
    assert!(report(
        &mut st,
        ("unfunded", None),
        awaiting,
        false,
        now + 300
    ));
    assert!(
        held(&st, 0),
        "an older status arriving late replaces nothing"
    );
    assert!(report(
        &mut st,
        ("unfunded", None),
        awaiting,
        false,
        now + 302
    ));
    assert!(!held(&st, 0));

    // A late older status that saw the deposit keeps the address.
    let mut st = scanned_wallet();
    let now = clock_now();
    quote(&mut st, now, "seen", true);
    assert!(report(&mut st, ("seen", None), awaiting, false, now + 2));
    assert!(report(&mut st, ("seen", None), Active, true, now + 1));
    chain_agrees(st.wallet().db(), now + 300);
    assert!(report(&mut st, ("seen", None), awaiting, false, now + 300));
    assert!(held(&st, 0), "the deposit evidence sticks");
}

/// How long past its deadline a started quote with no fresh conclusive status keeps its slot.
const STARTED_GRACE: i64 = 24 * 60 * 60;

/// Prepares a receive reservation at device time `now`, returning the index it issued.
fn issue(st: &mut State, now: i64) -> Option<u64> {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now)
        .unwrap()
        .ok()
        .map(|key| key.key_id().index())
}

/// A started quote that never gets a status holds its slot until a day past its deadline,
/// then the slot is released and its unpaid address is reissued under a new floor.
#[test]
fn a_started_quote_without_a_status_releases_a_day_after_its_deadline() {
    let mut st = scanned_wallet();
    let now = clock_now();
    quote(&mut st, now, "silent", true);
    let deadline = now + 60;
    for held_at in [deadline + 23 * 3600, deadline + STARTED_GRACE - 1] {
        chain_agrees(st.wallet().db(), held_at);
        assert_ne!(issue(&mut st, held_at), Some(0));
        assert!(
            held(&st, 0),
            "held at {}s past the deadline",
            held_at - deadline
        );
    }
    let later = deadline + 25 * 3600;
    chain_agrees(st.wallet().db(), later);
    let before = operations(&st);
    assert_eq!(issue(&mut st, later), Some(0));
    assert_eq!(reservation(&st, 0), (Some(later), Some(i64::from(before))));
}

/// The day's limit applies only to a quote with no status. One seen funded, or whose last
/// status was active, keeps its slot past it.
#[test]
fn a_funded_or_active_quote_keeps_its_slot_past_the_started_limit() {
    let inconclusive = Terminal(ReceiptExpectation::Unknown);
    for (status, funded) in [(inconclusive, true), (Active, false)] {
        let mut st = scanned_wallet();
        let now = clock_now();
        quote(&mut st, now, "kept", true);
        assert!(report(&mut st, ("kept", None), status, funded, now + 1));
        let later = now + 60 + 25 * 3600;
        chain_agrees(st.wallet().db(), later);
        assert_ne!(issue(&mut st, later), Some(0));
        assert!(held(&st, 0), "{status:?}, funded {funded}");
    }
}

/// Releasing a silent quote's slot keeps its address monitored, so a payment arriving
/// afterwards is still recovered, and the paid address is not issued again.
#[test]
fn a_payment_after_a_silent_quote_is_released_is_still_recovered() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let (key, _) = quote(&mut st, now, "late", true);
    let later = now + 60 + 25 * 3600;
    chain_agrees(st.wallet().db(), later);
    let account = st.test_account().unwrap().id();
    // A status for an address this wallet never quoted only runs the release check.
    assert!(!report(&mut st, ("unquoted", None), Active, false, later));
    assert!(!held(&st, 0));
    store::restore::tests::discovery::pay_candidate(&mut st, key);
    let (_, receivers) = st.wallet().db().one_time_receivers(account).unwrap();
    assert!(
        receivers.iter().any(|r| r.work.key == key),
        "still monitored"
    );
    catch_up(&mut st);
    assert_eq!(
        store::restore::tests::discovery::one_time_notes(&st),
        [(100_000, false)]
    );
    let next = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, later)
        .unwrap();
    assert!(next.is_err() || next.unwrap().key_id().index() != 0);
}

/// A device clock days ahead cannot release a silent quote's slot while block time is
/// within a day of its deadline. Once block time passes that, the slot is released.
#[test]
fn a_fast_clock_cannot_release_a_silent_quote_early() {
    let mut st = scanned_wallet();
    let now = clock_now();
    quote(&mut st, now, "silent", true);
    let deadline = now + 60;
    let fast = deadline + 5 * 86_400;
    chain_agrees(st.wallet().db(), deadline + STARTED_GRACE - 1);
    assert_ne!(issue(&mut st, fast), Some(0));
    assert!(held(&st, 0));
    chain_agrees(st.wallet().db(), deadline + STARTED_GRACE);
    assert_eq!(issue(&mut st, fast), Some(0));
}

/// A funded quote whose latest status awaits a deposit is held by its funding evidence past
/// the day's limit. A late payout recovered then must not let that limit release it: a reorg
/// that drops the payout and an empty replacement history mark the key unpaid again, and
/// reissuing it would hand the funded quote's receiver to a second quote.
#[test]
fn a_reorged_late_payout_keeps_a_funded_quote_past_the_started_limit() {
    let awaiting = zakura_one_time_ivk::swap::OperationStatus::AwaitingDeposit;
    let mut st = scanned_wallet();
    let now = clock_now();
    let (key, _) = quote(&mut st, now, "funded", true);
    assert!(report(&mut st, ("funded", None), awaiting, false, now + 2));
    assert!(report(&mut st, ("funded", None), Active, true, now + 1));
    let later = now + 60 + 25 * 3600;
    chain_agrees(st.wallet().db(), later);
    assert_ne!(issue(&mut st, later), Some(0));
    assert!(held(&st, 0), "the funding evidence holds it");

    let floor = tip(&st).height;
    store::restore::tests::discovery::pay_candidate(&mut st, key);
    catch_up(&mut st);
    assert_eq!(
        store::restore::tests::discovery::one_time_notes(&st),
        [(100_000, false)]
    );
    chain_agrees(st.wallet().db(), later);
    assert_ne!(issue(&mut st, later), Some(0));
    assert!(held(&st, 0), "a paid key keeps needing a fresh status");

    st.truncate_to_height(floor);
    st.generate_and_scan_empty_blocks(3);
    check_window(&mut st);
    let used: bool = value(
        st.wallet().conn(),
        "SELECT used FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [0u64.to_be_bytes()],
    );
    assert!(!used, "the empty replacement history clears the payment");
    chain_agrees(st.wallet().db(), later);
    assert_ne!(issue(&mut st, later), Some(0));
    assert!(held(&st, 0));
}

/// Beginning a request needs a future deadline, and each request gets a fresh identity.
#[test]
fn begin_needs_a_future_deadline_and_returns_a_fresh_request() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    assert!(matches!(
        db.begin_receive_operation(account, 0, now, now),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(operations(&st), 0);
    let db = st.wallet_mut().db_mut();
    let first = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    let second = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    assert_ne!(first, second);
    for request in [&first, &second] {
        assert_eq!(request.len(), 32);
        assert!(request.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

/// Deposit instructions bind one operation in the account. Repeating an acceptance can
/// lower its deadline but not change its address or memo, and another request, on the same
/// reservation or another, cannot take the same instructions, though another memo makes
/// them distinct. A status then matches the one operation, and an unknown request is an
/// error.
#[test]
fn deposit_instructions_bind_one_operation_and_cannot_change() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    let first = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    let sibling = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    let shared = || accepted("shared", Some("m1"), now + 60);
    for _ in 0..2 {
        db.finish_receive_operation(account, &first, &shared())
            .unwrap();
    }
    let invalid = |r: Result<(), SqliteClientError>| {
        matches!(r, Err(SqliteClientError::InvalidOneTimeIvkInput(_)))
    };
    assert!(invalid(db.finish_receive_operation(
        account,
        &sibling,
        &shared()
    )));
    assert!(invalid(db.finish_receive_operation(
        account,
        &first,
        &accepted("shared", Some("m2"), now + 60)
    )));
    assert!(invalid(db.finish_receive_operation(
        account,
        &first,
        &accepted("shared", None, now + 60)
    )));
    db.start_receive_operation(account, &first, now)
        .unwrap()
        .unwrap();

    let other = reserve_receive(&mut st, now).key_id().index();
    assert_eq!(other, 1);
    let db = st.wallet_mut().db_mut();
    let elsewhere = db
        .begin_receive_operation(account, other, now + 60, now)
        .unwrap()
        .unwrap();
    assert!(invalid(db.finish_receive_operation(
        account,
        &elsewhere,
        &shared()
    )));
    db.finish_receive_operation(account, &elsewhere, &accepted("shared", None, now + 60))
        .unwrap();

    db.finish_receive_operation(account, &first, &accepted("shared", Some("m1"), now + 30))
        .unwrap();
    assert_eq!(
        db.start_receive_operation(account, &first, now)
            .unwrap()
            .unwrap(),
        ReceiveDeposit {
            address: "shared".into(),
            memo: Some("m1".into()),
            deadline: now + 30,
        }
    );
    assert!(report(
        &mut st,
        ("shared", Some("m1")),
        Active,
        false,
        now + 5
    ));
    let observed: Vec<(String, i64)> = rows(
        st.wallet().conn(),
        "SELECT request, observed_at FROM ironwood_one_time_operations
         WHERE reference = 'shared' ORDER BY id",
        [],
    );
    assert_eq!(observed, [(first.clone(), now + 5), (elsewhere, now)]);
    assert!(
        st.wallet_mut()
            .db_mut()
            .start_receive_operation(account, "unknown", now)
            .is_err()
    );
}

/// A request keeps the caller's clock as its time, even behind block times ahead of it, and
/// an accepted deadline is checked against the earlier of the two, so one still ahead of the
/// request is kept though the latest block time has passed it.
#[test]
fn finish_checks_the_deadline_against_the_real_request_time() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    chain_agrees(st.wallet().db(), now + 3600);
    let db = st.wallet_mut().db_mut();
    let request = db
        .begin_receive_operation(account, 0, now + 3600, now)
        .unwrap()
        .unwrap();
    let begun: i64 = value(
        st.wallet().conn(),
        "SELECT begun_at FROM ironwood_one_time_operations WHERE request = ?1",
        [&request],
    );
    assert_eq!(begun, now);
    st.wallet_mut()
        .db_mut()
        .finish_receive_operation(account, &request, &accepted("a", None, now + 1800))
        .unwrap();
    let deadline: i64 = value(
        st.wallet().conn(),
        "SELECT deadline FROM ironwood_one_time_operations WHERE request = ?1",
        [&request],
    );
    assert_eq!(deadline, now + 1800);
}

/// An accepted deadline that has passed by the earlier of the request time and the latest
/// block time is refused without changing the operation, but one only behind a fast device
/// clock is kept, since the provider sets it by its own clock.
#[test]
fn finish_refuses_an_accepted_deadline_that_has_passed() {
    let mut st = scanned_wallet();
    let chain = clock_now();
    let fast = chain + 86_400;
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, chain);
    let db = st.wallet_mut().db_mut();
    let request = db
        .begin_receive_operation(account, 0, fast + 60, fast)
        .unwrap()
        .unwrap();
    let stored = |st: &State| -> (Option<String>, i64) {
        row(
            st.wallet().conn(),
            "SELECT reference, deadline FROM ironwood_one_time_operations WHERE request = ?1",
            [&request],
        )
    };
    let before = stored(&st);
    for passed in [chain - 30 * 86_400, chain] {
        assert!(matches!(
            st.wallet_mut().db_mut().finish_receive_operation(
                account,
                &request,
                &accepted("a", None, passed)
            ),
            Err(SqliteClientError::InvalidOneTimeIvkInput(_))
        ));
        assert_eq!(stored(&st), before);
    }
    let db = st.wallet_mut().db_mut();
    db.finish_receive_operation(account, &request, &accepted("a", None, chain + 3600))
        .unwrap();
    assert_eq!(
        db.start_receive_operation(account, &request, fast)
            .unwrap()
            .unwrap()
            .deadline,
        chain + 3600
    );
}

/// Starting refuses an accepted quote whose deadline has passed by the earlier of the
/// caller's clock and the latest block time, on a first start or a restart, without
/// marking it started. A device clock days slow still starts a live quote.
#[test]
fn start_refuses_a_quote_past_its_deadline() {
    let started = |st: &State, request: &str| -> bool {
        value(
            st.wallet().conn(),
            "SELECT started FROM ironwood_one_time_operations WHERE request = ?1",
            [request],
        )
    };
    // A late first start.
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (_, request) = quote(&mut st, now, "late", false);
    chain_agrees(st.wallet().db(), now + 120);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .start_receive_operation(account, &request, now + 120)
            .unwrap(),
        Err(ReservationPolicy::Stale)
    );
    assert!(!started(&st, &request));

    // A device clock two days slow.
    let mut st = scanned_wallet();
    let now = clock_now();
    let slow = now - 2 * 86_400;
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    let request = db
        .begin_receive_operation(account, 0, now + 3600, slow)
        .unwrap()
        .unwrap();
    db.finish_receive_operation(account, &request, &accepted("slow", None, now + 3600))
        .unwrap();
    db.start_receive_operation(account, &request, slow + 10)
        .unwrap()
        .unwrap();

    // A late restart.
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (_, request) = quote(&mut st, now, "restart", true);
    chain_agrees(st.wallet().db(), now + 120);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .start_receive_operation(account, &request, now + 120)
            .unwrap(),
        Err(ReservationPolicy::Stale)
    );
}

/// A reservation with two accepted quote requests starts only one, so one receiver never
/// has two quotes a user could fund. Restarting the first returns its instructions again,
/// and the started reservation takes no new request.
#[test]
fn one_reservation_starts_only_one_accepted_quote() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    let first = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    let second = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    db.finish_receive_operation(account, &first, &accepted("first", None, now + 60))
        .unwrap();
    db.finish_receive_operation(account, &second, &accepted("second", None, now + 60))
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            db.start_receive_operation(account, &first, now)
                .unwrap()
                .unwrap()
                .address,
            "first"
        );
    }
    assert_eq!(
        db.start_receive_operation(account, &second, now).unwrap(),
        Err(ReservationPolicy::Stale)
    );
    let started: u32 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_operations WHERE started = 1",
        [],
    );
    assert_eq!(started, 1);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .begin_receive_operation(account, 0, now + 60, now)
            .unwrap(),
        Err(ReservationPolicy::Stale)
    );
}

/// A paid reservation holding an unstarted quote edit and the started quote that was paid
/// is released only once every quote has settled: the edit's deadline has passed and the
/// paid quote's status is fresh. Both operations remain, and the paid address is not
/// issued again.
#[test]
fn paid_reservation_closes_once_every_quote_settles() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    reserve_receive(&mut st, now);
    let db = st.wallet_mut().db_mut();
    let edit = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    let paid = db
        .begin_receive_operation(account, 0, now + 60, now)
        .unwrap()
        .unwrap();
    db.finish_receive_operation(account, &edit, &accepted("edit", None, now + 60))
        .unwrap();
    db.finish_receive_operation(account, &paid, &accepted("paid", None, now + 60))
        .unwrap();
    db.start_receive_operation(account, &paid, now)
        .unwrap()
        .unwrap();
    let payment =
        store::restore::tests::discovery::pay_candidate(&mut st, KeyId::new(Purpose::Receive, 0));
    let owed = Terminal(ReceiptExpectation::Positive(None));
    let account_paid = |st: &mut State, at: i64| {
        st.wallet_mut()
            .db_mut()
            .record_operation_status(
                account,
                "paid",
                None,
                Observation {
                    status: owed,
                    funded: true,
                    receipts: vec![payment.txid],
                },
                at,
            )
            .unwrap()
    };
    assert!(account_paid(&mut st, now));
    catch_up(&mut st);
    let used: bool = value(
        st.wallet().conn(),
        "SELECT used FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = X'0000000000000000'",
        [],
    );
    assert!(used);
    let awaiting = zakura_one_time_ivk::swap::OperationStatus::AwaitingDeposit;
    chain_agrees(st.wallet().db(), now + 59);
    assert!(report(&mut st, ("edit", None), awaiting, false, now + 1));
    assert!(held(&st, 0));
    chain_agrees(st.wallet().db(), now + 300);
    assert!(report(&mut st, ("edit", None), awaiting, false, now + 300));
    assert!(held(&st, 0), "the paid quote's status is stale");
    assert!(account_paid(&mut st, now + 300));
    assert!(!held(&st, 0));
    assert_eq!(operations(&st), 2);
    let next = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now + 300)
        .unwrap();
    assert!(next.is_err() || next.unwrap().key_id().index() != 0);
}

/// An operation is found by its deposit address and memo: a status for another memo on the
/// same address matches nothing and changes nothing, and a payout status records its
/// expected amount but keeps the deadline.
#[test]
fn provider_statuses_update_the_operation_or_leave_it_alone() {
    let mut st = scanned_wallet();
    let now = clock_now();
    quote(&mut st, now, "payout", true);
    let stored = |st: &State| -> (i64, u8, Option<i64>, i64) {
        row(
            st.wallet().conn(),
            "SELECT observed_at, expectation, expected_value, deadline
             FROM ironwood_one_time_operations WHERE reference = 'payout'",
            [],
        )
    };
    let before = stored(&st);
    assert!(!report(
        &mut st,
        ("payout", Some("memo")),
        Active,
        false,
        now + 1
    ));
    assert_eq!(stored(&st), before);
    assert!(report(&mut st, ("payout", None), Active, false, now + 2));
    let owed = Terminal(ReceiptExpectation::Positive(Some(
        Zatoshis::const_from_u64(5_000),
    )));
    assert!(report(&mut st, ("payout", None), owed, false, now + 3));
    assert_eq!(stored(&st), (now + 3, 2, Some(5_000), before.3));
}

/// A fresh unfunded status reclaims an abandoned started reservation at once, keeping its
/// operation, so the next reservation reissues the address and the old quote cannot start
/// again. A paid one is released instead and its address is not issued again.
#[test]
fn statuses_reclaim_abandoned_reservations_and_release_paid_ones() {
    let awaiting = zakura_one_time_ivk::swap::OperationStatus::AwaitingDeposit;
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (_, old) = quote(&mut st, now, "abandoned", true);
    chain_agrees(st.wallet().db(), now + 120);
    assert!(report(
        &mut st,
        ("abandoned", None),
        awaiting,
        false,
        now + 120
    ));
    assert!(!held(&st, 0));
    assert_eq!(operations(&st), 1);
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.prepare_receive_reservation(account, now + 120)
            .unwrap()
            .unwrap()
            .key_id()
            .index(),
        0
    );
    assert_eq!(
        db.start_receive_operation(account, &old, now + 120)
            .unwrap(),
        Err(ReservationPolicy::Stale)
    );

    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let (key, _) = quote(&mut st, now, "paid", true);
    let payment = store::restore::tests::discovery::pay_candidate(&mut st, key);
    catch_up(&mut st);
    chain_agrees(st.wallet().db(), now + 120);
    promise_payout(&mut st, "paid", &[payment.txid], now + 120);
    assert!(!held(&st, 0));
    let next = st
        .wallet_mut()
        .db_mut()
        .prepare_receive_reservation(account, now + 120)
        .unwrap();
    assert!(next.is_err() || next.unwrap().key_id().index() != 0);
}

/// A payment the directory reported for a reserved address but that waits for admission
/// may be another device's, so beginning or starting a quote on it waits with
/// `ReceiveHistory`, and issuance passes it by.
#[test]
fn quoting_waits_for_a_queued_payment_to_its_address() {
    let mut st = scanned_wallet();
    let now = clock_now();
    let account = st.test_account().unwrap().id();
    let key = reserve_receive(&mut st, now).key_id();
    let db = st.wallet_mut().db_mut();
    let request = db
        .begin_receive_operation(account, 0, now + 3600, now)
        .unwrap()
        .unwrap();
    db.finish_receive_operation(account, &request, &accepted("queued", None, now + 3600))
        .unwrap();
    exec(
        st.wallet().conn(),
        "INSERT INTO ironwood_one_time_payment_recovery
             (one_time_key_id, txid, action_index, height, block_hash, tx_index, position,
              encrypted_note)
         SELECT id, zeroblob(32), 0, 1, zeroblob(32), 1, 0, zeroblob(148)
         FROM ironwood_one_time_keys WHERE purpose = 1 AND key_index = ?1",
        [key.index().to_be_bytes()],
    );
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.begin_receive_operation(account, 0, now + 3600, now)
            .unwrap(),
        Err(ReservationPolicy::ReceiveHistory)
    );
    assert_eq!(
        db.start_receive_operation(account, &request, now).unwrap(),
        Err(ReservationPolicy::ReceiveHistory)
    );
    let next = db.prepare_receive_reservation(account, now).unwrap();
    assert!(next.is_err() || next.unwrap().key_id().index() != 0);
}
