use super::*;
use zakura_dynamic_ivk::lifecycle::{
    COMPLETION_LIMIT_SECS as LIMIT, NearStatus, Observation,
    OperationStatus::{Active, Terminal},
    ReceiptExpectation::{None as NoReceipt, Positive, Unknown},
    near_observation,
};

const HOUR: i64 = 60 * 60;
const DAY: i64 = 24 * HOUR;

/// Unix time the fixed test clock stamps on registered keys as `registered_at`.
fn registered_at() -> i64 {
    unix_now(&test_clock())
}

/// The height above the scanned tip, where a newly issued key starts scanning.
fn next_height(st: &State) -> BlockHeight {
    st.wallet().chain_height().unwrap().unwrap() + 1
}

/// Issues the next refund key, trial-decrypted from [`next_height`].
fn refund_key(st: &mut State) -> DynamicKey {
    let account = st.test_account().unwrap().id();
    let from = next_height(st);
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, from)
}

/// Mines and scans a block paying `value` to `key`, and returns its height.
fn pay(st: &mut State, key: &DynamicKey, value: u64) -> BlockHeight {
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(key.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(value),
    );
    st.scan_cached_blocks_with_dynamic_ivks(height, 1);
    height
}

/// Mines blocks until the latest receipt has the untrusted confirmations closing needs.
fn confirm(st: &mut State) {
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(9);
}

/// Closes the test account's finished keys at `now` and returns how many closed.
fn close(st: &mut State, now: i64) -> usize {
    let account = st.test_account().unwrap().id();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    close_at(st.wallet_mut().db_mut(), account, now, tip)
}

/// Records `status` at `now` for the test account's `key` operation `swap`.
fn observe_swap(st: &mut State, key: KeyId, status: OperationStatus, now: i64) {
    let account = st.test_account().unwrap().id();
    observe(st.wallet_mut().db_mut(), account, key, "swap", status, now).unwrap();
}

/// `operation`'s stored `(observed_at, expectation, expected_value, deadline)`.
fn operation_row(st: &State, operation: &str) -> (i64, u8, Option<i64>, Option<i64>) {
    st.wallet()
        .conn()
        .query_row(
            "SELECT observed_at, expectation, expected_value, deadline
             FROM ironwood_dynamic_operations WHERE reference = ?1",
            [operation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

/// Newer observations replace older ones, an older one arriving late is ignored, a
/// deadline only fills in a missing one, and an expected amount must be positive.
#[test]
fn observations_are_monotonic_and_only_fill_a_missing_deadline() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let expect = |value| Terminal(Positive(Some(Zatoshis::const_from_u64(value))));
    // Each observation, its time, and the stored row afterwards.
    for (status, deadline, at, row) in [
        (Active, None, 100, (100, 0, None, None)),
        (
            Terminal(NoReceipt),
            Some(1_000),
            200,
            (200, 1, None, Some(1_000)),
        ),
        (Active, Some(10), 150, (200, 1, None, Some(1_000))),
        (
            Terminal(Positive(None)),
            Some(2_000),
            300,
            (300, 2, None, Some(1_000)),
        ),
        (
            expect(70_000),
            None,
            400,
            (400, 2, Some(70_000), Some(1_000)),
        ),
        (Active, None, 450, (450, 0, None, Some(1_000))),
        (Terminal(Unknown), None, 500, (500, 3, None, Some(1_000))),
    ] {
        let observation = Observation { status, deadline };
        let db = st.wallet_mut().db_mut();
        observe_with(db, account, key, "swap", observation, at).unwrap();
        assert_eq!(operation_row(&st, "swap"), row, "at {at}");
    }
    let db = st.wallet_mut().db_mut();
    assert!(matches!(
        observe(db, account, key, "swap", expect(0), 600),
        Err(SqliteClientError::InvalidDynamicIvkInput(_))
    ));
    assert_eq!(operation_row(&st, "swap").0, 500);
}

/// A refund key whose deposit this wallet did not fund starts once the provider reports
/// a refund owed.
#[test]
fn a_refund_owed_starts_an_unfunded_refund_key() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = next_height(&st);
    // Reserved as issuance does: it starts only when its funding transaction is stored.
    let db = st.wallet_mut().db_mut();
    let key = tx(db, |c, p| {
        reserve_next(
            c,
            p,
            account,
            Purpose::Refund,
            from,
            Discovery::Funding,
            clock_now(),
        )
    })
    .unwrap()
    .unwrap()
    .key_id();
    observe(db, account, key, "deposit", Active, 100).unwrap();
    let record = |db: &mut Db, status: &str, at| {
        let status = NearStatus {
            status,
            ..Default::default()
        };
        let observation = near_observation(Purpose::Refund, &status);
        db.record_operation_status(account, "deposit", None, observation, false, at)
            .unwrap()
    };
    assert!(record(db, "PROCESSING", 100));
    assert!(scanning_keys(&st).is_empty());
    let db = st.wallet_mut().db_mut();
    assert!(record(db, "REFUNDED", 200));
    assert_eq!(scanning_keys(&st), [key]);
}

/// A final status with no receipt closes a key at once; an inconclusive one holds it
/// until the limit.
#[test]
fn a_final_status_closes_a_key_and_an_inconclusive_one_waits_for_the_limit() {
    for (status, open_at, closes_at) in [
        (Terminal(NoReceipt), None, HOUR),
        (Terminal(Unknown), Some(HOUR + DAY), LIMIT),
    ] {
        let mut st = scanned_wallet();
        let key = refund_key(&mut st).key_id();
        observe_swap(&mut st, key, status, registered_at() + HOUR);
        if let Some(open_at) = open_at {
            assert_eq!(close(&mut st, registered_at() + open_at), 0);
        }
        let closes_at = registered_at() + closes_at;
        assert_eq!(close(&mut st, closes_at), 1);
        let closed_at: Option<i64> = st
            .wallet()
            .conn()
            .query_row("SELECT closed_at FROM ironwood_receiving_keys", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(closed_at, Some(closes_at));
        assert_eq!(close(&mut st, closes_at + LIMIT), 0);
    }
}

/// A key expecting a receipt stays open until its receipts cover the expected amount,
/// or any receipt without one, with the untrusted confirmations, then closes.
#[test]
fn expected_receipts_keep_a_key_open_until_received_and_confirmed() {
    for (expected, payments) in [(Some(150_000), &[100_000, 50_000][..]), (None, &[10_000])] {
        let mut st = scanned_wallet();
        let key = refund_key(&mut st);
        let terminal = registered_at() + HOUR;
        let status = Terminal(Positive(expected.map(Zatoshis::const_from_u64)));
        observe_swap(&mut st, key.key_id(), status, terminal);
        for value in payments {
            assert_eq!(close(&mut st, terminal), 0);
            pay(&mut st, &key, *value);
        }
        st.generate_and_scan_empty_blocks_with_dynamic_ivks(8);
        assert_eq!(close(&mut st, terminal), 0);
        st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
        assert_eq!(close(&mut st, terminal), 1);
    }
}

#[test]
fn rewound_receipt_keeps_key_open_until_mined_again() {
    let mut st = scanned_wallet();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    let height = pay(&mut st, &key, 10_000);
    confirm(&mut st);
    st.truncate_to_height_retaining_cache(height - 1);
    assert_eq!(close(&mut st, terminal), 0);
    st.scan_cached_blocks_with_dynamic_ivks(height, 10);
    assert_eq!(close(&mut st, terminal), 1);
}

#[test]
fn a_rewind_reopens_a_closed_key_whose_receipt_it_unmines() {
    let mut st = scanned_wallet();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    let height = pay(&mut st, &key, 10_000);
    confirm(&mut st);
    assert_eq!(close(&mut st, terminal), 1);
    assert!(scanning_keys(&st).is_empty());
    // A repair rewind below the receipt un-mines it, so the key scans again and the
    // rescan mines the receipt again; the key closes once it is confirmed again.
    st.truncate_to_height_retaining_cache(height - 1);
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    // Past its limit, it waits for the unmined receipt, which can be mined until it expires.
    assert_eq!(close(&mut st, terminal + LIMIT), 0);
    st.scan_cached_blocks_with_dynamic_ivks(height, 10);
    assert_eq!(unspent_keys(&st, height + 9), [Some(key.key_id())]);
    assert_eq!(close(&mut st, terminal), 1);
}

#[test]
fn a_key_closes_once_its_last_operation_is_final() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let first = registered_at() + HOUR;
    let db = st.wallet_mut().db_mut();
    observe(db, account, key, "finished", Terminal(NoReceipt), first).unwrap();
    observe(db, account, key, "pending", Active, first).unwrap();
    assert_eq!(close(&mut st, first + DAY), 0);
    let last = first + 2 * HOUR;
    let db = st.wallet_mut().db_mut();
    observe(db, account, key, "pending", Terminal(NoReceipt), last).unwrap();
    assert_eq!(close(&mut st, last), 1);
}

/// Whatever the status, a key closes the completion limit after its latest deadline, or
/// after registration without one.
#[test]
fn the_limit_counts_from_the_latest_deadline_or_registration() {
    let registered = registered_at();
    let (earlier, later) = (registered + HOUR, registered + 2 * HOUR);
    let operations = [
        ("finished", Terminal(NoReceipt), Some(earlier)),
        ("pending", Active, Some(later)),
    ];
    for (operations, limit) in [
        (&operations[..], later + LIMIT),
        (&[("pending", Active, None)], registered + LIMIT),
        (&[], registered + LIMIT),
    ] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let key = refund_key(&mut st).key_id();
        for &(operation, status, deadline) in operations {
            let db = st.wallet_mut().db_mut();
            let observation = Observation { status, deadline };
            observe_with(db, account, key, operation, observation, registered).unwrap();
        }
        assert_eq!(close(&mut st, limit - 1), 0);
        assert_eq!(close(&mut st, limit), 1);
    }
}

#[test]
fn closing_uses_the_earlier_of_the_clock_and_the_tip_block_time() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    refund_key(&mut st);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let limit = registered_at() + LIMIT;
    let year = 365 * 24 * HOUR;
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, limit - 1, tip), 0);
    // A clock that runs fast does not move the tip block's time.
    let closed = db.close_finished_dynamic_keys(account, limit + year, tip);
    assert_eq!(closed.unwrap(), 0);
    st.wallet()
        .conn()
        .execute(
            "UPDATE blocks SET time = ?2 WHERE height = ?1",
            rusqlite::params![u32::from(tip), limit + year],
        )
        .unwrap();
    // One that runs slow only delays closing.
    let db = st.wallet_mut().db_mut();
    let closed = db.close_finished_dynamic_keys(account, limit - 1, tip);
    assert_eq!(closed.unwrap(), 0);
    let closed = db.close_finished_dynamic_keys(account, limit, tip);
    assert_eq!(closed.unwrap(), 1);
}

#[test]
fn keys_stay_open_while_a_rescan_is_queued() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let terminal = registered_at() + HOUR;
    let tip = st.wallet().chain_height().unwrap().unwrap();
    observe_swap(&mut st, key, Terminal(NoReceipt), terminal);
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, tip);
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .any(|r| r.block_range().contains(&tip))
    );
    assert_eq!(close(&mut st, terminal + DAY), 0);
    st.scan_cached_blocks_with_dynamic_ivks(tip, 1);
    assert_eq!(close(&mut st, terminal + DAY), 1);
}

/// An incoming key stays open while its reservation is, here held by a quote request
/// with an unknown outcome. Closing releases the reservation once it can, and an unpaid
/// key without one closes at its limit like any other.
#[test]
fn incoming_key_closes_only_once_paid_and_released() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = next_height(&st);
    let now = registered_at();
    let db = st.wallet_mut().db_mut();
    let reserved = prepare_from(db, account, now, from, None).unwrap().unwrap();
    let index = reserved.key_id().index();
    tx(db, |c, _| {
        store::reservations::begin(c, account, index, "pending", now + DAY, now)
    })
    .unwrap()
    .unwrap();
    let unpaid = reserve_key(db, account, Purpose::Receive, from);
    let terminal = now + HOUR;
    for key in [&reserved, &unpaid] {
        observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    }
    pay(&mut st, &reserved, 10_000);
    confirm(&mut st);
    let released = now + DAY + RECEIVE_RECLAIM_SECONDS;
    assert_eq!(close(&mut st, released - 1), 0);
    assert_eq!(close(&mut st, released), 1);
    assert_eq!(close(&mut st, now + LIMIT - 1), 0);
    assert_eq!(close(&mut st, now + LIMIT), 1);
    assert!(scanning_keys(&st).is_empty());
}

#[test]
fn abandoned_quote_edit_does_not_hold_a_released_key_open() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = next_height(&st);
    let now = registered_at();
    let deadline = now + HOUR;
    let db = st.wallet_mut().db_mut();
    let reservation = prepare_from(db, account, now, from, None).unwrap().unwrap();
    let index = reservation.key_id().index();
    for request in ["edit", "accepted"] {
        tx(db, |c, _| {
            store::reservations::begin(c, account, index, request, deadline, now)
        })
        .unwrap()
        .unwrap();
        db.finish_receive_operation(account, request, &accepted(request, None, deadline))
            .unwrap();
    }
    db.start_receive_operation(account, "accepted")
        .unwrap()
        .unwrap();
    pay(&mut st, &reservation, 70_000);
    confirm(&mut st);
    let released = deadline + RECEIVE_RECLAIM_SECONDS;
    let payout = Some(Zatoshis::const_from_u64(70_000));
    for (request, status, amount_out, funded) in [
        ("edit", "PENDING_DEPOSIT", None, false),
        ("accepted", "SUCCESS", payout, true),
    ] {
        let status = NearStatus {
            status,
            amount_out,
            deadline: Some(deadline),
            ..Default::default()
        };
        let observation = near_observation(Purpose::Receive, &status);
        st.wallet_mut()
            .db_mut()
            .record_operation_status(account, request, None, observation, funded, released)
            .unwrap();
    }
    assert_eq!(close(&mut st, released + DAY), 1);
}

#[test]
fn closed_key_stops_scanning_but_keeps_its_notes() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let height = pay(&mut st, &key, 40_000);
    let terminal = registered_at() + HOUR;
    observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    // The receipt is not deep enough yet to survive a reorg on a closed key.
    assert_eq!(close(&mut st, terminal), 0);
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    confirm(&mut st);
    assert_eq!(close(&mut st, terminal), 1);
    assert!(scanning_keys(&st).is_empty());
    let notes = st
        .wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account, height)
        .unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].dynamic_key_id(), Some(key.key_id()));
    assert_eq!(notes[0].note().value().inner(), 40_000);
}

#[test]
fn keys_close_only_at_the_confirmed_tip() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    let tip = st.wallet().chain_height().unwrap().unwrap();
    observe_swap(&mut st, key.key_id(), Terminal(NoReceipt), terminal);
    // The network reports a block the wallet has not stored or scanned yet.
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, terminal + DAY, tip + 1), 0);
    assert_eq!(close_at(db, account, terminal + DAY, tip), 1);
}
