use super::*;
use zakura_swap_receiving::lifecycle::{
    COMPLETION_LIMIT_SECS as LIMIT, Observation,
    OperationStatus::{Active, Terminal},
    ProviderStatus,
    ReceiptExpectation::{None as NoReceipt, Positive, Unknown},
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
fn refund_key(st: &mut State) -> RegisteredKey {
    let account = st.test_account().unwrap().id();
    let from = next_height(st);
    st.wallet_mut()
        .db_mut()
        .reserve_swap_receiving_key_from(account, Purpose::Refund, from)
        .unwrap()
}

/// Mines and scans a block paying `value` to `key`, and returns its height.
fn pay(st: &mut State, key: &RegisteredKey, value: u64) -> BlockHeight {
    let (height, _, _) = st.generate_next_block(
        &IronwoodFvk(key.full_viewing_key().clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(value),
    );
    st.scan_cached_blocks(height, 1);
    height
}

/// Mines blocks until the latest receipt has the untrusted confirmations closing needs.
fn confirm(st: &mut State) {
    st.generate_and_scan_empty_blocks(9);
}

/// Closes the test account's finished keys at `now` and returns how many closed.
fn close(st: &mut State, now: i64) -> usize {
    let account = st.test_account().unwrap().id();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    st.wallet_mut()
        .db_mut()
        .close_finished_swap_keys_at(account, now, tip)
        .unwrap()
}

/// `operation`'s stored `(observed_at, expectation, expected_value, deadline)`.
fn operation_row(conn: &Connection, operation: &str) -> (i64, u8, Option<i64>, Option<i64>) {
    conn.query_row(
        "SELECT observed_at, expectation, expected_value, deadline
         FROM ironwood_swap_operations WHERE operation_id = ?1",
        [operation],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .unwrap()
}

#[test]
fn older_observations_are_ignored() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let db = st.wallet_mut().db_mut();
    let finished = Observation {
        status: Terminal(NoReceipt),
        deadline: Some(900),
    };
    db.record_swap_observation(account, key, "swap", finished, 200)
        .unwrap();
    let stale = Observation {
        status: Active,
        deadline: Some(800),
    };
    db.record_swap_observation(account, key, "swap", stale, 100)
        .unwrap();
    assert_eq!(operation_row(&db.conn, "swap"), (200, 1, None, Some(900)));
}

#[test]
fn newer_statuses_replace_older_ones() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let db = st.wallet_mut().db_mut();
    for (status, at, expectation) in [
        (Terminal(NoReceipt), 100, 1),
        (Terminal(Positive(None)), 200, 2),
        (Active, 300, 0),
        (Terminal(Unknown), 400, 3),
    ] {
        db.observe_swap_operation(account, key, "swap", status, at)
            .unwrap();
        assert_eq!(
            operation_row(&db.conn, "swap"),
            (at, expectation, None, None)
        );
    }
}

#[test]
fn deadline_keeps_the_last_known_value() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let db = st.wallet_mut().db_mut();
    let active = |deadline| Observation {
        status: Active,
        deadline,
    };
    db.record_swap_observation(account, key, "swap", active(Some(1_000)), 100)
        .unwrap();
    db.record_swap_observation(account, key, "swap", active(None), 200)
        .unwrap();
    assert_eq!(operation_row(&db.conn, "swap").3, Some(1_000));
    db.record_swap_observation(account, key, "swap", active(Some(2_000)), 300)
        .unwrap();
    assert_eq!(operation_row(&db.conn, "swap").3, Some(2_000));
}

#[test]
fn expected_receipt_amount_is_stored_and_must_be_positive() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let db = st.wallet_mut().db_mut();
    let expect = |value| Terminal(Positive(Some(Zatoshis::const_from_u64(value))));
    db.observe_swap_operation(account, key, "swap", expect(70_000), 100)
        .unwrap();
    assert!(matches!(
        db.observe_swap_operation(account, key, "swap", expect(0), 200),
        Err(Error::Wallet(SqliteClientError::CorruptedData(_)))
    ));
    assert_eq!(
        operation_row(&db.conn, "swap"),
        (100, 2, Some(70_000), None)
    );
}

#[test]
fn refund_without_expected_receipt_closes_at_its_final_status() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let terminal = registered_at() + HOUR;
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key, "swap", Terminal(NoReceipt), terminal)
        .unwrap();
    assert_eq!(close(&mut st, terminal), 1);
    assert_eq!(close(&mut st, terminal + LIMIT), 0);
    let closed_at: Option<i64> = st
        .wallet()
        .conn()
        .query_row("SELECT closed_at FROM ironwood_receiving_keys", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(closed_at, Some(terminal));
}

#[test]
fn inconclusive_status_keeps_key_open_until_the_limit() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let failed = registered_at() + HOUR;
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key, "swap", Terminal(Unknown), failed)
        .unwrap();
    assert_eq!(close(&mut st, failed + DAY), 0);
    assert_eq!(close(&mut st, registered_at() + LIMIT), 1);
}

/// Expects `expected` on a refund key, then pays it `payments` in turn: the key stays
/// open until the last payment has the untrusted confirmations, then closes.
fn closes_once_received(expected: Option<u64>, payments: &[u64]) {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    let status = Terminal(Positive(expected.map(Zatoshis::const_from_u64)));
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key.key_id(), "swap", status, terminal)
        .unwrap();
    for value in payments {
        assert_eq!(close(&mut st, terminal), 0);
        pay(&mut st, &key, *value);
    }
    st.generate_and_scan_empty_blocks(8);
    assert_eq!(close(&mut st, terminal), 0);
    st.generate_and_scan_empty_blocks(1);
    assert_eq!(close(&mut st, terminal), 1);
}

#[test]
fn expected_amount_keeps_key_open_until_fully_received() {
    closes_once_received(Some(150_000), &[100_000, 50_000]);
}

#[test]
fn expected_receipt_without_amount_keeps_key_open_until_any_receipt() {
    closes_once_received(None, &[10_000]);
}

#[test]
fn rewound_receipt_keeps_key_open_until_mined_again() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    let status = Terminal(Positive(None));
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key.key_id(), "swap", status, terminal)
        .unwrap();
    let height = pay(&mut st, &key, 10_000);
    confirm(&mut st);
    st.truncate_to_height_retaining_cache(height - 1);
    assert_eq!(close(&mut st, terminal), 0);
    st.scan_cached_blocks(height, 10);
    assert_eq!(close(&mut st, terminal), 1);
}

#[test]
fn a_rewind_reopens_a_closed_key_whose_receipt_it_unmines() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    let status = Terminal(Positive(None));
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key.key_id(), "swap", status, terminal)
        .unwrap();
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
    st.scan_cached_blocks(height, 10);
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
    db.observe_swap_operation(account, key, "finished", Terminal(NoReceipt), first)
        .unwrap();
    db.observe_swap_operation(account, key, "pending", Active, first)
        .unwrap();
    assert_eq!(close(&mut st, first + DAY), 0);
    let last = first + 2 * HOUR;
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key, "pending", Terminal(NoReceipt), last)
        .unwrap();
    assert_eq!(close(&mut st, last), 1);
}

#[test]
fn limit_counts_from_the_latest_deadline_whatever_the_status() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let registered = registered_at();
    let (earlier, later) = (registered + HOUR, registered + 2 * HOUR);
    let db = st.wallet_mut().db_mut();
    for (operation, status, deadline) in [
        ("finished", Terminal(NoReceipt), earlier),
        ("pending", Active, later),
    ] {
        let observation = Observation {
            status,
            deadline: Some(deadline),
        };
        db.record_swap_observation(account, key, operation, observation, registered)
            .unwrap();
    }
    assert_eq!(close(&mut st, earlier + LIMIT), 0);
    assert_eq!(close(&mut st, later + LIMIT - 1), 0);
    assert_eq!(close(&mut st, later + LIMIT), 1);
}

#[test]
fn limit_without_a_deadline_counts_from_registration() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let unobserved = refund_key(&mut st).key_id();
    let pending = refund_key(&mut st).key_id();
    let from = next_height(&st);
    let db = st.wallet_mut().db_mut();
    db.observe_swap_operation(account, pending, "swap", Active, registered_at() + HOUR)
        .unwrap();
    db.recover_swap_receiving_key(account, KeyId::new(Purpose::Refund, 5), from)
        .unwrap();
    assert_eq!(scanning_keys(&st), [unobserved, pending]);
    assert_eq!(close(&mut st, registered_at() + LIMIT - 1), 0);
    assert_eq!(close(&mut st, registered_at() + LIMIT), 2);
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
    assert_eq!(
        db.close_finished_swap_keys_at(account, limit - 1, tip)
            .unwrap(),
        0
    );
    // A clock that runs fast does not move the tip block's time.
    assert_eq!(
        db.close_finished_swap_keys(account, limit + year, tip)
            .unwrap(),
        0
    );
    st.wallet()
        .conn()
        .execute(
            "UPDATE blocks SET time = ?2 WHERE height = ?1",
            rusqlite::params![u32::from(tip), limit + year],
        )
        .unwrap();
    // One that runs slow only delays closing.
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.close_finished_swap_keys(account, limit - 1, tip)
            .unwrap(),
        0
    );
    assert_eq!(db.close_finished_swap_keys(account, limit, tip).unwrap(), 1);
}

#[test]
fn keys_stay_open_while_a_rescan_is_queued() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
    let terminal = registered_at() + HOUR;
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    db.observe_swap_operation(account, key, "swap", Terminal(NoReceipt), terminal)
        .unwrap();
    db.reserve_swap_receiving_key_from(account, Purpose::Refund, tip)
        .unwrap();
    assert!(
        st.wallet()
            .suggest_scan_ranges()
            .unwrap()
            .iter()
            .any(|r| r.block_range().contains(&tip))
    );
    assert_eq!(close(&mut st, terminal + DAY), 0);
    st.scan_cached_blocks(tip, 1);
    assert_eq!(close(&mut st, terminal + DAY), 1);
}

#[test]
fn incoming_key_closes_only_once_paid_and_released() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = next_height(&st);
    let db = st.wallet_mut().db_mut();
    let reserved = db
        .prepare_swap_receive_reservation_from(account, registered_at(), from)
        .unwrap()
        .key;
    let unpaid = db
        .reserve_swap_receiving_key_from(account, Purpose::Receive, from)
        .unwrap();
    let terminal = registered_at() + HOUR;
    for key in [&reserved, &unpaid] {
        let status = Terminal(Positive(None));
        db.observe_swap_operation(account, key.key_id(), "swap", status, terminal)
            .unwrap();
    }
    pay(&mut st, &reserved, 10_000);
    confirm(&mut st);
    assert_eq!(close(&mut st, terminal + DAY), 0);
    st.wallet_mut()
        .db_mut()
        .reap_swap_receive_reservations(account, terminal + DAY)
        .unwrap();
    assert_eq!(close(&mut st, terminal + DAY), 1);
    // Without an open reservation, an unpaid key closes at its limit like any other.
    assert_eq!(close(&mut st, registered_at() + LIMIT - 1), 0);
    assert_eq!(close(&mut st, registered_at() + LIMIT), 1);
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
    let reservation = db
        .prepare_swap_receive_reservation_from(account, now, from)
        .unwrap();
    for request in ["edit", "accepted"] {
        db.begin_swap_receive_quote_as(account, reservation.id, request, deadline, now)
            .unwrap();
        db.finish_swap_receive_quote(account, request, &accepted(request, None, deadline))
            .unwrap();
    }
    db.start_swap_receive_quote(account, "accepted").unwrap();
    pay(&mut st, &reservation.key, 70_000);
    confirm(&mut st);
    let released = deadline + RECEIVE_RECLAIM_SECONDS;
    let payout = Some(Zatoshis::const_from_u64(70_000));
    let db = st.wallet_mut().db_mut();
    for (request, status, amount_out, funded) in [
        ("edit", "PENDING_DEPOSIT", None, false),
        ("accepted", "SUCCESS", payout, true),
    ] {
        let status = ProviderStatus {
            status,
            amount_out,
            deadline: Some(deadline),
            ..Default::default()
        };
        db.observe_swap_receive_quote(account, request, &status, funded, released)
            .unwrap();
    }
    db.reap_swap_receive_reservations(account, released)
        .unwrap();
    assert_eq!(close(&mut st, released + DAY), 1);
}

#[test]
fn reissued_key_limit_ignores_an_earlier_reservations_deadline() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let start = registered_at();
    let first_deadline = start + HOUR;
    let reclaimed = first_deadline + RECEIVE_RECLAIM_SECONDS;
    let from = next_height(&st);
    let db = st.wallet_mut().db_mut();
    let first = db
        .prepare_swap_receive_reservation_from(account, start, from)
        .unwrap();
    db.begin_swap_receive_quote_as(account, first.id, "first", first_deadline, start)
        .unwrap();
    db.finish_swap_receive_quote(account, "first", &accepted("first", None, first_deadline))
        .unwrap();
    let pending = ProviderStatus {
        status: "PENDING_DEPOSIT",
        ..Default::default()
    };
    db.observe_swap_receive_quote(account, "first", &pending, false, reclaimed)
        .unwrap();
    assert_eq!(
        db.reap_swap_receive_reservations(account, reclaimed)
            .unwrap(),
        [first.id]
    );
    // Reissued after the first quote's limit has passed, once nothing fresher is left.
    db.abandon_receive_indices(account, 1..RECEIVE_GAP_LIMIT, from)
        .unwrap();
    let reissued = first_deadline + LIMIT + DAY;
    let second = db
        .prepare_swap_receive_reservation_from(account, reissued, from)
        .unwrap();
    assert_eq!(second.key.key_id(), first.key.key_id());
    db.begin_swap_receive_quote_as(account, second.id, "second", reissued + HOUR, reissued)
        .unwrap();
    db.finish_swap_receive_quote(
        account,
        "second",
        &accepted("second", None, reissued + HOUR),
    )
    .unwrap();
    db.start_swap_receive_quote(account, "second").unwrap();
    pay(&mut st, &second.key, 1_000);
    let settled = reissued + 2 * HOUR;
    let success = ProviderStatus {
        status: "SUCCESS",
        amount_out: Some(Zatoshis::const_from_u64(70_000)),
        ..Default::default()
    };
    let db = st.wallet_mut().db_mut();
    db.observe_swap_receive_quote(account, "second", &success, true, settled)
        .unwrap();
    db.reap_swap_receive_reservations(account, settled).unwrap();
    assert_eq!(close(&mut st, settled), 0);
    pay(&mut st, &second.key, 69_000);
    confirm(&mut st);
    assert_eq!(close(&mut st, settled), 1);
}

#[test]
fn closed_key_stops_scanning_but_keeps_its_notes() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let height = pay(&mut st, &key, 40_000);
    let terminal = registered_at() + HOUR;
    let status = Terminal(Positive(None));
    st.wallet_mut()
        .db_mut()
        .observe_swap_operation(account, key.key_id(), "swap", status, terminal)
        .unwrap();
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
    assert_eq!(notes[0].swap_key_id(), Some(key.key_id()));
    assert_eq!(notes[0].note().value().inner(), 40_000);
}

#[test]
fn keys_close_only_at_the_confirmed_tip() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let terminal = registered_at() + HOUR;
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    db.observe_swap_operation(account, key.key_id(), "swap", Terminal(NoReceipt), terminal)
        .unwrap();
    // The network reports a block the wallet has not stored or scanned yet.
    assert_eq!(
        db.close_finished_swap_keys_at(account, terminal + DAY, tip + 1)
            .unwrap(),
        0
    );
    assert_eq!(
        db.close_finished_swap_keys_at(account, terminal + DAY, tip)
            .unwrap(),
        1
    );
}
