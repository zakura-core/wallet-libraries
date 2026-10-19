use super::*;
use zakura_one_time_ivk::swap::{
    COMPLETION_LIMIT_SECS as LIMIT, Observation,
    OperationStatus::{Active, AwaitingDeposit, Terminal},
    REFUND_WATCH_SECS,
    ReceiptExpectation::{None as NoReceipt, Positive, Unknown},
};

const HOUR: i64 = 60 * 60;
const DAY: i64 = 24 * HOUR;

/// Unix time the fixed test clock stamps on registered keys as `registered_at`.
fn registered_at() -> i64 {
    clock_now()
}

/// The height above the scanned tip, where a newly issued key starts scanning.
fn next_height(st: &State) -> BlockHeight {
    st.wallet().chain_height().unwrap().unwrap() + 1
}

/// Issues the next refund key, trial-decrypted from [`next_height`].
fn refund_key(st: &mut State) -> OneTimeKey {
    let account = st.test_account().unwrap().id();
    let from = next_height(st);
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, from)
}

/// Issues the next incoming key without a reservation, trial-decrypted from
/// [`next_height`], for the closing rules every key but a refund key follows.
fn swap_key(st: &mut State) -> OneTimeKey {
    let account = st.test_account().unwrap().id();
    let from = next_height(st);
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Receive, from)
}

/// Mines blocks until the latest receipt has the untrusted confirmations closing needs.
fn confirm(st: &mut State) {
    st.generate_and_scan_empty_blocks_with_one_time_ivks(9);
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

/// `operation`'s stored `(observed_at, expectation, expected_value, funded)`.
fn operation_row(st: &State, operation: &str) -> (i64, u8, Option<i64>, bool) {
    let sql = "SELECT observed_at, expectation, expected_value, funded
               FROM ironwood_one_time_operations WHERE reference = ?1";
    row(st.wallet().conn(), sql, [operation])
}

/// An observation of `status` without a deposit.
fn status(status: OperationStatus) -> Observation {
    Observation {
        status,
        funded: false,
    }
}

/// Newer observations replace older ones, an older one arriving late is ignored except
/// that a deposit it saw sticks, and an expected amount must be positive.
#[test]
fn observations_are_monotonic_and_a_seen_deposit_sticks() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = swap_key(&mut st).key_id();
    let expect = |value| Terminal(Positive(Some(Zatoshis::const_from_u64(value))));
    // Each observation, its time, and the stored row afterwards.
    for (status, funded, at, row) in [
        (Active, false, 100, (100, 0, None, false)),
        (Terminal(NoReceipt), false, 200, (200, 1, None, false)),
        (Active, true, 150, (200, 1, None, true)),
        (Terminal(Positive(None)), false, 300, (300, 2, None, true)),
        (expect(70_000), false, 400, (400, 2, Some(70_000), true)),
        (Active, false, 450, (450, 0, None, true)),
        (AwaitingDeposit, false, 470, (470, 4, None, true)),
        (Terminal(Unknown), false, 500, (500, 3, None, true)),
    ] {
        let observation = Observation { status, funded };
        let db = st.wallet_mut().db_mut();
        observe_with(db, account, key, ("swap", at), observation, at).unwrap();
        assert_eq!(operation_row(&st, "swap"), row, "at {at}");
    }
    let db = st.wallet_mut().db_mut();
    assert!(matches!(
        observe(db, account, key, "swap", expect(0), 600),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(operation_row(&st, "swap").0, 500);
}

/// Conflicting observations requested in the same second leave the same row whichever
/// arrives last: an expected receipt, even of an unreported amount, is never replaced by
/// no receipt or a smaller amount,
/// nor an inconclusive end by no receipt, so a stale answer cannot settle the key before
/// its receipt arrives.
#[test]
fn equal_time_observations_never_lower_the_expected_receipt() {
    let expect = |value| Terminal(Positive(Some(Zatoshis::const_from_u64(value))));
    for (a, b, row) in [
        (
            expect(70_000),
            Terminal(NoReceipt),
            (100, 2, Some(70_000), false),
        ),
        (
            expect(70_000),
            Terminal(Positive(None)),
            (100, 2, Some(70_000), false),
        ),
        (
            expect(70_000),
            expect(50_000),
            (100, 2, Some(70_000), false),
        ),
        (
            Terminal(Positive(None)),
            Terminal(NoReceipt),
            (100, 2, None, false),
        ),
        (
            Terminal(Unknown),
            Terminal(NoReceipt),
            (100, 3, None, false),
        ),
    ] {
        for (first, second) in [(a, b), (b, a)] {
            let mut st = scanned_wallet();
            let account = st.test_account().unwrap().id();
            let key = swap_key(&mut st).key_id();
            for observation in [first, second] {
                let db = st.wallet_mut().db_mut();
                observe(db, account, key, "swap", observation, 100).unwrap();
            }
            assert_eq!(operation_row(&st, "swap"), row, "{first:?} then {second:?}");
        }
    }
}

/// A refund key whose deposit this wallet did not fund never starts scanning, whatever
/// the provider reports, even with its history lookup pending. Only storing its funding
/// transaction starts it, and the receiver directory recovers a refund from elsewhere.
#[test]
fn no_status_starts_an_unfunded_refund_key() {
    for owed in [Terminal(Positive(None)), Terminal(Unknown)] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let key = KeyId::new(Purpose::Refund, 0);
        let held = [derive(&st, key)
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes()];
        let contains = |r: &[[u8; 43]]| r.iter().map(|r| held.contains(r)).collect();
        let now = clock_now();
        let seen = ProviderSeen {
            until: now,
            contains: &contains,
        };
        let through = tip(&st);
        // The provider saw the first refund address, so it awaits a lookup.
        let db = st.wallet_mut().db_mut();
        let issued = db.reserve_refund_key(account, now, through.height, Some(&seen));
        let issued = issued.unwrap().unwrap().key_id();
        assert_eq!(issued.index(), 1);
        for key in [key, issued] {
            observe(
                db,
                account,
                key,
                &format!("deposit-{}", key.index()),
                Active,
                100,
            )
            .unwrap();
        }
        for key in [key, issued] {
            let deposit = format!("deposit-{}", key.index());
            let recorded = db.record_operation_status(account, &deposit, None, status(owed), 200);
            assert!(recorded.unwrap());
        }
        assert!(scanning_keys(&st).is_empty(), "{owed:?}");
    }
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
        let key = swap_key(&mut st).key_id();
        observe_swap(&mut st, key, status, registered_at() + HOUR);
        if let Some(open_at) = open_at {
            assert_eq!(close(&mut st, registered_at() + open_at), 0);
        }
        let closes_at = registered_at() + closes_at;
        assert_eq!(close(&mut st, closes_at), 1);
        let sql = "SELECT closed_at FROM ironwood_one_time_keys";
        assert_eq!(
            value::<Option<i64>>(st.wallet().conn(), sql, []),
            Some(closes_at)
        );
        assert_eq!(close(&mut st, closes_at + LIMIT), 0);
    }
}

/// A key expecting a receipt stays open, still scanning, until its receipts cover the
/// expected amount, or any receipt without one, with the untrusted confirmations, then
/// closes.
#[test]
fn expected_receipts_keep_a_key_open_until_received_and_confirmed() {
    for (expected, payments) in [(Some(150_000), &[100_000, 50_000][..]), (None, &[10_000])] {
        let mut st = scanned_wallet();
        let key = swap_key(&mut st);
        let terminal = registered_at() + HOUR;
        let status = Terminal(Positive(expected.map(Zatoshis::const_from_u64)));
        observe_swap(&mut st, key.key_id(), status, terminal);
        for value in payments {
            assert_eq!(close(&mut st, terminal), 0);
            pay(&mut st, key.full_viewing_key(), *value);
        }
        st.generate_and_scan_empty_blocks_with_one_time_ivks(8);
        assert_eq!(close(&mut st, terminal), 0);
        assert_eq!(scanning_keys(&st), [key.key_id()]);
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        assert_eq!(close(&mut st, terminal), 1);
    }
}

/// A rewind that un-mines a receipt keeps its key open, or reopens it if it closed, so
/// scanning again from the rewind mines the receipt again; past its limit, the key waits
/// for the unmined receipt, which can be mined until it expires. Once the receipt is
/// confirmed again, the key closes.
#[test]
fn a_rewind_that_unmines_a_receipt_keeps_or_reopens_its_key() {
    for closed_first in [false, true] {
        let mut st = scanned_wallet();
        let key = swap_key(&mut st);
        let terminal = registered_at() + HOUR;
        observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
        let height = pay(&mut st, key.full_viewing_key(), 10_000);
        confirm(&mut st);
        if closed_first {
            assert_eq!(close(&mut st, terminal), 1);
            assert!(scanning_keys(&st).is_empty());
        }
        st.truncate_to_height_retaining_cache(height - 1);
        assert_eq!(scanning_keys(&st), [key.key_id()]);
        assert_eq!(close(&mut st, terminal + LIMIT), 0);
        st.scan_cached_blocks_with_one_time_ivks(height, 10);
        assert_eq!(unspent_keys(&st, height + 9), [Some(key.key_id())]);
        assert_eq!(close(&mut st, terminal), 1);
    }
}

/// A rewind that keeps a closed key's receipt but leaves it short of the untrusted
/// confirmations reopens the key, which then scans the replacement blocks; one that
/// leaves the receipt confirmed does not.
#[test]
fn a_rewind_reopens_a_closed_key_whose_receipt_it_leaves_unconfirmed() {
    let mut st = scanned_wallet();
    let key = swap_key(&mut st);
    let terminal = registered_at() + HOUR;
    observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    let height = pay(&mut st, key.full_viewing_key(), 10_000);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(10);
    assert_eq!(close(&mut st, terminal), 1);
    st.truncate_to_height(height + 9);
    assert!(scanning_keys(&st).is_empty());
    st.truncate_to_height(height + 8);
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    let replacement = pay(&mut st, key.full_viewing_key(), 20_000);
    assert_eq!(replacement, height + 9);
    assert_eq!(unspent_keys(&st, replacement), [Some(key.key_id()); 2]);
}

/// A closed key a rewind below its start reopens scans from the first rescanned block, so
/// a replacement payment below its old start is found.
#[test]
fn a_key_reopened_below_its_start_scans_from_the_rewind() {
    let mut st = scanned_wallet();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    let key = swap_key(&mut st);
    let terminal = registered_at() + HOUR;
    observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    let height = pay(&mut st, key.full_viewing_key(), 10_000);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(10);
    assert_eq!(close(&mut st, terminal), 1);
    st.truncate_to_height(height - 2);
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    let recipient = IronwoodFvk(key.full_viewing_key().clone());
    let value = Zatoshis::const_from_u64(20_000);
    let (replacement, _, _) =
        st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    st.scan_cached_blocks_with_one_time_ivks(replacement, 1);
    assert_eq!(unspent_keys(&st, replacement), [Some(key.key_id())]);
}

#[test]
fn a_key_closes_once_its_last_operation_is_final() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = swap_key(&mut st).key_id();
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
/// after registration without operations.
#[test]
fn the_limit_counts_from_the_latest_deadline_or_registration() {
    let registered = registered_at();
    let (earlier, later) = (registered + HOUR, registered + 2 * HOUR);
    let operations = [
        ("finished", Terminal(NoReceipt), earlier),
        ("pending", Active, later),
    ];
    for (operations, limit) in [(&operations[..], later + LIMIT), (&[], registered + LIMIT)] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let key = swap_key(&mut st).key_id();
        for &(operation, s, deadline) in operations {
            let db = st.wallet_mut().db_mut();
            let operation = (operation, deadline);
            observe_with(db, account, key, operation, status(s), registered).unwrap();
        }
        assert_eq!(close(&mut st, limit - 1), 0);
        assert_eq!(close(&mut st, limit), 1);
    }
}

/// Keys close only at a tip the wallet stored and fully scanned, never while a rescan is
/// queued, and at the earlier of the caller's clock and the tip block's time.
#[test]
fn closing_needs_the_scanned_tip_and_the_earlier_of_clock_and_block_time() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = swap_key(&mut st).key_id();
    let terminal = registered_at() + HOUR;
    let tip = st.wallet().chain_height().unwrap().unwrap();
    observe_swap(&mut st, key, Terminal(NoReceipt), terminal);
    // The network reports a block the wallet has not stored or scanned yet.
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, terminal + DAY, tip + 1), 0);
    // Another key's activation queues a rescan of the tip.
    reserve_key(db, account, Purpose::Receive, tip);
    let ranges = st.wallet().suggest_scan_ranges().unwrap();
    assert!(ranges.iter().any(|r| r.block_range().contains(&tip)));
    assert_eq!(close(&mut st, terminal + DAY), 0);
    st.scan_cached_blocks_with_one_time_ivks(tip, 1);
    assert_eq!(close(&mut st, terminal + DAY), 1);

    // The other key, without operations, closes at its limit.
    let limit = registered_at() + LIMIT;
    let year = 365 * DAY;
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, limit - 1, tip), 0);
    // A clock that runs fast does not move the tip block's time.
    let closed = db.close_finished_one_time_keys(account, limit + year, tip);
    assert_eq!(closed.unwrap(), 0);
    let sql = "UPDATE blocks SET time = ?2 WHERE height = ?1";
    exec(
        &db.conn,
        sql,
        rusqlite::params![u32::from(tip), limit + year],
    );
    // One that runs slow only delays closing.
    let closed = db.close_finished_one_time_keys(account, limit - 1, tip);
    assert_eq!(closed.unwrap(), 0);
    let closed = db.close_finished_one_time_keys(account, limit, tip);
    assert_eq!(closed.unwrap(), 1);
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
    let reserved = prepare_from(db, account, now, from, Some(&empty_seen(now)))
        .unwrap()
        .unwrap();
    let index = reserved.key_id().index();
    tx(db, |c, _| {
        store::swap::reservations::begin(
            c,
            account,
            index,
            "pending",
            now + DAY,
            now,
            Some(&empty_seen(now)),
        )
    })
    .unwrap()
    .unwrap();
    let unpaid = reserve_key(db, account, Purpose::Receive, from);
    let terminal = now + HOUR;
    for key in [&reserved, &unpaid] {
        observe_swap(&mut st, key.key_id(), Terminal(Positive(None)), terminal);
    }
    pay(&mut st, reserved.full_viewing_key(), 10_000);
    confirm(&mut st);
    let released = now + DAY + RECEIVE_RECLAIM_SECONDS;
    assert_eq!(close(&mut st, released - 1), 0);
    assert_eq!(close(&mut st, released), 1);
    assert_eq!(close(&mut st, now + LIMIT - 1), 0);
    assert_eq!(close(&mut st, now + LIMIT), 1);
    assert!(scanning_keys(&st).is_empty());
}

/// Starts an incoming reservation with deadline `registered_at() + HOUR` and records an
/// underpayment's `INCOMPLETE_DEPOSIT` for it. Returns its key and deadline.
fn underpaid_reservation(st: &mut State) -> (OneTimeKey, i64) {
    let account = st.test_account().unwrap().id();
    let from = next_height(st);
    let now = registered_at();
    let deadline = now + HOUR;
    let db = st.wallet_mut().db_mut();
    let key = prepare_from(db, account, now, from, Some(&empty_seen(now)))
        .unwrap()
        .unwrap();
    let index = key.key_id().index();
    tx(db, |c, _| {
        store::swap::reservations::begin(
            c,
            account,
            index,
            "swap",
            deadline,
            now,
            Some(&empty_seen(now)),
        )
    })
    .unwrap()
    .unwrap();
    db.finish_receive_operation(account, "swap", &accepted("swap", None, deadline))
        .unwrap()
        .unwrap();
    db.start_receive_operation(account, "swap", now)
        .unwrap()
        .unwrap();
    record_receive_status(st, Active, now + HOUR);
    (key, deadline)
}

/// Records provider `status` for the test account's funded incoming operation `swap` at
/// `at`.
fn record_receive_status(st: &mut State, s: OperationStatus, at: i64) {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let funded = Observation {
        status: s,
        funded: true,
    };
    db.record_operation_status(account, "swap", None, funded, at)
        .unwrap();
}

/// A started incoming reservation whose last status stays active, as an underpayment's
/// `INCOMPLETE_DEPOSIT` does, stops scanning at the limit after its deadline but stays
/// reserved, so issuance never reissues its address.
#[test]
fn a_started_reservation_left_active_stops_scanning_at_the_limit() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let (key, deadline) = underpaid_reservation(&mut st);
    assert_eq!(close(&mut st, deadline + LIMIT - 1), 0);
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    assert_eq!(close(&mut st, deadline + LIMIT), 1);
    assert!(scanning_keys(&st).is_empty());
    let from = next_height(&st);
    let db = st.wallet_mut().db_mut();
    let next = prepare_from(
        db,
        account,
        deadline + LIMIT,
        from,
        Some(&empty_seen(deadline + LIMIT)),
    );
    assert_ne!(next.unwrap().unwrap().key_id(), key.key_id());
}

/// Records `status` for the test account's refund operation `swap` at `at`.
fn record_swap(st: &mut State, s: OperationStatus, at: i64) {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.record_operation_status(account, "swap", None, status(s), at)
        .unwrap();
}

/// A refund owed, with the expected amount if any.
fn owed(value: Option<u64>) -> OperationStatus {
    Terminal(Positive(value.map(Zatoshis::const_from_u64)))
}

/// Closes a refund key whose operation `swap` reported no refund, returning when.
fn closed_without_refund(st: &mut State) -> i64 {
    let key = refund_key(st).key_id();
    let at = registered_at() + HOUR;
    observe_swap(st, key, Terminal(NoReceipt), at);
    assert_eq!(close(st, at), 1);
    at
}

/// Closes a key once its operation `swap` settled with a payment of 50,000, returning
/// when: a refund key, or a started incoming reservation that is then released. The
/// key's note survives closing.
fn closed_settled(st: &mut State, incoming: bool) -> i64 {
    let at = registered_at() + 2 * HOUR;
    let key = if incoming {
        let (key, _) = underpaid_reservation(st);
        pay(st, key.full_viewing_key(), 50_000);
        confirm(st);
        record_receive_status(st, owed(Some(50_000)), at);
        key
    } else {
        let key = refund_key(st);
        observe_swap(st, key.key_id(), owed(Some(50_000)), at);
        pay(st, key.full_viewing_key(), 50_000);
        confirm(st);
        key
    };
    assert_eq!(close(st, at), 1, "{:?}", key.key_id());
    let tip = st.wallet().chain_height().unwrap().unwrap();
    assert_eq!(unspent_keys(st, tip), [Some(key.key_id())]);
    at
}

/// Closes a key at its limit while its operation `swap` is still active, returning when: a
/// refund key [`REFUND_WATCH_SECS`] after its deadline, or a started incoming reservation
/// at its completion limit.
fn closed_at_the_limit(st: &mut State, incoming: bool) -> i64 {
    let limit = if incoming {
        underpaid_reservation(st).1 + LIMIT
    } else {
        // Its operation's deadline is its registration (see `observe`).
        let key = refund_key(st).key_id();
        observe_swap(st, key, Active, registered_at() + HOUR);
        registered_at() + REFUND_WATCH_SECS
    };
    assert_eq!(close(st, limit), 1);
    limit
}

/// No provider status reopens a closed key, however it closed and whatever the status
/// reports; the status is still recorded. A payment it implies is found by the paid
/// filter or a history recheck instead (see `close_finished_one_time_keys`).
#[test]
fn statuses_never_reopen_a_closed_key() {
    type Close = fn(&mut State) -> i64;
    type Update = fn(&mut State, i64);
    let cases: [(&str, Close, Update); 6] = [
        ("refund owed after none", closed_without_refund, |st, at| {
            record_swap(st, owed(None), at)
        }),
        (
            "inconclusive after none",
            closed_without_refund,
            |st, at| record_swap(st, Terminal(Unknown), at),
        ),
        (
            "raised refund",
            |st| closed_settled(st, false),
            |st, at| record_swap(st, owed(Some(80_000)), at),
        ),
        (
            "corrected payout",
            |st| closed_settled(st, true),
            |st, at| record_receive_status(st, owed(Some(80_000)), at),
        ),
        (
            "refund owed past the limit",
            |st| closed_at_the_limit(st, false),
            |st, at| record_swap(st, owed(None), at),
        ),
        (
            "payout past the limit",
            |st| closed_at_the_limit(st, true),
            |st, at| {
                record_receive_status(st, Terminal(NoReceipt), at);
                record_receive_status(st, owed(Some(50_000)), at + 1);
            },
        ),
    ];
    for (case, close_key, update) in cases {
        let mut st = scanned_wallet();
        let closed_at = close_key(&mut st);
        let queued = st.wallet().suggest_scan_ranges().unwrap();
        update(&mut st, closed_at + HOUR);
        assert!(scanning_keys(&st).is_empty(), "{case}");
        assert_eq!(st.wallet().suggest_scan_ranges().unwrap(), queued, "{case}");
        assert!(operation_row(&st, "swap").0 >= closed_at + HOUR, "{case}");
    }
}

#[test]
fn abandoned_quote_edit_does_not_hold_a_released_key_open() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = next_height(&st);
    let now = registered_at();
    let deadline = now + HOUR;
    let db = st.wallet_mut().db_mut();
    let reservation = prepare_from(db, account, now, from, Some(&empty_seen(now)))
        .unwrap()
        .unwrap();
    let index = reservation.key_id().index();
    for request in ["edit", "accepted"] {
        tx(db, |c, _| {
            store::swap::reservations::begin(
                c,
                account,
                index,
                request,
                deadline,
                now,
                Some(&empty_seen(now)),
            )
        })
        .unwrap()
        .unwrap();
        db.finish_receive_operation(account, request, &accepted(request, None, deadline))
            .unwrap()
            .unwrap();
    }
    db.start_receive_operation(account, "accepted", now)
        .unwrap()
        .unwrap();
    pay(&mut st, reservation.full_viewing_key(), 70_000);
    confirm(&mut st);
    let released = deadline + RECEIVE_RECLAIM_SECONDS;
    chain_agrees(st.wallet().db(), released);
    let payout = Some(Zatoshis::const_from_u64(70_000));
    for (request, status, funded) in [
        ("edit", AwaitingDeposit, false),
        ("accepted", Terminal(Positive(payout)), true),
    ] {
        let observation = Observation { status, funded };
        let db = st.wallet_mut().db_mut();
        db.record_operation_status(account, request, None, observation, released)
            .unwrap();
    }
    assert_eq!(close(&mut st, released + DAY), 1);
}

/// A refund key stops scanning [`REFUND_WATCH_SECS`] after its deadline by the device
/// clock, though a refund it received is still unconfirmed and the wallet has blocks to
/// catch up on. The next scan closes it before choosing its keys, so the backlog is never
/// scanned with it. A later refund in the backlog is left to the receiver directory.
#[test]
fn a_refund_watch_ends_before_the_backlog_is_scanned() {
    use zcash_client_backend::data_api::one_time_ivk::OneTimeIvkWrite as _;
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st);
    let deadline = registered_at() + HOUR;
    let db = st.wallet_mut().db_mut();
    let operation = ("swap", deadline);
    observe_with(
        db,
        account,
        key.key_id(),
        operation,
        status(owed(None)),
        deadline,
    )
    .unwrap();
    let received = pay(&mut st, key.full_viewing_key(), 10_000);
    // The wallet goes offline while a later refund lands in blocks it has not scanned.
    let recipient = IronwoodFvk(key.full_viewing_key().clone());
    let value = Zatoshis::const_from_u64(20_000);
    let (late, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
    for _ in 0..5 {
        st.generate_empty_block();
    }
    let db = st.wallet_mut().db_mut();
    let ends = deadline + REFUND_WATCH_SECS;
    db.clock.tick(std::time::Duration::from_secs(
        (ends - 1 - clock_now()) as u64,
    ));
    db.expire_refund_watches().unwrap();
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    let db = st.wallet_mut().db_mut();
    db.clock.tick(std::time::Duration::from_secs(1));
    st.scan_cached_blocks_with_one_time_ivks(late, 6);
    assert!(scanning_keys(&st).is_empty());
    assert_eq!(unspent_keys(&st, late + 5), [Some(key.key_id())]);
    let sql = "SELECT t.mined_height FROM ironwood_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id
               WHERE n.one_time_key_id IS NOT NULL";
    let mined: Vec<u32> = column(st.wallet().conn(), sql, []);
    assert_eq!(mined, [u32::from(received)]);
}

/// A refund key whose operations settled closes at once, even before the wallet confirms
/// a tip, while a pending receipt beyond what the provider promised does not hold it.
#[test]
fn a_settled_refund_closes_without_waiting_for_its_deadline() {
    let mut st = scanned_wallet();
    let key = refund_key(&mut st);
    let at = registered_at() + HOUR;
    observe_swap(&mut st, key.key_id(), owed(Some(10_000)), at);
    pay(&mut st, key.full_viewing_key(), 10_000);
    pay(&mut st, key.full_viewing_key(), 5_000);
    // The first receipt has the untrusted confirmations, and the second one block fewer.
    st.generate_and_scan_empty_blocks_with_one_time_ivks(8);
    assert_eq!(scanning_keys(&st), [key.key_id()]);
    let account = st.test_account().unwrap().id();
    let tip = st.wallet().chain_height().unwrap().unwrap();
    // The network reports a block the wallet has not stored yet.
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, at, tip + 1), 1);
    assert!(scanning_keys(&st).is_empty());
}
