use super::*;
use zakura_one_time_ivk::swap::{
    OperationStatus::{Active, AwaitingDeposit, Terminal},
    ReceiptExpectation::{None as NoReceipt, Positive, Unknown},
};

/// Reserves one known funded refund identity for observation tests.
fn refund_key(st: &mut State) -> OneTimeKey {
    let account = st.test_account().unwrap().id();
    let from = tip(st).height + 1;
    reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, from)
}

/// `operation`'s stored `(observed_at, expectation, expected_value, funded)`.
fn operation_row(st: &State, operation: &str) -> (i64, u8, Option<i64>, bool) {
    let sql = "SELECT observed_at, expectation, expected_value, funded
               FROM ironwood_one_time_operations WHERE reference = ?1";
    row(st.wallet().conn(), sql, [operation])
}

/// Newer observations replace older ones, an older one arriving late is ignored except
/// that a deposit it saw sticks, and an expected amount must be positive.
#[test]
fn observations_are_monotonic_and_a_seen_deposit_sticks() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = refund_key(&mut st).key_id();
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
        let observation = Observation {
            status,
            funded,
            receipts: vec![],
        };
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
            let key = refund_key(&mut st).key_id();
            for observation in [first, second] {
                let db = st.wallet_mut().db_mut();
                observe(db, account, key, "swap", observation, 100).unwrap();
            }
            assert_eq!(operation_row(&st, "swap"), row, "{first:?} then {second:?}");
        }
    }
}
