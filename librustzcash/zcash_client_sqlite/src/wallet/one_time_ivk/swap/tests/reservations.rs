use super::*;
use ReservationPolicy::{Coverage, Gap, SeenUnavailable, Stale};
use store::restore::tests::discovery::look_up;
use zakura_one_time_ivk::swap::{
    OperationStatus::{Active, AwaitingDeposit, Terminal},
    ReceiptExpectation::{self, Positive},
};
use zcash_client_backend::data_api::one_time_ivk::recovery::OneTimeRecoveryWrite;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

/// `(observed_at, expectation, expected_value, deadline)` of an operation.
type Operation = (i64, u8, Option<i64>, Option<i64>);
const NOW: i64 = 1_000_000;
/// A terminal status whose receipt is inconclusive.
const INCONCLUSIVE: OperationStatus = Terminal(ReceiptExpectation::Unknown);
/// A completed swap's payout, of an unreported amount.
const PAID: OperationStatus = Terminal(Positive(None));
/// A conclusive end with no Zcash receipt, such as a refund on the source chain.
const NO_RECEIPT: OperationStatus = Terminal(ReceiptExpectation::None);
/// A time when every quote with the default deadline is past it and the cooldown.
const EXPIRED: i64 = NOW + 61 + RECEIVE_RECLAIM_SECONDS;

/// An Ironwood wallet scanned through one block holding an ordinary note, whose windows
/// were checked against a seen set.
fn fixture() -> State {
    let mut st = undiscovered();
    let account = st.test_account().unwrap().id();
    see_at(st.wallet_mut().db_mut(), account, &[], NOW);
    settle_empty_filters(st.wallet_mut().db_mut(), account, NOW);
    st
}

/// A funded wallet whose windows were never checked against a seen set, so issuance
/// waits.
fn undiscovered() -> State {
    let mut st = ironwood_wallet();
    let ordinary = parent(&st);
    pay(&mut st, &ordinary, 100_000);
    st
}

/// Resumes the draft or reserves the next address, scanned from above the tip.
fn try_prepare(st: &mut State, now: i64, seen: Option<&ProviderSeen<'_>>) -> Policy<OneTimeKey> {
    let account = st.test_account().unwrap().id();
    let from = tip(st).height + 1;
    prepare_from(st.wallet_mut().db_mut(), account, now, from, seen)
}

/// [`try_prepare`] with an empty seen set read at `now` (see [`empty_seen`]), expecting a
/// key.
fn prepare(st: &mut State, now: i64) -> OneTimeKey {
    try_prepare(st, now, Some(&empty_seen(now)))
        .unwrap()
        .unwrap()
}

/// Prepares at `now` with a seen set read then that holds `held`.
fn try_prepare_seen(st: &mut State, now: i64, held: &[[u8; 43]]) -> Policy<OneTimeKey> {
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = ProviderSeen {
        since: 0,
        until: now,
        contains: &contains,
    };
    let first = try_prepare(st, now, Some(&seen))?;
    if matches!(first, Err(Gap)) {
        // Membership can invalidate preparation. Let the background derivation step run.
        let account = st.test_account().unwrap().id();
        st.wallet_mut()
            .db_mut()
            .prepare_one_time_recovery(account, 1024, now)?;
        try_prepare(st, now, Some(&seen))
    } else {
        Ok(first)
    }
}

/// [`try_prepare_seen`], expecting a key.
fn prepare_seen(st: &mut State, now: i64, held: &[[u8; 43]]) -> OneTimeKey {
    try_prepare_seen(st, now, held).unwrap().unwrap()
}

/// Begins operation request `req` on `key`'s reservation at `now` with `deadline`, with
/// an empty seen set read then.
fn begin_at(st: &mut State, key: &OneTimeKey, req: &str, deadline: i64, now: i64) -> Policy<()> {
    begin_seen(st, key, req, (deadline, now), Some(&empty_seen(now)))
}

/// Begins operation request `req` on `key`'s reservation with `(deadline, now)` and `seen`.
fn begin_seen(
    st: &mut State,
    key: &OneTimeKey,
    req: &str,
    (deadline, now): (i64, i64),
    seen: Option<&ProviderSeen<'_>>,
) -> Policy<()> {
    let account = st.test_account().unwrap().id();
    let index = key.key_id().index();
    st.wallet_mut()
        .db_mut()
        .prepare_one_time_recovery(account, 1024, now)
        .unwrap();
    tx(st.wallet_mut().db_mut(), |c, _| {
        store::swap::reservations::begin(c, account, index, req, deadline, now, seen)
    })
}

/// [`begin_at`] at `NOW` with a deadline of `NOW + 60`.
fn begin(st: &mut State, key: &OneTimeKey, request: &str) -> Policy<()> {
    begin_at(st, key, request, NOW + 60, NOW)
}

/// Finishes `request` with outcome `out`, returning the policy that refused it, if any.
fn try_finish(st: &mut State, request: &str, out: &OperationOutcome) -> Policy<()> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.finish_receive_operation(account, request, out)
}

/// [`try_finish`] on a request that was not retired.
fn finish(st: &mut State, request: &str, out: &OperationOutcome) -> Result<(), SqliteClientError> {
    try_finish(st, request, out).map(|finished| finished.unwrap())
}

/// Starts `request` at [`NOW`], returning its deposit or the policy that refused it.
fn start(st: &mut State, request: &str) -> Policy<ReceiveDeposit> {
    start_at(st, request, NOW)
}

/// Starts `request` at `now`, returning its deposit or the policy that refused it.
fn start_at(st: &mut State, request: &str, now: i64) -> Policy<ReceiveDeposit> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.start_receive_operation(account, request, now)
}

/// Begins `request` and accepts it with deposit address `request` and a deadline of
/// `NOW + 60`, then optionally starts it.
fn quote(st: &mut State, key: &OneTimeKey, request: &str, started: bool) {
    let account = st.test_account().unwrap().id();
    settle_empty_filters(st.wallet_mut().db_mut(), account, NOW);
    begin(st, key, request).unwrap().unwrap();
    finish(st, request, &accepted(request, None, NOW + 60)).unwrap();
    if started {
        start(st, request).unwrap().unwrap();
    }
}

/// An observation of `status`, with whether the provider saw a deposit.
fn observed(status: OperationStatus, funded: bool) -> Observation {
    Observation { status, funded }
}

/// Records provider `observation` at `now` for the operation with this deposit address
/// and memo, as an app does with each status it fetches, with the chain agreeing (see
/// [`chain_agrees`]). Returns whether one matched.
fn report_with(
    st: &mut State,
    (deposit, memo): (&str, Option<&str>),
    observation: Observation,
    now: i64,
) -> bool {
    let account = st.test_account().unwrap().id();
    chain_agrees(st.wallet().db(), now);
    settle_empty_filters(st.wallet_mut().db_mut(), account, now);
    let db = st.wallet_mut().db_mut();
    let recorded = db.record_operation_status(account, deposit, memo, observation, now);
    recorded.unwrap()
}

/// [`report_with`] `status`, without a memo.
fn report(st: &mut State, deposit: &str, status: OperationStatus, funded: bool, now: i64) {
    report_with(st, (deposit, None), observed(status, funded), now);
}

/// Reaps the test account's reservations at `now`, with the chain agreeing (see
/// [`chain_agrees`]), returning the reclaimed indices.
fn reap(st: &mut State, now: i64) -> Vec<u64> {
    let account = st.test_account().unwrap().id();
    chain_agrees(st.wallet().db(), now);
    settle_empty_filters(st.wallet_mut().db_mut(), account, now);
    tx(st.wallet_mut().db_mut(), |c, p| {
        store::swap::reservations::reap(c, p, account, now)
    })
    .unwrap()
}

/// Whether `key`'s reservation is open.
fn reserved(st: &State, key: &OneTimeKey) -> bool {
    let sql = format!(
        "SELECT {RESERVED} FROM ironwood_one_time_keys k
         WHERE k.purpose = 1 AND k.key_index = ?1"
    );
    let index = key.key_id().index().to_be_bytes();
    value(st.wallet().conn(), &sql, [index])
}

/// Mines blocks until the latest receipt has the untrusted confirmations that raise
/// the recovery bound.
fn confirm(st: &mut State) {
    let untrusted = ConfirmationsPolicy::default().untrusted().get();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(untrusted as usize - 1);
}

/// The policy that refused `result`, or `None` if it succeeded.
fn refusal<T>(result: Policy<T>) -> Option<ReservationPolicy> {
    result.unwrap().err()
}

/// Whether `result` failed as invalid input.
fn rejected_input<T>(result: Result<T, SqliteClientError>) -> bool {
    matches!(result, Err(SqliteClientError::InvalidOneTimeIvkInput(_)))
}

/// The height `key` is trial-decrypted from, or `None` while it is not scanning.
fn active_from(st: &State, key: KeyId) -> Option<BlockHeight> {
    let sql = "SELECT CASE WHEN closed_at IS NULL THEN active_from END
               FROM ironwood_one_time_keys WHERE purpose = ?1 AND key_index = ?2";
    let purpose = purpose_code(key.purpose()).unwrap();
    let params = rusqlite::params![purpose, key.index().to_be_bytes()];
    value::<Option<u32>>(st.wallet().conn(), sql, params).map(BlockHeight::from)
}

/// The operation begun as `request`, if any.
fn operation(st: &State, request: &str) -> Option<Operation> {
    let sql = "SELECT observed_at, expectation, expected_value, deadline
               FROM ironwood_one_time_operations WHERE request = ?1";
    rows(st.wallet().conn(), sql, [request]).pop()
}

/// Whether the wallet holds an unspent note received by `key`.
fn holds_note(st: &State, key: KeyId) -> bool {
    unspent_keys(st, tip(st).height).contains(&Some(key))
}

/// Registers incoming `indices` as quoted and then abandoned addresses, with unknown
/// outcomes, which issuance reuses only when nothing fresh is left.
fn abandon_indices(st: &mut State, indices: std::ops::Range<u64>) {
    let account = st.test_account().unwrap().id();
    let from = tip(st).height + 1;
    let quoted = "INSERT INTO ironwood_one_time_operations
                      (one_time_key_id, request, deadline, begun_at)
                  VALUES (?1, ?2, 0, 0)";
    let closed = "UPDATE ironwood_one_time_keys
                  SET reserved_at = 0, released_at = 0, closed_at = 0 WHERE id = ?1";
    tx(st.wallet_mut().db_mut(), |c, p| {
        for index in indices {
            let key = KeyId::new(Purpose::Receive, index);
            let (id, _) = register(c, p, account, key, from, true, Discovery::Scan, 0)?;
            let request = format!("abandoned-{index}");
            exec(c, quoted, rusqlite::params![id, request]);
            exec(c, closed, [id]);
        }
        Ok(())
    })
    .unwrap();
}

/// Issues through `prepare_receive_reservation` at the tip, with a seen set read at
/// `until` that holds the incoming addresses at `held`, if any.
fn issue(st: &mut State, seen: Option<(i64, &[u64])>) -> Result<u64, ReservationPolicy> {
    let held: Vec<[u8; 43]> = seen
        .map_or(&[][..], |(_, held)| held)
        .iter()
        .map(|&index| {
            let fvk = derive(st, KeyId::new(Purpose::Receive, index));
            fvk.address_at(0u32, Scope::External).to_raw_address_bytes()
        })
        .collect();
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = seen.map(|(until, _)| ProviderSeen {
        since: 0,
        until,
        contains: &contains,
    });
    let account = st.test_account().unwrap().id();
    let through = tip(st).height;
    chain_agrees(st.wallet().db(), NOW);
    let db = st.wallet_mut().db_mut();
    db.prepare_one_time_recovery(account, 1024, NOW).unwrap();
    let issued = db.prepare_receive_reservation(account, NOW, through, seen.as_ref());
    issued.unwrap().map(|k| k.key_id().index())
}

/// Completes window growth without any receiver lookup for provider membership alone.
fn finish_seen_checks(st: &mut State) -> usize {
    let account = st.test_account().unwrap().id();
    see_at(st.wallet_mut().db_mut(), account, &[], NOW);
    value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_keys WHERE provider_seen=1",
        [],
    )
}

/// A reservation is reclaimed, without a status if unstarted, once its latest quote
/// deadline, or its creation without a quote, is the cooldown in the past; a started one
/// also needs a fresh status for each accepted quote. A provider deadline past the
/// requested one is capped, so it cannot hold the address longer.
#[test]
fn reclamation_waits_for_the_latest_deadline_plus_cooldown() {
    for case in ["unquoted", "lost response", "started"] {
        let mut st = fixture();
        let r = prepare(&mut st, NOW);
        let mut eligible_at = NOW + RECEIVE_RECLAIM_SECONDS;
        if case != "unquoted" {
            quote(&mut st, &r, "first", false);
            // A later request asks for a later deadline.
            let second = begin_at(&mut st, &r, "second", NOW + 120, NOW + 30);
            second.unwrap().unwrap();
            eligible_at += 120;
        }
        if case == "started" {
            finish(&mut st, "second", &accepted("second", None, NOW + 9_999)).unwrap();
            let started = start(&mut st, "second").unwrap().unwrap();
            assert_eq!(started.deadline, NOW + 120);
            assert_eq!(operation(&st, "second").unwrap().3, Some(NOW + 120));
            for request in ["first", "second"] {
                report(&mut st, request, AwaitingDeposit, false, eligible_at - 1);
            }
        }
        assert!(reap(&mut st, eligible_at - 1).is_empty(), "{case}");
        assert_eq!(reap(&mut st, eligible_at), [0], "{case}");
    }
}

/// A device clock days ahead of the chain cannot reclaim a reservation, started or not,
/// while its provider deadline has not passed by block time, since the provider may still
/// take a deposit. Once the chain catches up, it is reclaimed.
#[test]
fn a_fast_clock_cannot_reclaim_before_the_deadline_by_block_time() {
    for started in [false, true] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let r = prepare(&mut st, NOW);
        begin(&mut st, &r, "quote").unwrap().unwrap();
        finish(&mut st, "quote", &accepted("deposit", None, NOW + 60)).unwrap();
        let fast = EXPIRED + 5 * 24 * 60 * 60;
        // The chain is still before the deadline.
        chain_agrees(st.wallet().db(), NOW);
        if started {
            start(&mut st, "quote").unwrap().unwrap();
            let waiting = observed(AwaitingDeposit, false);
            let db = st.wallet_mut().db_mut();
            db.record_operation_status(account, "deposit", None, waiting, fast - 10)
                .unwrap();
        }
        let reaped = tx(st.wallet_mut().db_mut(), |c, p| {
            store::swap::reservations::reap(c, p, account, fast)
        });
        assert!(reaped.unwrap().is_empty(), "started={started}");
        assert_eq!(
            reap(&mut st, fast),
            [r.key_id().index()],
            "started={started}"
        );
    }
}

/// A fresh status reclaims an abandoned started reservation at once: its key stops
/// scanning but keeps its quotes. A paid one is released instead, even when only
/// scanning found the payment, and keeps scanning. Their quotes were shown for funding,
/// so none of these addresses is issued again, and accepted quotes move the bound rather
/// than fill it.
#[test]
fn statuses_reclaim_abandoned_reservations_and_release_paid_ones() {
    let mut st = fixture();
    let keys: Vec<_> = (0..RECEIVE_GAP_LIMIT)
        .map(|i| {
            let r = prepare(&mut st, NOW);
            assert_eq!(r.key_id().index(), i);
            quote(&mut st, &r, &format!("quote-{i}"), true);
            r
        })
        .collect();
    // Index 1 is abandoned, 0 and 3 report their payouts, and 2's status misses its
    // payment. The rest of the window stays reserved.
    let paid = [&keys[0], &keys[2], &keys[3]];
    for r in paid {
        pay(&mut st, r.full_viewing_key(), 100_000);
    }
    let abandoned = keys[1].key_id();
    assert!(scanning_keys(&st).contains(&abandoned));
    report(&mut st, "quote-1", AwaitingDeposit, false, EXPIRED);
    assert!(!reserved(&st, &keys[1]));
    assert!(operation(&st, "quote-1").is_some());
    assert!(!scanning_keys(&st).contains(&abandoned));
    report(&mut st, "quote-0", PAID, true, EXPIRED);
    report(&mut st, "quote-2", AwaitingDeposit, false, EXPIRED);
    report(&mut st, "quote-3", PAID, true, EXPIRED);
    for r in paid {
        assert!(!reserved(&st, r), "{:?}", r.key_id());
        assert!(scanning_keys(&st).contains(&r.key_id()), "{:?}", r.key_id());
    }
    assert!(reap(&mut st, EXPIRED).is_empty());
    let issued = prepare_seen(&mut st, EXPIRED, &[]);
    assert_eq!(issued.key_id().index(), RECEIVE_GAP_LIMIT);
}

/// A request whose answer was lost is possibly accepted, but its address is reused once
/// its reservation is reclaimed and no fresh address is left, whether or not the seen set
/// holds it, since this wallet's own request may have given it out. A set that holds it
/// moves the bound instead, so a fresh address comes first. Without a set nothing is
/// issued.
#[test]
fn lost_requests_are_reused_when_no_fresh_address_is_left() {
    let cases = [
        ("unchecked", Err(SeenUnavailable)),
        ("held", Ok(RECEIVE_GAP_LIMIT)),
        ("unseen", Ok(0)),
    ];
    for (case, next) in cases {
        let mut st = fixture();
        let lost = prepare(&mut st, NOW);
        begin(&mut st, &lost, "lost").unwrap().unwrap();
        let now = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
        assert_eq!(reap(&mut st, now), [0]);
        abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
        let held = [lost.receiver().to_raw_address_bytes()];
        let prepared = match case {
            "unchecked" => try_prepare(&mut st, now, None),
            "held" => try_prepare_seen(&mut st, now, &held),
            _ => try_prepare_seen(&mut st, now, &[]),
        };
        let index = prepared.unwrap().map(|key| key.key_id().index());
        assert_eq!(index, next, "{case}");
    }
}

/// A started reservation stays reserved while its conclusive status is stale, and its key
/// keeps scanning when keys close, so a fresh status can still find it scanned empty and
/// reclaim it. A key closed while reserved would hold its address forever.
#[test]
fn a_reserved_key_stays_open_until_a_fresh_status_reclaims_it() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "refunded", true);
    report(&mut st, "refunded", NO_RECEIPT, false, NOW + 61);
    let height = tip(&st).height;
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, EXPIRED, height), 0);
    assert!(reserved(&st, &r));
    assert!(active_from(&st, r.key_id()).is_some());
    report(&mut st, "refunded", NO_RECEIPT, false, EXPIRED);
    assert!(!reserved(&st, &r));
}

/// A started reservation needs a fresh conclusive status: a funded swap's is a refund,
/// and an older status arriving late does not replace a newer one, though its deposit
/// evidence sticks, so a later fresh unfunded status cannot reclaim the address.
#[test]
fn a_started_reservation_needs_a_fresh_conclusive_status() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "funded", true);
    report(&mut st, "funded", INCONCLUSIVE, true, EXPIRED);
    assert!(reserved(&st, &r));
    report(&mut st, "funded", NO_RECEIPT, true, EXPIRED + 1);
    assert!(!reserved(&st, &r));

    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "accepted", true);
    let expired = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    report(&mut st, "accepted", AwaitingDeposit, false, expired - 1);
    assert!(reap(&mut st, expired + 120).is_empty());
    report(&mut st, "accepted", Active, false, expired + 121);
    report(&mut st, "accepted", AwaitingDeposit, false, expired + 120);
    assert!(reap(&mut st, expired + 121).is_empty());
    report(&mut st, "accepted", AwaitingDeposit, false, expired + 122);
    assert!(!reserved(&st, &r));

    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "late", true);
    let funded = |st: &State| -> bool {
        let sql = "SELECT funded FROM ironwood_one_time_operations";
        value(st.wallet().conn(), sql, [])
    };
    report(&mut st, "late", AwaitingDeposit, false, NOW + 2);
    report(&mut st, "late", Active, true, NOW + 1);
    let row = Some((NOW + 2, 4, None, Some(NOW + 60)));
    assert_eq!(operation(&st, "late"), row);
    assert!(funded(&st));
    report(&mut st, "late", AwaitingDeposit, false, EXPIRED);
    assert!(funded(&st));
    assert!(reap(&mut st, EXPIRED).is_empty());
    assert!(reserved(&st, &r));
    assert!(active_from(&st, r.key_id()).is_some());
    assert_ne!(prepare(&mut st, EXPIRED).key_id(), r.key_id());
}

/// After a restart the same draft is resumed, and a quote request the provider rejected
/// keeps it until the requested deadline. The next swap then gets another address, and
/// the rejected one is reissued only once no fresh one is left under the bound.
#[test]
fn a_rejected_quote_frees_its_address_once_the_bound_forces_it() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    reopen(&mut st);
    assert_eq!(prepare(&mut st, NOW).key_id(), r.key_id());
    begin(&mut st, &r, "too-low").unwrap().unwrap();
    finish(&mut st, "too-low", &OperationOutcome::Rejected).unwrap();
    let begun = Some((NOW, 0, None, Some(NOW + 60)));
    assert_eq!(operation(&st, "too-low"), begun);
    assert_eq!(prepare(&mut st, NOW + 1).key_id(), r.key_id());
    chain_agrees(st.wallet().db(), NOW + 60);
    let next = prepare_seen(&mut st, NOW + 60, &[]);
    assert_eq!(next.key_id().index(), 1);
    assert!(!reserved(&st, &r));
    abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
    let issued = prepare_seen(&mut st, EXPIRED, &[]);
    assert_eq!(issued.key_id(), r.key_id());
}

/// A request finishes one way only: a rejected quote cannot later be accepted and
/// started, and an accepted one cannot later be rejected.
#[test]
fn a_finished_request_keeps_its_outcome() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    begin(&mut st, &r, "too-low").unwrap().unwrap();
    finish(&mut st, "too-low", &OperationOutcome::Rejected).unwrap();
    finish(&mut st, "too-low", &OperationOutcome::Rejected).unwrap();
    let late = finish(&mut st, "too-low", &accepted("too-low", None, NOW + 60));
    assert!(rejected_input(late));
    assert!(!matches!(start(&mut st, "too-low"), Ok(Ok(_))));
    let next = prepare(&mut st, NOW + 1);
    quote(&mut st, &next, "fine", false);
    assert!(rejected_input(finish(
        &mut st,
        "fine",
        &OperationOutcome::Rejected
    )));
}

/// An active status, as an adapter reports for one it does not recognize, releases
/// nothing; another memo on the same deposit address is another operation; a payout
/// records its amount, keeping the deadline.
#[test]
fn provider_statuses_update_the_operation_or_leave_it_alone() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "payout", true);
    let deadline = Some(NOW + 60);
    assert_eq!(operation(&st, "payout"), Some((NOW, 0, None, deadline)));
    let active = observed(Active, false);
    let matched = report_with(&mut st, ("payout", None), active, EXPIRED);
    assert!(matched);
    assert!(reap(&mut st, EXPIRED).is_empty());
    assert_eq!(operation(&st, "payout"), Some((EXPIRED, 0, None, deadline)));
    let other = ("payout", Some("memo"));
    let matched = report_with(&mut st, other, observed(NO_RECEIPT, true), EXPIRED);
    assert!(!matched);
    let payout = Terminal(Positive(Some(Zatoshis::const_from_u64(5_000))));
    let payout = observed(payout, true);
    let matched = report_with(&mut st, ("payout", None), payout, EXPIRED + 1);
    assert!(matched);
    let row = (EXPIRED + 1, 2, Some(5_000), deadline);
    assert_eq!(operation(&st, "payout"), Some(row));
}

/// An unfunded quote edit holds a paid reservation until its deadline has passed the
/// cooldown and its status is fresh; then the reservation is released, keeping its
/// quotes, and issuance moves on.
#[test]
fn paid_reservation_closes_once_every_quote_settles() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "edit", false);
    quote(&mut st, &r, "paid", true);
    pay(&mut st, r.full_viewing_key(), 100_000);
    report(&mut st, "paid", PAID, true, NOW + 1);
    report(&mut st, "edit", AwaitingDeposit, false, NOW + 1);
    let expired = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    for now in [NOW + 2, expired] {
        reap(&mut st, now);
        assert!(reserved(&st, &r));
    }
    report(&mut st, "edit", AwaitingDeposit, false, expired);
    assert!(!reserved(&st, &r));
    assert!(operation(&st, "paid").is_some());
    assert_eq!(prepare(&mut st, expired).key_id().index(), 1);
}

/// A key issued for an address another install handed out, whose payment was scanned
/// without it, refuses quotes until its activation rescan, which finds the payment and
/// makes the reservation stale.
#[test]
fn activation_rescan_finds_a_payment_in_already_scanned_blocks() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let issued = tip(&st).height + 1;
    let key = KeyId::new(Purpose::Receive, 0);
    let fvk = derive(&st, key);
    pay(&mut st, &fvk, 100_000);
    let db = st.wallet_mut().db_mut();
    let r = prepare_from(db, account, NOW, issued, Some(&empty_seen(NOW)));
    let r = r.unwrap().unwrap();
    assert_eq!(r.key_id(), key);
    assert_eq!(refusal(begin(&mut st, &r, "unscanned")), Some(Coverage));
    st.scan_cached_blocks_with_one_time_ivks(issued, 1);
    assert!(holds_note(&st, key));
    assert_eq!(refusal(begin(&mut st, &r, "paid")), Some(Stale));
    assert_eq!(operation(&st, "paid"), None);
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 1);
}

/// Neither quoting nor reclamation, by a status or by reaping, runs until scanning
/// reaches a new tip, nor while a directory payment for the address is queued but not yet
/// admitted.
#[test]
fn quoting_and_reclamation_wait_for_the_tip_and_queued_candidates() {
    for queued in [false, true] {
        let mut st = fixture();
        let started = prepare(&mut st, NOW);
        quote(&mut st, &started, "started", true);
        let draft = prepare(&mut st, NOW);
        let behind = if queued {
            let sql = "INSERT INTO ironwood_one_time_payment_recovery
                       SELECT id, zeroblob(32), id, 100000, zeroblob(32), 1, 0, zeroblob(148),
                           100000, zeroblob(32), 0, NULL, NULL, NULL
                       FROM ironwood_one_time_keys";
            exec(st.wallet().conn(), sql, []);
            None
        } else {
            let (h, _) = st.generate_empty_block();
            st.wallet_mut().update_chain_tip(h).unwrap();
            Some(h)
        };
        let blocked = refusal(begin(&mut st, &draft, "blocked"));
        assert_eq!(blocked, Some(Coverage), "{queued}");
        report(&mut st, "started", AwaitingDeposit, false, EXPIRED);
        assert!(reserved(&st, &started), "{queued}");
        assert!(reap(&mut st, EXPIRED).is_empty(), "{queued}");
        if let Some(h) = behind {
            st.scan_cached_blocks_with_one_time_ivks(h, 1);
            let account = st.test_account().unwrap().id();
            settle_empty_filters(st.wallet_mut().db_mut(), account, NOW);
            begin(&mut st, &draft, "caught-up").unwrap().unwrap();
            assert_eq!(reap(&mut st, EXPIRED), [0, 1]);
        }
    }
}

/// Issuance waits for the seen check. Once it is done, issuance resumes at the lowest
/// address never quoted, unless a swap issued before the restore paid that address, which
/// recovery found.
#[test]
fn issuance_waits_for_the_seen_check_and_skips_addresses_recovery_found_paid() {
    for paid in [false, true] {
        let mut st = undiscovered();
        let key = KeyId::new(Purpose::Receive, 0);
        assert_eq!(refusal(try_prepare(&mut st, NOW, None)), Some(Gap));
        let account = st.test_account().unwrap().id();
        see_at(st.wallet_mut().db_mut(), account, &[], NOW);
        if paid {
            let fvk = derive(&st, key);
            let height = pay(&mut st, &fvk, 100_000);
            let candidate = candidate_at(&st, height, &fvk);
            let publication = cover(&mut st, account, &[key]);
            let db = st.wallet_mut().db_mut();
            assert!(look_up(db, account, key, publication, &[candidate]));
        }
        let issued = prepare(&mut st, NOW).key_id().index();
        assert_eq!(issued, u64::from(paid), "{paid}");
    }
}

/// Issuance checks an address it has not registered against the seen set. Seen hits that
/// widen the window are registered and looked up first, so issuance waits rather than
/// issuing one unchecked, then skips one the set holds. Here
/// the old device's quotes reached the provider for the first window and the next
/// address, or only for the next one.
#[test]
fn issuance_checks_addresses_past_the_lookahead_against_the_seen_set() {
    let window = RECEIVE_GAP_LIMIT;
    for held in [(0..=window).collect(), vec![window]] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let seen = Some((NOW, &held[..]));
        if held.len() > 1 {
            // The first window's hits wait for their lookups; the next pass registers the
            // address past it before issuing.
            assert_eq!(issue(&mut st, seen), Err(Gap));
            assert!(finish_seen_checks(&mut st) > 0);
        } else {
            for expected in 0..window {
                let index = issue(&mut st, seen).unwrap();
                assert_eq!(index, expected);
                let key = KeyId::new(Purpose::Receive, index);
                let key = get_key(st.wallet().db(), account, key).unwrap().unwrap();
                quote(&mut st, &key, &format!("quote-{index}"), true);
            }
        }
        assert_eq!(issue(&mut st, seen), Ok(window + 1), "{held:?}");
    }
}

/// Restored addresses the provider saw move the bound and are never reused, nor is one
/// whose quote was shown here, though every other address in the window was quoted and
/// abandoned: the address the bound now allows comes first.
#[test]
fn issuance_skips_restored_addresses_the_provider_saw() {
    let mut st = undiscovered();
    // The old device quoted the first three addresses.
    let seen: Vec<_> = (0..3).map(|i| KeyId::new(Purpose::Receive, i)).collect();
    let account = st.test_account().unwrap().id();
    see(st.wallet_mut().db_mut(), account, &seen);
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 3);
    abandon_indices(&mut st, 4..RECEIVE_GAP_LIMIT + 3);
    let draft = prepare(&mut st, NOW);
    assert_eq!(draft.key_id().index(), 3);
    quote(&mut st, &draft, "after-restore", true);
    report(&mut st, "after-restore", AwaitingDeposit, false, EXPIRED);
    assert!(!reserved(&st, &draft));
    let issued = prepare_seen(&mut st, EXPIRED, &[]);
    assert_eq!(issued.key_id().index(), RECEIVE_GAP_LIMIT + 3);
}

/// A payment moves the recovery bound only once it has the untrusted confirmations, so a
/// reorg that drops it cannot leave an issued address past the bound. Here expired quotes
/// with unknown outcomes hold every other address in the window.
#[test]
fn only_a_confirmed_payment_moves_the_bound() {
    let mut st = fixture();
    let first = prepare(&mut st, NOW);
    begin(&mut st, &first, "lost").unwrap().unwrap();
    pay(&mut st, first.full_viewing_key(), 100_000);
    let account = st.test_account().unwrap().id();
    settle_empty_filters(st.wallet_mut().db_mut(), account, NOW);
    let expired = NOW + 60;
    for i in 1..RECEIVE_GAP_LIMIT {
        chain_agrees(st.wallet().db(), expired);
        let r = prepare(&mut st, expired);
        assert_eq!(r.key_id().index(), i);
        begin(&mut st, &r, &format!("lost-{i}")).unwrap().unwrap();
    }
    chain_agrees(st.wallet().db(), expired);
    let limited = refusal(try_prepare(&mut st, expired, Some(&empty_seen(expired))));
    assert_eq!(limited, Some(ReservationPolicy::Limit));
    confirm(&mut st);
    chain_agrees(st.wallet().db(), expired);
    assert_eq!(
        prepare(&mut st, expired).key_id().index(),
        RECEIVE_GAP_LIMIT
    );
}

/// A rewind removes a payment but not its used marker, and the provider saw every
/// earlier address, so the draft past them stays within recovery and the paid address
/// is never reissued. A paid swap with an inconclusive outcome is not reclaimed.
#[test]
fn reorg_retains_used_marker_and_seen_addresses_keep_the_bound() {
    let mut st = fixture();
    let before_payment = tip(&st).height;
    let first = prepare(&mut st, NOW);
    quote(&mut st, &first, "first", true);
    pay(&mut st, first.full_viewing_key(), 100_000);
    confirm(&mut st);
    for i in 1..RECEIVE_GAP_LIMIT {
        let r = prepare(&mut st, NOW);
        let request = format!("funded-{i}");
        quote(&mut st, &r, &request, true);
        report(&mut st, &request, Active, true, NOW + 1);
    }
    let draft = prepare(&mut st, NOW);
    assert_eq!(draft.key_id().index(), RECEIVE_GAP_LIMIT);
    st.truncate_to_height_retaining_cache(before_payment);
    assert_eq!(prepare(&mut st, NOW).key_id(), draft.key_id());
    begin(&mut st, &draft, "beyond").unwrap().unwrap();
    report(&mut st, "first", INCONCLUSIVE, false, EXPIRED);
    assert!(active_from(&st, first.key_id()).is_some());
}

/// Issuance refuses a tip too far ahead of the scanned one and waits for the seen check,
/// even on an account created from a fresh seed. It then takes the lowest address never
/// quoted, scanned from above the scanned tip, while a refund key starts scanning only
/// once its funding transaction is stored.
#[test]
fn issuance_starts_after_the_scanned_tip_once_the_seen_check_is_done() {
    {
        let mut st = undiscovered();
        let account = st.test_account().unwrap().id();
        let (h, _) = st.generate_empty_block();
        st.wallet_mut().update_chain_tip(h).unwrap();
        st.scan_cached_blocks_with_one_time_ivks(h, 1);
        let through = tip(&st);
        let db = st.wallet_mut().db_mut();
        assert!(all_keys(db, account).unwrap().is_empty());
        let behind = through.height + ISSUANCE_TIP_LAG + 1;
        let issued = db.prepare_receive_reservation(account, NOW, behind, None);
        assert_eq!(refusal(issued), Some(Coverage));
        let refund = reserve_refund(db, account, behind);
        assert_eq!(refusal(refund), Some(Coverage));
        let near = through.height + ISSUANCE_TIP_LAG;
        let issued = db.prepare_receive_reservation(account, NOW, near, None);
        assert_eq!(refusal(issued), Some(Gap));
        see_at(db, account, &[], NOW);
        let seen = empty_seen(NOW);
        let issued = db.prepare_receive_reservation(account, NOW, near, Some(&seen));
        let r = issued.unwrap().unwrap().key_id();
        assert_eq!(r, KeyId::new(Purpose::Receive, 0));
        let refund = reserve_refund(db, account, through.height);
        let refund = refund.unwrap().unwrap().key_id();
        assert_eq!(refund, KeyId::new(Purpose::Refund, 0));
        assert_eq!(active_from(&st, r), Some(through.height + 1));
        assert_eq!(active_from(&st, refund), None);
    }
}

/// Starting an accepted quote returns its deposit instructions and starts only its
/// reservation. A repeated acceptance can lower the deadline but not change the address
/// or memo, and a deposit identity belongs to one operation in the account, on the same
/// reservation or another, so the instructions shown keep matching provider statuses.
/// A new review resumes an accepted, unstarted draft until its deadline, then abandons it.
#[test]
fn deposit_instructions_bind_one_operation_and_cannot_change() {
    let mut st = fixture();
    let shared = |memo, deadline| accepted("shared", memo, deadline);
    // Both quotes share a deposit address and differ only by memo.
    let first = prepare(&mut st, NOW);
    begin(&mut st, &first, "first").unwrap().unwrap();
    for _ in 0..2 {
        finish(&mut st, "first", &shared(Some("memo-1"), NOW + 60)).unwrap();
    }
    begin(&mut st, &first, "retry").unwrap().unwrap();
    let shown = start(&mut st, "first").unwrap().unwrap();
    let shown = OperationOutcome::Accepted(shown);
    assert_eq!(shown, shared(Some("memo-1"), NOW + 60));
    let second = prepare(&mut st, NOW);
    assert_ne!(second.key_id(), first.key_id());
    begin(&mut st, &second, "second").unwrap().unwrap();
    // Another reservation's unaccepted operation cannot take the started identity.
    let taken = finish(&mut st, "second", &shared(Some("memo-1"), NOW + 60));
    assert!(rejected_input(taken));
    finish(&mut st, "second", &shared(None, NOW + 60)).unwrap();
    for (request, memo) in [
        ("first", Some("memo-2")),
        ("first", None),
        ("retry", Some("memo-1")),
        ("second", Some("memo-1")),
    ] {
        let finished = finish(&mut st, request, &shared(memo, NOW + 60));
        assert!(rejected_input(finished), "{request} {memo:?}");
    }
    // An identical repeat succeeds and can only lower the deadline.
    finish(&mut st, "first", &shared(Some("memo-1"), NOW + 30)).unwrap();
    let restarted = start(&mut st, "first").unwrap().unwrap();
    let restarted = OperationOutcome::Accepted(restarted);
    assert_eq!(restarted, shared(Some("memo-1"), NOW + 30));
    let waiting = observed(AwaitingDeposit, false);
    let matched = report_with(&mut st, ("shared", Some("memo-1")), waiting, NOW + 1);
    assert!(matched);
    assert_eq!(operation(&st, "first").unwrap().0, NOW + 1);
    assert_eq!(operation(&st, "second").unwrap().0, NOW);
    assert_eq!(prepare(&mut st, NOW).key_id(), second.key_id());
    chain_agrees(st.wallet().db(), NOW + 60);
    assert_eq!(prepare(&mut st, NOW + 60).key_id().index(), 2);
    assert_eq!(refusal(start(&mut st, "second")), Some(Stale));
    assert_eq!(refusal(start(&mut st, "retry")), Some(Stale));
    assert!(rejected_input(start(&mut st, "unknown")));
}

/// Beginning a request needs a future deadline, and returns a fresh request identity
/// each time, which finishes and starts the operation.
#[test]
fn begin_needs_a_future_deadline_and_returns_a_fresh_request() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    assert!(rejected_input(begin_at(&mut st, &r, "expired", NOW, NOW)));
    assert_eq!(operation(&st, "expired"), None);
    let index = r.key_id().index();
    let db = st.wallet_mut().db_mut();
    let [first, second] = [(); 2].map(|_| {
        let seen = empty_seen(NOW);
        let begun = db.begin_receive_operation(account, index, NOW + 60, NOW, Some(&seen));
        begun.unwrap().unwrap()
    });
    assert_eq!(first.len(), 32);
    assert_ne!(first, second);
    finish(&mut st, &first, &accepted("deposit", None, NOW + 60)).unwrap();
    assert_eq!(start(&mut st, &first).unwrap().unwrap().address, "deposit");
}

/// An accepted deadline that has passed by the earlier of the request time and the latest
/// block time is refused without changing the operation, but one only behind a fast
/// device clock is kept, since the provider sets it by its own clock.
#[test]
fn finish_refuses_an_accepted_deadline_that_has_passed() {
    let mut st = fixture();
    let chain_time: i64 = value(
        st.wallet().conn(),
        "SELECT time FROM blocks ORDER BY height DESC LIMIT 1",
        [],
    );
    // The device clock runs a day ahead of the chain.
    let now = chain_time + 24 * 60 * 60;
    let r = prepare(&mut st, NOW);
    begin_at(&mut st, &r, "fast", now + 60, now)
        .unwrap()
        .unwrap();
    let before = operation(&st, "fast");
    for passed in [chain_time - 30 * 24 * 60 * 60, chain_time] {
        let finished = finish(&mut st, "fast", &accepted("deposit", None, passed));
        assert!(rejected_input(finished), "{passed}");
        assert_eq!(operation(&st, "fast"), before);
    }
    let deadline = chain_time + 60 * 60;
    finish(&mut st, "fast", &accepted("deposit", None, deadline)).unwrap();
    assert_eq!(start(&mut st, "fast").unwrap().unwrap().deadline, deadline);
}

/// Starting refuses an accepted quote whose deadline has passed by the earlier of the
/// caller's clock and the latest block time, on a first start or a restart, without
/// marking it started. A device clock days fast or slow still starts a live quote.
#[test]
fn start_refuses_a_quote_past_its_deadline() {
    const DAY: i64 = 24 * 60 * 60;
    let started = |st: &State| -> bool {
        let sql = "SELECT started FROM ironwood_one_time_operations WHERE request = 'quote'";
        value(st.wallet().conn(), sql, [])
    };
    // Each case: the device clock when the quote is begun, the accepted deadline, the
    // chain's time and the device clock at start, and whether it starts.
    for (case, begun, deadline, chain, at, starts) in [
        (
            "late first start",
            NOW,
            NOW + 60,
            NOW + 120,
            NOW + 120,
            false,
        ),
        ("fast device", NOW, NOW + 60, NOW, NOW + 5 * DAY, true),
        (
            "slow device",
            NOW - 2 * DAY,
            NOW + 3600,
            NOW,
            NOW - 2 * DAY + 10,
            true,
        ),
    ] {
        let mut st = fixture();
        let r = prepare(&mut st, NOW);
        begin_at(&mut st, &r, "quote", begun + 3600, begun)
            .unwrap()
            .unwrap();
        finish(&mut st, "quote", &accepted("deposit", None, deadline)).unwrap();
        chain_agrees(st.wallet().db(), chain);
        let start = start_at(&mut st, "quote", at);
        assert_eq!(start.unwrap().is_ok(), starts, "{case}");
        assert_eq!(started(&st), starts, "{case}");
    }
    // A restart after the deadline is refused too.
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    begin(&mut st, &r, "quote").unwrap().unwrap();
    finish(&mut st, "quote", &accepted("deposit", None, NOW + 60)).unwrap();
    chain_agrees(st.wallet().db(), NOW);
    assert!(start_at(&mut st, "quote", NOW).unwrap().is_ok());
    chain_agrees(st.wallet().db(), NOW + 120);
    assert_eq!(refusal(start_at(&mut st, "quote", NOW + 120)), Some(Stale));
}

/// A reservation with two accepted quote requests starts only one: the other is refused
/// once the first has started, while restarting the first returns its instructions again,
/// so one receiver never has two quotes a user could fund.
#[test]
fn one_reservation_starts_only_one_accepted_quote() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    for request in ["first", "second"] {
        begin(&mut st, &r, request).unwrap().unwrap();
        finish(&mut st, request, &accepted(request, None, NOW + 60)).unwrap();
    }
    for _ in 0..2 {
        assert_eq!(start(&mut st, "first").unwrap().unwrap().address, "first");
    }
    assert_eq!(refusal(start(&mut st, "second")), Some(Stale));
    let sql = "SELECT request FROM ironwood_one_time_operations WHERE started = 1";
    let started: Vec<String> = column(st.wallet().conn(), sql, []);
    assert_eq!(started, ["first"]);
    assert_eq!(refusal(begin(&mut st, &r, "third")), Some(Stale));
}

/// Refund issuance skips a refund address the provider's seen set holds, such as one an
/// unfunded quote used before a restore, and registers it for a lookup, so a
/// later reservation whose set lacks it does not issue it either.
#[test]
fn refund_issuance_skips_addresses_the_provider_saw() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let first = KeyId::new(Purpose::Refund, 0);
    let held = [derive(&st, first)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes()];
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = ProviderSeen {
        since: 0,
        until: NOW,
        contains: &contains,
    };
    let through = tip(&st).height;
    let db = st.wallet_mut().db_mut();
    let issued = db.reserve_refund_key(account, NOW, through, Some(&seen));
    assert_eq!(issued.unwrap().unwrap().key_id().index(), 1);
    let sql = "SELECT k.provider_seen FROM ironwood_one_time_keys k JOIN ironwood_block_receivers r ON r.account_id=k.account_id AND r.purpose=k.purpose AND r.key_index=k.key_index WHERE k.purpose=0 AND k.key_index=?1";
    let seen_and_due: Vec<bool> = column(&db.conn, sql, [first.index().to_be_bytes()]);
    assert_eq!(seen_and_due, [true]);
    // The reserved key was never exposed, so it is reused first.
    db.prepare_one_time_recovery(account, 1024, NOW).unwrap();
    let again = db.reserve_refund_key(account, NOW, through, Some(&empty_seen(NOW)));
    assert_eq!(again.unwrap().unwrap().key_id().index(), 1);
    let seen = empty_seen(NOW);
    db.begin_refund_operation(account, 1, NOW + 60, NOW, Some(&seen))
        .unwrap()
        .unwrap();
    db.prepare_one_time_recovery(account, 1024, NOW).unwrap();
    let next = db.reserve_refund_key(account, NOW, through, Some(&empty_seen(NOW)));
    assert_eq!(next.unwrap().unwrap().key_id().index(), 2);
}

/// A seen set that holds every receiver stops refund issuance with `Gap` once it probed
/// every index the bound allows, keeping the keys it registered. They move the bound, so
/// the next reservation continues past them instead of probing them again.
#[test]
fn refund_issuance_bounds_seen_set_probes() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let through = tip(&st).height;
    let probes = std::cell::Cell::new(0u64);
    let contains = |receivers: &[[u8; 43]]| {
        probes.set(probes.get() + receivers.len() as u64);
        vec![true; receivers.len()]
    };
    let everything = ProviderSeen {
        since: 0,
        until: NOW,
        contains: &contains,
    };
    let db = st.wallet_mut().db_mut();
    let issued = db.reserve_refund_key(account, NOW, through, Some(&everything));
    assert!(matches!(issued.unwrap(), Err(Gap)));
    let held = probes.get();
    assert_eq!(held, RECEIVE_GAP_LIMIT);
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_keys k JOIN ironwood_block_receivers r ON r.account_id=k.account_id AND r.purpose=k.purpose AND r.key_index=k.key_index WHERE k.purpose=0 AND k.provider_seen";
    assert_eq!(value::<u64>(&db.conn, sql, []), held);

    let nothing = |receivers: &[[u8; 43]]| vec![false; receivers.len()];
    let seen = ProviderSeen {
        since: 0,
        until: NOW,
        contains: &nothing,
    };
    db.prepare_one_time_recovery(account, 1024, NOW).unwrap();
    let next = db.reserve_refund_key(account, NOW, through, Some(&seen));
    assert_eq!(next.unwrap().unwrap().key_id().index(), held);
}

/// A large supported window cannot turn one reservation into unbounded key derivation.
#[test]
fn widened_refund_window_resumes_after_one_hundred_provider_hits() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let through = tip(&st).height;
    let high = KeyId::new(Purpose::Refund, 500);
    tx(st.wallet_mut().db_mut(), |c, p| {
        let (id, _) = register(c, p, account, high, through, false, Discovery::Filter, NOW)?;
        store::swap::reservations::record_provider_seen(c, id)
    })
    .unwrap();
    see_at(st.wallet_mut().db_mut(), account, &[], NOW);
    let probes = std::cell::Cell::new(0usize);
    let contains = |receivers: &[[u8; 43]]| {
        probes.set(probes.get() + receivers.len());
        vec![true; receivers.len()]
    };
    let seen = ProviderSeen {
        since: 0,
        until: NOW,
        contains: &contains,
    };
    let db = st.wallet_mut().db_mut();
    for expected in [101, 201] {
        db.prepare_one_time_recovery(account, 1024, NOW).unwrap();
        probes.set(0);
        assert!(matches!(
            db.reserve_refund_key(account, NOW, through, Some(&seen))
                .unwrap(),
            Err(Gap)
        ));
        assert_eq!(probes.get(), 100);
        let registered: i64 = value(
            &db.conn,
            "SELECT COUNT(*) FROM ironwood_one_time_keys WHERE purpose=0 AND provider_seen=1",
            [],
        );
        assert_eq!(registered, expected);
    }
}

/// Abandoned requests with unknown outcomes fill the bound without moving it, since a
/// restore walks past only receipts, seen addresses and accepted quotes, so issuance
/// reuses the lowest of them. An accepted quote moves the bound.
#[test]
fn only_accepted_quotes_move_the_bound() {
    for (accepted, issued) in [(false, Ok(0)), (true, Ok(30))] {
        let mut st = fixture();
        abandon_indices(&mut st, 0..RECEIVE_GAP_LIMIT);
        if accepted {
            let sql = "UPDATE ironwood_one_time_operations SET reference = 'accepted'
                       WHERE request = 'abandoned-0'";
            exec(st.wallet().conn(), sql, []);
        }
        let prepared = try_prepare(&mut st, NOW, Some(&empty_seen(NOW))).unwrap();
        let index = prepared.map(|key| key.key_id().index());
        assert_eq!(index, issued, "accepted={accepted}");
    }
}

/// A single-address seen probe accepts only one answer. A malformed answer for an
/// address no key has registered fails issuance, for a refund key and for an incoming
/// one past the lookahead, rather than counting the address as unseen.
#[test]
fn single_address_seen_probes_reject_malformed_answers() {
    for answer in [vec![], vec![true, true]] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let through = tip(&st).height;
        let probed = |key| {
            derive(&st, key)
                .address_at(0u32, Scope::External)
                .to_raw_address_bytes()
        };
        let refund = probed(KeyId::new(Purpose::Refund, 0));
        let incoming = probed(KeyId::new(Purpose::Receive, RECEIVE_GAP_LIMIT));
        // Bulk queries of registered keys are answered correctly.
        let contains = |receivers: &[[u8; 43]]| match receivers {
            [r] if *r == refund || *r == incoming => answer.clone(),
            _ => vec![false; receivers.len()],
        };
        let seen = ProviderSeen {
            since: 0,
            until: NOW,
            contains: &contains,
        };
        let db = st.wallet_mut().db_mut();
        assert!(rejected_input(db.reserve_refund_key(
            account,
            NOW,
            through,
            Some(&seen)
        )));

        for _ in 0..RECEIVE_GAP_LIMIT {
            let index = issue(&mut st, Some((NOW, &[])));
            let key = KeyId::new(Purpose::Receive, index.unwrap());
            let key = get_key(st.wallet().db(), account, key).unwrap().unwrap();
            quote(
                &mut st,
                &key,
                &format!("quote-{}", key.key_id().index()),
                true,
            );
        }
        let db = st.wallet_mut().db_mut();
        let issued = db.prepare_receive_reservation(account, NOW, through, Some(&seen));
        assert!(rejected_input(issued), "{answer:?}");
    }
}

/// Issuing an incoming or refund address needs a seen set whose read began within the
/// last 15 minutes of the caller's clock and at most a minute ahead of it, so the set
/// shows what another device of the seed gave the provider until shortly before now.
#[test]
fn issuance_needs_a_fresh_seen_set() {
    use zakura_one_time_ivk::swap::{PROVIDER_READ_CLOCK_SKEW_SECS, PROVIDER_READ_MAX_AGE_SECS};
    for (case, until, fresh) in [
        ("none", None, false),
        ("stale", Some(NOW - PROVIDER_READ_MAX_AGE_SECS - 1), false),
        (
            "future",
            Some(NOW + PROVIDER_READ_CLOCK_SKEW_SECS + 1),
            false,
        ),
        ("oldest", Some(NOW - PROVIDER_READ_MAX_AGE_SECS), true),
        ("ahead", Some(NOW + PROVIDER_READ_CLOCK_SKEW_SECS), true),
    ] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let through = tip(&st).height;
        let seen = until.map(|until| ProviderSeen {
            since: 0,
            until,
            contains: &holds_nothing,
        });
        let expected = (!fresh).then_some(SeenUnavailable);
        let before = all_keys(st.wallet().db(), account).unwrap().len();
        let db = st.wallet_mut().db_mut();
        let incoming = db.prepare_receive_reservation(account, NOW, through, seen.as_ref());
        assert_eq!(refusal(incoming), expected, "{case}");
        db.prepare_one_time_recovery(account, 1024, NOW).unwrap();
        let refund = db.reserve_refund_key(account, NOW, through, seen.as_ref());
        assert_eq!(refusal(refund), expected, "{case}");
        let keys = all_keys(st.wallet().db(), account).unwrap().len();
        assert_eq!(keys - before, if fresh { 2 } else { 0 }, "{case}");
    }
}

/// Recovery registers the keys a restored seed used without a seen set, which issuance
/// then needs.
#[test]
fn recovery_registers_keys_without_a_seen_set() {
    let mut st = undiscovered();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 0);
    see(st.wallet_mut().db_mut(), account, &[key]);
    assert!(get_key(st.wallet().db(), account, key).unwrap().is_some());
    assert_eq!(
        refusal(try_prepare(&mut st, NOW, None)),
        Some(SeenUnavailable)
    );
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 1);
}

/// A draft never quoted is checked against a fresh seen set before its first quote, in
/// `prepare` and in `begin`. One the set holds was given to the provider by another
/// device, so it is retired: released and never issued, but still scanning in case that
/// swap pays it.
#[test]
fn an_unquoted_draft_is_checked_before_its_first_quote() {
    for checked_in in ["begin", "prepare"] {
        let mut st = fixture();
        let r = prepare(&mut st, NOW);
        let held = [r.receiver().to_raw_address_bytes()];
        let contains =
            |receivers: &[[u8; 43]]| receivers.iter().map(|x| held.contains(x)).collect();
        let holds = ProviderSeen {
            since: 0,
            until: NOW,
            contains: &contains,
        };
        let stale = empty_seen(NOW - 901);
        if checked_in == "begin" {
            for seen in [None, Some(&stale)] {
                let refused = begin_seen(&mut st, &r, "first", (NOW + 60, NOW), seen);
                assert_eq!(refusal(refused), Some(SeenUnavailable));
            }
            assert!(reserved(&st, &r));
            let refused = begin_seen(&mut st, &r, "first", (NOW + 60, NOW), Some(&holds));
            assert_eq!(refusal(refused), Some(Stale));
            assert_eq!(operation(&st, "first"), None);
        } else {
            assert_eq!(
                refusal(try_prepare(&mut st, NOW, None)),
                Some(SeenUnavailable)
            );
            let next = prepare_seen(&mut st, NOW, &held);
            assert_eq!(next.key_id().index(), 1, "{checked_in}");
        }
        assert!(!reserved(&st, &r), "{checked_in}");
        assert!(active_from(&st, r.key_id()).is_some(), "{checked_in}");
        let next = prepare_seen(&mut st, NOW, &held);
        assert_eq!(next.key_id().index(), 1, "{checked_in}");
    }
}

/// A quoted draft is resumed, even without a seen set, while its latest request's
/// deadline holds, however often it is quoted again. After that, `begin` refuses another
/// request on it, and the next attempt gets another address, which needs a fresh set.
#[test]
fn a_quoted_draft_is_resumed_until_its_deadline() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "first", false);
    chain_agrees(st.wallet().db(), NOW + 30);
    for at in [NOW + 10, NOW + 30] {
        let resumed = try_prepare(&mut st, at, None).unwrap().unwrap();
        assert_eq!(resumed.key_id(), r.key_id());
        let requote = begin_seen(&mut st, &r, &format!("edit-{at}"), (NOW + 60, at), None);
        requote.unwrap().unwrap();
    }
    chain_agrees(st.wallet().db(), NOW + 60);
    let late = begin_seen(&mut st, &r, "late", (NOW + 120, NOW + 60), None);
    assert_eq!(refusal(late), Some(Stale));
    assert_eq!(operation(&st, "late"), None);
    let refused = try_prepare(&mut st, NOW + 60, None);
    assert_eq!(refusal(refused), Some(SeenUnavailable));
    assert!(!reserved(&st, &r));
    assert_eq!(prepare(&mut st, NOW + 60).key_id().index(), 1);
}

/// A draft is reusable until the deadline its latest request asked for when the outcome
/// is a rejection or unknown, and until the accepted deadline otherwise. A rejected or
/// accepted draft is then abandoned. One with only unknown outcomes stays reserved until
/// reaping reclaims it, the cooldown after its deadline.
#[test]
fn a_draft_is_reusable_until_its_latest_request_expires() {
    for (case, expires) in [
        ("rejected", NOW + 120),
        ("unknown", NOW + 120),
        ("accepted", NOW + 60),
    ] {
        let mut st = fixture();
        let r = prepare(&mut st, NOW);
        begin_at(&mut st, &r, "quote", NOW + 120, NOW)
            .unwrap()
            .unwrap();
        match case {
            "rejected" => finish(&mut st, "quote", &OperationOutcome::Rejected).unwrap(),
            "accepted" => finish(&mut st, "quote", &accepted("quote", None, expires)).unwrap(),
            _ => {}
        }
        chain_agrees(st.wallet().db(), expires - 1);
        assert_eq!(prepare(&mut st, expires - 1).key_id(), r.key_id(), "{case}");
        chain_agrees(st.wallet().db(), expires);
        assert_eq!(prepare(&mut st, expires).key_id().index(), 1, "{case}");
        assert_eq!(reserved(&st, &r), case == "unknown", "{case}");
        if case == "unknown" {
            let reclaim = expires + RECEIVE_RECLAIM_SECONDS;
            assert!(reap(&mut st, reclaim - 1).is_empty());
            assert!(reap(&mut st, reclaim).contains(&0));
            assert!(!reserved(&st, &r));
        }
    }
}

/// A started reservation is never resumed as a draft, even while its deadline holds.
#[test]
fn a_started_reservation_is_never_resumed() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "started", true);
    chain_agrees(st.wallet().db(), NOW);
    assert_eq!(
        refusal(try_prepare(&mut st, NOW, None)),
        Some(SeenUnavailable)
    );
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 1);
    assert_eq!(
        start(&mut st, "started").unwrap().unwrap().address,
        "started"
    );
}

/// A day, in seconds.
const DAY: i64 = 24 * 60 * 60;

/// `request`'s stored request time.
fn begun_at(st: &State, request: &str) -> i64 {
    let sql = "SELECT begun_at FROM ironwood_one_time_operations WHERE request = ?1";
    value(st.wallet().conn(), sql, [request])
}

/// A reservation without an operation floor, as one made before the floor existed, counts
/// every request on its key, even one begun before `reserved_at` after the clock was set
/// back. While its latest request is live it is resumed, not retired, though the set holds
/// the address its own request gave the provider. Once that request has expired, `begin`
/// refuses another as stale, and with only unknown outcomes it stays reserved until reaped.
#[test]
fn a_reservation_without_a_floor_counts_every_request() {
    for case in ["live", "expired"] {
        let mut st = fixture();
        let r = prepare(&mut st, NOW);
        begin(&mut st, &r, "old").unwrap().unwrap();
        let sql = "UPDATE ironwood_one_time_keys SET reservation_floor = NULL, reserved_at = ?1
                   WHERE purpose = 1 AND key_index = ?2";
        let index = r.key_id().index().to_be_bytes();
        exec(st.wallet().conn(), sql, rusqlite::params![NOW + 30, index]);
        let held = [r.receiver().to_raw_address_bytes()];
        if case == "live" {
            chain_agrees(st.wallet().db(), NOW + 10);
            let resumed = prepare_seen(&mut st, NOW + 10, &held);
            assert_eq!(resumed.key_id(), r.key_id());
            let edit = begin_seen(&mut st, &r, "edit", (NOW + 60, NOW + 10), None);
            edit.unwrap().unwrap();
        } else {
            chain_agrees(st.wallet().db(), NOW + 60);
            let seen = empty_seen(NOW + 60);
            let late = begin_seen(&mut st, &r, "late", (NOW + 120, NOW + 60), Some(&seen));
            assert_eq!(refusal(late), Some(Stale));
            assert_eq!(operation(&st, "late"), None);
            assert_eq!(prepare(&mut st, NOW + 60).key_id().index(), 1);
        }
        assert!(reserved(&st, &r), "{case}");
    }
}

/// A reissued address's earlier requests belong to its earlier reservation, so the new
/// one starts never quoted: it needs a fresh set before its first request, and takes one
/// though the old request expired long ago.
#[test]
fn a_reissued_address_ignores_its_earlier_requests() {
    let mut st = fixture();
    let lost = prepare(&mut st, NOW);
    begin(&mut st, &lost, "lost").unwrap().unwrap();
    let now = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    assert_eq!(reap(&mut st, now), [0]);
    abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
    let reissued = prepare_seen(&mut st, now, &[]);
    assert_eq!(reissued.key_id(), lost.key_id());
    let unchecked = try_prepare(&mut st, now, None);
    assert_eq!(refusal(unchecked), Some(SeenUnavailable));
    let again = begin_seen(&mut st, &reissued, "again", (now + 60, now), None);
    assert_eq!(refusal(again), Some(SeenUnavailable));
    begin_at(&mut st, &reissued, "again", now + 60, now)
        .unwrap()
        .unwrap();
    let resumed = try_prepare(&mut st, now + 10, None).unwrap().unwrap();
    assert_eq!(resumed.key_id(), lost.key_id());
}

/// A request stores the caller's clock as its time, even behind a reservation made while
/// the clock ran a day fast. An accepted deadline is checked against that time, so one
/// still ahead of it is kept, though a block time ahead of the corrected clock has passed it.
#[test]
fn finish_checks_the_deadline_against_the_real_request_time() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW + DAY);
    chain_agrees(st.wallet().db(), NOW + 60 * 60);
    begin_at(&mut st, &r, "corrected", NOW + 60 * 60, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(begun_at(&st, "corrected"), NOW);
    let deadline = NOW + 30 * 60;
    finish(&mut st, "corrected", &accepted("deposit", None, deadline)).unwrap();
    assert_eq!(operation(&st, "corrected").unwrap().3, Some(deadline));
}

/// A reissued address is quoted though the seen set holds it, since this wallet's own
/// earlier request may have given it out, and its earlier request stays retired: a late
/// answer to it is refused and can never be started.
#[test]
fn a_reissued_address_is_quoted_though_the_seen_set_holds_it() {
    let mut st = fixture();
    let lost = prepare(&mut st, NOW);
    begin(&mut st, &lost, "lost").unwrap().unwrap();
    let now = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    assert_eq!(reap(&mut st, now), [0]);
    abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
    let key = prepare_seen(&mut st, now, &[]);
    assert_eq!(key.key_id(), lost.key_id());
    let held = [key.receiver().to_raw_address_bytes()];
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let holds = ProviderSeen {
        since: 0,
        until: now,
        contains: &contains,
    };
    begin_seen(&mut st, &key, "again", (now + 60, now), Some(&holds))
        .unwrap()
        .unwrap();
    assert!(reserved(&st, &key));
    let late = try_finish(&mut st, "lost", &accepted("late", None, now + 60));
    assert_eq!(refusal(late), Some(Stale));
    assert_eq!(refusal(start_at(&mut st, "lost", now)), Some(Stale));
}

/// A provider hit retires an unquoted draft without inventing a local-operation watch.
#[test]
fn an_idle_draft_another_device_quoted_keeps_filter_history() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let draft = prepare(&mut st, NOW);
    let now = NOW + RECEIVE_RECLAIM_SECONDS;
    let held = [draft.receiver().to_raw_address_bytes()];
    assert_eq!(prepare_seen(&mut st, now, &held).key_id().index(), 1);
    assert!(!reserved(&st, &draft));
    let count: u64 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_one_time_operations WHERE local_watch_deadline IS NOT NULL",
        [],
    );
    assert_eq!(count, 0);
    let count: u64 = value(
        st.wallet().conn(),
        "SELECT COUNT(*) FROM ironwood_block_receivers r JOIN accounts a ON a.id=r.account_id WHERE a.uuid=?1 AND r.purpose=1 AND r.key_index=?2",
        rusqlite::params![account.0, draft.key_id().index().to_be_bytes()],
    );
    assert_eq!(count, 1);
}

/// Reserves a refund key at `now`, with the chain agreeing and an empty seen set read then.
fn reserve_refund_at(st: &mut State, now: i64) -> Policy<OneTimeKey> {
    let account = st.test_account().unwrap().id();
    let through = tip(st).height;
    chain_agrees(st.wallet().db(), now);
    let db = st.wallet_mut().db_mut();
    db.prepare_one_time_recovery(account, 1024, now).unwrap();
    db.reserve_refund_key(account, now, through, Some(&empty_seen(now)))
}

/// Begins a quote request on refund key `index` at `now`, asking for a deadline a minute
/// later, with an empty seen set read then.
fn begin_refund_at(st: &mut State, index: u64, now: i64) -> Policy<String> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.prepare_one_time_recovery(account, 1024, now).unwrap();
    db.begin_refund_operation(account, index, now + 60, now, Some(&empty_seen(now)))
}

/// Records, at `now`, the accepted quote for `deposit` that answers refund `request`, begun
/// at `begun` (see [`begin_refund_at`]), with the deadline the request asked for.
fn record_refund(
    st: &mut State,
    request: &str,
    deposit: &str,
    (begun, now): (i64, i64),
) -> Policy<()> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.record_refund_operation(account, request, deposit, begun + 60, now)
}

/// Reopens the wallet as after a crash, with an RNG seeded apart from every earlier one,
/// since a reopened test RNG would repeat earlier request identities.
fn crash(st: &mut State) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CRASHES: AtomicU64 = AtomicU64::new(1);
    let seed = CRASHES.fetch_add(1, Ordering::Relaxed);
    let path = st.wallet().data_file_path().to_owned();
    let rng = zcash_client_backend::data_api::testing::TestRng::seed_from_u64(seed);
    let reopened = WalletDb::for_path(path, *st.network(), test_clock(), rng).unwrap();
    *st.wallet_mut().db_mut() = reopened;
}

/// Reserves and quotes `count` refund keys at `now`, expecting `indices`, whose requests
/// stay unanswered until their deadline a minute later.
fn expose_refunds(st: &mut State, indices: std::ops::Range<u64>, now: i64) {
    for index in indices {
        let key = reserve_refund_at(st, now).unwrap().unwrap();
        assert_eq!(key.key_id().index(), index);
        begin_refund_at(st, index, now).unwrap().unwrap();
    }
}

/// A transparent deposit address on the test network.
fn deposit_address(st: &State, byte: u8) -> String {
    p2pkh(byte).encode(st.network())
}

/// A quote shown for funding is never reissued, even once the bound forces reuse. Here
/// incoming address 0 was started and refund key 0 recorded, and every other index the
/// bound allows was abandoned, so issuance reuses index 1.
#[test]
fn a_quote_shown_for_funding_is_never_reissued() {
    let mut st = fixture();
    let shown = prepare(&mut st, NOW);
    quote(&mut st, &shown, "shown", true);
    report(&mut st, "shown", AwaitingDeposit, false, EXPIRED);
    assert!(!reserved(&st, &shown));
    // The accepted quote moved the bound past index 30.
    abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT + 1);
    assert_eq!(prepare_seen(&mut st, EXPIRED, &[]).key_id().index(), 1);

    let mut st = fixture();
    let deposit = deposit_address(&st, 7);
    reserve_refund_at(&mut st, NOW).unwrap().unwrap();
    let shown = begin_refund_at(&mut st, 0, NOW).unwrap().unwrap();
    record_refund(&mut st, &shown, &deposit, (NOW, NOW))
        .unwrap()
        .unwrap();
    expose_refunds(&mut st, 1..RECEIVE_GAP_LIMIT + 1, NOW);
    let reused = reserve_refund_at(&mut st, NOW + 60).unwrap().unwrap();
    assert_eq!(reused.key_id().index(), 1);
}

/// A response to a request whose index was reissued is refused, so its quote is never
/// shown: an incoming request finished or started late, or a refund request recorded
/// late. The reissued index takes a new request.
#[test]
fn late_responses_to_a_reissued_index_are_refused() {
    let mut st = fixture();
    let old = prepare(&mut st, NOW);
    begin(&mut st, &old, "old").unwrap().unwrap();
    let now = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    assert_eq!(reap(&mut st, now), [0]);
    abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
    let reissued = prepare_seen(&mut st, now, &[]);
    assert_eq!(reissued.key_id(), old.key_id());
    let late = try_finish(&mut st, "old", &accepted("late", None, now + 60));
    assert_eq!(refusal(late), Some(Stale));
    let late = try_finish(&mut st, "old", &OperationOutcome::Rejected);
    assert_eq!(refusal(late), Some(Stale));
    assert_eq!(refusal(start_at(&mut st, "old", now)), Some(Stale));
    begin_at(&mut st, &reissued, "new", now + 60, now)
        .unwrap()
        .unwrap();
    finish(&mut st, "new", &accepted("new", None, now + 60)).unwrap();
    assert_eq!(
        start_at(&mut st, "new", now).unwrap().unwrap().address,
        "new"
    );

    let mut st = fixture();
    let deposit = deposit_address(&st, 7);
    reserve_refund_at(&mut st, NOW).unwrap().unwrap();
    let old = begin_refund_at(&mut st, 0, NOW).unwrap().unwrap();
    expose_refunds(&mut st, 1..RECEIVE_GAP_LIMIT, NOW);
    let reissued = reserve_refund_at(&mut st, NOW + 60).unwrap().unwrap();
    assert_eq!(reissued.key_id().index(), 0);
    // The response carries the deadline the old request asked for, which has passed.
    let late = record_refund(&mut st, &old, &deposit, (NOW, NOW + 60));
    assert_eq!(refusal(late), Some(Stale));
    let new = begin_refund_at(&mut st, 0, NOW + 60).unwrap().unwrap();
    record_refund(&mut st, &new, &deposit, (NOW + 60, NOW + 60))
        .unwrap()
        .unwrap();
}

/// A refund request survives a crash at each step, since the wallet keeps nothing about it
/// outside the database. One that never left needs a fresh seen set, and its key was never
/// exposed, so the next reservation returns it again. Once a request is saved, its outcome
/// counts as unknown, whether the crash came before it was sent, after, or before its
/// response was saved: its key is held until the request's deadline. A response saved
/// later binds its key for good, and once the bound forces reuse of an unanswered key, a
/// response arriving after that is refused.
#[test]
fn a_refund_request_survives_a_crash_at_each_step() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let deposit = deposit_address(&st, 7);
    let draft = reserve_refund_at(&mut st, NOW).unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    let unchecked = db.begin_refund_operation(account, 0, NOW + 60, NOW, None);
    assert_eq!(refusal(unchecked), Some(SeenUnavailable));
    crash(&mut st);
    let again = reserve_refund_at(&mut st, NOW).unwrap().unwrap();
    assert_eq!(again.key_id(), draft.key_id());
    // Key 0's response never arrives, and key 1's arrives only after a crash.
    let unanswered = begin_refund_at(&mut st, 0, NOW).unwrap().unwrap();
    crash(&mut st);
    let next = reserve_refund_at(&mut st, NOW).unwrap().unwrap();
    assert_eq!(next.key_id().index(), 1);
    let answered = begin_refund_at(&mut st, 1, NOW).unwrap().unwrap();
    crash(&mut st);
    assert_eq!(refusal(begin_refund_at(&mut st, 1, NOW)), Some(Stale));
    record_refund(&mut st, &answered, &deposit, (NOW, NOW))
        .unwrap()
        .unwrap();
    crash(&mut st);
    let db = st.wallet_mut().db_mut();
    assert!(db.refund_funding_memo(account, 1, &deposit).is_ok());
    // The recorded quote moved the bound past index 31.
    expose_refunds(&mut st, 2..RECEIVE_GAP_LIMIT + 2, NOW);
    assert_eq!(
        refusal(reserve_refund_at(&mut st, NOW)),
        Some(ReservationPolicy::Limit)
    );
    crash(&mut st);
    let reused = reserve_refund_at(&mut st, NOW + 60).unwrap().unwrap();
    assert_eq!(reused.key_id().index(), 0);
    crash(&mut st);
    let late = record_refund(&mut st, &unanswered, &deposit, (NOW, NOW + 60));
    assert_eq!(refusal(late), Some(Stale));
    // The shown quote's key stays blocked, and the reissued key takes a new request.
    assert_eq!(refusal(begin_refund_at(&mut st, 1, NOW + 60)), Some(Stale));
    let other = deposit_address(&st, 8);
    let new = begin_refund_at(&mut st, 0, NOW + 60).unwrap().unwrap();
    record_refund(&mut st, &new, &other, (NOW + 60, NOW + 60))
        .unwrap()
        .unwrap();
}

/// A seen hit on a sparse refund key, one an unauthenticated funding memo named far past
/// the window, blocks only that key: it moves neither the bound nor the window, so once
/// requests in progress hold every index the bound allows, issuance waits.
#[test]
fn a_seen_hit_on_a_sparse_refund_key_moves_nothing() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let sparse = KeyId::new(Purpose::Refund, 1_000_000);
    let from = tip(&st).height;
    tx(st.wallet_mut().db_mut(), |c, p| {
        register(c, p, account, sparse, from, false, Discovery::Lookup, NOW)
    })
    .unwrap();
    let held = [derive(&st, sparse)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes()];
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = ProviderSeen {
        since: 0,
        until: NOW,
        contains: &contains,
    };
    let through = tip(&st).height;
    chain_agrees(st.wallet().db(), NOW);
    let db = st.wallet_mut().db_mut();
    let issued = db.reserve_refund_key(account, NOW, through, Some(&seen));
    assert_eq!(issued.unwrap().unwrap().key_id().index(), 0);
    let sql = "SELECT provider_seen, advances_allocation, issuance_blocked
               FROM ironwood_one_time_keys WHERE purpose = 0 AND key_index = ?1";
    let facts: (bool, bool, bool) = row(&db.conn, sql, [sparse.index().to_be_bytes()]);
    assert_eq!(facts, (false, false, true));
    begin_refund_at(&mut st, 0, NOW).unwrap().unwrap();
    expose_refunds(&mut st, 1..RECEIVE_GAP_LIMIT, NOW);
    assert_eq!(
        refusal(reserve_refund_at(&mut st, NOW)),
        Some(ReservationPolicy::Limit)
    );
}

/// Thirty requests that fail one after another never move issuance past the bound: once
/// each is over, the next reservation reuses the lowest of them instead, for both
/// purposes. Rejections and lost refund responses leave no evidence another device could
/// follow.
#[test]
fn thirty_failed_requests_reuse_an_index_instead_of_passing_the_bound() {
    let mut st = fixture();
    let step = 60;
    for i in 0..RECEIVE_GAP_LIMIT {
        let now = NOW + step * i as i64;
        chain_agrees(st.wallet().db(), now);
        let r = prepare(&mut st, now);
        assert_eq!(r.key_id().index(), i);
        let request = format!("rejected-{i}");
        begin_at(&mut st, &r, &request, now + step, now)
            .unwrap()
            .unwrap();
        finish(&mut st, &request, &OperationOutcome::Rejected).unwrap();
    }
    let now = NOW + step * RECEIVE_GAP_LIMIT as i64;
    chain_agrees(st.wallet().db(), now);
    assert_eq!(prepare(&mut st, now).key_id().index(), 0);

    let mut st = fixture();
    for i in 0..RECEIVE_GAP_LIMIT {
        let now = NOW + step * i as i64;
        let key = reserve_refund_at(&mut st, now).unwrap().unwrap();
        assert_eq!(key.key_id().index(), i);
        begin_refund_at(&mut st, i, now).unwrap().unwrap();
    }
    let now = NOW + step * RECEIVE_GAP_LIMIT as i64;
    assert_eq!(
        reserve_refund_at(&mut st, now)
            .unwrap()
            .unwrap()
            .key_id()
            .index(),
        0
    );
}

/// A false-positive filter match settles after an exact empty scan without consuming the index.
#[test]
fn a_refund_key_with_an_empty_filter_match_is_issued_and_funded() {
    use zcash_client_backend::data_api::one_time_ivk::recovery::{
        FilterJudgment, History, OneTimeRecoveryRead,
    };
    let mut st = undiscovered();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Refund, 0);
    let block = tip(&st);
    let db = st.wallet_mut().db_mut();
    see_at(db, account, &[], NOW);
    db.accept_one_time_history(
        account,
        History {
            genesis: [1; 32],
            archive: [2; 32],
            epoch: 0,
        },
    )
    .unwrap();
    let work = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    assert!(
        db.record_one_time_filters(
            account,
            &work,
            &[FilterJudgment {
                block,
                hits: vec![key]
            }]
        )
        .unwrap()
    );
    assert_eq!(db.one_time_pending_matches(account, 1024).unwrap().len(), 1);
    tx(db, |c, p| {
        register(
            c,
            p,
            account,
            key,
            block.height,
            false,
            Discovery::Scan,
            NOW,
        )
        .map(|_| ())
    })
    .unwrap();
    st.scan_cached_blocks_with_one_time_ivks(block.height, 1);
    assert!(
        st.wallet()
            .db()
            .one_time_pending_matches(account, 1024)
            .unwrap()
            .is_empty()
    );
    let issued = reserve_refund_at(&mut st, NOW).unwrap().unwrap();
    assert_eq!(issued.key_id(), key);
    let deposit = deposit_address(&st, 7);
    let request = begin_refund_at(&mut st, 0, NOW).unwrap().unwrap();
    record_refund(&mut st, &request, &deposit, (NOW, NOW))
        .unwrap()
        .unwrap();
    assert!(
        st.wallet()
            .db()
            .refund_funding_memo(account, 0, &deposit)
            .is_ok()
    );
}

/// Expired refund requests wait for filter history, including a new tip between reserve and expose.
#[test]
fn refund_reuse_requires_filter_coverage_at_reservation_and_exposure() {
    let mut st = undiscovered();
    let account = st.test_account().unwrap().id();
    see_at(st.wallet_mut().db_mut(), account, &[], NOW);
    expose_refunds(&mut st, 0..RECEIVE_GAP_LIMIT, NOW);
    let now = NOW + 61;
    assert_eq!(refusal(reserve_refund_at(&mut st, now)), Some(Coverage));
    settle_empty_filters(st.wallet_mut().db_mut(), account, now);
    let key = reserve_refund_at(&mut st, now).unwrap().unwrap();
    assert_eq!(key.key_id().index(), 0);
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(height).unwrap();
    assert_eq!(refusal(begin_refund_at(&mut st, 0, now)), Some(Coverage));
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    settle_empty_filters(st.wallet_mut().db_mut(), account, now);
    assert!(begin_refund_at(&mut st, 0, now).unwrap().is_ok());
}
