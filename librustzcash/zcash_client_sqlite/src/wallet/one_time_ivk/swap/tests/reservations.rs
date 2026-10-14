use super::*;
use ReservationPolicy::{Coverage, Gap, Stale};
use zakura_one_time_ivk::swap::{
    OperationStatus::{Active, AwaitingDeposit, Terminal},
    ReceiptExpectation::{self, Positive},
};
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
/// A seen set read covering quotes begun from 0 to `NOW`.
const COVERING: (i64, i64) = (-SEEN_SLACK_SECONDS, NOW + SEEN_SLACK_SECONDS);
/// A time when every quote with the default deadline is past it and the cooldown.
const EXPIRED: i64 = NOW + 61 + RECEIVE_RECLAIM_SECONDS;

/// An Ironwood wallet scanned through one block holding an ordinary note.
fn fixture() -> State {
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

/// [`try_prepare`] without a seen set, expecting a key.
fn prepare(st: &mut State, now: i64) -> OneTimeKey {
    try_prepare(st, now, None).unwrap().unwrap()
}

/// Prepares with a seen set read from `since` to `until` that holds `held`.
fn try_prepare_seen(
    st: &mut State,
    now: i64,
    (since, until): (i64, i64),
    held: &[[u8; 43]],
) -> Policy<OneTimeKey> {
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = ProviderSeen {
        since,
        until,
        contains: &contains,
    };
    try_prepare(st, now, Some(&seen))
}

/// [`try_prepare_seen`], expecting a key.
fn prepare_seen(st: &mut State, now: i64, read: (i64, i64), held: &[[u8; 43]]) -> OneTimeKey {
    try_prepare_seen(st, now, read, held).unwrap().unwrap()
}

/// Begins operation request `req` on `key`'s reservation at `now` with `deadline`.
fn begin_at(st: &mut State, key: &OneTimeKey, req: &str, deadline: i64, now: i64) -> Policy<()> {
    let account = st.test_account().unwrap().id();
    let index = key.key_id().index();
    tx(st.wallet_mut().db_mut(), |c, _| {
        store::swap::reservations::begin(c, account, index, req, deadline, now)
    })
}

/// [`begin_at`] at `NOW` with a deadline of `NOW + 60`.
fn begin(st: &mut State, key: &OneTimeKey, request: &str) -> Policy<()> {
    begin_at(st, key, request, NOW + 60, NOW)
}

/// Finishes `request` with outcome `out`.
fn finish(st: &mut State, request: &str, out: &OperationOutcome) -> Result<(), SqliteClientError> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.finish_receive_operation(account, request, out)
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

/// Registers incoming `indices` as quoted and then abandoned addresses, which issuance
/// reuses only when nothing else is left.
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

/// Issues through `prepare_receive_reservation` at the tip, with a seen set read from
/// `since` to `until` that holds the incoming addresses at `held`, if any.
fn issue(st: &mut State, seen: Option<(i64, i64, &[u64])>) -> Result<u64, ReservationPolicy> {
    let held: Vec<[u8; 43]> = seen
        .map_or(&[][..], |(_, _, held)| held)
        .iter()
        .map(|&index| {
            let fvk = derive(st, KeyId::new(Purpose::Receive, index));
            fvk.address_at(0u32, Scope::External).to_raw_address_bytes()
        })
        .collect();
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = seen.map(|(since, until, _)| ProviderSeen {
        since,
        until,
        contains: &contains,
    });
    let account = st.test_account().unwrap().id();
    let through = tip(st).height;
    chain_agrees(st.wallet().db(), NOW);
    let db = st.wallet_mut().db_mut();
    let issued = db.prepare_receive_reservation(account, NOW, through, seen.as_ref());
    issued.unwrap().map(|k| k.key_id().index())
}

/// Finishes the test account's pending incoming sweeps after empty lookups at the tip,
/// as a receiver directory that saw nothing would. Returns how many it finished.
fn sweep_pending(st: &mut State) -> usize {
    let account = st.test_account().unwrap().id();
    let through = tip(st);
    let sql = "SELECT k.key_index FROM ironwood_one_time_sweeps s
               JOIN ironwood_one_time_keys k ON k.id = s.one_time_key_id
               WHERE k.purpose = 1 AND s.done_height IS NULL";
    let pending: Vec<Vec<u8>> = column(st.wallet().conn(), sql, []);
    let db = st.wallet_mut().db_mut();
    for index in &pending {
        let index = u64::from_be_bytes(index.as_slice().try_into().unwrap());
        finish_sweep(db, account, KeyId::new(Purpose::Receive, index), through);
    }
    pending.len()
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
/// scanning found the payment, and keeps scanning. Accepted quotes are always in the
/// seen set, so none of these addresses is issued again, and they move the recovery gap
/// rather than fill it.
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
    let issued = prepare_seen(&mut st, EXPIRED, COVERING, &[]);
    assert_eq!(issued.key_id().index(), RECEIVE_GAP_LIMIT);
}

/// A request whose answer was lost is reused, only when no fresh address is left, once a
/// seen set covering it shows the provider never had the address. One the set holds is
/// never issued again, even once a later set lacks it, and moves the gap. A quote within
/// the slack of the set's start or read may be missing from it, as the clocks differ, so
/// it counts as seen, but like one without a set it does not move the gap.
#[test]
fn lost_requests_are_reused_only_once_a_seen_set_shows_them_unseen() {
    let limit = Err(ReservationPolicy::Limit);
    let cases = [
        ("unchecked", limit, 0),
        ("held", Ok(RECEIVE_GAP_LIMIT), 1),
        // The set covers the other abandoned quotes, so the lowest is reused at once.
        ("stale", Ok(1), 0),
        ("early", limit, 0),
    ];
    for (case, next, reused) in cases {
        let mut st = fixture();
        let lost = prepare(&mut st, NOW);
        begin(&mut st, &lost, "lost").unwrap().unwrap();
        let now = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
        assert_eq!(reap(&mut st, now), [0]);
        abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
        let held = [lost.receiver().to_raw_address_bytes()];
        // Without a set, or with one that holds it or does not cover its quote, the
        // provider may have the address, so it is not reissued.
        let prepared = match case {
            "unchecked" => try_prepare(&mut st, now, None),
            "held" => try_prepare_seen(&mut st, now, COVERING, &held),
            "stale" => try_prepare_seen(&mut st, now, (COVERING.0, COVERING.1 - 1), &[]),
            _ => {
                // This wallet's clock may be ahead of the provider's, so a set starting
                // just before the window's quotes may lack them.
                let sql = "UPDATE ironwood_one_time_operations SET begun_at = ?1";
                exec(st.wallet().conn(), sql, [NOW]);
                let read = (NOW - SEEN_SLACK_SECONDS + 1, COVERING.1);
                try_prepare_seen(&mut st, now, read, &[])
            }
        };
        let prepared = prepared.unwrap();
        let index = prepared
            .as_ref()
            .map(|key| key.key_id().index())
            .map_err(|p| *p);
        assert_eq!(index, next, "{case}");
        let later = now + RECEIVE_RECLAIM_SECONDS;
        if let Ok(next) = prepared {
            begin(&mut st, &next, "lost-again").unwrap().unwrap();
            assert_eq!(reap(&mut st, later), [next.key_id().index()]);
        }
        // A covering set that lacks the address shows the provider never had it, and the
        // window holds no fresh address, so the lowest unseen abandoned one is reused.
        let issued = prepare_seen(&mut st, later, COVERING, &[]);
        assert_eq!(issued.key_id().index(), reused, "{case}");
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

/// After a restart the same draft is resumed, but a quote request the provider rejected
/// still gave it the address, so the next swap gets another, and the address is never
/// reissued, even once a covering seen set lacks it and the window holds nothing else.
#[test]
fn a_rejected_quote_never_frees_its_address() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    reopen(&mut st);
    assert_eq!(prepare(&mut st, NOW).key_id(), r.key_id());
    begin(&mut st, &r, "too-low").unwrap().unwrap();
    finish(&mut st, "too-low", &OperationOutcome::Rejected).unwrap();
    let begun = Some((NOW, 0, None, Some(NOW + 60)));
    assert_eq!(operation(&st, "too-low"), begun);
    let next = prepare_seen(&mut st, NOW + 1, COVERING, &[]);
    assert_eq!(next.key_id().index(), 1);
    abandon_indices(&mut st, 2..RECEIVE_GAP_LIMIT);
    let issued = try_prepare_seen(&mut st, EXPIRED, COVERING, &[]).unwrap();
    assert_ne!(issued.map(|key| key.key_id()).ok(), Some(r.key_id()));
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
    let r = prepare_from(db, account, NOW, issued, None);
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
/// reaches a new tip, nor while a restore sweep's directory payment for the address is
/// queued but not yet applied.
#[test]
fn quoting_and_reclamation_wait_for_the_tip_and_queued_candidates() {
    for queued in [false, true] {
        let mut st = fixture();
        let started = prepare(&mut st, NOW);
        quote(&mut st, &started, "started", true);
        let draft = prepare(&mut st, NOW);
        let behind = if queued {
            let sql = "INSERT INTO ironwood_one_time_payment_recovery
                       SELECT id, zeroblob(32), id, 100000, zeroblob(32), 1, 0, zeroblob(148)
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
            begin(&mut st, &draft, "caught-up").unwrap().unwrap();
            assert_eq!(reap(&mut st, EXPIRED), [0, 1]);
        }
    }
}

/// An unfinished incoming sweep blocks issuance, though a refund one does not. Once it
/// is done, issuance resumes at the lowest address never quoted, unless a swap issued
/// before the restore paid that address during the watch.
#[test]
fn issuance_waits_for_incoming_sweeps_and_skips_addresses_paid_during_the_watch() {
    for paid in [false, true] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let through = tip(&st);
        let db = st.wallet_mut().db_mut();
        let swept = watch(db, account, 0, through.height);
        recover(db, account, KeyId::new(Purpose::Refund, 0), through.height);
        assert_eq!(refusal(try_prepare(&mut st, NOW, None)), Some(Gap));
        finish_sweep(st.wallet_mut().db_mut(), account, swept.key_id(), through);
        if paid {
            pay(&mut st, swept.full_viewing_key(), 100_000);
            confirm(&mut st);
            assert!(holds_note(&st, swept.key_id()));
        }
        let issued = prepare(&mut st, NOW).key_id().index();
        assert_eq!(issued, u64::from(paid), "{paid}");
    }
}

/// Issuance checks an address past the registered lookahead against the seen set. Seen
/// hits that widen the window first register and sweep the newly exposed addresses, so
/// issuance waits rather than issuing one unchecked, then skips one the set holds. Here
/// the old device's quotes reached the provider for the first window and the next
/// address, or only for the next one.
#[test]
fn issuance_checks_addresses_past_the_lookahead_against_the_seen_set() {
    let window = RECEIVE_GAP_LIMIT;
    for held in [(0..=window).collect(), vec![window]] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        // Issuance registers the restore lookahead at the tip, then waits for its sweeps.
        assert_eq!(issue(&mut st, None), Err(Gap));
        assert_eq!(sweep_pending(&mut st) as u64, window);
        let seen = Some((0, NOW + SEEN_SLACK_SECONDS, &held[..]));
        if held.len() > 1 {
            for _ in 0..2 {
                assert_eq!(issue(&mut st, seen), Err(Gap));
                assert!(sweep_pending(&mut st) > 0);
            }
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

/// Restored addresses the provider saw move the gap and are never reused, even once
/// every other address in the window was quoted and abandoned, nor is one accepted here.
#[test]
fn issuance_skips_restored_addresses_the_provider_saw() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let swept_at = tip(&st);
    let db = st.wallet_mut().db_mut();
    lookahead(db, account);
    // The old device quoted the first three addresses.
    for index in 0..RECEIVE_GAP_LIMIT {
        let key = KeyId::new(Purpose::Receive, index);
        db.begin_one_time_sweep_attempt(account, key, NOW, index < 3)
            .unwrap();
        finish_sweep(db, account, key, swept_at);
    }
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 3);
    abandon_indices(&mut st, 4..RECEIVE_GAP_LIMIT + 3);
    let draft = prepare(&mut st, NOW);
    assert_eq!(draft.key_id().index(), 3);
    quote(&mut st, &draft, "after-restore", true);
    report(&mut st, "after-restore", AwaitingDeposit, false, EXPIRED);
    assert!(!reserved(&st, &draft));
    let issued = prepare_seen(&mut st, EXPIRED, COVERING, &[]);
    assert_eq!(issued.key_id().index(), RECEIVE_GAP_LIMIT + 3);
}

/// A payment moves the recovery bound only once it has the untrusted confirmations, so a
/// reorg that drops it cannot leave an issued address past the bound. Here quotes with
/// unknown outcomes hold every other address in the window.
#[test]
fn only_a_confirmed_payment_moves_the_bound() {
    let mut st = fixture();
    let first = prepare(&mut st, NOW);
    begin(&mut st, &first, "lost").unwrap().unwrap();
    pay(&mut st, first.full_viewing_key(), 100_000);
    for i in 1..RECEIVE_GAP_LIMIT {
        let r = prepare(&mut st, NOW);
        begin(&mut st, &r, &format!("lost-{i}")).unwrap().unwrap();
    }
    let limited = refusal(try_prepare(&mut st, NOW, None));
    assert_eq!(limited, Some(ReservationPolicy::Limit));
    confirm(&mut st);
    assert_eq!(prepare(&mut st, NOW).key_id().index(), RECEIVE_GAP_LIMIT);
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

/// Maintenance registers restore discovery only at the scanned tip, as lookahead keys
/// that wait for their sweeps without advancing allocation or scanning. Issuance refuses
/// a tip too far ahead of the scanned one and, unless the account was declared fresh,
/// waits for the sweeps. It then takes the lowest address never quoted, scanned from
/// above the scanned tip, while a refund key starts scanning only once its funding
/// transaction is stored.
#[test]
fn issuance_starts_after_the_scanned_tip_once_the_restore_lookahead_is_swept() {
    for fresh in [false, true] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let (h, _) = st.generate_empty_block();
        st.wallet_mut().update_chain_tip(h).unwrap();
        let db = st.wallet_mut().db_mut();
        if fresh {
            db.mark_one_time_account_fresh(account).unwrap();
        }
        db.maintain_one_time_ivks(account).unwrap();
        assert!(all_keys(db, account).unwrap().is_empty());
        st.scan_cached_blocks_with_one_time_ivks(h, 1);
        let through = tip(&st);
        let db = st.wallet_mut().db_mut();
        db.maintain_one_time_ivks(account).unwrap();
        let lookahead = all_keys(db, account).unwrap();
        let window = if fresh { 0 } else { RECEIVE_GAP_LIMIT };
        assert_eq!(lookahead.len() as u64, window, "fresh={fresh}");
        assert!(lookahead.iter().all(|k| !key_state(db, k.key_id()).1));
        assert!(scanning_keys(&st).is_empty());
        let db = st.wallet_mut().db_mut();
        let behind = through.height + ISSUANCE_TIP_LAG + 1;
        let issued = db.prepare_receive_reservation(account, NOW, behind, None);
        assert_eq!(refusal(issued), Some(Coverage));
        let refund = db.reserve_refund_key(account, behind, None);
        assert_eq!(refusal(refund), Some(Coverage));
        let near = through.height + ISSUANCE_TIP_LAG;
        let db = st.wallet_mut().db_mut();
        if !fresh {
            let issued = db.prepare_receive_reservation(account, NOW, near, None);
            assert_eq!(refusal(issued), Some(Gap));
            for key in lookahead {
                finish_sweep(db, account, key.key_id(), through);
            }
        }
        let issued = db.prepare_receive_reservation(account, NOW, near, None);
        let r = issued.unwrap().unwrap().key_id();
        assert_eq!(r, KeyId::new(Purpose::Receive, 0), "fresh={fresh}");
        let refund = db.reserve_refund_key(account, through.height, None);
        let refund = refund.unwrap().unwrap().key_id();
        assert_eq!(refund, KeyId::new(Purpose::Refund, 0));
        assert_eq!(active_from(&st, r), Some(through.height + 1));
        assert_eq!(active_from(&st, refund), None);
    }
}

/// A fresh account still skips an address the provider's seen set holds. Declaring an
/// account fresh again changes nothing, and one that already has one-time keys is refused.
#[test]
fn a_fresh_account_still_checks_the_seen_set() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.mark_one_time_account_fresh(account).unwrap();
    assert_eq!(issue(&mut st, Some((COVERING.0, COVERING.1, &[0]))), Ok(1));
    let db = st.wallet_mut().db_mut();
    db.mark_one_time_account_fresh(account).unwrap();
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    reserve_key(db, account, Purpose::Refund, BlockHeight::from_u32(100));
    assert!(rejected_input(db.mark_one_time_account_fresh(account)));
}

/// Starting an accepted quote returns its deposit instructions and starts only its
/// reservation. A repeated acceptance can lower the deadline but not change the address
/// or memo, and a deposit identity belongs to one operation in the account, on the same
/// reservation or another, so the instructions shown keep matching provider statuses.
/// A new review abandons an accepted, unstarted draft rather than reusing it.
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
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 2);
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
        let begun = db.begin_receive_operation(account, index, NOW + 60, NOW);
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
/// unfunded quote used before a restore, and registers it for a restore sweep, so a
/// later reservation without a set does not issue it either.
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
    let issued = db.reserve_refund_key(account, through, Some(&seen));
    assert_eq!(issued.unwrap().unwrap().key_id().index(), 1);
    let sql = "SELECT k.provider_seen AND s.done_height IS NULL FROM ironwood_one_time_keys k
               JOIN ironwood_one_time_sweeps s ON s.one_time_key_id = k.id
               WHERE k.purpose = 0 AND k.key_index = ?1";
    let seen_and_swept: Vec<bool> = column(&db.conn, sql, [first.index().to_be_bytes()]);
    assert_eq!(seen_and_swept, [true]);
    let next = db.reserve_refund_key(account, through, None);
    assert_eq!(next.unwrap().unwrap().key_id().index(), 2);
}

/// A seen set that holds every receiver stops refund issuance with `Gap` after a bounded
/// number of probes, keeping the keys it registered, so the next reservation continues past
/// them instead of probing them again.
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
    let issued = db.reserve_refund_key(account, through, Some(&everything));
    assert!(matches!(issued.unwrap(), Err(Gap)));
    let held = probes.get();
    assert_eq!(held, 100);
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_keys k
               JOIN ironwood_one_time_sweeps s ON s.one_time_key_id = k.id
               WHERE k.purpose = 0 AND k.provider_seen";
    assert_eq!(value::<u64>(&db.conn, sql, []), held);

    let nothing = |receivers: &[[u8; 43]]| vec![false; receivers.len()];
    let seen = ProviderSeen {
        since: 0,
        until: NOW,
        contains: &nothing,
    };
    let next = db.reserve_refund_key(account, through, Some(&seen));
    assert_eq!(next.unwrap().unwrap().key_id().index(), held);
}

/// Quotes only assumed seen, whose outcome is unknown and which no seen set covers, keep
/// their addresses from reissue but do not widen the gap, since a restore walks past only
/// receipts, seen addresses and accepted quotes; an accepted quote widens it.
#[test]
fn only_accepted_quotes_widen_the_gap() {
    for (accepted, issued) in [(false, Err(ReservationPolicy::Limit)), (true, Ok(30))] {
        let mut st = fixture();
        abandon_indices(&mut st, 0..RECEIVE_GAP_LIMIT);
        if accepted {
            let sql = "UPDATE ironwood_one_time_operations SET reference = 'accepted'
                       WHERE request = 'abandoned-0'";
            exec(st.wallet().conn(), sql, []);
        }
        let prepared = try_prepare(&mut st, NOW, None).unwrap();
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
            until: NOW + SEEN_SLACK_SECONDS,
            contains: &contains,
        };
        let db = st.wallet_mut().db_mut();
        assert!(rejected_input(db.reserve_refund_key(
            account,
            through,
            Some(&seen)
        )));

        assert_eq!(issue(&mut st, None), Err(Gap));
        assert_eq!(sweep_pending(&mut st) as u64, RECEIVE_GAP_LIMIT);
        for _ in 0..RECEIVE_GAP_LIMIT {
            let index = issue(&mut st, Some((0, NOW + SEEN_SLACK_SECONDS, &[])));
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
