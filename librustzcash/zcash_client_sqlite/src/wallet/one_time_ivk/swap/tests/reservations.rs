use super::*;
use zakura_one_time_ivk::swap::{
    OperationStatus::{Active, AwaitingDeposit, Terminal},
    ReceiptExpectation::{self, Positive},
};

/// `(observed_at, expectation, expected_value, deadline)` of an operation.
type Operation = (i64, u8, Option<i64>, Option<i64>);
const NOW: i64 = 1_000_000;
/// A terminal status whose receipt is inconclusive.
const INCONCLUSIVE: Observation = Observation {
    status: OperationStatus::Terminal(ReceiptExpectation::Unknown),
    deadline: None,
};
/// A completed swap's payout, of an unreported amount.
const PAID: OperationStatus = Terminal(Positive(None));
/// A conclusive end with no Zcash receipt, such as a refund on the source chain.
const NO_RECEIPT: OperationStatus = Terminal(ReceiptExpectation::None);

/// A file-backed wallet with Ironwood active, scanned through one block that holds an
/// ordinary note.
fn fixture() -> State {
    let mut st = ironwood_wallet();
    let ordinary = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let (h, _, _) = st.generate_next_block(
        &IronwoodFvk(ordinary),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks_with_one_time_ivks(h, 1);
    st
}

/// Resumes the draft or reserves the next address, scanned from the next unscanned
/// block, with the provider seen set `seen`.
fn try_prepare(st: &mut State, now: i64, seen: Option<&ProviderSeen<'_>>) -> Policy<OneTimeKey> {
    let account = st.test_account().unwrap().id();
    let from = tip(st).height + 1;
    prepare_from(st.wallet_mut().db_mut(), account, now, from, seen)
}

/// [`try_prepare`] without a seen set, expecting a key.
fn prepare(st: &mut State, now: i64) -> OneTimeKey {
    try_prepare(st, now, None).unwrap().unwrap()
}

/// Prepares with a seen set covering quotes begun from 0 to `NOW` that holds `held`.
fn prepare_seen(st: &mut State, now: i64, held: &[[u8; 43]]) -> OneTimeKey {
    let contains = |receivers: &[[u8; 43]]| receivers.iter().map(|r| held.contains(r)).collect();
    let seen = ProviderSeen {
        since: -SEEN_SLACK_SECONDS,
        until: NOW + SEEN_SLACK_SECONDS,
        contains: &contains,
    };
    try_prepare(st, now, Some(&seen)).unwrap().unwrap()
}

/// Begins operation `request` on `key`'s reservation at `now` with `deadline`.
fn begin_at(
    st: &mut State,
    key: &OneTimeKey,
    request: &str,
    deadline: i64,
    now: i64,
) -> Policy<()> {
    let account = st.test_account().unwrap().id();
    let index = key.key_id().index();
    tx(st.wallet_mut().db_mut(), |c, _| {
        store::swap::reservations::begin(c, account, index, request, deadline, now)
    })
}

/// Begins operation `request` on `key`'s reservation at `NOW` with a deadline of
/// `NOW + 60`, before contacting the provider.
fn begin(st: &mut State, key: &OneTimeKey, request: &str) -> Policy<()> {
    begin_at(st, key, request, NOW + 60, NOW)
}

/// Begins `request` and accepts it with deposit address `request` and a deadline of
/// `NOW + 60`, then optionally starts it.
fn quote(st: &mut State, key: &OneTimeKey, request: &str, start: bool) {
    let account = st.test_account().unwrap().id();
    begin(st, key, request).unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    db.finish_receive_operation(account, request, &accepted(request, None, NOW + 60))
        .unwrap();
    if start {
        db.start_receive_operation(account, request)
            .unwrap()
            .unwrap();
    }
}

/// Records `observation` for the operation with deposit address `deposit` at `now`.
fn record_observation(
    st: &mut State,
    deposit: &str,
    observation: Observation,
    funded: bool,
    now: i64,
) {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .record_operation_status(account, deposit, None, observation, funded, now)
        .unwrap();
}

/// Records provider `status`, without a deadline, for the operation with deposit address
/// `deposit`, requested at `now`, as an app does with each status it fetches.
fn observe(st: &mut State, deposit: &str, status: OperationStatus, funded: bool, now: i64) {
    let observation = Observation {
        status,
        deadline: None,
    };
    record_observation(st, deposit, observation, funded, now)
}

/// Reaps the test account's reservations at `now`, returning the reclaimed indices.
fn reap(st: &mut State, now: i64) -> Vec<u64> {
    let account = st.test_account().unwrap().id();
    tx(st.wallet_mut().db_mut(), |c, p| {
        store::swap::reservations::reap(c, p, account, now)
    })
    .unwrap()
}

/// Whether `key`'s reservation is open.
fn reserved(st: &State, key: &OneTimeKey) -> bool {
    st.wallet()
        .conn()
        .query_row(
            &format!(
                "SELECT {RESERVED} FROM ironwood_receiving_keys k
                 WHERE k.purpose = 1 AND k.key_index = ?1"
            ),
            [key.key_id().index().to_be_bytes()],
            |r| r.get(0),
        )
        .unwrap()
}

/// Mines and scans a payment to `key`'s address.
fn pay(st: &mut State, key: &FullViewingKey) {
    let (h, _, _) = st.generate_next_block(
        &IronwoodFvk(key.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks_with_one_time_ivks(h, 1);
}

/// Mines and scans blocks until the latest receipt has the default untrusted
/// confirmations, after which it raises the recovery bound.
fn confirm(st: &mut State) {
    st.generate_and_scan_empty_blocks_with_one_time_ivks(
        (zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default()
            .untrusted()
            .get()
            - 1) as usize,
    );
}

/// The policy that refused `result`, or `None` if it succeeded.
fn refusal<T>(result: Policy<T>) -> Option<ReservationPolicy> {
    result.unwrap().err()
}

/// The height `key` is trial-decrypted from, or `None` while it is not scanning.
fn active_from(st: &State, key: KeyId) -> Option<BlockHeight> {
    st.wallet()
        .conn()
        .query_row(
            "SELECT active_from FROM ironwood_receiving_keys
             WHERE purpose = ?1 AND key_index = ?2 AND closed_at IS NULL",
            rusqlite::params![purpose_code(key.purpose()), key.index().to_be_bytes()],
            |r| r.get::<_, Option<u32>>(0),
        )
        .optional()
        .unwrap()
        .flatten()
        .map(BlockHeight::from)
}

/// The operation begun as `request`, if any.
fn operation(st: &State, request: &str) -> Option<Operation> {
    st.wallet()
        .conn()
        .query_row(
            "SELECT observed_at, expectation, expected_value, deadline
             FROM ironwood_one_time_operations WHERE request = ?1",
            [request],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .unwrap()
}

/// Whether the wallet holds an unspent note received by `key`.
fn holds_note(st: &State, key: KeyId) -> bool {
    unspent_keys(st, tip(st).height).contains(&Some(key))
}

/// Registers incoming `indices` as addresses that were quoted and then abandoned,
/// which issuance reuses only when nothing else is left.
fn abandon_indices(st: &mut State, indices: std::ops::Range<u64>) {
    let account = st.test_account().unwrap().id();
    let from = tip(st).height + 1;
    tx(st.wallet_mut().db_mut(), |c, p| {
        for index in indices {
            let key = KeyId::new(Purpose::Receive, index);
            let (id, _) = register(c, p, account, key, from, true, Discovery::Scan, 0)?;
            c.execute(
                "INSERT INTO ironwood_one_time_operations (receiving_key_id, request, begun_at)
                 VALUES (?1, ?2, 0)",
                rusqlite::params![id, format!("abandoned-{index}")],
            )?;
            c.execute(
                "UPDATE ironwood_receiving_keys SET reserved_at = 0, released_at = 0,
                    closed_at = 0 WHERE id = ?1",
                [id],
            )?;
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn reclamation_waits_until_latest_quote_deadline_plus_cooldown() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "first", false);
    begin_at(&mut st, &r, "second", NOW + 120, NOW + 30)
        .unwrap()
        .unwrap();
    let db = st.wallet_mut().db_mut();
    // A provider deadline past the requested one is capped, so it cannot hold the
    // address longer.
    db.finish_receive_operation(account, "second", &accepted("second", None, NOW + 9_999))
        .unwrap();
    let started = db
        .start_receive_operation(account, "second")
        .unwrap()
        .unwrap();
    assert_eq!(started.deadline, NOW + 120);
    assert_eq!(operation(&st, "second").unwrap().3, Some(NOW + 120));

    let eligible_at = NOW + 120 + RECEIVE_RECLAIM_SECONDS;
    for request in ["first", "second"] {
        observe(&mut st, request, AwaitingDeposit, false, eligible_at - 1);
    }
    assert!(reap(&mut st, eligible_at - 1).is_empty());
    assert_eq!(reap(&mut st, eligible_at), [0]);
}

/// An unstarted reservation needs no status: it is reclaimed once its latest deadline,
/// or its creation without a quote, is the cooldown in the past.
#[test]
fn an_unstarted_reservation_is_reclaimed_after_its_latest_deadline() {
    for quoted in [false, true] {
        let mut st = fixture();
        let r = prepare(&mut st, NOW);
        let mut eligible_at = NOW + RECEIVE_RECLAIM_SECONDS;
        if quoted {
            quote(&mut st, &r, "accepted", false);
            // The lost response asked for a later deposit deadline than the accepted one.
            begin_at(&mut st, &r, "lost-response", NOW + 120, NOW + 1)
                .unwrap()
                .unwrap();
            eligible_at += 120;
        }
        assert!(reap(&mut st, eligible_at - 1).is_empty());
        assert_eq!(reap(&mut st, eligible_at), [0]);
    }
}

#[test]
fn reclaimed_hole_stops_scanning_and_keeps_its_quotes() {
    let mut st = fixture();
    let mut hole = None;
    for i in 0..5 {
        let r = prepare(&mut st, NOW);
        assert_eq!(r.key_id().index(), i);
        let request = format!("quote-{i}");
        quote(&mut st, &r, &request, true);
        if i == 1 {
            hole = Some(r);
        } else {
            pay(&mut st, r.full_viewing_key());
            observe(&mut st, &request, PAID, true, NOW + 1);
        }
    }
    let r = hole.unwrap();
    assert!(scanning_keys(&st).contains(&r.key_id()));
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    // The status reclaims the hole at once.
    observe(&mut st, "quote-1", AwaitingDeposit, false, now);
    assert!(!reserved(&st, &r));
    assert!(operation(&st, "quote-1").is_some());
    // Every quote is past its deadline and conclusive, so no swap can pay it.
    assert!(!scanning_keys(&st).contains(&r.key_id()));
    // The provider has the hole's address, so the next swap gets a fresh one.
    assert_eq!(prepare(&mut st, now).key_id().index(), 5);
}

/// A request whose answer was lost is reused, only when no fresh address is left, once a
/// seen set covering it shows the provider never had the address. One the set holds is
/// never issued again, even once a later set lacks it. A quote within the slack of the
/// set's start or read may be missing from it, as the clocks differ, so it counts as seen.
#[test]
fn lost_requests_are_reused_only_once_a_seen_set_shows_them_unseen() {
    let stale = |receivers: &[[u8; 43]]| vec![false; receivers.len()];
    for (case, reused) in [("unchecked", 0), ("held", 1), ("stale", 0), ("early", 0)] {
        let mut st = fixture();
        let account = st.test_account().unwrap().id();
        let lost = prepare(&mut st, NOW);
        begin(&mut st, &lost, "lost").unwrap().unwrap();
        let now = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
        assert_eq!(reap(&mut st, now), [0]);
        abandon_indices(&mut st, 1..RECEIVE_GAP_LIMIT);
        let held = [lost.receiver().to_raw_address_bytes()];
        // Without a set, or with one that holds it or does not cover its quote, the
        // provider may have the address, so like a seen one it moves the gap.
        let next = match case {
            "unchecked" => prepare(&mut st, now),
            "held" => prepare_seen(&mut st, now, &held),
            _ => {
                let from = tip(&st).height + 1;
                // This wallet's clock may be ahead of the provider's, so a set starting
                // just before the window's quotes may lack them.
                let (since, until) = match case {
                    "stale" => (-SEEN_SLACK_SECONDS, NOW + SEEN_SLACK_SECONDS - 1),
                    _ => {
                        st.wallet()
                            .conn()
                            .execute(
                                "UPDATE ironwood_one_time_operations SET begun_at = ?1",
                                [NOW],
                            )
                            .unwrap();
                        (NOW - SEEN_SLACK_SECONDS + 1, NOW + SEEN_SLACK_SECONDS)
                    }
                };
                let set = ProviderSeen {
                    since,
                    until,
                    contains: &stale,
                };
                let db = st.wallet_mut().db_mut();
                prepare_from(db, account, now, from, Some(&set))
                    .unwrap()
                    .unwrap()
            }
        };
        assert_eq!(next.key_id().index(), RECEIVE_GAP_LIMIT, "{case}");
        begin(&mut st, &next, "lost-again").unwrap().unwrap();
        let later = now + RECEIVE_RECLAIM_SECONDS;
        assert_eq!(reap(&mut st, later), [RECEIVE_GAP_LIMIT]);
        // A covering set that lacks the address shows the provider never had it, and the
        // window holds no fresh address, so the lowest unseen abandoned one is reused.
        let issued = prepare_seen(&mut st, later, &[]);
        assert_eq!(issued.key_id().index(), reused, "{case}");
    }
}

/// A started reservation needs a fresh conclusive status: a funded swap's is a refund,
/// and an older status arriving late does not replace a newer one.
#[test]
fn a_started_reservation_needs_a_fresh_conclusive_status() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "funded", true);
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    record_observation(&mut st, "funded", INCONCLUSIVE, true, now);
    assert!(reserved(&st, &r));
    observe(&mut st, "funded", NO_RECEIPT, true, now + 1);
    assert!(!reserved(&st, &r));

    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "accepted", true);
    let expired = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "accepted", AwaitingDeposit, false, expired - 1);
    assert!(reap(&mut st, expired + 120).is_empty());
    observe(&mut st, "accepted", Active, false, expired + 121);
    observe(&mut st, "accepted", AwaitingDeposit, false, expired + 120);
    assert!(reap(&mut st, expired + 121).is_empty());
    observe(&mut st, "accepted", AwaitingDeposit, false, expired + 122);
    assert!(!reserved(&st, &r));
}

/// Deposit evidence from a status arriving late still sticks, so a later fresh
/// unfunded status cannot reclaim the address.
#[test]
fn late_funded_status_prevents_reclamation() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "late", true);
    let funded = |st: &State| -> bool {
        st.wallet()
            .conn()
            .query_row(
                "SELECT funded FROM ironwood_one_time_operations WHERE request = 'late'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    observe(&mut st, "late", AwaitingDeposit, false, NOW + 2);
    observe(&mut st, "late", Active, true, NOW + 1);
    assert_eq!(
        operation(&st, "late"),
        Some((NOW + 2, 4, None, Some(NOW + 60)))
    );
    assert!(funded(&st));
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "late", AwaitingDeposit, false, now);
    assert!(funded(&st));
    assert!(reap(&mut st, now).is_empty());
    assert!(reserved(&st, &r));
    assert!(active_from(&st, r.key_id()).is_some());
    assert_ne!(prepare(&mut st, now).key_id(), r.key_id());
}

#[test]
fn restart_and_rejected_quote_reuse_the_same_draft() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    begin(&mut st, &r, "too-low").unwrap().unwrap();
    assert_eq!(
        operation(&st, "too-low"),
        Some((NOW, 0, None, Some(NOW + 60)))
    );
    st.wallet_mut()
        .db_mut()
        .finish_receive_operation(account, "too-low", &OperationOutcome::Rejected)
        .unwrap();
    assert_eq!(operation(&st, "too-low"), None);
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    let again = prepare(&mut st, NOW + 1);
    assert_eq!(again.key_id(), r.key_id());
    quote(&mut st, &again, "accepted", true);
    assert_eq!(prepare(&mut st, NOW + 2).key_id().index(), 1);
}

/// Accepted quotes are always in the seen set, so their addresses are never issued
/// again and move the recovery gap rather than fill it.
#[test]
fn accepted_quotes_move_the_recovery_gap() {
    let mut st = fixture();
    let mut first = None;
    for i in 0..RECEIVE_GAP_LIMIT {
        let r = prepare(&mut st, NOW);
        assert_eq!(r.key_id().index(), i);
        quote(&mut st, &r, &format!("quote-{i}"), true);
        first.get_or_insert(r);
    }
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "quote-0", AwaitingDeposit, false, now);
    assert!(!reserved(&st, &first.unwrap()));
    assert_eq!(
        prepare_seen(&mut st, now, &[]).key_id().index(),
        RECEIVE_GAP_LIMIT
    );
}

#[test]
fn provider_statuses_update_the_operation_or_leave_it_alone() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "payout", true);
    let deadline = Some(NOW + 60);
    assert_eq!(operation(&st, "payout"), Some((NOW, 0, None, deadline)));
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    // An active status, as an adapter reports for one it does not recognize, releases
    // nothing.
    let active = Observation {
        status: Active,
        deadline,
    };
    record_observation(&mut st, "payout", active, false, now);
    assert!(reap(&mut st, now).is_empty());
    assert_eq!(operation(&st, "payout"), Some((now, 0, None, deadline)));
    // Another memo on the same deposit address is another operation.
    let finished = Observation {
        status: NO_RECEIPT,
        deadline: None,
    };
    let db = st.wallet_mut().db_mut();
    let matched = db.record_operation_status(account, "payout", Some("memo"), finished, true, now);
    assert!(!matched.unwrap());
    let success = Observation {
        status: Terminal(Positive(Some(Zatoshis::const_from_u64(5_000)))),
        deadline,
    };
    record_observation(&mut st, "payout", success, true, now + 1);
    assert_eq!(
        operation(&st, "payout"),
        Some((now + 1, 2, Some(5_000), deadline))
    );
}

#[test]
fn paid_reservation_closes_once_every_quote_settles() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "edit", false);
    quote(&mut st, &r, "paid", true);
    pay(&mut st, r.full_viewing_key());
    observe(&mut st, "paid", PAID, true, NOW + 1);
    observe(&mut st, "edit", AwaitingDeposit, false, NOW + 1);
    let expired = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    // An unfunded edit holds the reservation until its deadline has passed the
    // cooldown and its status is fresh.
    for now in [NOW + 2, expired] {
        reap(&mut st, now);
        assert!(reserved(&st, &r));
    }
    observe(&mut st, "edit", AwaitingDeposit, false, expired);
    assert!(!reserved(&st, &r));
    assert!(operation(&st, "paid").is_some());
    assert_eq!(prepare(&mut st, expired).key_id().index(), 1);
}

#[test]
fn late_payment_found_by_scanning_prevents_reclamation_and_reuse() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "late", true);
    pay(&mut st, r.full_viewing_key());
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "late", AwaitingDeposit, false, now);
    // The paid reservation is released, but its key is not reclaimed.
    assert!(scanning_keys(&st).contains(&r.key_id()));
    assert!(reap(&mut st, now).is_empty());
    assert_eq!(prepare(&mut st, now).key_id().index(), 1);
}

#[test]
fn activation_rescan_finds_a_payment_in_already_scanned_blocks() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let issued = tip(&st).height + 1;
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let key = KeyId::new(Purpose::Receive, 0);
    // Another install handed out the address, and its payment was scanned without the key.
    pay(&mut st, &key.derive(&parent).unwrap());
    let db = st.wallet_mut().db_mut();
    let r = prepare_from(db, account, NOW, issued, None)
        .unwrap()
        .unwrap();
    assert_eq!(r.key_id(), key);
    assert_eq!(
        refusal(begin(&mut st, &r, "unscanned")),
        Some(ReservationPolicy::Coverage)
    );
    st.scan_cached_blocks_with_one_time_ivks(issued, 1);
    assert!(holds_note(&st, key));
    assert_eq!(
        refusal(begin(&mut st, &r, "paid")),
        Some(ReservationPolicy::Stale)
    );
    assert_eq!(operation(&st, "paid"), None);
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 1);
}

#[test]
fn quote_waits_for_scanning_to_reach_a_new_tip() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    let (h, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(h).unwrap();
    assert_eq!(
        refusal(begin(&mut st, &r, "behind")),
        Some(ReservationPolicy::Coverage)
    );
    st.scan_cached_blocks_with_one_time_ivks(h, 1);
    begin(&mut st, &r, "caught-up").unwrap().unwrap();
}

#[test]
fn reclamation_waits_for_scanning_to_reach_the_tip() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "abandoned", true);
    let (h, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(h).unwrap();
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "abandoned", AwaitingDeposit, false, now);
    assert!(reserved(&st, &r));
    st.scan_cached_blocks_with_one_time_ivks(h, 1);
    assert_eq!(reap(&mut st, now), [0]);
}

#[test]
fn queued_restore_candidate_blocks_quoting_and_reclamation() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    // A sweep's directory payment for the address, queued but not yet applied.
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO ironwood_one_time_payment_recovery
             SELECT id, zeroblob(32), 0, 100000, zeroblob(32), 1, 0, zeroblob(676)
             FROM ironwood_receiving_keys WHERE purpose = 1 AND key_index = ?1",
            [r.key_id().index().to_be_bytes()],
        )
        .unwrap();
    assert_eq!(
        refusal(begin(&mut st, &r, "pending")),
        Some(ReservationPolicy::Coverage)
    );
    assert!(reap(&mut st, NOW + RECEIVE_RECLAIM_SECONDS).is_empty());
}

#[test]
fn undone_incoming_sweep_blocks_new_reservations() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let swept = watch(db, account, 0, through.height).key_id();
    recover(db, account, KeyId::new(Purpose::Refund, 0), through.height);
    assert_eq!(
        refusal(try_prepare(&mut st, NOW, None)),
        Some(ReservationPolicy::Gap)
    );
    finish_sweep(st.wallet_mut().db_mut(), account, swept, through);
    // Issuance resumes at the lowest address never quoted.
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 0);
}

/// Issues through `prepare_receive_reservation` at the tip, with a seen set read from
/// `since` to `until` that holds the incoming addresses at `held`, if any.
fn issue(st: &mut State, seen: Option<(i64, i64, &[u64])>) -> Result<u64, ReservationPolicy> {
    let parent = FullViewingKey::from(st.test_account().unwrap().usk().orchard());
    let held: Vec<[u8; 43]> = seen
        .map_or(&[][..], |(_, _, held)| held)
        .iter()
        .map(|&index| {
            let fvk = KeyId::new(Purpose::Receive, index).derive(&parent).unwrap();
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
    let db = st.wallet_mut().db_mut();
    let issued = db.prepare_receive_reservation(account, NOW, through, seen.as_ref());
    issued.unwrap().map(|k| k.key_id().index())
}

/// Finishes the test account's pending incoming sweeps after empty lookups at the tip,
/// as a receiver directory that saw nothing would. Returns how many it finished.
fn sweep_pending(st: &mut State) -> usize {
    let account = st.test_account().unwrap().id();
    let through = tip(st);
    let pending: Vec<Vec<u8>> = st
        .wallet()
        .conn()
        .prepare(
            "SELECT k.key_index FROM ironwood_one_time_sweeps s
             JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
             WHERE k.purpose = 1 AND s.done_height IS NULL",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let db = st.wallet_mut().db_mut();
    for index in &pending {
        let index = u64::from_be_bytes(index.as_slice().try_into().unwrap());
        finish_sweep(db, account, KeyId::new(Purpose::Receive, index), through);
    }
    pending.len()
}

/// Through the public path, seen hits that widen the window first register and sweep
/// the newly exposed addresses, so issuance waits rather than issuing one unchecked,
/// and a newly exposed address the set holds is skipped once checked.
#[test]
fn seen_hits_extend_the_lookahead_before_issuance() {
    let window = RECEIVE_GAP_LIMIT;
    let held: Vec<u64> = (0..=window).collect();
    let mut st = fixture();
    assert_eq!(issue(&mut st, None), Err(ReservationPolicy::Gap));
    sweep_pending(&mut st);
    let seen = Some((0, NOW + SEEN_SLACK_SECONDS, &held[..]));
    for _ in 0..2 {
        assert_eq!(issue(&mut st, seen), Err(ReservationPolicy::Gap));
        assert!(sweep_pending(&mut st) > 0);
    }
    assert_eq!(issue(&mut st, seen), Ok(window + 1));
}

/// An address past the registered lookahead is checked against the seen set before it
/// is issued: here the old device's requests for the first window never reached the
/// provider, but its quote for the next address did.
#[test]
fn issuance_checks_unregistered_addresses_against_the_seen_set() {
    let window = RECEIVE_GAP_LIMIT;
    let mut st = fixture();
    assert_eq!(issue(&mut st, None), Err(ReservationPolicy::Gap));
    sweep_pending(&mut st);
    let held = [window];
    let seen = Some((0, NOW + SEEN_SLACK_SECONDS, &held[..]));
    let account = st.test_account().unwrap().id();
    for expected in 0..window {
        let index = issue(&mut st, seen).unwrap();
        assert_eq!(index, expected);
        let key = get_key(
            st.wallet().db(),
            account,
            KeyId::new(Purpose::Receive, index),
        );
        quote(
            &mut st,
            &key.unwrap().unwrap(),
            &format!("quote-{index}"),
            true,
        );
    }
    assert_eq!(issue(&mut st, seen), Ok(window + 1));
}

#[test]
fn issuance_skips_restored_addresses_the_provider_saw() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let swept_at = tip(&st);
    let db = st.wallet_mut().db_mut();
    lookahead(db, account, RECEIVE_GAP_LIMIT as u32, swept_at.height);
    // The old device quoted the first three addresses.
    for index in 0..RECEIVE_GAP_LIMIT {
        let key = KeyId::new(Purpose::Receive, index);
        db.begin_one_time_sweep_attempt(account, key, NOW, index < 3)
            .unwrap();
        queue_lookup(db, account, key, swept_at, &[]).unwrap();
        db.apply_one_time_sweep(account, key, swept_at, swept_at, WATCHED, |_, _| None)
            .unwrap()
            .unwrap();
    }
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 3);
    // Seen addresses move the gap and are never reused, even once every other address
    // in the window was quoted and abandoned, nor is one accepted here.
    abandon_indices(&mut st, 4..RECEIVE_GAP_LIMIT + 3);
    let draft = prepare(&mut st, NOW);
    assert_eq!(draft.key_id().index(), 3);
    quote(&mut st, &draft, "after-restore", true);
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "after-restore", AwaitingDeposit, false, now);
    assert!(!reserved(&st, &draft));
    assert_eq!(
        prepare_seen(&mut st, now, &[]).key_id().index(),
        RECEIVE_GAP_LIMIT + 3
    );
}

#[test]
fn payout_during_restore_watch_excludes_the_index() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let swept_at = tip(&st);
    let db = st.wallet_mut().db_mut();
    let swept = watch(db, account, 0, swept_at.height);
    finish_sweep(db, account, swept.key_id(), swept_at);
    // A swap issued before a restore pays out after the sweep, during the watch.
    pay(&mut st, swept.full_viewing_key());
    confirm(&mut st);
    assert!(holds_note(&st, swept.key_id()));
    // The paid address is never issued again.
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 1);
}

#[test]
fn reorg_retains_used_marker_and_seen_addresses_keep_the_bound() {
    let mut st = fixture();
    let before_payment = tip(&st).height;
    let first = prepare(&mut st, NOW);
    quote(&mut st, &first, "first", true);
    pay(&mut st, first.full_viewing_key());
    confirm(&mut st);
    for i in 1..RECEIVE_GAP_LIMIT {
        let r = prepare(&mut st, NOW);
        let request = format!("funded-{i}");
        quote(&mut st, &r, &request, true);
        observe(&mut st, &request, Active, true, NOW + 1);
    }
    let draft = prepare(&mut st, NOW);
    assert_eq!(draft.key_id().index(), RECEIVE_GAP_LIMIT);
    // The rewind removes the payment, but the provider saw every earlier address, so the
    // draft stays within recovery and the paid address is still never reissued.
    st.truncate_to_height_retaining_cache(before_payment);
    assert_eq!(prepare(&mut st, NOW).key_id(), draft.key_id());
    begin(&mut st, &draft, "beyond").unwrap().unwrap();
    // A paid swap with an inconclusive outcome is not reclaimed.
    let now = NOW + RECEIVE_RECLAIM_SECONDS + 61;
    record_observation(&mut st, "first", INCONCLUSIVE, false, now);
    assert!(active_from(&st, first.key_id()).is_some());
}

#[test]
fn issuance_starts_after_the_scanned_tip_once_the_restore_lookahead_is_swept() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let behind = through.height + ISSUANCE_TIP_LAG + 1;
    assert_eq!(
        refusal(db.prepare_receive_reservation(account, NOW, behind, None)),
        Some(ReservationPolicy::Coverage)
    );
    assert_eq!(
        refusal(db.reserve_refund_key(account, behind)),
        Some(ReservationPolicy::Coverage)
    );
    // A wallet cannot tell a fresh seed from a restore, so it sweeps the lookahead first.
    let near = through.height + ISSUANCE_TIP_LAG;
    assert_eq!(
        refusal(db.prepare_receive_reservation(account, NOW, near, None)),
        Some(ReservationPolicy::Gap)
    );
    let lookahead = all_keys(db, account).unwrap();
    assert_eq!(lookahead.len() as u64, RECEIVE_GAP_LIMIT);
    for key in lookahead {
        finish_sweep(db, account, key.key_id(), through);
    }
    let r = db
        .prepare_receive_reservation(account, NOW, near, None)
        .unwrap()
        .unwrap();
    // Issuance takes the lowest address never quoted.
    assert_eq!(r.key_id(), KeyId::new(Purpose::Receive, 0));
    let refund = db
        .reserve_refund_key(account, through.height)
        .unwrap()
        .unwrap()
        .key_id();
    assert_eq!(refund, KeyId::new(Purpose::Refund, 0));
    assert_eq!(active_from(&st, r.key_id()), Some(through.height + 1));
    // A refund key starts scanning only when its funding transaction is stored.
    assert_eq!(active_from(&st, refund), None);
}

#[test]
fn starting_a_quote_returns_its_deposit_and_starts_only_its_reservation() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    // Both quotes share a deposit address and differ only by memo.
    let first = prepare(&mut st, NOW);
    begin(&mut st, &first, "first").unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    db.finish_receive_operation(
        account,
        "first",
        &accepted("shared", Some("memo-1"), NOW + 60),
    )
    .unwrap();
    assert_eq!(
        db.start_receive_operation(account, "first")
            .unwrap()
            .unwrap(),
        ReceiveDeposit {
            address: "shared".into(),
            memo: Some("memo-1".into()),
            deadline: NOW + 60,
        }
    );
    let second = prepare(&mut st, NOW);
    assert_ne!(second.key_id(), first.key_id());
    begin(&mut st, &second, "second").unwrap().unwrap();
    let db = st.wallet_mut().db_mut();
    db.finish_receive_operation(
        account,
        "second",
        &accepted("shared", Some("memo-2"), NOW + 60),
    )
    .unwrap();
    // Starting the first quote again changes nothing else. The provider has the second
    // draft's address, so a new review abandons it rather than reusing it.
    db.start_receive_operation(account, "first")
        .unwrap()
        .unwrap();
    assert_eq!(prepare(&mut st, NOW).key_id().index(), 2);
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        refusal(db.start_receive_operation(account, "second")),
        Some(ReservationPolicy::Stale)
    );
    assert!(matches!(
        db.start_receive_operation(account, "unknown"),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
}

/// A repeated acceptance can lower the deadline but not change the deposit address or
/// memo, so the instructions already shown keep matching provider statuses.
#[test]
fn accepted_deposit_instructions_cannot_change() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let mut shown = None;
    for (request, memo) in [("memo", Some("memo-1")), ("plain", None)] {
        let key = prepare(&mut st, NOW);
        begin(&mut st, &key, request).unwrap().unwrap();
        let db = st.wallet_mut().db_mut();
        db.finish_receive_operation(account, request, &accepted("shared", memo, NOW + 60))
            .unwrap();
        shown.get_or_insert(
            db.start_receive_operation(account, request)
                .unwrap()
                .unwrap(),
        );
    }
    let shown = shown.unwrap();
    let db = st.wallet_mut().db_mut();
    for (request, memo) in [
        ("memo", Some("memo-2")),
        ("memo", None),
        ("plain", Some("memo-1")),
    ] {
        assert!(matches!(
            db.finish_receive_operation(account, request, &accepted("shared", memo, NOW + 60)),
            Err(SqliteClientError::InvalidOneTimeIvkInput(_))
        ));
    }
    // An identical repeat succeeds and can only lower the deadline.
    db.finish_receive_operation(
        account,
        "memo",
        &accepted("shared", Some("memo-1"), NOW + 30),
    )
    .unwrap();
    assert_eq!(
        db.start_receive_operation(account, "memo")
            .unwrap()
            .unwrap(),
        ReceiveDeposit {
            deadline: NOW + 30,
            ..shown
        }
    );
    let observation = Observation {
        status: AwaitingDeposit,
        deadline: None,
    };
    db.record_operation_status(
        account,
        "shared",
        Some("memo-1"),
        observation,
        false,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(operation(&st, "memo").unwrap().0, NOW + 1);
    assert_eq!(operation(&st, "plain").unwrap().0, NOW);
}

/// A deposit identity, its address and memo, belongs to one operation in the account: an
/// identical repeat on that operation succeeds, and another operation cannot take it, on
/// the same reservation or another.
#[test]
fn a_deposit_identity_binds_only_one_operation() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "first", false);
    let deposit = accepted("first", None, NOW + 60);
    st.wallet_mut()
        .db_mut()
        .finish_receive_operation(account, "first", &deposit)
        .unwrap();
    begin(&mut st, &r, "retry").unwrap().unwrap();
    st.wallet_mut()
        .db_mut()
        .start_receive_operation(account, "first")
        .unwrap()
        .unwrap();
    let other = prepare(&mut st, NOW);
    assert_ne!(other.key_id(), r.key_id());
    begin(&mut st, &other, "other").unwrap().unwrap();
    for request in ["retry", "other"] {
        let db = st.wallet_mut().db_mut();
        assert!(matches!(
            db.finish_receive_operation(account, request, &deposit),
            Err(SqliteClientError::InvalidOneTimeIvkInput(_))
        ));
        assert!(matches!(
            db.start_receive_operation(account, request),
            Ok(Err(ReservationPolicy::Stale))
        ));
    }
}

#[test]
fn begin_returns_a_fresh_request_identity() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    let db = st.wallet_mut().db_mut();
    let index = r.key_id().index();
    let first = db
        .begin_receive_operation(account, index, NOW + 60, NOW)
        .unwrap()
        .unwrap();
    let second = db
        .begin_receive_operation(account, index, NOW + 60, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(first.len(), 32);
    assert_ne!(first, second);
    db.finish_receive_operation(account, &first, &accepted("deposit", None, NOW + 60))
        .unwrap();
    let deposit = db
        .start_receive_operation(account, &first)
        .unwrap()
        .unwrap();
    assert_eq!(deposit.address, "deposit");
}

#[test]
fn begin_requires_a_future_deadline() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    assert!(matches!(
        begin_at(&mut st, &r, "expired", NOW, NOW),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(operation(&st, "expired"), None);
}

#[test]
fn statuses_reclaim_abandoned_reservations_and_release_settled_ones() {
    let mut st = fixture();
    let abandoned = prepare(&mut st, NOW);
    quote(&mut st, &abandoned, "abandoned", true);
    let paid = prepare(&mut st, NOW);
    quote(&mut st, &paid, "paid", true);
    pay(&mut st, paid.full_viewing_key());
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "abandoned", AwaitingDeposit, false, now);
    observe(&mut st, "paid", PAID, true, now);
    // Both reservations are done.
    assert!(!reserved(&st, &abandoned) && !reserved(&st, &paid));
    assert!(reap(&mut st, now).is_empty());
    assert!(!scanning_keys(&st).contains(&abandoned.key_id()));
    assert_eq!(prepare(&mut st, now).key_id().index(), 2);
}

#[test]
fn maintenance_registers_restore_discovery_only_at_the_tip() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let (h, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(h).unwrap();
    let db = st.wallet_mut().db_mut();
    db.maintain_one_time_ivks(account).unwrap();
    assert!(all_keys(db, account).unwrap().is_empty());
    st.scan_cached_blocks_with_one_time_ivks(h, 1);
    let db = st.wallet_mut().db_mut();
    db.maintain_one_time_ivks(account).unwrap();
    let keys = all_keys(db, account).unwrap();
    assert_eq!(keys.len() as u64, RECEIVE_GAP_LIMIT);
    assert!(keys.iter().all(|k| !key_state(db, k.key_id()).1));
    // Each waits for its restore sweep rather than being scanned.
    assert!(scanning_keys(&st).is_empty());
}
