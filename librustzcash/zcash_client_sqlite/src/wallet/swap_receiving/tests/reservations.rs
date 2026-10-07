use super::*;
use zakura_swap_receiving::lifecycle::ProviderStatus;

/// `(observed_at, expectation, expected_value, deadline)` of an operation.
type Operation = (i64, u8, Option<i64>, Option<i64>);
const NOW: i64 = 1_000_000;

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
    st.scan_cached_blocks(h, 1);
    st
}

/// Resumes the draft or reserves the next address, scanned from the next unscanned block.
fn try_prepare(st: &mut State, now: i64) -> Result<ReceiveReservation, Error> {
    let account = st.test_account().unwrap().id();
    let from = tip(st).height + 1;
    st.wallet_mut()
        .db_mut()
        .prepare_swap_receive_reservation_from(account, now, from)
}

/// [`try_prepare`], expecting a reservation.
fn prepare(st: &mut State, now: i64) -> ReceiveReservation {
    try_prepare(st, now).unwrap()
}

/// Saves quote `request` on `r` at `NOW` with a deadline of `NOW + 60`, before
/// contacting the provider.
fn begin(st: &mut State, r: &ReceiveReservation, request: &str) -> Result<(), Error> {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .begin_swap_receive_quote_as(account, r.id, request, NOW + 60, NOW)
}

/// Begins and accepts quote `request` with a deadline of `NOW + 60`, then optionally starts it.
fn quote(st: &mut State, r: &ReceiveReservation, request: &str, start: bool) {
    let account = st.test_account().unwrap().id();
    begin(st, r, request).unwrap();
    let db = st.wallet_mut().db_mut();
    db.finish_swap_receive_quote(account, request, &accepted(request, None, NOW + 60))
        .unwrap();
    if start {
        db.start_swap_receive_quote(account, request).unwrap();
    }
}

/// Records provider `status` for quote `request`, checked at `now`.
fn observe(st: &mut State, request: &str, status: &str, funded: bool, now: i64) {
    let account = st.test_account().unwrap().id();
    let status = ProviderStatus {
        status,
        ..Default::default()
    };
    st.wallet_mut()
        .db_mut()
        .observe_swap_receive_quote(account, request, &status, funded, now)
        .unwrap();
}

/// Reaps the test account's reservations at `now`, returning those reclaimed.
fn reap(st: &mut State, now: i64) -> Vec<i64> {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .reap_swap_receive_reservations(account, now)
        .unwrap()
}

/// Mines and scans a payment to `key`'s address.
fn pay(st: &mut State, key: &FullViewingKey) {
    let (h, _, _) = st.generate_next_block(
        &IronwoodFvk(key.clone()),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000),
    );
    st.scan_cached_blocks(h, 1);
}

/// Mines and scans blocks until the latest receipt has the default untrusted
/// confirmations, after which it raises the recovery bound.
fn confirm(st: &mut State) {
    st.generate_and_scan_empty_blocks(
        (zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default()
            .untrusted()
            .get()
            - 1) as usize,
    );
}

/// The policy that refused `result`, or `None` if it succeeded.
fn refusal<T>(result: Result<T, Error>) -> Option<ReservationPolicy> {
    match result {
        Ok(_) => None,
        Err(Error::ReservationPolicy(policy)) => Some(policy),
        Err(e) => panic!("unexpected error: {e}"),
    }
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

/// The key operation recorded for quote `request`, if any.
fn operation(st: &State, request: &str) -> Option<Operation> {
    st.wallet()
        .conn()
        .query_row(
            "SELECT observed_at, expectation, expected_value, deadline
             FROM ironwood_swap_operations WHERE operation_id = 'receive-quote:' || ?1",
            [request],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .unwrap()
}

/// Whether the wallet holds an unspent note received by `key`.
fn holds_note(st: &State, key: KeyId) -> bool {
    let account = st.test_account().unwrap().id();
    st.wallet()
        .db()
        .get_unspent_ironwood_notes_at_historical_height(account, tip(st).height)
        .unwrap()
        .iter()
        .any(|n| n.swap_key_id() == Some(key))
}

#[test]
fn reclamation_waits_until_latest_quote_deadline_plus_cooldown() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "first", false);
    let db = st.wallet_mut().db_mut();
    db.begin_swap_receive_quote_as(account, r.id, "second", NOW + 120, NOW + 30)
        .unwrap();
    db.finish_swap_receive_quote(account, "second", &accepted("second", None, NOW + 120))
        .unwrap();
    db.start_swap_receive_quote(account, "second").unwrap();

    let eligible_at = NOW + 120 + RECEIVE_RECLAIM_SECONDS;
    for request in ["first", "second"] {
        observe(&mut st, request, "PENDING_DEPOSIT", false, eligible_at - 1);
    }
    assert!(reap(&mut st, eligible_at - 1).is_empty());
    assert_eq!(reap(&mut st, eligible_at), [r.id]);
}

#[test]
fn unquoted_draft_waits_until_creation_plus_cooldown() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    let eligible_at = NOW + RECEIVE_RECLAIM_SECONDS;
    assert!(reap(&mut st, eligible_at - 1).is_empty());
    assert_eq!(reap(&mut st, eligible_at), [r.id]);
}

#[test]
fn reclaimed_hole_stops_scanning_and_keeps_its_quotes() {
    let mut st = fixture();
    let mut hole = None;
    for i in 0..5 {
        let r = prepare(&mut st, NOW);
        assert_eq!(r.key.key_id().index(), i);
        let request = format!("quote-{i}");
        quote(&mut st, &r, &request, true);
        if i == 1 {
            hole = Some(r);
        } else {
            pay(&mut st, r.key.full_viewing_key());
            observe(&mut st, &request, "SUCCESS", true, NOW + 1);
        }
    }
    let r = hole.unwrap();
    assert!(scanning_keys(&st).contains(&r.key.key_id()));
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "quote-1", "PENDING_DEPOSIT", false, now);
    assert_eq!(reap(&mut st, now), [r.id]);
    assert!(operation(&st, "quote-1").is_some());
    // Every quote is past its deadline and conclusive, so no swap can pay it.
    assert!(!scanning_keys(&st).contains(&r.key.key_id()));
    // The provider has the hole's address, so the next swap gets a fresh one.
    assert_eq!(prepare(&mut st, now).key.key_id().index(), 5);
}

#[test]
fn issuance_reuses_the_lowest_abandoned_address_only_when_none_is_fresh() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let first = prepare(&mut st, NOW);
    quote(&mut st, &first, "first", true);
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "first", "PENDING_DEPOSIT", false, now);
    assert_eq!(reap(&mut st, now), [first.id]);
    let from = tip(&st).height + 1;
    st.wallet_mut()
        .db_mut()
        .abandon_receive_indices(account, 2..RECEIVE_GAP_LIMIT, from)
        .unwrap();
    // Address 1 is the window's only fresh one, so it goes before the lower 0.
    let second = prepare(&mut st, now);
    assert_eq!(second.key.key_id().index(), 1);
    st.wallet_mut()
        .db_mut()
        .begin_swap_receive_quote_as(account, second.id, "second", now + 60, now)
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .finish_swap_receive_quote(account, "second", &accepted("second", None, now + 60))
        .unwrap();
    let later = now + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "second", "PENDING_DEPOSIT", false, later);
    assert_eq!(reap(&mut st, later), [second.id]);
    // With every address in the window quoted, the lowest abandoned one is reused.
    assert_eq!(prepare(&mut st, later).key.key_id(), first.key.key_id());
}

#[test]
fn restart_and_rejected_quote_reuse_the_same_draft() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    begin(&mut st, &r, "too-low").unwrap();
    assert_eq!(
        operation(&st, "too-low"),
        Some((NOW, 0, None, Some(NOW + 60)))
    );
    st.wallet_mut()
        .db_mut()
        .finish_swap_receive_quote(account, "too-low", &QuoteOutcome::Rejected)
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
    assert_eq!(again.id, r.id);
    assert_eq!(again.key.receiver(), r.key.receiver());
    quote(&mut st, &again, "accepted", true);
    assert_eq!(prepare(&mut st, NOW + 2).key.key_id().index(), 1);
}

#[test]
fn unfunded_reservations_are_capped_until_a_deposit_or_payment_is_seen() {
    let mut st = fixture();
    let mut reservations = Vec::new();
    for i in 0..RECEIVE_UNFUNDED_LIMIT {
        let r = prepare(&mut st, NOW);
        quote(&mut st, &r, &format!("quote-{i}"), true);
        reservations.push(r);
    }
    let limit = u64::from(RECEIVE_UNFUNDED_LIMIT);
    assert_eq!(
        refusal(try_prepare(&mut st, NOW)),
        Some(ReservationPolicy::Limit)
    );
    // The provider seeing a deposit frees a slot.
    observe(&mut st, "quote-0", "PROCESSING", true, NOW + 1);
    let next = prepare(&mut st, NOW + 1);
    assert_eq!(next.key.key_id().index(), limit);
    quote(&mut st, &next, "quote-next", true);
    assert_eq!(
        refusal(try_prepare(&mut st, NOW + 1)),
        Some(ReservationPolicy::Limit)
    );
    // So does the payment arriving, without any provider status.
    pay(&mut st, reservations[1].key.full_viewing_key());
    assert_eq!(prepare(&mut st, NOW + 2).key.key_id().index(), limit + 1);
}

#[test]
fn funded_deposits_without_zec_receipts_cannot_exceed_recovery_gap() {
    let mut st = fixture();
    let mut first = None;
    for i in 0..RECEIVE_GAP_LIMIT {
        let r = prepare(&mut st, NOW);
        assert_eq!(r.key.key_id().index(), i);
        let request = format!("quote-{i}");
        quote(&mut st, &r, &request, true);
        observe(&mut st, &request, "PROCESSING", true, NOW + 1);
        if i == 0 {
            first = Some(r);
        }
    }
    assert_eq!(
        refusal(try_prepare(&mut st, NOW)),
        Some(ReservationPolicy::Gap)
    );
    pay(&mut st, first.unwrap().key.full_viewing_key());
    // An unconfirmed receipt could still be reorged away, so it moves nothing yet.
    assert_eq!(
        refusal(try_prepare(&mut st, NOW + 2)),
        Some(ReservationPolicy::Gap)
    );
    confirm(&mut st);
    assert_eq!(
        prepare(&mut st, NOW + 2).key.key_id().index(),
        RECEIVE_GAP_LIMIT
    );
}

#[test]
fn unknown_outcomes_expire_but_stale_or_out_of_order_observations_do_not_release() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "accepted", false);
    // The lost response asked for a later deposit deadline than the accepted quote.
    st.wallet_mut()
        .db_mut()
        .begin_swap_receive_quote_as(account, r.id, "lost-response", NOW + 120, NOW + 1)
        .unwrap();
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "accepted", "PENDING_DEPOSIT", false, now);
    assert!(reap(&mut st, now).is_empty());
    let expired = NOW + 120 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "accepted", "PENDING_DEPOSIT", false, expired);
    assert!(reap(&mut st, expired + 121).is_empty());
    observe(&mut st, "accepted", "PROCESSING", false, expired + 122);
    observe(&mut st, "accepted", "PENDING_DEPOSIT", false, expired + 121);
    assert!(reap(&mut st, expired + 122).is_empty());
    observe(&mut st, "accepted", "PENDING_DEPOSIT", false, expired + 123);
    assert_eq!(reap(&mut st, expired + 123), [r.id]);
}

#[test]
fn provider_statuses_update_the_quote_operation_or_leave_it_alone() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "payout", true);
    let deadline = Some(NOW + 60);
    assert_eq!(operation(&st, "payout"), Some((NOW, 0, None, deadline)));
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    let unknown = ProviderStatus {
        status: "NEW_STATE",
        deadline,
        ..Default::default()
    };
    let db = st.wallet_mut().db_mut();
    db.observe_swap_receive_quote(account, "payout", &unknown, false, now)
        .unwrap();
    assert!(reap(&mut st, now).is_empty());
    assert_eq!(operation(&st, "payout"), Some((NOW, 0, None, deadline)));
    let success = ProviderStatus {
        status: "SUCCESS",
        amount_out: Some(Zatoshis::const_from_u64(5_000)),
        deadline,
        ..Default::default()
    };
    st.wallet_mut()
        .db_mut()
        .observe_swap_receive_quote(account, "payout", &success, true, now + 1)
        .unwrap();
    assert_eq!(
        operation(&st, "payout"),
        Some((now + 1, 2, Some(5_000), deadline))
    );
}

#[test]
fn paid_reservation_closes_once_every_quote_settles() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "edit", false);
    quote(&mut st, &r, "paid", true);
    pay(&mut st, r.key.full_viewing_key());
    observe(&mut st, "paid", "SUCCESS", true, NOW + 1);
    observe(&mut st, "edit", "PENDING_DEPOSIT", false, NOW + 1);
    let expired = NOW + 60 + RECEIVE_RECLAIM_SECONDS;
    let db = st.wallet_mut().db_mut();
    // An unfunded edit holds the reservation until its deadline has passed the
    // cooldown and its status is fresh.
    for now in [NOW + 2, expired] {
        db.reap_swap_receive_reservations(account, now).unwrap();
        assert_eq!(
            db.swap_receive_quotes_due(account, expired + 30)
                .unwrap()
                .len(),
            2
        );
    }
    observe(&mut st, "edit", "PENDING_DEPOSIT", false, expired);
    let db = st.wallet_mut().db_mut();
    db.reap_swap_receive_reservations(account, expired).unwrap();
    assert!(
        db.swap_receive_quotes_due(account, expired + 30)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.swap_receive_reservation(account, r.id)
            .unwrap()
            .key
            .key_id(),
        r.key.key_id()
    );
    assert!(operation(&st, "paid").is_some());
    assert_eq!(prepare(&mut st, expired).key.key_id().index(), 1);
}

#[test]
fn late_payment_found_by_scanning_prevents_reclamation_and_reuse() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "late", true);
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "late", "PENDING_DEPOSIT", false, now);
    pay(&mut st, r.key.full_viewing_key());
    assert!(reap(&mut st, now).is_empty());
    assert_eq!(prepare(&mut st, now).key.key_id().index(), 1);
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
    let r = st
        .wallet_mut()
        .db_mut()
        .prepare_swap_receive_reservation_from(account, NOW, issued)
        .unwrap();
    assert_eq!(r.key.key_id(), key);
    assert_eq!(
        refusal(begin(&mut st, &r, "unscanned")),
        Some(ReservationPolicy::Coverage)
    );
    st.scan_cached_blocks(issued, 1);
    assert!(holds_note(&st, key));
    assert_eq!(
        refusal(begin(&mut st, &r, "paid")),
        Some(ReservationPolicy::Stale)
    );
    assert_eq!(operation(&st, "paid"), None);
    assert_eq!(prepare(&mut st, NOW).key.key_id().index(), 1);
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
    st.scan_cached_blocks(h, 1);
    begin(&mut st, &r, "caught-up").unwrap();
}

#[test]
fn reclamation_waits_for_scanning_to_reach_the_tip() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    quote(&mut st, &r, "abandoned", true);
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "abandoned", "PENDING_DEPOSIT", false, now);
    let (h, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(h).unwrap();
    assert!(reap(&mut st, now).is_empty());
    st.scan_cached_blocks(h, 1);
    assert_eq!(reap(&mut st, now), [r.id]);
}

#[test]
fn queued_restore_candidate_blocks_quoting_and_reclamation() {
    let mut st = fixture();
    let r = prepare(&mut st, NOW);
    // A sweep's directory payment for the address, queued but not yet applied.
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO ironwood_swap_payment_recovery
             SELECT id, zeroblob(32), 0, 100000, zeroblob(32), 1, 0, zeroblob(676)
             FROM ironwood_receiving_keys WHERE purpose = 1 AND key_index = ?1",
            [r.key.key_id().index().to_be_bytes()],
        )
        .unwrap();
    let now = NOW + RECEIVE_RECLAIM_SECONDS;
    assert_eq!(
        refusal(begin(&mut st, &r, "pending")),
        Some(ReservationPolicy::Coverage)
    );
    assert!(reap(&mut st, now).is_empty());
}

#[test]
fn undone_incoming_sweep_blocks_new_reservations() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let swept = db
        .watch_swap_receive_key(account, 0, through.height)
        .unwrap()
        .key_id();
    db.recover_swap_receiving_key(account, KeyId::new(Purpose::Refund, 0), through.height)
        .unwrap();
    assert_eq!(
        refusal(try_prepare(&mut st, NOW)),
        Some(ReservationPolicy::Gap)
    );
    st.wallet_mut()
        .db_mut()
        .finish_sweep(account, swept, through)
        .unwrap();
    // Issuance resumes at the lowest address never quoted.
    assert_eq!(prepare(&mut st, NOW).key.key_id().index(), 0);
}

#[test]
fn issuance_skips_restored_addresses_the_provider_saw() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let swept_at = tip(&st);
    let db = st.wallet_mut().db_mut();
    db.maintain_swap_receive_lookahead(account, RECEIVE_GAP_LIMIT as u32, swept_at.height)
        .unwrap();
    // The old device quoted the first three addresses.
    for index in 0..RECEIVE_GAP_LIMIT {
        let key = KeyId::new(Purpose::Receive, index);
        db.queue_swap_lookup(account, key, swept_at, &[]).unwrap();
        let provider = ProviderView {
            recent: false,
            seen: index < 3,
        };
        db.apply_swap_sweep(account, key, swept_at, swept_at, provider, |_, _| None)
            .unwrap();
    }
    assert_eq!(prepare(&mut st, NOW).key.key_id().index(), 3);
}

#[test]
fn payout_during_restore_watch_excludes_the_index() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let swept_at = tip(&st);
    let swept = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, swept_at.height)
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .finish_sweep(account, swept.key_id(), swept_at)
        .unwrap();
    // A swap issued before a restore pays out after the sweep, during the watch.
    pay(&mut st, swept.full_viewing_key());
    confirm(&mut st);
    assert!(holds_note(&st, swept.key_id()));
    // The paid address is never issued again.
    assert_eq!(prepare(&mut st, NOW).key.key_id().index(), 1);
}

#[test]
fn reorg_retains_used_marker_and_rechecks_draft_recovery_bound() {
    let mut st = fixture();
    let before_payment = tip(&st).height;
    let first = prepare(&mut st, NOW);
    quote(&mut st, &first, "first", true);
    pay(&mut st, first.key.full_viewing_key());
    confirm(&mut st);
    for i in 1..RECEIVE_GAP_LIMIT {
        let r = prepare(&mut st, NOW);
        let request = format!("funded-{i}");
        quote(&mut st, &r, &request, true);
        observe(&mut st, &request, "PROCESSING", true, NOW + 1);
    }
    let draft = prepare(&mut st, NOW);
    assert_eq!(draft.key.key_id().index(), RECEIVE_GAP_LIMIT);
    st.truncate_to_height_retaining_cache(before_payment);
    assert_eq!(
        refusal(try_prepare(&mut st, NOW)),
        Some(ReservationPolicy::Gap)
    );
    assert_eq!(
        refusal(begin(&mut st, &draft, "beyond")),
        Some(ReservationPolicy::Gap)
    );
    let now = NOW + RECEIVE_RECLAIM_SECONDS + 61;
    observe(&mut st, "first", "FAILED", false, now);
    assert!(!reap(&mut st, now).contains(&first.id));
}

#[test]
fn issuance_starts_after_the_scanned_tip_once_the_restore_lookahead_is_swept() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let behind = through.height + ISSUANCE_TIP_LAG + 1;
    assert_eq!(
        refusal(db.prepare_swap_receive_reservation(account, NOW, behind)),
        Some(ReservationPolicy::Coverage)
    );
    assert_eq!(
        refusal(db.reserve_swap_refund_key(account, behind)),
        Some(ReservationPolicy::Coverage)
    );
    // A wallet cannot tell a fresh seed from a restore, so it sweeps the lookahead first.
    let near = through.height + ISSUANCE_TIP_LAG;
    assert_eq!(
        refusal(db.prepare_swap_receive_reservation(account, NOW, near)),
        Some(ReservationPolicy::Gap)
    );
    let lookahead = db.get_swap_receiving_keys(account).unwrap();
    assert_eq!(lookahead.len() as u64, RECEIVE_GAP_LIMIT);
    for key in lookahead {
        db.finish_sweep(account, key.key_id(), through).unwrap();
    }
    let r = db
        .prepare_swap_receive_reservation(account, NOW, near)
        .unwrap();
    // Issuance takes the lowest address never quoted.
    assert_eq!(r.key.key_id(), KeyId::new(Purpose::Receive, 0));
    let refund = db
        .reserve_swap_refund_key(account, through.height)
        .unwrap()
        .key_id();
    assert_eq!(refund, KeyId::new(Purpose::Refund, 0));
    assert_eq!(active_from(&st, r.key.key_id()), Some(through.height + 1));
    // A refund key starts scanning only when its funding transaction is stored.
    assert_eq!(active_from(&st, refund), None);
}

#[test]
fn starting_a_quote_returns_its_deposit_and_starts_only_its_reservation() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    // Both quotes share a deposit address and differ only by memo.
    let first = prepare(&mut st, NOW);
    begin(&mut st, &first, "first").unwrap();
    let db = st.wallet_mut().db_mut();
    db.finish_swap_receive_quote(
        account,
        "first",
        &accepted("shared", Some("memo-1"), NOW + 60),
    )
    .unwrap();
    assert_eq!(
        db.start_swap_receive_quote(account, "first").unwrap(),
        ReceiveDeposit {
            address: "shared".into(),
            memo: Some("memo-1".into()),
            deadline: NOW + 60,
        }
    );
    let second = prepare(&mut st, NOW);
    assert_ne!(second.id, first.id);
    begin(&mut st, &second, "second").unwrap();
    let db = st.wallet_mut().db_mut();
    db.finish_swap_receive_quote(
        account,
        "second",
        &accepted("shared", Some("memo-2"), NOW + 60),
    )
    .unwrap();
    // Starting the first quote again leaves the second reservation as the draft.
    db.start_swap_receive_quote(account, "first").unwrap();
    assert_eq!(prepare(&mut st, NOW).id, second.id);
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        refusal(db.start_swap_receive_quote(account, "unknown")),
        Some(ReservationPolicy::Stale)
    );
    db.start_swap_receive_quote(account, "second").unwrap();
    assert_eq!(prepare(&mut st, NOW).key.key_id().index(), 2);
}

#[test]
fn begin_returns_a_fresh_request_identity() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    let db = st.wallet_mut().db_mut();
    let first = db
        .begin_swap_receive_quote(account, r.id, NOW + 60, NOW)
        .unwrap();
    let second = db
        .begin_swap_receive_quote(account, r.id, NOW + 60, NOW)
        .unwrap();
    assert_eq!(first.len(), 32);
    assert_ne!(first, second);
    db.finish_swap_receive_quote(account, &first, &accepted("deposit", None, NOW + 60))
        .unwrap();
    assert_eq!(
        db.start_swap_receive_quote(account, &first)
            .unwrap()
            .address,
        "deposit"
    );
}

#[test]
fn begin_requires_a_future_deadline() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let r = prepare(&mut st, NOW);
    assert!(
        st.wallet_mut()
            .db_mut()
            .begin_swap_receive_quote_as(account, r.id, "expired", NOW, NOW)
            .is_err()
    );
    assert_eq!(operation(&st, "expired"), None);
}

#[test]
fn reaping_reclaims_abandoned_reservations() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let abandoned = prepare(&mut st, NOW);
    quote(&mut st, &abandoned, "abandoned", true);
    let paid = prepare(&mut st, NOW);
    quote(&mut st, &paid, "paid", true);
    pay(&mut st, paid.key.full_viewing_key());
    let now = NOW + 61 + RECEIVE_RECLAIM_SECONDS;
    observe(&mut st, "abandoned", "PENDING_DEPOSIT", false, now);
    observe(&mut st, "paid", "SUCCESS", true, now);
    assert_eq!(reap(&mut st, now), [abandoned.id]);
    // Both reservations are done: nothing is left to poll.
    assert!(
        st.wallet()
            .db()
            .swap_receive_quotes_due(account, now + 31)
            .unwrap()
            .is_empty()
    );
    assert!(reap(&mut st, now).is_empty());
    assert!(!scanning_keys(&st).contains(&abandoned.key.key_id()));
    assert_eq!(prepare(&mut st, now).key.key_id().index(), 2);
}

#[test]
fn maintenance_registers_restore_discovery_only_at_the_tip() {
    let mut st = fixture();
    let account = st.test_account().unwrap().id();
    let (h, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(h).unwrap();
    let db = st.wallet_mut().db_mut();
    db.maintain_swap_receiving(account).unwrap();
    assert!(db.get_swap_receiving_keys(account).unwrap().is_empty());
    st.scan_cached_blocks(h, 1);
    let db = st.wallet_mut().db_mut();
    db.maintain_swap_receiving(account).unwrap();
    let keys = db.get_swap_receiving_keys(account).unwrap();
    assert_eq!(keys.len() as u64, RECEIVE_GAP_LIMIT);
    assert!(
        keys.iter()
            .all(|k| !db.swap_key_state(account, k.key_id()).1)
    );
    // Each waits for its restore sweep rather than being scanned.
    assert!(db.swap_scanning_keys(account).unwrap().is_empty());
}
