use super::*;
use rusqlite::params;
use std::{collections::BTreeMap, num::NonZeroU32};
use zakura_one_time_ivk::swap::{OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation};

const NOW: i64 = 1_000;

/// Scans `count` new empty blocks and returns the new tip.
fn advance(st: &mut State, count: usize) -> ChainPoint {
    st.generate_and_scan_empty_blocks_with_one_time_ivks(count);
    tip(st)
}

/// Prepares up to 64 of the test account's due sweeps.
fn prepare(
    st: &mut State,
    through: ChainPoint,
    now: i64,
) -> Result<Vec<DiscoveryWork>, SweepDeferral> {
    let account = st.test_account().unwrap().id();
    let limit = NonZeroU32::new(64).unwrap();
    let db = st.wallet_mut().db_mut();
    let prepared = db.prepare_one_time_sweeps(account, through, now, limit);
    prepared.unwrap()
}

/// A scanned wallet, its test account and its tip.
fn setup() -> (State, AccountUuid, ChainPoint) {
    let st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let point = tip(&st);
    (st, account, point)
}

/// Keys of the due sweeps, in selection order.
fn due(st: &mut State, through: ChainPoint, now: i64) -> Vec<KeyId> {
    let work = prepare(st, through, now).unwrap();
    work.into_iter().map(|w| w.key).collect()
}

/// Starts an attempt at the test account's sweep of `key` at `now`, as `seen` if set.
fn begin(st: &mut State, key: KeyId, now: i64, seen: bool) {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.begin_one_time_sweep_attempt(account, key, now, seen)
        .unwrap();
}

/// Records the test account's paid filter `checked` results at `publication`.
fn check(st: &mut State, publication: ChainPoint, checked: &[(KeyId, bool)]) {
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.record_paid_filter_check(account, publication, checked)
        .unwrap();
}

/// Applies `key`'s sweep through `through` at `publication`, expecting it applied. With
/// `witness`, a queued payment is witnessed as the chain's first leaf.
fn sweep(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    (through, publication): (ChainPoint, ChainPoint),
    recent: bool,
    witness: bool,
) {
    let siblings = witness.then(|| first_leaf_path().auth_path().map(|h| h.to_bytes()));
    let applied =
        db.apply_one_time_sweep(account, key, through, publication, recent, |_, _| siblings);
    assert_eq!(applied.unwrap(), Ok(PaymentApplication::Applied));
}

/// [`sweep`] after an empty lookup at `publication`, without a witness.
fn finish_empty(
    db: &mut Db,
    account: AccountUuid,
    key: KeyId,
    points: (ChainPoint, ChainPoint),
    recent: bool,
) {
    queue_lookup(db, account, key, points.1, &[]).unwrap();
    sweep(db, account, key, points, recent, false);
}

/// Registers restored `key` from `from`: an incoming key as a lookahead watch, a refund key
/// as recovered evidence.
fn restore(db: &mut Db, account: AccountUuid, key: KeyId, from: BlockHeight) -> OneTimeKey {
    match key.purpose() {
        Purpose::Receive => watch(db, account, key.index(), from),
        _ => recover(db, account, key, from),
    }
}

/// Closes refund `key` at `now` after its swap finished without a refund.
fn close_unrefunded(db: &mut Db, account: AccountUuid, key: KeyId, now: i64, tip: BlockHeight) {
    let no_refund = OperationStatus::Terminal(ReceiptExpectation::None);
    observe(db, account, key, "swap", no_refund, now).unwrap();
    assert_eq!(close_at(db, account, now, tip), 1);
}

/// Closed keys no paid filter at or above `height` has checked.
fn recheck(st: &State, height: BlockHeight) -> Vec<KeyId> {
    let account = st.test_account().unwrap().id();
    let db = st.wallet();
    let keys = db.one_time_keys_to_recheck(account, height).unwrap();
    keys.iter().map(|w| w.key).collect()
}

/// Whether `account`'s history through `height` is still pending.
fn history_pending(db: &Db, account: AccountUuid, height: BlockHeight) -> bool {
    db.one_time_history_pending(account, height).unwrap()
}

/// Restored keys are swept rather than scanned, and an unswept incoming key cannot be
/// issued. Recovery evidence for a key the wallet already scans needs no sweep.
#[test]
fn restored_keys_are_swept_instead_of_scanned_or_issued() {
    let (mut st, account, through) = setup();
    let db = st.wallet_mut().db_mut();
    let incoming = watch(db, account, 0, through.height);
    let refund = recover(db, account, KeyId::new(Purpose::Refund, 4), through.height);
    let gap = reserve(db, account, Purpose::Receive, through.height + 1);
    assert!(matches!(gap, Ok(Err(ReservationPolicy::Gap))));
    assert!(scanning_keys(&st).is_empty());
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    let db = st.wallet_mut().db_mut();
    let issued = reserve_key(db, account, Purpose::Refund, through.height).key_id();
    recover(db, account, issued, through.height);
    let work = prepare(&mut st, through, NOW).unwrap();
    let swept: Vec<_> = work.iter().map(|w| (w.key, w.receiver)).collect();
    let expected = [incoming, refund].map(|k| (k.key_id(), k.receiver().to_raw_address_bytes()));
    assert_eq!(swept, expected);
}

/// Selection takes a bounded batch without deriving keys, and leases only the started
/// record, so a stopped batch cannot starve its tail.
#[test]
fn bounded_batches_do_not_derive_ten_thousand_restored_keys() {
    let (mut st, account, through) = setup();
    let db = st.wallet_mut().db_mut();
    let (owner, _) = account_key(&db.conn, &db.params, account).unwrap();
    // Zero receivers would fail any derivation check, so selection must not derive.
    let keys = "INSERT INTO ironwood_receiving_keys
        (account_id, purpose, key_index, receiver, scan_from, advances_allocation)
        VALUES (?1, 0, ?2, zeroblob(43), ?3, 1)";
    let sweeps = "INSERT INTO ironwood_one_time_sweeps (receiving_key_id)
        SELECT id FROM ironwood_receiving_keys";
    tx(db, |c, _| {
        let mut insert = c.prepare(keys)?;
        for i in 0u64..10_000 {
            insert.execute(params![owner.0, i.to_be_bytes(), u32::from(through.height)])?;
        }
        c.execute(sweeps, [])?;
        Ok(())
    })
    .unwrap();
    let batch = prepare(&mut st, through, NOW).unwrap();
    assert_eq!(batch.len(), 64);
    assert!(batch.iter().all(|w| w.receiver == [0; 43]));
    let first = batch[0].key;
    begin(&mut st, first, NOW, false);
    let batch = due(&mut st, through, NOW);
    assert_eq!(batch[0].index(), 1);
    assert!(!batch.contains(&first));
}

/// A sweep is due once the chain reaches its scan start, and is prepared only at a
/// canonical chain point.
#[test]
fn sweeps_are_due_from_their_scan_start_at_canonical_points() {
    let (mut st, account, base) = setup();
    let key = watch(st.wallet_mut().db_mut(), account, 0, base.height + 1).key_id();
    assert!(due(&mut st, base, NOW).is_empty());
    let removed = advance(&mut st, 2);
    st.truncate_to_height(base.height);
    let next = advance(&mut st, 1);
    assert_eq!(due(&mut st, next, NOW), [key]);
    let replaced = advance(&mut st, 1);
    let stale = prepare(&mut st, removed, NOW);
    assert!(matches!(stale, Err(SweepDeferral::UnknownAnchor)));
    assert_eq!(due(&mut st, replaced, NOW), [key]);
}

/// Each attempt defers its sweep, doubling from one minute to a twelve-hour cap.
#[test]
fn attempts_back_off_from_one_minute_to_twelve_hours() {
    let (mut st, account, through) = setup();
    let key = watch(st.wallet_mut().db_mut(), account, 0, through.height).key_id();
    let mut now = NOW;
    let delays = (0..10).map(|i| 60 << i).chain([43_200, 43_200]);
    for delay in delays {
        begin(&mut st, key, now, false);
        assert!(due(&mut st, through, now + delay - 1).is_empty(), "{delay}");
        assert_eq!(due(&mut st, through, now + delay), [key], "{delay}");
        now += delay;
    }
}

/// A lookup is queued whole or not at all: only at a canonical, scanned anchor, with
/// consistent candidates none above it. Its candidates and coverage survive a restart, and
/// coverage is the current answer's, even an older publication's, since its candidates
/// replace the newer answer's.
#[test]
fn lookups_queue_atomically_at_canonical_anchors_and_survive_restart() {
    let (mut st, account, before) = setup();
    let key = KeyId::new(Purpose::Receive, 8);
    watch(st.wallet_mut().db_mut(), account, 8, before.height);
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let forked = ChainPoint {
        hash: BlockHash([9; 32]),
        ..through
    };
    let unscanned = ChainPoint {
        height: through.height + 1,
        ..through
    };
    let mut moved = candidate.clone();
    moved.position += 1; // same output identity, conflicting location
    let conflicting = [candidate.clone(), moved];
    let one = std::slice::from_ref(&candidate);
    let db = st.wallet_mut().db_mut();
    let rejected = [
        (forked, &[][..]),
        (unscanned, &[]),
        (through, &conflicting),
        (before, one),
    ];
    for (i, (anchor, payments)) in rejected.into_iter().enumerate() {
        let queued = queue_lookup(db, account, key, anchor, payments);
        assert!(queued.is_err(), "{i}");
    }
    assert!(pending(db, account, key).is_empty());
    assert_eq!(lookup_coverage(db, account, key), None);
    queue_lookup(db, account, key, through, one).unwrap();
    reopen(&mut st);
    let db = st.wallet_mut().db_mut();
    assert!(pending(db, account, key) == [candidate]);
    assert_eq!(lookup_coverage(db, account, key), Some(through));
    queue_lookup(db, account, key, before, &[]).unwrap();
    assert_eq!(lookup_coverage(db, account, key), Some(before));
}

/// A finished sweep of a restored refund or incoming key rescans from the block after its
/// lookup, including blocks already scanned, so its watch finds a payment made since.
#[test]
fn finished_sweeps_rescan_for_payments_after_their_lookup() {
    for (purpose, index) in [(Purpose::Refund, 3), (Purpose::Receive, 0)] {
        let key = KeyId::new(purpose, index);
        let (mut st, account, anchor) = setup();
        let db = st.wallet_mut().db_mut();
        let restored = restore(db, account, key, anchor.height);
        let paid = pay(&mut st, restored.full_viewing_key(), 50_000);
        assert!(unspent_keys(&st, paid).is_empty(), "{key:?}");
        finish_sweep(st.wallet_mut().db_mut(), account, key, anchor);
        assert_eq!(scanning_keys(&st), [key], "{key:?}");
        let rescan = ScanRange::from_parts(paid..paid + 1, ScanPriority::Historic);
        let ranges = st.wallet().suggest_scan_ranges().unwrap();
        assert_eq!(ranges, [rescan], "{key:?}");
        st.scan_cached_blocks_with_one_time_ivks(paid, 1);
        assert_eq!(unspent_keys(&st, paid), [Some(key)], "{key:?}");
    }
}

/// Finished incoming sweeps watch their keys whether paid or not, so a payment after the
/// lookup is not missed.
#[test]
fn finished_incoming_sweeps_watch_paid_and_unpaid_keys() {
    let (mut st, account, from) = setup();
    let paid = KeyId::new(Purpose::Receive, 8);
    let db = st.wallet_mut().db_mut();
    let unpaid = watch(db, account, 0, from.height).key_id();
    watch(db, account, 8, from.height);
    let candidate = pay_candidate(&mut st, paid);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    queue_lookup(db, account, paid, through, std::slice::from_ref(&candidate)).unwrap();
    let applied = apply(db, account, paid, &candidate, through, &first_leaf_path());
    assert_eq!(applied, PaymentApplication::Applied);
    sweep(db, account, paid, (through, through), WATCHED, false);
    finish_sweep(db, account, unpaid, through);
    assert_eq!(scanning_keys(&st), [unpaid, paid]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
}

/// A sweep outside any recent set closes a key that was not scanning at its lookup, but a
/// key already watched keeps scanning when a rewind reruns its sweep.
#[test]
fn an_unwatched_sweep_closes_only_a_key_that_was_not_scanning() {
    let (mut st, account, _) = setup();
    // Leave room above the birthday for the rewind below.
    let through = advance(&mut st, 2);
    let db = st.wallet_mut().db_mut();
    let idle = watch(db, account, 0, through.height).key_id();
    let watched = watch(db, account, 1, through.height).key_id();
    finish_empty(db, account, idle, (through, through), false);
    finish_sweep(db, account, watched, through);
    assert_eq!(scanning_keys(&st), [watched]);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    st.truncate_to_height_retaining_cache(through.height - 1);
    st.scan_cached_blocks_with_one_time_ivks(through.height, 2);
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    finish_empty(db, account, watched, (tip, tip), false);
    assert_eq!(scanning_keys(&st), [watched]);
}

/// A closed key without a known payment, swept or scanned here, is rechecked only
/// against a publication newer than its last check: a paid filter miss records that
/// publication, and a hit queues a sweep. A key with a known payment is never rechecked.
#[test]
fn a_newer_paid_filter_rechecks_closed_unpaid_keys() {
    let (mut st, account, anchor) = setup();
    let db = st.wallet_mut().db_mut();
    let [missed, hit] = [0, 1].map(|index| watch(db, account, index, anchor.height).key_id());
    for key in [missed, hit] {
        finish_empty(db, account, key, (anchor, anchor), false);
    }
    // A refund key scanned here that closes without a refund has never been swept.
    let scanned = reserve_key(db, account, Purpose::Refund, anchor.height + 1).key_id();
    close_unrefunded(db, account, scanned, 0, anchor.height);
    assert_eq!(recheck(&st, anchor.height), [scanned]);
    let publication = advance(&mut st, 1);
    assert_eq!(recheck(&st, publication.height), [missed, hit, scanned]);
    let checked = [(missed, false), (hit, true), (scanned, false)];
    check(&mut st, publication, &checked);
    assert!(recheck(&st, publication.height).is_empty());
    assert_eq!(due(&mut st, publication, NOW), [hit]);
    let newer = advance(&mut st, 1);
    assert_eq!(recheck(&st, newer.height), [missed, scanned]);
    check(&mut st, newer, &[(missed, false), (scanned, true)]);
    assert_eq!(due(&mut st, newer, NOW), [hit, scanned]);
    // A key paid before the birthday is not rechecked, whatever later publications hold.
    let sql = "UPDATE ironwood_receiving_keys SET paid_before_birthday = 1";
    exec(st.wallet().conn(), sql, []);
    assert!(recheck(&st, newer.height + 1).is_empty());
}

/// A recent sweep finished at a publication behind the wallet's tip watches each key,
/// seen or not: rescanning from the block after the lookup finds payments up to the tip
/// before any key can close, and scanning finds later ones.
#[test]
fn a_lagging_recent_sweep_watches_its_keys() {
    let (mut st, account, anchor) = setup();
    let db = st.wallet_mut().db_mut();
    let keys = [
        watch(db, account, 0, anchor.height),
        recover(db, account, KeyId::new(Purpose::Refund, 0), anchor.height),
        watch(db, account, 1, anchor.height),
    ];
    let ids = keys.each_ref().map(|k| k.key_id());
    for key in &keys {
        pay(&mut st, key.full_viewing_key(), 50_000);
    }
    let through = advance(&mut st, 1);
    assert!(unspent_keys(&st, through.height).is_empty());
    for key in ids {
        begin(&mut st, key, NOW, key == ids[2]);
        let db = st.wallet_mut().db_mut();
        finish_empty(db, account, key, (through, anchor), WATCHED);
    }
    let scanning: HashSet<_> = scanning_keys(&st).into_iter().collect();
    assert_eq!(scanning, HashSet::from(ids));
    // However late the clock, no key closes before the rescan.
    let late = clock_now() + 2 * RESTORE_WATCH_SECS;
    let db = st.wallet_mut().db_mut();
    assert_eq!(close_at(db, account, late, through.height), 0);
    let replay = anchor.height + 1;
    let rescan = ScanRange::from_parts(replay..through.height + 1, ScanPriority::Historic);
    assert_eq!(st.wallet().suggest_scan_ranges().unwrap(), [rescan]);
    st.scan_cached_blocks_with_one_time_ivks(replay, keys.len() + 1);
    let received = |st: &State, key| {
        let keys = unspent_keys(st, tip(st).height);
        keys.iter().filter(|k| **k == Some(key)).count()
    };
    assert!(ids.iter().all(|&key| received(&st, key) == 1));
    for key in &keys {
        pay(&mut st, key.full_viewing_key(), 50_000);
    }
    assert!(ids.iter().all(|&key| received(&st, key) == 2));
}

/// A restored key with no known swap is watched for [`RESTORE_WATCH_SECS`] from its
/// sweep's lookup block, or registration if later, then closes. Issuing an incoming key
/// after its watch scans it again without a rescan, and history after the watch is swept
/// again only on request.
#[test]
fn restored_keys_are_watched_then_closed_and_reissued_without_rescan() {
    for (purpose, index) in [(Purpose::Receive, 0), (Purpose::Refund, 0)] {
        let key = KeyId::new(purpose, index);
        let (mut st, account, anchor) = setup();
        let db = st.wallet_mut().db_mut();
        restore(db, account, key, anchor.height);
        finish_sweep(db, account, key, anchor);
        db.update_chain_tip(anchor.height).unwrap();
        // Closing sets the tip block's time, so the sweep's own block stays behind it.
        let tip = advance(&mut st, 1).height;
        assert_eq!(scanning_keys(&st), [key], "{key:?}");
        let sql = "SELECT MAX(k.registered_at, b.time) FROM ironwood_receiving_keys k
            JOIN ironwood_one_time_sweeps s ON s.receiving_key_id = k.id
            JOIN blocks b ON b.height = s.done_height WHERE k.purpose = ?1";
        let purpose = purpose_code(key.purpose()).unwrap();
        let closes: i64 = value(st.wallet().conn(), sql, [purpose]);
        let closes = closes + RESTORE_WATCH_SECS;
        let db = st.wallet_mut().db_mut();
        assert_eq!(close_at(db, account, closes - 1, tip), 0, "{key:?}");
        assert_eq!(close_at(db, account, closes, tip), 1, "{key:?}");
        assert!(scanning_keys(&st).is_empty(), "{key:?}");
        if key.purpose() != Purpose::Receive {
            continue;
        }
        let through = advance(&mut st, 2);
        let db = st.wallet_mut().db_mut();
        let reservation = prepare_from(db, account, NOW, through.height + 1, None);
        assert_eq!(reservation.unwrap().unwrap().key_id(), key);
        assert_eq!(scanning_keys(&st), [key]);
        assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
        assert!(due(&mut st, through, NOW).is_empty());
    }
}

/// History is pending while a sweep is unfinished, whatever its retry backoff, and while a
/// queued candidate is unapplied.
#[test]
fn history_is_pending_until_sweeps_finish_and_candidates_apply() {
    let (mut st, account, before) = setup();
    let before = before.height;
    let key = KeyId::new(Purpose::Receive, 8);
    let db = st.wallet_mut().db_mut();
    assert!(!history_pending(db, account, before));
    watch(db, account, 8, before + 1);
    assert!(!history_pending(db, account, before));
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    assert!(history_pending(db, account, through.height));
    begin(&mut st, key, NOW, false);
    let db = st.wallet_mut().db_mut();
    assert!(history_pending(db, account, through.height));
    finish_sweep(db, account, key, through);
    assert!(!history_pending(db, account, through.height));
    queue_payment(db, account, key, &candidate).unwrap();
    assert!(history_pending(db, account, before));
    let applied = apply(db, account, key, &candidate, through, &first_leaf_path());
    assert_eq!(applied, PaymentApplication::Applied);
    assert!(!history_pending(db, account, through.height));
}

/// Candidates a late lookup queues after the sweep finished reopen it. A corrected answer
/// awaiting note data replaces them and stays unfinished across a reopen; once complete it
/// records coverage, and the sweep finishes by applying it.
#[test]
fn candidates_queued_after_finish_are_offered_again() {
    let (mut st, account, from) = setup();
    let key = KeyId::new(Purpose::Receive, 8);
    watch(st.wallet_mut().db_mut(), account, 8, from.height);
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    finish_sweep(db, account, key, through);
    // An overlapping attempt whose lease expired can still persist its lookup.
    let late = PendingPayment {
        tx_index: candidate.tx_index + 1,
        ..candidate.clone()
    };
    queue_lookup(db, account, key, through, &[late]).unwrap();
    assert_eq!(due(&mut st, through, NOW), [key]);
    let (corrected, data) = directory_answer(&candidate);
    let corrected = std::slice::from_ref(&corrected);
    begin(&mut st, key, NOW, false);
    let db = st.wallet_mut().db_mut();
    let queued = db.queue_directory_lookup(account, key, through, corrected, &BTreeMap::new());
    assert!(!queued.unwrap().unwrap());
    reopen(&mut st);
    let db = st.wallet_mut().db_mut();
    assert!(history_pending(db, account, through.height));
    assert_eq!(lookup_coverage(db, account, key), None);
    assert!(due(&mut st, through, NOW).is_empty());
    assert_eq!(due(&mut st, through, NOW + 60), [key]);
    let db = st.wallet_mut().db_mut();
    let queued = db.queue_directory_lookup(account, key, through, corrected, &data);
    assert!(queued.unwrap().unwrap());
    assert_eq!(lookup_coverage(db, account, key), Some(through));
    assert!(history_pending(db, account, through.height));
    sweep(db, account, key, (through, through), WATCHED, true);
    assert!(!history_pending(db, account, through.height));
    assert_eq!(unspent_keys(&st, through.height), [Some(key)]);
}

/// A rewind reruns only sweeps whose lookup it removed, without waiting out the last
/// attempt's lease, and a rewound sweep needs a new lookup before it can finish.
#[test]
fn rewind_reruns_only_sweeps_above_the_retained_chain() {
    let (mut st, account, kept) = setup();
    let db = st.wallet_mut().db_mut();
    let [early, late] = [0, 1].map(|i| watch(db, account, i, kept.height).key_id());
    finish_sweep(db, account, early, kept);
    let removed = advance(&mut st, 1);
    assert_eq!(due(&mut st, removed, NOW), [late]);
    begin(&mut st, late, NOW, false);
    finish_sweep(st.wallet_mut().db_mut(), account, late, removed);
    st.truncate_to_height(kept.height);
    let db = st.wallet_mut().db_mut();
    assert_eq!(lookup_coverage(db, account, early), Some(kept));
    assert_eq!(lookup_coverage(db, account, late), None);
    assert!(history_pending(db, account, kept.height));
    let rerun = db.apply_one_time_sweep(account, late, kept, kept, WATCHED, |_, _| None);
    assert!(matches!(rerun, Ok(Err(SweepDeferral::UnknownAnchor))));
    assert_eq!(due(&mut st, kept, NOW), [late]);
}

/// Issuing a lookahead key does not extend the lookahead, so issuance resumes at the same
/// key, but a payout to the edge key during its watch does.
#[test]
fn only_a_payout_extends_the_lookahead() {
    let (mut st, account, through) = setup();
    let window = RECEIVE_GAP_LIMIT;
    let db = st.wallet_mut().db_mut();
    lookahead(db, account, window as u32, through.height);
    for i in 0..window {
        finish_sweep(db, account, KeyId::new(Purpose::Receive, i), through);
    }
    let issue = |db: &mut Db| {
        let key = prepare_from(db, account, NOW, through.height + 1, None);
        key.unwrap().unwrap().key_id()
    };
    let issued = issue(db);
    assert_eq!(issued.index(), 0);
    lookahead(db, account, window as u32, through.height);
    assert!(due(&mut st, through, NOW).is_empty());
    assert_eq!(issue(st.wallet_mut().db_mut()), issued);
    let edge = KeyId::new(Purpose::Receive, window - 1);
    let fvk = derive(&st, edge);
    let paid = pay(&mut st, &fvk, 50_000);
    assert_eq!(unspent_keys(&st, paid), [Some(edge)]);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    lookahead(db, account, window as u32, through.height);
    let due = due(&mut st, through, NOW);
    let indices: Vec<_> = due.iter().map(|k| k.index()).collect();
    assert_eq!(indices, Vec::from_iter(window..2 * window));
}

/// Retained spend history shows whether a restored payment was spent long before the
/// lookup; without retention, ordinary pruning leaves no evidence either way.
#[test]
fn retained_spend_history_covers_early_spends_in_large_batches() {
    for (retained, spent) in [(false, true), (true, false), (true, true)] {
        let (mut st, account, from) = setup();
        let key = KeyId::new(Purpose::Receive, 8);
        let db = st.wallet_mut().db_mut();
        if retained {
            retain(db, account);
        }
        let watched = watch(db, account, 8, from.height);
        let candidate = pay_candidate(&mut st, key);
        if spent {
            let fvk = watched.full_viewing_key().clone();
            let note = candidate.encrypted_note.decrypt(&parent(&st), key).unwrap();
            let nf = note.note().nullifier(&fvk);
            let value = Zatoshis::const_from_u64(100_000);
            let to = unified(foreign_receiver());
            st.generate_next_block_spending(&IronwoodFvk(fvk), (nf, value), to, value);
        } else {
            st.generate_empty_block();
        }
        for _ in 0..200 {
            st.generate_empty_block();
        }
        st.scan_cached_blocks_with_one_time_ivks(candidate.height + 1, 201);
        let through = tip(&st);
        let status = spend_status(st.wallet_mut().db_mut(), account, key, &candidate, through);
        let label = format!("retained {retained}, spent {spent}");
        match (retained, spent) {
            (true, true) => assert!(matches!(status, Ok(SpendStatus::Spent(_))), "{label}"),
            (true, false) => assert_eq!(status, Ok(SpendStatus::Unspent), "{label}"),
            (false, _) => assert_eq!(status, Ok(SpendStatus::Unknown), "{label}"),
        }
    }
}

/// The history recheck sweeps a closed key and finds a refund paid after it closed; the
/// finished sweep reopens the key, so none is left to recheck.
#[test]
fn recheck_sweeps_closed_keys_and_finds_a_later_refund() {
    let (mut st, account, at) = setup();
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Refund, at.height + 1).key_id();
    close_unrefunded(db, account, key, NOW, at.height);
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    assert!(unspent_keys(&st, through.height).is_empty());
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.recheck_one_time_key_history(account).unwrap(), 1);
    assert_eq!(due(&mut st, through, NOW), [key]);
    let db = st.wallet_mut().db_mut();
    queue_lookup(db, account, key, through, std::slice::from_ref(&candidate)).unwrap();
    let applied = apply(db, account, key, &candidate, through, &first_leaf_path());
    assert_eq!(applied, PaymentApplication::Applied);
    sweep(db, account, key, (through, through), WATCHED, false);
    assert_eq!(unspent_keys(&st, through.height), [Some(key)]);
    assert_eq!(scanning_keys(&st), [key]);
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.recheck_one_time_key_history(account).unwrap(), 0);
}

/// A receipt that was decrypted but expired unmined is no payment: once its key closes,
/// the paid filter backstop still rechecks it and finds a later refund, after which the
/// key is not rechecked.
#[test]
fn an_expired_receipt_leaves_a_closed_key_to_the_paid_filter() {
    let (mut st, account, height) = setup();
    let height = height.height;
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Refund, height + 1);
    pay(&mut st, key.full_viewing_key(), 50_000);
    let key = key.key_id();
    // A rewind un-mines the receipt, which then expires.
    st.truncate_to_height(height);
    let sql = "UPDATE transactions SET expiry_height = ?1 WHERE mined_height IS NULL";
    exec(st.wallet().conn(), sql, [u32::from(height) + 1]);
    let expired = advance(&mut st, 1);
    close_unrefunded(st.wallet_mut().db_mut(), account, key, NOW, expired.height);
    let candidate = pay_candidate(&mut st, key);
    let publication = tip(&st);
    assert_eq!(recheck(&st, publication.height), [key]);
    check(&mut st, publication, &[(key, true)]);
    assert_eq!(due(&mut st, publication, NOW), [key]);
    let db = st.wallet_mut().db_mut();
    let one = std::slice::from_ref(&candidate);
    queue_lookup(db, account, key, publication, one).unwrap();
    sweep(db, account, key, (publication, publication), false, true);
    assert_eq!(unspent_keys(&st, publication.height), [Some(key)]);
    assert!(recheck(&st, publication.height + 1).is_empty());
}
