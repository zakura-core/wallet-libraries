use super::*;
use rusqlite::params;
use std::num::NonZeroU32;
use zakura_dynamic_ivk::lifecycle::{OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation};

const NOW: i64 = 1_000;

/// Scans `count` new empty blocks and returns the new tip.
fn advance(st: &mut State, count: usize) -> ChainPoint {
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(count);
    tip(st)
}

/// Prepares up to 64 of the test account's due sweeps.
fn batch(st: &mut State, through: ChainPoint, now: i64) -> Vec<DiscoveryWork> {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .prepare_dynamic_sweeps(account, through, now, NonZeroU32::new(64).unwrap())
        .unwrap()
        .unwrap()
}

/// Keys of the due sweeps, in selection order.
fn due(st: &mut State, through: ChainPoint, now: i64) -> Vec<KeyId> {
    batch(st, through, now).into_iter().map(|w| w.key).collect()
}

#[test]
fn restored_keys_are_swept_instead_of_scanned() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let incoming = watch(db, account, 0, through.height);
    let refund = recover(db, account, KeyId::new(Purpose::Refund, 4), through.height);
    assert!(scanning_keys(&st).is_empty());
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    // Recovery evidence for a key this wallet already scans needs no sweep.
    let db = st.wallet_mut().db_mut();
    let issued = reserve_key(db, account, Purpose::Refund, through.height).key_id();
    recover(db, account, issued, through.height);
    let work = batch(&mut st, through, NOW);
    let swept: Vec<_> = work.iter().map(|w| (w.key, w.receiver)).collect();
    assert_eq!(
        swept,
        [incoming, refund].map(|k| (k.key_id(), k.receiver().to_raw_address_bytes()))
    );
}

#[test]
fn bounded_batches_do_not_derive_ten_thousand_restored_keys() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let (owner, _) = account_key(db.conn.borrow(), &db.params, account).unwrap();
    // Zero receivers would fail any derivation check, so selection must not derive.
    tx(db, |c, _| {
        let mut insert = c.prepare(
            "INSERT INTO ironwood_receiving_keys
                (account_id, purpose, key_index, receiver, scan_from, advances_allocation)
             VALUES (?1, 0, ?2, zeroblob(43), ?3, 1)",
        )?;
        for i in 0u64..10_000 {
            insert.execute(params![owner.0, i.to_be_bytes(), u32::from(through.height)])?;
        }
        c.execute(
            "INSERT INTO ironwood_dynamic_sweeps (receiving_key_id) SELECT id FROM ironwood_receiving_keys",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let limit = NonZeroU32::new(64).unwrap();
    let batch = db
        .prepare_dynamic_sweeps(account, through, NOW, limit)
        .unwrap()
        .unwrap();
    assert_eq!(batch.len(), 64);
    assert!(batch.iter().all(|w| w.receiver == [0; 43]));
    // Only the started record is leased, so a stopped batch cannot starve its tail.
    let first = batch[0].key;
    db.begin_dynamic_sweep_attempt(account, first, NOW).unwrap();
    let batch = db
        .prepare_dynamic_sweeps(account, through, NOW, limit)
        .unwrap()
        .unwrap();
    assert_eq!(batch[0].key.index(), 1);
    assert!(batch.iter().all(|w| w.key != first));
}

#[test]
fn sweeps_are_due_once_the_chain_reaches_their_scan_from() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let key = watch(st.wallet_mut().db_mut(), account, 0, through.height + 1).key_id();
    assert!(due(&mut st, through, NOW).is_empty());
    let next = advance(&mut st, 1);
    assert_eq!(due(&mut st, next, NOW), [key]);
}

#[test]
fn a_batch_needs_a_canonical_chain_point() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let base = tip(&st);
    watch(st.wallet_mut().db_mut(), account, 0, base.height);
    let removed = advance(&mut st, 2);
    st.truncate_to_height(base.height);
    let replaced = advance(&mut st, 2);
    assert!(matches!(
        st.wallet_mut().db_mut().prepare_dynamic_sweeps(
            account,
            removed,
            NOW,
            NonZeroU32::new(64).unwrap()
        ),
        Ok(Err(SweepDeferral::UnknownAnchor))
    ));
    assert_eq!(batch(&mut st, replaced, NOW).len(), 1);
}

#[test]
fn a_batch_resumes_queued_lookups() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let older = tip(&st);
    let db = st.wallet_mut().db_mut();
    let keys: Vec<_> = (0..3)
        .map(|i| watch(db, account, i, older.height).key_id())
        .collect();
    // Any canonical lookup is resumed, however old.
    queue_lookup(db, account, keys[2], older, &[]).unwrap();
    let through = advance(&mut st, 1);
    queue_lookup(st.wallet_mut().db_mut(), account, keys[0], through, &[]).unwrap();
    let second = batch(&mut st, through, NOW);
    let lookups: Vec<_> = second.iter().map(|w| (w.key, w.lookup)).collect();
    assert_eq!(
        lookups,
        [
            (keys[0], Some(through)),
            (keys[1], None),
            (keys[2], Some(older))
        ]
    );
}

#[test]
fn attempts_back_off_from_one_minute_to_twelve_hours() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let key = watch(st.wallet_mut().db_mut(), account, 0, through.height).key_id();
    let mut now = NOW;
    for delay in [
        60, 120, 240, 480, 960, 1920, 3840, 7680, 15360, 30720, 43200, 43200,
    ] {
        st.wallet_mut()
            .db_mut()
            .begin_dynamic_sweep_attempt(account, key, now)
            .unwrap();
        assert!(due(&mut st, through, now + delay - 1).is_empty());
        assert_eq!(due(&mut st, through, now + delay), [key]);
        now += delay;
    }
}

#[test]
fn lookup_coverage_advances_only_with_canonical_anchors() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let older = tip(&st);
    let key = watch(st.wallet_mut().db_mut(), account, 0, older.height).key_id();
    let newer = advance(&mut st, 1);
    let db = st.wallet_mut().db_mut();
    let forked = ChainPoint {
        hash: BlockHash([9; 32]),
        ..newer
    };
    let unscanned = ChainPoint {
        height: newer.height + 1,
        ..newer
    };
    for anchor in [forked, unscanned] {
        assert!(queue_lookup(db, account, key, anchor, &[]).is_err());
    }
    assert_eq!(lookup_coverage(db, account, key), None);
    queue_lookup(db, account, key, newer, &[]).unwrap();
    queue_lookup(db, account, key, older, &[]).unwrap();
    assert_eq!(lookup_coverage(db, account, key), Some(newer));
}

#[test]
fn incomplete_lookup_is_atomic_and_pending_ciphertext_survives_restart() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let before = tip(&st);
    let key = KeyId::new(Purpose::Receive, 8);
    watch(st.wallet_mut().db_mut(), account, 8, before.height);
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let mut bad = candidate.clone();
    bad.position += 1; // same output identity, conflicting location
    assert!(queue_lookup(db, account, key, through, &[candidate.clone(), bad]).is_err());
    // A lookup cannot report a payment above its own anchor.
    assert!(queue_lookup(db, account, key, before, std::slice::from_ref(&candidate)).is_err());
    assert!(pending(db, account, key).is_empty());
    assert_eq!(lookup_coverage(db, account, key), None);
    queue_lookup(db, account, key, through, std::slice::from_ref(&candidate)).unwrap();
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    assert!(pending(&reopened, account, key) == [candidate]);
    assert_eq!(lookup_coverage(&reopened, account, key), Some(through));
}

#[test]
fn finished_refund_sweep_scans_from_the_next_block_including_scanned_blocks() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Refund, 3);
    let fvk = recover(st.wallet_mut().db_mut(), account, key, anchor.height)
        .full_viewing_key()
        .clone();
    let (refunded, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(refunded, 1);
    assert!(unspent_keys(&st, refunded).is_empty());
    finish_sweep(st.wallet_mut().db_mut(), account, key, anchor);
    assert_eq!(scanning_keys(&st), [key]);
    assert_eq!(
        st.wallet().suggest_scan_ranges().unwrap(),
        [ScanRange::from_parts(
            refunded..refunded + 1,
            ScanPriority::Historic
        )]
    );
    st.scan_cached_blocks_with_dynamic_ivks(refunded, 1);
    assert_eq!(unspent_keys(&st, refunded), [Some(key)]);
}

#[test]
fn finished_incoming_sweeps_watch_paid_and_unpaid_keys() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = tip(&st).height;
    let paid = KeyId::new(Purpose::Receive, 8);
    let db = st.wallet_mut().db_mut();
    let unpaid = watch(db, account, 0, from).key_id();
    watch(db, account, 8, from);
    let candidate = pay_candidate(&mut st, paid);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    queue_lookup(db, account, paid, through, std::slice::from_ref(&candidate)).unwrap();
    assert_eq!(
        apply_payment(
            db,
            account,
            paid,
            &candidate,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    db.apply_dynamic_sweep(account, paid, through, through, WATCHED, |_, _| None)
        .unwrap()
        .unwrap();
    finish_sweep(db, account, unpaid, through);
    // A paid key also scans on, so a payment after the lookup is not missed.
    assert_eq!(scanning_keys(&st), [unpaid, paid]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
}

#[test]
fn an_unwatched_sweep_closes_only_a_key_that_was_not_scanning() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    // Leave room above the birthday for the rewind below.
    let through = advance(&mut st, 2);
    let db = st.wallet_mut().db_mut();
    let idle = watch(db, account, 0, through.height).key_id();
    let watched = watch(db, account, 1, through.height).key_id();
    queue_lookup(db, account, idle, through, &[]).unwrap();
    assert_eq!(
        db.apply_dynamic_sweep(
            account,
            idle,
            through,
            through,
            ProviderView::default(),
            |_, _| None
        )
        .unwrap()
        .unwrap(),
        PaymentApplication::Applied
    );
    finish_sweep(db, account, watched, through);
    // No swap reached the idle key in the last day, so nothing more can arrive.
    assert_eq!(scanning_keys(&st), [watched]);
    // A rewind below the lookup runs the watched key's sweep again. Unwatched now,
    // the key keeps scanning, since something else may still need it.
    st.generate_and_scan_empty_blocks_with_dynamic_ivks(1);
    st.truncate_to_height_retaining_cache(through.height - 1);
    st.scan_cached_blocks_with_dynamic_ivks(through.height, 2);
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    queue_lookup(db, account, watched, tip, &[]).unwrap();
    assert_eq!(
        db.apply_dynamic_sweep(
            account,
            watched,
            tip,
            tip,
            ProviderView::default(),
            |_, _| None
        )
        .unwrap()
        .unwrap(),
        PaymentApplication::Applied
    );
    assert_eq!(scanning_keys(&st), [watched]);
}

#[test]
fn watched_key_finds_a_payout_after_its_sweep() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Receive, 0);
    let db = st.wallet_mut().db_mut();
    let fvk = watch(db, account, 0, anchor.height)
        .full_viewing_key()
        .clone();
    let (paid, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(paid, 1);
    assert!(unspent_keys(&st, paid).is_empty());
    // The sweep's anchor precedes the payout, which the watch's rescan finds.
    finish_sweep(st.wallet_mut().db_mut(), account, key, anchor);
    assert_eq!(
        st.wallet().suggest_scan_ranges().unwrap(),
        [ScanRange::from_parts(
            paid..paid + 1,
            ScanPriority::Historic
        )]
    );
    st.scan_cached_blocks_with_dynamic_ivks(paid, 1);
    assert_eq!(unspent_keys(&st, paid), [Some(key)]);
}

#[test]
fn issuing_a_key_after_its_watch_needs_no_rescan() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Receive, 0);
    let db = st.wallet_mut().db_mut();
    watch(db, account, 0, anchor.height);
    finish_sweep(db, account, key, anchor);
    db.update_chain_tip(anchor.height).unwrap();
    // Closing sets the tip block's time, so the sweep's own block stays behind it.
    let tip = advance(&mut st, 1).height;
    // The watch runs from the sweep's lookup block, or registration if later.
    let registered: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT MAX(k.registered_at, b.time) FROM ironwood_receiving_keys k
             JOIN ironwood_dynamic_sweeps s ON s.receiving_key_id = k.id
             JOIN blocks b ON b.height = s.done_height WHERE k.purpose = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // No swap is known for a restored address, so it is only watched.
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        close_at(db, account, registered + RESTORE_WATCH_SECS - 1, tip),
        0
    );
    assert_eq!(
        close_at(db, account, registered + RESTORE_WATCH_SECS, tip),
        1
    );
    assert!(scanning_keys(&st).is_empty());
    let through = advance(&mut st, 2);
    let reservation = prepare_from(
        st.wallet_mut().db_mut(),
        account,
        NOW,
        through.height + 1,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(reservation.key_id(), key);
    assert_eq!(scanning_keys(&st), [key]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    // History after the watch is swept again only on request.
    assert!(due(&mut st, through, NOW).is_empty());
}

/// A lookahead address no one was given starts at issuance, however long after its
/// sweep, without rescanning the blocks in between.
#[test]
fn issuing_an_unquoted_swept_key_starts_at_issuance() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Receive, 0);
    let db = st.wallet_mut().db_mut();
    watch(db, account, 0, anchor.height);
    queue_lookup(db, account, key, anchor, &[]).unwrap();
    let unseen = ProviderView {
        recent: false,
        seen: false,
    };
    assert_eq!(
        db.apply_dynamic_sweep(account, key, anchor, anchor, unseen, |_, _| None)
            .unwrap()
            .unwrap(),
        PaymentApplication::Applied
    );
    assert!(scanning_keys(&st).is_empty());
    let through = advance(&mut st, 20);
    let reservation = prepare_from(
        st.wallet_mut().db_mut(),
        account,
        NOW,
        through.height + 1,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(reservation.key_id(), key);
    assert_eq!(scanning_keys(&st), [key]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
}

#[test]
fn restored_refund_key_is_watched_for_a_day() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Refund, 0);
    let db = st.wallet_mut().db_mut();
    recover(db, account, key, anchor.height);
    finish_sweep(db, account, key, anchor);
    db.update_chain_tip(anchor.height).unwrap();
    // Closing sets the tip block's time, so the sweep's own block stays behind it.
    let tip = advance(&mut st, 1).height;
    assert_eq!(scanning_keys(&st), [key]);
    // The watch runs from the sweep's lookup block, or registration if later.
    let registered: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT MAX(k.registered_at, b.time) FROM ironwood_receiving_keys k
             JOIN ironwood_dynamic_sweeps s ON s.receiving_key_id = k.id
             JOIN blocks b ON b.height = s.done_height WHERE k.purpose = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        close_at(db, account, registered + RESTORE_WATCH_SECS - 1, tip),
        0
    );
    assert_eq!(
        close_at(db, account, registered + RESTORE_WATCH_SECS, tip),
        1
    );
    assert!(scanning_keys(&st).is_empty());
}

#[test]
fn swept_key_cannot_be_issued_while_its_sweep_is_pending() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let key = watch(db, account, 0, through.height).key_id();
    assert!(matches!(
        reserve(db, account, Purpose::Receive, through.height + 1),
        Ok(Err(ReservationPolicy::Gap))
    ));
    assert!(scanning_keys(&st).is_empty());
    assert_eq!(due(&mut st, through, NOW), [key]);
}

#[test]
fn history_is_pending_until_sweeps_finish_and_candidates_apply() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let before = tip(&st).height;
    let key = KeyId::new(Purpose::Receive, 8);
    let db = st.wallet_mut().db_mut();
    assert!(!db.dynamic_history_pending(account, before).unwrap());
    watch(db, account, 8, before + 1);
    assert!(!db.dynamic_history_pending(account, before).unwrap());
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    assert!(db.dynamic_history_pending(account, through.height).unwrap());
    // Retry backoff never makes an unfinished restore appear complete.
    db.begin_dynamic_sweep_attempt(account, key, NOW).unwrap();
    assert!(db.dynamic_history_pending(account, through.height).unwrap());
    finish_sweep(db, account, key, through);
    assert!(!db.dynamic_history_pending(account, through.height).unwrap());
    queue_payment(db, account, key, &candidate).unwrap();
    assert!(db.dynamic_history_pending(account, before).unwrap());
    assert_eq!(
        apply_payment(
            db,
            account,
            key,
            &candidate,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    assert!(!db.dynamic_history_pending(account, through.height).unwrap());
}

#[test]
fn candidates_queued_after_finish_are_offered_again() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 8);
    let from = tip(&st).height;
    watch(st.wallet_mut().db_mut(), account, 8, from);
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    finish_sweep(db, account, key, through);
    // An overlapping attempt whose lease expired can still persist its lookup.
    queue_lookup(db, account, key, through, &[candidate]).unwrap();
    assert_eq!(due(&mut st, through, NOW), [key]);
}

#[test]
fn rewind_reruns_only_sweeps_above_the_retained_chain() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let kept = tip(&st);
    let db = st.wallet_mut().db_mut();
    let [early, late] = [0, 1].map(|i| watch(db, account, i, kept.height).key_id());
    finish_sweep(db, account, early, kept);
    let removed = advance(&mut st, 1);
    assert_eq!(due(&mut st, removed, NOW), [late]);
    let db = st.wallet_mut().db_mut();
    finish_sweep(db, account, late, removed);
    st.truncate_to_height(kept.height);
    let db = st.wallet_mut().db_mut();
    assert_eq!(lookup_coverage(db, account, early), Some(kept));
    assert_eq!(lookup_coverage(db, account, late), None);
    assert!(db.dynamic_history_pending(account, kept.height).unwrap());
    // The rewound sweep needs a new lookup before it can finish.
    assert!(matches!(
        db.apply_dynamic_sweep(account, late, kept, kept, WATCHED, |_, _| None),
        Ok(Err(SweepDeferral::UnknownAnchor))
    ));
    assert_eq!(due(&mut st, kept, NOW), [late]);
}

#[test]
fn rewound_sweep_does_not_wait_out_its_last_attempt_lease() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let kept = tip(&st);
    let key = watch(st.wallet_mut().db_mut(), account, 0, kept.height).key_id();
    let removed = advance(&mut st, 1);
    let db = st.wallet_mut().db_mut();
    db.begin_dynamic_sweep_attempt(account, key, NOW).unwrap();
    finish_sweep(db, account, key, removed);
    st.truncate_to_height(kept.height);
    assert_eq!(due(&mut st, kept, NOW), [key]);
}

#[test]
fn issuing_a_lookahead_key_does_not_extend_the_lookahead() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let window = RECEIVE_GAP_LIMIT;
    let db = st.wallet_mut().db_mut();
    lookahead(db, account, window as u32, through.height);
    for i in 0..window {
        finish_sweep(db, account, KeyId::new(Purpose::Receive, i), through);
    }
    let issued = prepare_from(db, account, NOW, through.height + 1, None)
        .unwrap()
        .unwrap();
    assert_eq!(issued.key_id().index(), 0);
    lookahead(db, account, window as u32, through.height);
    assert!(due(&mut st, through, NOW).is_empty());
    let resumed = prepare_from(
        st.wallet_mut().db_mut(),
        account,
        NOW,
        through.height + 1,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(resumed.key_id(), issued.key_id());
}

#[test]
fn payout_during_the_watch_extends_the_lookahead() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    lookahead(db, account, 3, through.height);
    for i in 0..3 {
        finish_sweep(db, account, KeyId::new(Purpose::Receive, i), through);
    }
    let edge = KeyId::new(Purpose::Receive, 2);
    let fvk = all_keys(db, account)
        .unwrap()
        .into_iter()
        .find(|k| k.key_id() == edge)
        .unwrap()
        .full_viewing_key()
        .clone();
    let (paid, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    st.scan_cached_blocks_with_dynamic_ivks(paid, 1);
    assert_eq!(unspent_keys(&st, paid), [Some(edge)]);
    let through = tip(&st);
    lookahead(st.wallet_mut().db_mut(), account, 3, through.height);
    let indices: Vec<_> = due(&mut st, through, NOW)
        .iter()
        .map(|k| k.index())
        .collect();
    assert_eq!(indices, [3, 4, 5]);
}

#[test]
fn retained_spend_history_covers_early_spends_in_large_batches() {
    use orchard::keys::SpendingKey;
    use zcash_keys::address::{Address, UnifiedAddress};

    for (retained, spent) in [(false, true), (true, false), (true, true)] {
        let mut st = scanned_wallet();
        let account = st.test_account().unwrap().id();
        let key = KeyId::new(Purpose::Receive, 8);
        let from = tip(&st).height;
        let db = st.wallet_mut().db_mut();
        if retained {
            retain(db, account);
        }
        let fvk = watch(db, account, 8, from).full_viewing_key().clone();
        let candidate = pay_candidate(&mut st, key);
        if spent {
            let nf = candidate
                .encrypted_note
                .decrypt(
                    &FullViewingKey::from(st.test_account().unwrap().usk().orchard()),
                    key,
                )
                .unwrap()
                .note()
                .nullifier(&fvk);
            let noise = FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap());
            let to = UnifiedAddress::from_receivers(
                Some(noise.address_at(0u32, Scope::External)),
                None,
                None,
            )
            .unwrap();
            st.generate_next_block_spending(
                &IronwoodFvk(fvk),
                (nf, Zatoshis::const_from_u64(100_000)),
                Address::Unified(to),
                Zatoshis::const_from_u64(100_000),
            );
        } else {
            st.generate_empty_block();
        }
        for _ in 0..200 {
            st.generate_empty_block();
        }
        let first = candidate.height + 1;
        st.scan_cached_blocks_with_dynamic_ivks(first, 201);
        let through = tip(&st);
        let status = spend_status(st.wallet_mut().db_mut(), account, key, &candidate, through);
        match (retained, spent) {
            (true, true) => {
                assert!(matches!(status, Ok(SpendStatus::Spent(_))))
            }
            (true, false) => assert_eq!(status, Ok(SpendStatus::Unspent)),
            // Without retention, ordinary pruning leaves no evidence of the spend.
            (false, _) => assert_eq!(status, Ok(SpendStatus::Unknown)),
        }
    }
}

#[test]
fn recheck_sweeps_closed_keys_and_finds_a_later_refund() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let tip_height = tip(&st).height;
    let db = st.wallet_mut().db_mut();
    let key = reserve_key(db, account, Purpose::Refund, tip_height + 1).key_id();
    let finished = OperationStatus::Terminal(ReceiptExpectation::None);
    observe(db, account, key, "swap", finished, NOW).unwrap();
    assert_eq!(close_at(db, account, NOW, tip_height), 1);
    // A second refund arrives after the key closed, so scanning misses it.
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    assert!(unspent_keys(&st, through.height).is_empty());
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.recheck_dynamic_key_history(account).unwrap(), 1);
    assert_eq!(due(&mut st, through, NOW), [key]);
    let db = st.wallet_mut().db_mut();
    queue_lookup(db, account, key, through, std::slice::from_ref(&candidate)).unwrap();
    assert_eq!(
        apply_payment(
            db,
            account,
            key,
            &candidate,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    db.apply_dynamic_sweep(account, key, through, through, WATCHED, |_, _| None)
        .unwrap()
        .unwrap();
    assert_eq!(unspent_keys(&st, through.height), [Some(key)]);
    // The finished sweep reopens the key until it closes again, so no key is left to
    // recheck.
    assert_eq!(scanning_keys(&st), [key]);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .recheck_dynamic_key_history(account)
            .unwrap(),
        0
    );
}
