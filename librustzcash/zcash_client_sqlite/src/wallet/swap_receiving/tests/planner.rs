use super::*;
use rusqlite::params;
use std::num::NonZeroU32;
use zakura_swap_receiving::lifecycle::{OperationStatus, RESTORE_WATCH_SECS, ReceiptExpectation};

const NOW: i64 = 1_000;

/// Scans `count` new empty blocks and returns the new tip.
fn advance(st: &mut State, count: usize) -> ChainPoint {
    st.generate_and_scan_empty_blocks(count);
    tip(st)
}

/// Prepares up to 64 of the test account's due sweeps.
fn batch(st: &mut State, through: ChainPoint, now: i64) -> Vec<DiscoveryWork> {
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .prepare_swap_discovery_batch(account, through, now, NonZeroU32::new(64).unwrap())
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
    let incoming = db
        .watch_swap_receive_key(account, 0, through.height)
        .unwrap();
    let refund = db
        .recover_swap_receiving_key(account, KeyId::new(Purpose::Refund, 4), through.height)
        .unwrap();
    assert!(scanning_keys(&st).is_empty());
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    // Recovery evidence for a key this wallet already scans needs no sweep.
    let db = st.wallet_mut().db_mut();
    let issued = db
        .reserve_swap_receiving_key_from(account, Purpose::Refund, through.height)
        .unwrap()
        .key_id();
    db.recover_swap_receiving_key(account, issued, through.height)
        .unwrap();
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
    db.transactionally::<_, _, Error>(|db| {
        let mut insert = db.conn.0.prepare(
            "INSERT INTO ironwood_receiving_keys
                (account_id, purpose, key_index, receiver, scan_from, advances_allocation)
             VALUES (?1, 0, ?2, zeroblob(43), ?3, 1)",
        )?;
        for i in 0u64..10_000 {
            insert.execute(params![owner.0, i.to_be_bytes(), u32::from(through.height)])?;
        }
        db.conn.0.execute(
            "INSERT INTO ironwood_swap_sweeps (receiving_key_id) SELECT id FROM ironwood_receiving_keys",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let limit = NonZeroU32::new(64).unwrap();
    let batch = db
        .prepare_swap_discovery_batch(account, through, NOW, limit)
        .unwrap();
    assert_eq!(batch.len(), 64);
    assert!(batch.iter().all(|w| w.receiver == [0; 43]));
    // Only the started record is leased, so a stopped batch cannot starve its tail.
    let first = batch[0].key;
    db.begin_swap_discovery_attempt(account, first, NOW)
        .unwrap();
    let batch = db
        .prepare_swap_discovery_batch(account, through, NOW, limit)
        .unwrap();
    assert_eq!(batch[0].key.index(), 1);
    assert!(batch.iter().all(|w| w.key != first));
}

#[test]
fn sweeps_are_due_once_the_chain_reaches_their_scan_from() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, through.height + 1)
        .unwrap()
        .key_id();
    assert!(due(&mut st, through, NOW).is_empty());
    let next = advance(&mut st, 1);
    assert_eq!(due(&mut st, next, NOW), [key]);
}

#[test]
fn a_batch_needs_a_canonical_chain_point() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let base = tip(&st);
    st.wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, base.height)
        .unwrap();
    let removed = advance(&mut st, 2);
    st.truncate_to_height(base.height);
    let replaced = advance(&mut st, 2);
    assert!(matches!(
        st.wallet_mut().db_mut().prepare_swap_discovery_batch(
            account,
            removed,
            NOW,
            NonZeroU32::new(64).unwrap()
        ),
        Err(Error::SweepDeferred(SweepDeferral::UnknownAnchor))
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
        .map(|i| {
            db.watch_swap_receive_key(account, i, older.height)
                .unwrap()
                .key_id()
        })
        .collect();
    // Any canonical lookup is resumed, however old.
    db.queue_swap_lookup(account, keys[2], older, &[]).unwrap();
    let through = advance(&mut st, 1);
    st.wallet_mut()
        .db_mut()
        .queue_swap_lookup(account, keys[0], through, &[])
        .unwrap();
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
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, through.height)
        .unwrap()
        .key_id();
    let mut now = NOW;
    for delay in [
        60, 120, 240, 480, 960, 1920, 3840, 7680, 15360, 30720, 43200, 43200,
    ] {
        st.wallet_mut()
            .db_mut()
            .begin_swap_discovery_attempt(account, key, now)
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
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, older.height)
        .unwrap()
        .key_id();
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
        assert!(db.queue_swap_lookup(account, key, anchor, &[]).is_err());
    }
    assert_eq!(db.swap_lookup_coverage(account, key).unwrap(), None);
    db.queue_swap_lookup(account, key, newer, &[]).unwrap();
    db.queue_swap_lookup(account, key, older, &[]).unwrap();
    assert_eq!(db.swap_lookup_coverage(account, key).unwrap(), Some(newer));
}

#[test]
fn incomplete_lookup_is_atomic_and_pending_ciphertext_survives_restart() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let before = tip(&st);
    let key = KeyId::new(Purpose::Receive, 8);
    st.wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 8, before.height)
        .unwrap();
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let mut bad = candidate.clone();
    bad.position += 1; // same output identity, conflicting location
    assert!(
        db.queue_swap_lookup(account, key, through, &[candidate.clone(), bad])
            .is_err()
    );
    // A lookup cannot report a payment above its own anchor.
    assert!(
        db.queue_swap_lookup(account, key, before, std::slice::from_ref(&candidate))
            .is_err()
    );
    assert!(db.pending_swap_payments(account, key).unwrap().is_empty());
    assert_eq!(db.swap_lookup_coverage(account, key).unwrap(), None);
    db.queue_swap_lookup(account, key, through, std::slice::from_ref(&candidate))
        .unwrap();
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    assert!(reopened.pending_swap_payments(account, key).unwrap() == [candidate]);
    assert_eq!(
        reopened.swap_lookup_coverage(account, key).unwrap(),
        Some(through)
    );
}

#[test]
fn finished_refund_sweep_scans_from_the_next_block_including_scanned_blocks() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Refund, 3);
    let fvk = st
        .wallet_mut()
        .db_mut()
        .recover_swap_receiving_key(account, key, anchor.height)
        .unwrap()
        .full_viewing_key()
        .clone();
    let (refunded, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(70_000),
    );
    st.scan_cached_blocks(refunded, 1);
    assert!(unspent_keys(&st, refunded).is_empty());
    st.wallet_mut()
        .db_mut()
        .finish_sweep(account, key, anchor)
        .unwrap();
    assert_eq!(scanning_keys(&st), [key]);
    assert_eq!(
        st.wallet().suggest_scan_ranges().unwrap(),
        [ScanRange::from_parts(
            refunded..refunded + 1,
            ScanPriority::Historic
        )]
    );
    st.scan_cached_blocks(refunded, 1);
    assert_eq!(unspent_keys(&st, refunded), [Some(key)]);
}

#[test]
fn finished_incoming_sweeps_watch_paid_and_unpaid_keys() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let from = tip(&st).height;
    let paid = KeyId::new(Purpose::Receive, 8);
    let db = st.wallet_mut().db_mut();
    let unpaid = db
        .watch_swap_receive_key(account, 0, from)
        .unwrap()
        .key_id();
    db.watch_swap_receive_key(account, 8, from).unwrap();
    let candidate = pay_candidate(&mut st, paid);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    db.queue_swap_lookup(account, paid, through, std::slice::from_ref(&candidate))
        .unwrap();
    assert_eq!(
        db.apply_pending_swap_payment(
            account,
            paid,
            &candidate,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    db.apply_swap_sweep(account, paid, through, through, WATCHED, |_, _| None)
        .unwrap();
    db.finish_sweep(account, unpaid, through).unwrap();
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
    let idle = db
        .watch_swap_receive_key(account, 0, through.height)
        .unwrap()
        .key_id();
    let watched = db
        .watch_swap_receive_key(account, 1, through.height)
        .unwrap()
        .key_id();
    db.queue_swap_lookup(account, idle, through, &[]).unwrap();
    assert_eq!(
        db.apply_swap_sweep(
            account,
            idle,
            through,
            through,
            ProviderView::default(),
            |_, _| None
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    db.finish_sweep(account, watched, through).unwrap();
    // No swap reached the idle key in the last day, so nothing more can arrive.
    assert_eq!(scanning_keys(&st), [watched]);
    // A rewind below the lookup runs the watched key's sweep again. Unwatched now,
    // the key keeps scanning, since something else may still need it.
    st.generate_and_scan_empty_blocks(1);
    st.truncate_to_height_retaining_cache(through.height - 1);
    st.scan_cached_blocks(through.height, 2);
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    db.queue_swap_lookup(account, watched, tip, &[]).unwrap();
    assert_eq!(
        db.apply_swap_sweep(
            account,
            watched,
            tip,
            tip,
            ProviderView::default(),
            |_, _| None
        )
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
    let fvk = db
        .watch_swap_receive_key(account, 0, anchor.height)
        .unwrap()
        .full_viewing_key()
        .clone();
    let (paid, _, _) = st.generate_next_block(
        &IronwoodFvk(fvk),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(50_000),
    );
    st.scan_cached_blocks(paid, 1);
    assert!(unspent_keys(&st, paid).is_empty());
    // The sweep's anchor precedes the payout, which the watch's rescan finds.
    st.wallet_mut()
        .db_mut()
        .finish_sweep(account, key, anchor)
        .unwrap();
    assert_eq!(
        st.wallet().suggest_scan_ranges().unwrap(),
        [ScanRange::from_parts(
            paid..paid + 1,
            ScanPriority::Historic
        )]
    );
    st.scan_cached_blocks(paid, 1);
    assert_eq!(unspent_keys(&st, paid), [Some(key)]);
}

#[test]
fn issuing_a_key_after_its_watch_needs_no_rescan() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Receive, 0);
    let db = st.wallet_mut().db_mut();
    db.watch_swap_receive_key(account, 0, anchor.height)
        .unwrap();
    db.finish_sweep(account, key, anchor).unwrap();
    db.update_chain_tip(anchor.height).unwrap();
    let registered: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT registered_at FROM ironwood_receiving_keys WHERE purpose = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // No swap is known for a restored address, so it is only watched.
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.close_finished_swap_keys_at(account, registered + RESTORE_WATCH_SECS - 1, anchor.height)
            .unwrap(),
        0
    );
    assert_eq!(
        db.close_finished_swap_keys_at(account, registered + RESTORE_WATCH_SECS, anchor.height)
            .unwrap(),
        1
    );
    assert!(scanning_keys(&st).is_empty());
    let through = advance(&mut st, 2);
    let reservation = st
        .wallet_mut()
        .db_mut()
        .prepare_swap_receive_reservation_from(account, NOW, through.height + 1)
        .unwrap();
    assert_eq!(reservation.key.key_id(), key);
    assert_eq!(scanning_keys(&st), [key]);
    assert!(st.wallet().suggest_scan_ranges().unwrap().is_empty());
    // History after the watch is swept again only on request.
    assert!(due(&mut st, through, NOW).is_empty());
}

#[test]
fn restored_refund_key_is_watched_for_a_day() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let anchor = tip(&st);
    let key = KeyId::new(Purpose::Refund, 0);
    let db = st.wallet_mut().db_mut();
    db.recover_swap_receiving_key(account, key, anchor.height)
        .unwrap();
    db.finish_sweep(account, key, anchor).unwrap();
    db.update_chain_tip(anchor.height).unwrap();
    assert_eq!(scanning_keys(&st), [key]);
    let registered: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT registered_at FROM ironwood_receiving_keys WHERE purpose = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.close_finished_swap_keys_at(account, registered + RESTORE_WATCH_SECS - 1, anchor.height)
            .unwrap(),
        0
    );
    assert_eq!(
        db.close_finished_swap_keys_at(account, registered + RESTORE_WATCH_SECS, anchor.height)
            .unwrap(),
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
    let key = db
        .watch_swap_receive_key(account, 0, through.height)
        .unwrap()
        .key_id();
    assert!(matches!(
        db.reserve_swap_receiving_key_from(account, Purpose::Receive, through.height + 1),
        Err(Error::ReservationPolicy(ReservationPolicy::Gap))
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
    assert!(!db.swap_history_pending(account, before).unwrap());
    db.watch_swap_receive_key(account, 8, before + 1).unwrap();
    assert!(!db.swap_history_pending(account, before).unwrap());
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    assert!(db.swap_history_pending(account, through.height).unwrap());
    // Retry backoff never makes an unfinished restore appear complete.
    db.begin_swap_discovery_attempt(account, key, NOW).unwrap();
    assert!(db.swap_history_pending(account, through.height).unwrap());
    db.finish_sweep(account, key, through).unwrap();
    assert!(!db.swap_history_pending(account, through.height).unwrap());
    db.queue_swap_payment(account, key, &candidate).unwrap();
    assert!(db.swap_history_pending(account, before).unwrap());
    assert_eq!(
        db.apply_pending_swap_payment(
            account,
            key,
            &candidate,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    assert!(!db.swap_history_pending(account, through.height).unwrap());
}

#[test]
fn candidates_queued_after_finish_are_offered_again() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let key = KeyId::new(Purpose::Receive, 8);
    let from = tip(&st).height;
    st.wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 8, from)
        .unwrap();
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    db.finish_sweep(account, key, through).unwrap();
    // An overlapping attempt whose lease expired can still persist its lookup.
    db.queue_swap_lookup(account, key, through, &[candidate])
        .unwrap();
    assert_eq!(due(&mut st, through, NOW), [key]);
}

#[test]
fn rewind_reruns_only_sweeps_above_the_retained_chain() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let kept = tip(&st);
    let db = st.wallet_mut().db_mut();
    let [early, late] = [0, 1].map(|i| {
        db.watch_swap_receive_key(account, i, kept.height)
            .unwrap()
            .key_id()
    });
    db.finish_sweep(account, early, kept).unwrap();
    let removed = advance(&mut st, 1);
    assert_eq!(due(&mut st, removed, NOW), [late]);
    let db = st.wallet_mut().db_mut();
    db.finish_sweep(account, late, removed).unwrap();
    st.truncate_to_height(kept.height);
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.swap_lookup_coverage(account, early).unwrap(), Some(kept));
    assert_eq!(db.swap_lookup_coverage(account, late).unwrap(), None);
    assert!(db.swap_history_pending(account, kept.height).unwrap());
    // The rewound sweep needs a new lookup before it can finish.
    assert!(matches!(
        db.apply_swap_sweep(account, late, kept, kept, WATCHED, |_, _| None),
        Err(Error::SweepDeferred(SweepDeferral::UnknownAnchor))
    ));
    assert_eq!(due(&mut st, kept, NOW), [late]);
}

#[test]
fn rewound_sweep_does_not_wait_out_its_last_attempt_lease() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let kept = tip(&st);
    let key = st
        .wallet_mut()
        .db_mut()
        .watch_swap_receive_key(account, 0, kept.height)
        .unwrap()
        .key_id();
    let removed = advance(&mut st, 1);
    let db = st.wallet_mut().db_mut();
    db.begin_swap_discovery_attempt(account, key, NOW).unwrap();
    db.finish_sweep(account, key, removed).unwrap();
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
    db.maintain_swap_receive_lookahead(account, window as u32, through.height)
        .unwrap();
    for i in 0..window {
        db.finish_sweep(account, KeyId::new(Purpose::Receive, i), through)
            .unwrap();
    }
    let issued = db
        .prepare_swap_receive_reservation_from(account, NOW, through.height + 1)
        .unwrap();
    assert_eq!(issued.key.key_id().index(), 0);
    db.maintain_swap_receive_lookahead(account, window as u32, through.height)
        .unwrap();
    assert!(due(&mut st, through, NOW).is_empty());
    let resumed = st
        .wallet_mut()
        .db_mut()
        .prepare_swap_receive_reservation_from(account, NOW, through.height + 1)
        .unwrap();
    assert_eq!(resumed.id, issued.id);
}

#[test]
fn payout_during_the_watch_extends_the_lookahead() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    db.maintain_swap_receive_lookahead(account, 3, through.height)
        .unwrap();
    for i in 0..3 {
        db.finish_sweep(account, KeyId::new(Purpose::Receive, i), through)
            .unwrap();
    }
    let edge = KeyId::new(Purpose::Receive, 2);
    let fvk = db
        .get_swap_receiving_keys(account)
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
    st.scan_cached_blocks(paid, 1);
    assert_eq!(unspent_keys(&st, paid), [Some(edge)]);
    let through = tip(&st);
    st.wallet_mut()
        .db_mut()
        .maintain_swap_receive_lookahead(account, 3, through.height)
        .unwrap();
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
            db.retain_swap_spend_history(account).unwrap();
        }
        let fvk = db
            .watch_swap_receive_key(account, 8, from)
            .unwrap()
            .full_viewing_key()
            .clone();
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
        st.scan_cached_blocks(first, 201);
        let through = tip(&st);
        let status = st
            .wallet_mut()
            .db_mut()
            .swap_payment_spend_status(account, key, &candidate, through)
            .unwrap();
        match (retained, spent) {
            (true, true) => {
                assert!(matches!(status, SpendStatus::Spent(_)))
            }
            (true, false) => assert_eq!(status, SpendStatus::Unspent),
            // Without retention, ordinary pruning leaves no evidence of the spend.
            (false, _) => assert_eq!(status, SpendStatus::Unknown),
        }
    }
}

#[test]
fn recheck_sweeps_closed_keys_and_finds_a_later_refund() {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let tip_height = tip(&st).height;
    let db = st.wallet_mut().db_mut();
    let key = db
        .reserve_swap_receiving_key_from(account, Purpose::Refund, tip_height + 1)
        .unwrap()
        .key_id();
    let finished = OperationStatus::Terminal(ReceiptExpectation::None);
    db.observe_swap_operation(account, key, "swap", finished, NOW)
        .unwrap();
    assert_eq!(
        db.close_finished_swap_keys_at(account, NOW, tip_height)
            .unwrap(),
        1
    );
    // A second refund arrives after the key closed, so scanning misses it.
    let candidate = pay_candidate(&mut st, key);
    let through = tip(&st);
    assert!(unspent_keys(&st, through.height).is_empty());
    let db = st.wallet_mut().db_mut();
    assert_eq!(db.recheck_swap_history(account).unwrap(), 1);
    assert_eq!(due(&mut st, through, NOW), [key]);
    let db = st.wallet_mut().db_mut();
    db.queue_swap_lookup(account, key, through, std::slice::from_ref(&candidate))
        .unwrap();
    assert_eq!(
        db.apply_pending_swap_payment(
            account,
            key,
            &candidate,
            through,
            (through, &first_leaf_path())
        )
        .unwrap(),
        PaymentApplication::Applied
    );
    db.apply_swap_sweep(account, key, through, through, WATCHED, |_, _| None)
        .unwrap();
    assert_eq!(unspent_keys(&st, through.height), [Some(key)]);
    // The finished sweep reopens the key until it closes again, so no key is left to
    // recheck.
    assert_eq!(scanning_keys(&st), [key]);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .recheck_swap_history(account)
            .unwrap(),
        0
    );
}
