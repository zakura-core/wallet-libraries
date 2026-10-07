use super::apply::fixture;
use super::*;
use zakura_swap_receiving::lifecycle::OperationStatus;

/// Completes the restore sweep of every key registered to `account` at `through`.
fn finish_sweeps<CL: Clock, R>(
    db: &mut WalletDb<Connection, LocalNetwork, CL, R>,
    account: AccountUuid,
    through: ChainPoint,
) {
    for key in db.get_swap_receiving_keys(account).unwrap() {
        db.finish_sweep(account, key.key_id(), through).unwrap();
    }
}

/// [`fixture`] retaining spend history, with its payment applied and the sweeps
/// finished at its tip, including those of the lookahead the import extends.
/// Release waits for the queued payment and then for that lookahead.
fn swept() -> (State, RegisteredKey, ChainPoint) {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.retain_swap_spend_history(account).unwrap();
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    assert_eq!(
        db.apply_pending_swap_payment(account, key.key_id(), &candidate, through, (through, &path))
            .unwrap(),
        PaymentApplication::Applied
    );
    // Import advances allocation. Finishing must create and wait for the new window.
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    finish_sweeps(db, account, through);
    (st, key, through)
}

#[test]
fn retention_completion_waits_for_candidates_and_extended_lookahead() {
    let (mut st, key, through) = swept();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    // A provider outcome still pending does not hold covered history.
    db.observe_swap_operation(
        account,
        key.key_id(),
        "restored",
        OperationStatus::Active,
        1000,
    )
    .unwrap();
    assert!(
        db.finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap(),
        Some(through.height + 1)
    );
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap(),
        Some(through.height + 1)
    );
    let wrong = ChainPoint {
        hash: BlockHash([99; 32]),
        ..through
    };
    assert!(
        !st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, wrong, 1)
            .unwrap()
    );
}

#[test]
fn undone_sweeps_and_queued_candidates_hold_spend_evidence() {
    let (mut st, key, candidate, original, path) = fixture();
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .retain_swap_spend_history(account)
        .unwrap();
    for _ in 0..2 {
        let (height, _) = st.generate_empty_block();
        st.scan_cached_blocks(height, 1);
    }
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    db.finish_sweep(account, KeyId::new(Purpose::Receive, 0), tip)
        .unwrap();
    // The candidate predates its key's own sweep start.
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(&db.conn).unwrap(),
        Some(candidate.height)
    );
    db.apply_pending_swap_payment(account, key.key_id(), &candidate, tip, (original, &path))
        .unwrap();
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    db.finish_sweep(account, KeyId::new(Purpose::Receive, 9), tip)
        .unwrap();
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(&db.conn).unwrap(),
        Some(db.swap_key_state(account, key.key_id()).0)
    );
    db.finish_sweep(account, key.key_id(), tip).unwrap();
    assert!(
        db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
}

#[test]
fn scanned_keys_never_hold_spend_evidence() {
    let (mut st, _, through) = swept();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let refund = db
        .recover_swap_receiving_key(account, KeyId::new(Purpose::Refund, 0), through.height)
        .unwrap();
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    // A completed refund sweep scans its key from the next block.
    db.finish_sweep(account, refund.key_id(), through).unwrap();
    let (height, _) = st.generate_empty_block();
    st.scan_cached_blocks(height, 1);
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    let scanning = db.get_swap_scanning_keys().unwrap();
    assert!(scanning.iter().any(|k| k.key_id() == refund.key_id()));
    assert!(
        db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(&db.conn).unwrap(),
        Some(height + 1)
    );
}

#[test]
fn retention_prunes_other_pools_and_respects_the_oldest_account() {
    use zcash_protocol::PoolType;
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .retain_swap_spend_history(account)
        .unwrap();
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let (other, _) = st
        .wallet_mut()
        .db_mut()
        .create_account("other", &seed, &birthday, None)
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .retain_swap_spend_history(other)
        .unwrap();
    let conn = st.wallet_mut().conn_mut();
    // Use small synthetic heights to isolate shared pruning from network activation.
    conn.execute(
        "UPDATE ironwood_swap_spend_retention SET nullifier_retention_height=0",
        [],
    )
    .unwrap();
    conn.execute("UPDATE ironwood_swap_spend_retention SET nullifier_retention_height=200 WHERE account_id=(SELECT id FROM accounts WHERE uuid=?1)", [account.0]).unwrap();
    for (pool, nf) in [
        (PoolType::SAPLING, 1u8),
        (PoolType::ORCHARD, 2),
        (PoolType::IRONWOOD, 3),
    ] {
        conn.execute(
            "INSERT OR IGNORE INTO tx_locator_map VALUES(100,0,?1)",
            [[9u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nullifier_map VALUES(?1,?2,100,0)",
            rusqlite::params![crate::wallet::encoding::pool_code(pool), [nf; 32]],
        )
        .unwrap();
    }
    conn.execute("INSERT INTO ironwood_nullifier_scan_blocks VALUES(100)", [])
        .unwrap();
    let tx = conn.transaction().unwrap();
    crate::wallet::prune_nullifier_map(&tx, 300.into()).unwrap();
    assert_eq!(
        tx.query_row("SELECT COUNT(*) FROM nullifier_map", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        tx.query_row("SELECT COUNT(*) FROM tx_locator_map", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        1
    );
    tx.commit().unwrap();
    conn.execute(
        "UPDATE ironwood_swap_spend_retention SET nullifier_retention_height=250",
        [],
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    crate::wallet::prune_nullifier_map(&tx, 300.into()).unwrap();
    for table in [
        "nullifier_map",
        "tx_locator_map",
        "ironwood_nullifier_scan_blocks",
    ] {
        assert_eq!(
            tx.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
    tx.commit().unwrap();
}

#[test]
fn missing_spend_history_queues_replay_and_recovers_after_restart() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    st.wallet_mut()
        .db_mut()
        .retain_swap_spend_history(account)
        .unwrap();
    st.wallet()
        .conn()
        .execute("DELETE FROM ironwood_nullifier_scan_blocks", [])
        .unwrap();
    st.wallet()
        .conn()
        .execute(
            "UPDATE ironwood_swap_spend_retention SET nullifier_retention_height=?1",
            [u32::from(through.height + 1)],
        )
        .unwrap();
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_pending_swap_payment(
                account,
                key.key_id(),
                &candidate,
                through,
                (through, &path)
            )
            .unwrap(),
        PaymentApplication::AwaitingSpendHistory
    );
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    *st.wallet_mut().db_mut() = reopened;
    let ranges = st.wallet().db().suggest_scan_ranges().unwrap();
    assert!(
        ranges
            .iter()
            .any(|r| r.block_range().contains(&candidate.height))
    );
    assert!(
        st.wallet()
            .db()
            .get_unspent_ironwood_notes_at_historical_height(account, through.height)
            .unwrap()
            .is_empty()
    );
    st.scan_cached_blocks(candidate.height, 1);
    assert_eq!(
        st.wallet_mut()
            .db_mut()
            .apply_pending_swap_payment(
                account,
                key.key_id(),
                &candidate,
                through,
                (through, &path)
            )
            .unwrap(),
        PaymentApplication::Applied
    );
}

#[test]
fn retention_waits_for_internal_memos_until_their_blocks_are_scanned() {
    let (mut st, _, through) = swept();
    let account = st.test_account().unwrap().id();
    // Model a normal internal note whose memo enhancement has not finished.
    st.wallet().conn().execute("UPDATE ironwood_received_notes SET receiving_key_id=NULL,recipient_key_scope=1,memo=NULL", []).unwrap();
    assert!(
        !st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap(),
        Some(through.height)
    );
    // A marker without funding-account evidence, once scanning from the birthday covers
    // its block, was funded before the birthday or is not this wallet's. It no longer
    // holds back the release.
    let move_memo = |st: &State, height: BlockHeight, block: Option<u32>| {
        st.wallet()
            .conn()
            .execute(
                "UPDATE transactions SET mined_height = ?1, block = ?2 WHERE id_tx IN
                 (SELECT transaction_id FROM ironwood_received_notes)",
                rusqlite::params![u32::from(height), block],
            )
            .unwrap();
    };
    st.wallet()
        .conn()
        .execute("UPDATE ironwood_received_notes SET memo=X'FF5A535750'", [])
        .unwrap();
    let mined: u32 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT t.mined_height FROM transactions t
             JOIN ironwood_received_notes n ON n.transaction_id = t.id_tx",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // One that enhancement found above the scanned height still holds it back.
    move_memo(&st, through.height + 1, None);
    assert!(
        !st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    move_memo(&st, mined.into(), Some(mined));
    assert!(
        st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
}

#[test]
fn retention_rewinds_and_resumes_for_new_blocks() {
    let (mut st, _, original) = swept();
    let account = st.test_account().unwrap().id();
    assert!(
        st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, original, 1)
            .unwrap()
    );
    let (height, _) = st.generate_empty_block();
    st.scan_cached_blocks(height, 1);
    let tip = tip(&st);
    finish_sweeps(st.wallet_mut().db_mut(), account, tip);
    assert!(
        st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap(),
        Some(height + 1)
    );
    st.truncate_to_height_retaining_cache(original.height);
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap(),
        Some(original.height + 1)
    );
    st.scan_cached_blocks(height, 1);
    assert_eq!(
        st.wallet()
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height=?1",
                [u32::from(height)],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
        1
    );
    // The rewind removed the sweeps' completion, so they hold evidence until rerun.
    let db = st.wallet_mut().db_mut();
    assert!(
        !db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
    finish_sweeps(db, account, tip);
    assert!(
        db.finish_swap_nullifier_recovery_with(account, tip, 1)
            .unwrap()
    );
}

#[test]
fn completed_recovery_retains_the_next_large_batch_until_reconciled() {
    let (mut st, _, original) = swept();
    let account = st.test_account().unwrap().id();
    assert!(
        st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, original, 1)
            .unwrap()
    );
    for _ in 0..201 {
        st.generate_empty_block();
    }
    st.scan_cached_blocks(original.height + 1, 201);
    let through = tip(&st);
    let count = |conn: &Connection| {
        conn.query_row(
            "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height>?1",
            [u32::from(original.height)],
            |r| r.get::<_, u32>(0),
        )
        .unwrap()
    };
    assert_eq!(count(st.wallet().conn()), 201);
    assert!(
        st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, through, 1)
            .unwrap()
    );
    assert_eq!(count(st.wallet().conn()), crate::PRUNING_DEPTH + 1);
    assert_eq!(
        st.wallet()
            .db()
            .get_unspent_ironwood_notes_at_historical_height(account, through.height)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn completion_does_not_enable_discovery_for_an_unregistered_account() {
    let (mut st, _, _, through, _) = fixture();
    let account = st.test_account().unwrap().id();
    let before = st
        .wallet()
        .db()
        .get_swap_receiving_keys(account)
        .unwrap()
        .len();
    assert!(
        !st.wallet_mut()
            .db_mut()
            .finish_swap_nullifier_recovery_with(account, through, 50)
            .unwrap()
    );
    assert_eq!(
        st.wallet()
            .db()
            .get_swap_receiving_keys(account)
            .unwrap()
            .len(),
        before
    );
    assert_eq!(
        crate::wallet::ironwood_nullifier_retention_height(st.wallet().conn()).unwrap(),
        None
    );
}

#[test]
fn repeated_missing_history_does_not_restart_the_public_replay() {
    let (mut st, _, _, through, _) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.transactionally::<_, _, Error>(|tx| tx.queue_swap_spend_history(account, through.height))
        .unwrap();
    db.conn.borrow().execute_batch("CREATE TEMP TABLE replay_queue_writes(n INTEGER); INSERT INTO replay_queue_writes VALUES(0);
        CREATE TEMP TRIGGER replay_insert AFTER INSERT ON scan_queue BEGIN UPDATE replay_queue_writes SET n=n+1; END;
        CREATE TEMP TRIGGER replay_delete AFTER DELETE ON scan_queue BEGIN UPDATE replay_queue_writes SET n=n+1; END;
        CREATE TEMP TRIGGER replay_update AFTER UPDATE ON scan_queue BEGIN UPDATE replay_queue_writes SET n=n+1; END;").unwrap();
    db.transactionally::<_, _, Error>(|tx| tx.queue_swap_spend_history(account, through.height))
        .unwrap();
    assert_eq!(
        db.conn
            .borrow()
            .query_row("SELECT n FROM replay_queue_writes", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
}

#[test]
fn note_before_the_birthday_is_dropped_without_queuing_replay() {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let (owner, _) = account_key(db.conn.borrow(), &db.params, account).unwrap();
    db.conn
        .borrow()
        .execute(
            "UPDATE accounts SET birthday_height=?2 WHERE id=?1",
            rusqlite::params![owner.0, u32::from(candidate.height) + 1],
        )
        .unwrap();
    assert_eq!(
        db.apply_pending_swap_payment(account, key.key_id(), &candidate, through, (through, &path))
            .unwrap(),
        PaymentApplication::BeforeBirthday
    );
    assert!(
        db.pending_swap_payments(account, key.key_id())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.conn
            .borrow()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_swap_spend_retention
                 WHERE replay_through IS NOT NULL",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
        0
    );
}
