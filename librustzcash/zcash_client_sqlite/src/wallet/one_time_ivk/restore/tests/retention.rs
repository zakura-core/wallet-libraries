use super::apply::{fixture, fixture_in};
use super::*;
use rusqlite::params;
use zakura_one_time_ivk::swap::OperationStatus;

/// Releases `account`'s retained nullifiers at `through`.
fn finish(db: &mut Db, account: AccountUuid, through: ChainPoint) -> bool {
    finish_recovery(db, account, through).unwrap()
}

/// The wallet's Ironwood nullifier retention height.
fn retained_from(db: &Db) -> Option<BlockHeight> {
    crate::wallet::ironwood_nullifier_retention_height(&db.conn).unwrap()
}

/// Completes the restore sweep of every key registered to `account` at `through`.
fn finish_sweeps(db: &mut Db, account: AccountUuid, through: ChainPoint) {
    finish_sweeps_except(db, account, None, through);
}

/// [`finish_sweeps`], leaving `except`'s sweep alone.
fn finish_sweeps_except(
    db: &mut Db,
    account: AccountUuid,
    except: Option<KeyId>,
    through: ChainPoint,
) {
    for key in all_keys(db, account).unwrap() {
        if Some(key.key_id()) != except {
            finish_sweep(db, account, key.key_id(), through);
        }
    }
}

/// Adds a second account from the test seed.
fn other_account<C>(st: &mut TestState<C, TestDb, LocalNetwork>) -> AccountUuid {
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let db = st.wallet_mut().db_mut();
    db.create_account("other", &seed, &birthday, None)
        .unwrap()
        .0
}

/// [`fixture`] retaining spend history, with its payment applied and the sweeps
/// finished at its tip, including those of the lookahead the import extends.
/// Release waits for the queued payment and then for that lookahead.
fn swept() -> (State, OneTimeKey, ChainPoint) {
    let (mut st, key, candidate, through, path) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    retain(db, account);
    assert!(!finish(db, account, through));
    let applied = apply(db, account, key.key_id(), &candidate, through, &path);
    assert_eq!(applied, PaymentApplication::Applied);
    // Import advances allocation. Finishing must create and wait for the new window.
    assert!(!finish(db, account, through));
    finish_sweeps(db, account, through);
    (st, key, through)
}

/// Whether the wallet suggests scanning `height`.
fn suggests_scanning(st: &State, height: BlockHeight) -> bool {
    let ranges = st.wallet().db().suggest_scan_ranges().unwrap();
    ranges.iter().any(|r| r.block_range().contains(&height))
}

/// Completion ignores a pending provider outcome and releases above its chain point, which
/// survives a reopen and must be canonical. Later completions retain the next large batch
/// only to the pruning depth, keeping the restored note.
#[test]
fn completed_recovery_survives_reopen_and_retains_the_next_large_batch() {
    let (mut st, key, original) = swept();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let active = OperationStatus::Active;
    observe(db, account, key.key_id(), "restored", active, 1000).unwrap();
    assert!(finish(db, account, original));
    assert_eq!(retained_from(db), Some(original.height + 1));
    reopen(&mut st);
    let db = st.wallet_mut().db_mut();
    assert_eq!(retained_from(db), Some(original.height + 1));
    let wrong = ChainPoint {
        hash: BlockHash([99; 32]),
        ..original
    };
    assert!(!finish(db, account, wrong));
    for _ in 0..201 {
        st.generate_empty_block();
    }
    st.scan_cached_blocks_with_one_time_ivks(original.height + 1, 201);
    let through = tip(&st);
    let sql = "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height > ?1";
    let above = |db: &Db| value::<u32>(&db.conn, sql, [u32::from(original.height)]);
    let db = st.wallet_mut().db_mut();
    assert_eq!(above(db), 201);
    assert!(finish(db, account, through));
    assert_eq!(above(db), crate::PRUNING_DEPTH + 1);
    assert_eq!(notes(&st, through.height).len(), 1);
}

/// Unfinished sweeps and queued candidates hold spend evidence: from the candidate's
/// height while it predates its key's sweep start, then from that start until the key's
/// sweep finishes.
#[test]
fn undone_sweeps_and_queued_candidates_hold_spend_evidence() {
    let (mut st, key, candidate, original, path) = fixture();
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    let paid = Some(key.key_id());
    assert!(!finish(db, account, tip));
    finish_sweeps_except(db, account, paid, tip);
    assert!(!finish(db, account, tip));
    assert_eq!(retained_from(db), Some(candidate.height));
    let anchored = (original, &path);
    apply_payment(db, account, key.key_id(), &candidate, tip, anchored).unwrap();
    // The payment extends the lookahead above its key.
    assert!(!finish(db, account, tip));
    finish_sweeps_except(db, account, paid, tip);
    assert!(!finish(db, account, tip));
    assert_eq!(retained_from(db), Some(key_state(db, key.key_id()).0));
    finish_sweep(db, account, key.key_id(), tip);
    assert!(finish(db, account, tip));
}

/// A recovered refund key holds spend evidence until its sweep finishes; once the key
/// scans, it never does.
#[test]
fn scanned_keys_never_hold_spend_evidence() {
    let (mut st, _, through) = swept();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let refund = KeyId::new(Purpose::Refund, 0);
    recover(db, account, refund, through.height);
    assert!(!finish(db, account, through));
    // A completed refund sweep scans its key from the next block.
    finish_sweep(db, account, refund, through);
    let height = st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    assert!(scanning_keys(&st).contains(&refund));
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    assert!(finish(db, account, tip));
    assert_eq!(retained_from(db), Some(height + 1));
}

/// Pruning the nullifier map drops other pools' entries but keeps Ironwood entries the
/// oldest account's retention still needs, until every account's retention passes them.
#[test]
fn retention_prunes_other_pools_and_respects_the_oldest_account() {
    use zcash_protocol::PoolType;
    let mut st = wallet(false);
    let account = st.test_account().unwrap().id();
    retain(st.wallet_mut().db_mut(), account);
    let other = other_account(&mut st);
    retain(st.wallet_mut().db_mut(), other);
    let conn = st.wallet_mut().conn_mut();
    // Use small synthetic heights to isolate shared pruning from network activation.
    let set = "UPDATE ironwood_one_time_spend_retention SET nullifier_retention_height = ?1";
    exec(conn, set, [0]);
    let mine = format!("{set} WHERE account_id = (SELECT id FROM accounts WHERE uuid = ?2)");
    exec(conn, &mine, params![200, account.0]);
    exec(
        conn,
        "INSERT INTO tx_locator_map VALUES (100, 0, ?1)",
        [[9u8; 32]],
    );
    let pools = [PoolType::SAPLING, PoolType::ORCHARD, PoolType::IRONWOOD];
    for (pool, nf) in pools.into_iter().zip(1u8..) {
        let pool = crate::wallet::encoding::pool_code(pool);
        let sql = "INSERT INTO nullifier_map VALUES (?1, ?2, 100, 0)";
        exec(conn, sql, params![pool, [nf; 32]]);
    }
    exec(
        conn,
        "INSERT INTO ironwood_nullifier_scan_blocks VALUES (100)",
        [],
    );
    let tables = [
        "nullifier_map",
        "tx_locator_map",
        "ironwood_nullifier_scan_blocks",
    ];
    let prune = |conn: &mut Connection| {
        let tx = conn.transaction().unwrap();
        crate::wallet::prune_nullifier_map(&tx, 300.into()).unwrap();
        tx.commit().unwrap();
        tables.map(|t| value::<u32>(conn, &format!("SELECT COUNT(*) FROM {t}"), []))
    };
    assert_eq!(prune(conn)[..2], [1, 1]);
    exec(conn, set, [250]);
    assert_eq!(prune(conn), [0, 0, 0]);
}

/// A payment without covering spend history awaits a queued replay, which survives a
/// reopen and lets the payment apply once scanned. Deleting another account discards a
/// completed replay's coverage, so the payment awaits a new replay.
#[test]
fn missing_spend_history_queues_a_replay_that_survives_restart_and_account_deletion() {
    for requeue in [false, true] {
        let mut st = ironwood_wallet();
        let other = other_account(&mut st);
        let (mut st, key, candidate, through, path) = fixture_in(st);
        let account = st.test_account().unwrap().id();
        let db = st.wallet_mut().db_mut();
        retain(db, account);
        exec(&db.conn, "DELETE FROM ironwood_nullifier_scan_blocks", []);
        let sql = "UPDATE ironwood_one_time_spend_retention SET nullifier_retention_height = ?1";
        exec(&db.conn, sql, [u32::from(through.height + 1)]);
        let try_apply = |st: &mut State| {
            let db = st.wallet_mut().db_mut();
            apply(db, account, key.key_id(), &candidate, through, &path)
        };
        let awaiting = PaymentApplication::AwaitingSpendHistory;
        assert_eq!(try_apply(&mut st), awaiting, "{requeue}");
        reopen(&mut st);
        assert!(suggests_scanning(&st, candidate.height), "{requeue}");
        assert!(notes(&st, through.height).is_empty(), "{requeue}");
        if requeue {
            // The replay completes, but the payment stays queued.
            st.scan_cached_blocks_with_one_time_ivks(candidate.height, 1);
            assert!(!suggests_scanning(&st, candidate.height));
            st.wallet_mut().delete_account(other).unwrap();
            assert_eq!(try_apply(&mut st), awaiting);
            assert!(suggests_scanning(&st, candidate.height));
        }
        st.scan_cached_blocks_with_one_time_ivks(candidate.height, 1);
        assert_eq!(try_apply(&mut st), PaymentApplication::Applied, "{requeue}");
    }
}

/// An internal note awaiting memo enhancement holds the release until its block is
/// scanned. A readable marker without funding-account evidence, once scanning from the
/// birthday covers its block, was funded before the birthday or is not this wallet's, so
/// it holds the release only until its key is swept; one that enhancement found above the
/// scanned height still holds it.
#[test]
fn retention_waits_for_internal_memos_until_their_blocks_are_scanned() {
    let (mut st, _, through) = swept();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let internal = "UPDATE ironwood_received_notes
        SET one_time_key_id = NULL, recipient_key_scope = 1, memo = NULL";
    exec(&db.conn, internal, []);
    assert!(!finish(db, account, through));
    assert_eq!(retained_from(db), Some(through.height));
    let memo = zakura_one_time_ivk::swap::RefundMemo::new(7).encode();
    exec(
        &db.conn,
        "UPDATE ironwood_received_notes SET memo = ?1",
        [memo],
    );
    let mined = "SELECT t.mined_height FROM transactions t
        JOIN ironwood_received_notes n ON n.transaction_id = t.id_tx";
    let mined: u32 = value(&db.conn, mined, []);
    let mine_at = "UPDATE transactions SET mined_height = ?1, block = ?2
        WHERE id_tx IN (SELECT transaction_id FROM ironwood_received_notes)";
    let above = u32::from(through.height + 1);
    exec(&db.conn, mine_at, params![above, None::<u32>]);
    assert!(!finish(db, account, through));
    exec(&db.conn, mine_at, params![mined, mined]);
    assert!(!finish(db, account, through));
    finish_sweeps(db, account, through);
    assert!(finish(db, account, through));
}

/// Completion rewinds with the chain, its replay recording rescanned blocks again, and
/// the rewound sweeps hold evidence until they rerun.
#[test]
fn retention_rewinds_and_resumes_for_new_blocks() {
    let (mut st, _, original) = swept();
    let account = st.test_account().unwrap().id();
    assert!(finish(st.wallet_mut().db_mut(), account, original));
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let tip = tip(&st);
    let db = st.wallet_mut().db_mut();
    finish_sweeps(db, account, tip);
    assert!(finish(db, account, tip));
    assert_eq!(retained_from(db), Some(tip.height + 1));
    st.truncate_to_height_retaining_cache(original.height);
    assert_eq!(retained_from(st.wallet().db()), Some(original.height + 1));
    st.scan_cached_blocks_with_one_time_ivks(tip.height, 1);
    let db = st.wallet_mut().db_mut();
    let sql = "SELECT COUNT(*) FROM ironwood_nullifier_scan_blocks WHERE height = ?1";
    assert_eq!(value::<u32>(&db.conn, sql, [u32::from(tip.height)]), 1);
    assert!(!finish(db, account, tip));
    finish_sweeps(db, account, tip);
    assert!(finish(db, account, tip));
}

/// Completion neither registers a lookahead nor sets a release height for an account
/// that never retained spend history.
#[test]
fn completion_does_not_enable_discovery_for_an_unregistered_account() {
    let (mut st, _, _, through, _) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    exec(
        &db.conn,
        "DELETE FROM ironwood_one_time_spend_retention",
        [],
    );
    let before = all_keys(db, account).unwrap().len();
    assert!(!finish_recovery(db, account, through).unwrap());
    assert_eq!(all_keys(db, account).unwrap().len(), before);
    assert_eq!(retained_from(db), None);
}

/// Queuing spend history again while its replay is queued leaves the scan queue alone.
#[test]
fn repeated_missing_history_does_not_restart_the_public_replay() {
    let (mut st, _, candidate, through, _) = fixture();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    let replay = |db: &mut Db| {
        let queue = store::restore::retention::queue_spend_history;
        tx(db, |c, p| {
            queue(c, p, account, candidate.height, through.height)
        })
        .unwrap()
    };
    replay(db);
    let count = "CREATE TEMP TABLE writes(n INTEGER); INSERT INTO writes VALUES (0);
        CREATE TEMP TRIGGER i AFTER INSERT ON scan_queue BEGIN UPDATE writes SET n = n + 1; END;
        CREATE TEMP TRIGGER d AFTER DELETE ON scan_queue BEGIN UPDATE writes SET n = n + 1; END;
        CREATE TEMP TRIGGER u AFTER UPDATE ON scan_queue BEGIN UPDATE writes SET n = n + 1; END;";
    db.conn.execute_batch(count).unwrap();
    replay(db);
    assert_eq!(value::<u32>(&db.conn, "SELECT n FROM writes", []), 0);
}

/// Missing spend history is replayed from the payment's block, not the account's
/// birthday: blocks below the payment stay out of the scan queue, and blocks whose
/// nullifiers are already retained aren't scanned again.
#[test]
fn spend_history_replays_from_the_payment_not_the_birthday() {
    let (mut st, _, candidate, _, _) = fixture();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(6);
    let through = tip(&st);
    let from = candidate.height + 3;
    let db = st.wallet_mut().db_mut();
    let unmark = "DELETE FROM ironwood_nullifier_scan_blocks WHERE height < ?1";
    exec(&db.conn, unmark, [u32::from(from + 2)]);
    // As after a finished restore, which releases retained nullifiers.
    let release = "UPDATE ironwood_one_time_spend_retention SET nullifier_retention_height = ?1";
    exec(&db.conn, release, [u32::from(through.height + 1)]);
    let queue = store::restore::retention::queue_spend_history;
    tx(db, |c, p| queue(c, p, account, from, through.height)).unwrap();
    assert!(suggests_scanning(&st, from));
    assert!(suggests_scanning(&st, from + 1));
    assert!(!suggests_scanning(&st, from - 1));
    assert!(!suggests_scanning(&st, from + 2));
    assert_eq!(retained_from(st.wallet().db()), Some(from));
}

/// A later payment older than a queued replay's start extends the replay down to its own
/// block, so it doesn't wait on a replay that will never cover it.
#[test]
fn an_older_payment_extends_a_queued_replay_downward() {
    let (mut st, _, candidate, _, _) = fixture();
    let account = st.test_account().unwrap().id();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(6);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    exec(&db.conn, "DELETE FROM ironwood_nullifier_scan_blocks", []);
    let queue = store::restore::retention::queue_spend_history;
    let newer = candidate.height + 4;
    tx(db, |c, p| queue(c, p, account, newer, through.height)).unwrap();
    assert!(!suggests_scanning(&st, newer - 1));
    let older = candidate.height + 1;
    let db = st.wallet_mut().db_mut();
    tx(db, |c, p| queue(c, p, account, older, through.height)).unwrap();
    for height in u32::from(older)..=u32::from(through.height) {
        assert!(
            suggests_scanning(&st, BlockHeight::from(height)),
            "{height}"
        );
    }
    assert!(!suggests_scanning(&st, older - 1));
}

/// A payment before the account's birthday is dropped as applied, without queuing a
/// replay of its spend history.
#[test]
fn note_before_the_birthday_is_dropped_without_queuing_replay() {
    let (mut st, key, candidate, _, path) = fixture();
    let account = st.test_account().unwrap().id();
    // The payment must precede the birthday block, which the wallet has scanned.
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    let through = tip(&st);
    let db = st.wallet_mut().db_mut();
    let (owner, _) = account_key(&db.conn, &db.params, account).unwrap();
    let sql = "UPDATE accounts SET birthday_height = ?2 WHERE id = ?1";
    exec(
        &db.conn,
        sql,
        params![owner.0, u32::from(candidate.height) + 1],
    );
    let applied = apply(db, account, key.key_id(), &candidate, through, &path);
    assert_eq!(applied, PaymentApplication::Applied);
    assert!(pending(db, account, key.key_id()).is_empty());
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_spend_retention
        WHERE replay_through IS NOT NULL";
    assert_eq!(value::<u32>(&db.conn, sql, []), 0);
}
