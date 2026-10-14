//! Receipt lifecycle tests using the real migrated schema, independent of a network service.
use super::*;
use crate::{
    WalletDb,
    testing::db::{test_clock, test_rng},
    wallet::init::WalletMigrator,
};
use zcash_client_backend::data_api::{
    TransactionStatus,
    status::{TransactionStatusMode, TransactionStatusWork},
    transparent_ledger::TransparentLedgerMode,
};
use zcash_protocol::consensus::Network;

fn database(
    path: &std::path::Path,
) -> WalletDb<
    rusqlite::Connection,
    Network,
    crate::util::testing::FixedClock,
    zcash_client_backend::data_api::testing::TestRng,
> {
    let mut db = WalletDb::for_path(path, Network::TestNetwork, test_clock(), test_rng()).unwrap();
    WalletMigrator::new().init_or_migrate(&mut db).unwrap();
    db
}
fn seed(conn: &Connection) -> TxId {
    let txid = TxId::from_bytes([9; 32]);
    conn.execute(
        "INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (100, ?1, 0, X'00')",
        [[7u8; 32]],
    )
    .unwrap();
    conn.execute("INSERT INTO transactions (txid, block, mined_height, tx_index, min_observed_height, expiry_height) VALUES (?1, 100, 100, 3, 100, 103)", [txid.as_ref()]).unwrap();
    conn.execute_batch(
        "INSERT INTO scan_queue (block_range_start, block_range_end, priority) VALUES (1, 501, 10)",
    )
    .unwrap();
    txid
}
fn rewind(conn: &mut Connection) {
    let tx = conn.transaction().unwrap();
    super::super::queue_status_for_unobservable_transactions(&tx, Some(BlockHeight::from_u32(99)))
        .unwrap();
    capture_before_rewind(&tx, BlockHeight::from_u32(99), BlockHeight::from_u32(99)).unwrap();
    tx.execute_batch("UPDATE transactions SET block = NULL, mined_height = NULL, tx_index = NULL; DELETE FROM blocks WHERE height = 100;").unwrap();
    tx.commit().unwrap();
}
fn accept(conn: &mut Connection, hash: [u8; 32]) {
    let tx = conn.transaction().unwrap();
    tx.execute("INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (100, ?1, 0, X'00') ON CONFLICT (height) DO UPDATE SET hash=excluded.hash", [hash]).unwrap();
    reconcile_scanned_blocks(
        &tx,
        &Network::TestNetwork,
        #[cfg(feature = "transparent-inputs")]
        &GapLimits::default(),
        &[(BlockHeight::from_u32(100), BlockHash(hash))],
    )
    .unwrap();
    tx.commit().unwrap();
}
fn receipts(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM tx_reconfirmation_receipts", [], |r| {
        r.get(0)
    })
    .unwrap()
}
fn work(conn: &Connection) -> Vec<TransactionStatusWork> {
    super::super::transaction_status_work(
        conn,
        TransactionStatusMode::Public,
        Some(TransparentLedgerMode::Public),
    )
    .unwrap()
}
fn observed(conn: &mut Connection, txid: TxId, status: TransactionStatus) {
    let tx = conn.transaction().unwrap();
    super::super::set_transaction_status(
        &tx,
        &Network::TestNetwork,
        #[cfg(feature = "transparent-inputs")]
        &GapLimits::default(),
        txid,
        status,
    )
    .unwrap();
    tx.commit().unwrap();
}

#[test]
fn receipt_survives_reopen_and_restores_index_without_network_or_payload_completion() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    let txid = seed(&db.conn);
    db.conn
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (?1, 1)",
            [txid.as_ref()],
        )
        .unwrap();
    rewind(&mut db.conn);
    assert!(work(&db.conn).is_empty());
    drop(db);
    let mut db = database(file.path());
    assert_eq!(receipts(&db.conn), 1);
    // Neither a high contiguous scan frontier nor an empty batch is inclusion evidence.
    let tx = db.conn.transaction().unwrap();
    reconcile_scanned_blocks(
        &tx,
        &Network::TestNetwork,
        #[cfg(feature = "transparent-inputs")]
        &GapLimits::default(),
        &[],
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(work(&db.conn).is_empty());
    accept(&mut db.conn, [7; 32]);
    assert_eq!(receipts(&db.conn), 0);
    let state: (u32, u32, u16, u32, Option<u32>) = db.conn.query_row(
        "SELECT mined_height, block, tx_index, min_observed_height, confirmed_unmined_at_height FROM transactions", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap();
    assert_eq!(state, (100, 100, 3, 100, None));
    assert!(work(&db.conn).is_empty());
    assert_eq!(
        db.conn
            .query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = 1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        db.conn
            .query_row(
                "SELECT reconfirm_mined FROM tx_retrieval_queue WHERE query_type = 0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn changed_block_exposes_private_fallback_without_manufacturing_inclusion_bounds() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    let txid = seed(&db.conn);
    rewind(&mut db.conn);
    accept(&mut db.conn, [8; 32]);
    crate::wallet::transparent_ledger::apply_transparent_policy(
        &db.conn,
        Some(TransparentLedgerMode::Public),
        TransparentLedgerMode::PrivateRequired,
    )
    .unwrap();
    let pending = super::super::transaction_status_work(
        &db.conn,
        TransactionStatusMode::Public,
        Some(TransparentLedgerMode::PrivateRequired),
    )
    .unwrap();
    assert!(
        matches!(pending.as_slice(), [TransactionStatusWork::Private(r)] if r.txid() == txid && r.earliest_possible_inclusion().is_none())
    );
    // Errors (including incomplete coverage) do not invoke the completed-observation write.
    drop(db);
    let mut db = database(file.path());
    assert_eq!(receipts(&db.conn), 1);
    assert_eq!(
        db.conn
            .query_row("SELECT reconfirm_mined FROM tx_retrieval_queue", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert!(
        super::super::transaction_status_work(
            &db.conn,
            TransactionStatusMode::Public,
            Some(TransparentLedgerMode::PrivateRequired)
        )
        .unwrap()
        .iter()
        .all(|r| matches!(r, TransactionStatusWork::Private(_)))
    );
    observed(
        &mut db.conn,
        txid,
        TransactionStatus::Mined(BlockHeight::from_u32(101)),
    );
    assert_eq!(receipts(&db.conn), 0);
    assert_eq!(
        db.conn
            .query_row("SELECT mined_height FROM transactions", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        101
    );
}

#[test]
fn completed_negative_supersedes_receipt_and_terminal_obligation() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    let txid = seed(&db.conn);
    rewind(&mut db.conn);
    accept(&mut db.conn, [8; 32]);
    assert_eq!(work(&db.conn).len(), 1);
    observed(&mut db.conn, txid, TransactionStatus::TxidNotRecognized);
    assert_eq!(receipts(&db.conn), 0);
    assert!(work(&db.conn).is_empty());
    accept(&mut db.conn, [7; 32]);
    assert!(
        db.conn
            .query_row("SELECT mined_height IS NULL FROM transactions", [], |r| {
                r.get::<_, bool>(0)
            })
            .unwrap()
    );
}

#[test]
fn missing_block_hash_uses_status_fallback_and_schema_rejects_fabricated_receipts() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    seed(&db.conn);
    db.conn
        .execute_batch("UPDATE transactions SET block = NULL; DELETE FROM blocks")
        .unwrap();
    rewind(&mut db.conn);
    assert_eq!(receipts(&db.conn), 0);
    assert_eq!(work(&db.conn).len(), 1); // remains active despite expiry + reorg depth
    for (height, hash, index) in [
        (100i64, vec![0u8; 31], Some(3i64)),
        (-1, vec![0; 32], None),
        (4294967296, vec![0; 32], None),
        (100, vec![0; 32], Some(65536)),
    ] {
        assert!(db.conn.execute("INSERT INTO tx_reconfirmation_receipts (transaction_id, mined_height, block_hash, tx_index) SELECT id_tx, ?1, ?2, ?3 FROM transactions", rusqlite::params![height,hash,index]).is_err());
    }
}

#[test]
fn repeated_rewind_revalidates_changed_receipt_and_newer_mined_state_wins() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    let txid = seed(&db.conn);
    rewind(&mut db.conn);
    accept(&mut db.conn, [8; 32]);
    assert_eq!(work(&db.conn).len(), 1);
    rewind(&mut db.conn);
    assert!(work(&db.conn).is_empty());
    accept(&mut db.conn, [7; 32]);
    assert_eq!(
        db.conn
            .query_row("SELECT mined_height FROM transactions", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        100
    );
    rewind(&mut db.conn);
    // Model a newer authoritative ingestion before the old receipt's height is scanned.
    db.conn
        .execute_batch("UPDATE transactions SET mined_height = 101, min_observed_height = 100")
        .unwrap();
    accept(&mut db.conn, [7; 32]);
    assert_eq!(receipts(&db.conn), 0);
    assert_eq!(
        db.conn
            .query_row(
                "SELECT mined_height FROM transactions WHERE txid=?1",
                [txid.as_ref()],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
        101
    );
}

#[test]
fn capture_and_reconciliation_failure_roll_back_receipts_metadata_and_flags() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    seed(&db.conn);
    db.conn.execute_batch("CREATE TRIGGER reject_receipt BEFORE INSERT ON tx_reconfirmation_receipts BEGIN SELECT RAISE(ABORT, 'receipt failure'); END").unwrap();
    {
        let tx = db.conn.transaction().unwrap();
        super::super::queue_status_for_unobservable_transactions(
            &tx,
            Some(BlockHeight::from_u32(99)),
        )
        .unwrap();
        assert!(
            capture_before_rewind(&tx, BlockHeight::from_u32(99), BlockHeight::from_u32(99))
                .is_err()
        );
    }
    assert_eq!(
        db.conn
            .query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.conn
        .execute_batch("DROP TRIGGER reject_receipt")
        .unwrap();
    rewind(&mut db.conn);
    db.conn.execute_batch("CREATE TRIGGER reject_resolution BEFORE DELETE ON tx_reconfirmation_receipts BEGIN SELECT RAISE(ABORT, 'resolution failure'); END").unwrap();
    {
        let tx = db.conn.transaction().unwrap();
        tx.execute(
            "INSERT INTO blocks (height,hash,time,sapling_tree) VALUES (100,?1,0,X'00')",
            [[7u8; 32]],
        )
        .unwrap();
        assert!(
            reconcile_scanned_blocks(
                &tx,
                &Network::TestNetwork,
                #[cfg(feature = "transparent-inputs")]
                &GapLimits::default(),
                &[(BlockHeight::from_u32(100), BlockHash([7; 32]))]
            )
            .is_err()
        );
    }
    assert_eq!(receipts(&db.conn), 1);
    assert!(
        db.conn
            .query_row("SELECT mined_height IS NULL FROM transactions", [], |r| {
                r.get::<_, bool>(0)
            })
            .unwrap()
    );
    assert_eq!(
        db.conn
            .query_row("SELECT reconfirm_mined FROM tx_retrieval_queue", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    assert_eq!(
        db.conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn receipts_cascade_with_transaction_deletion() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut db = database(file.path());
    seed(&db.conn);
    rewind(&mut db.conn);
    assert_eq!(receipts(&db.conn), 1);
    db.conn.execute_batch("DELETE FROM transactions").unwrap();
    assert_eq!(receipts(&db.conn), 0);
}

#[test]
fn six_wallet_shielded_associations_are_excluded_from_capture_and_queue() {
    // Isolate the eligibility predicate, including pools disabled in this build. Foreign-key
    // note construction is covered by existing real-wallet shielded scan fixtures.
    for table in [
        "sapling_received_notes",
        "sapling_received_note_spends",
        "orchard_received_notes",
        "orchard_received_note_spends",
        "ironwood_received_notes",
        "ironwood_received_note_spends",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE transactions(id_tx INTEGER PRIMARY KEY, txid BLOB, mined_height INTEGER, tx_index INTEGER); CREATE TABLE blocks(height INTEGER, hash BLOB); CREATE TABLE tpir_meta(id INTEGER, applied_mode INTEGER, policy_generation INTEGER, min_reader_version INTEGER); INSERT INTO tpir_meta VALUES(0,0,0,1); CREATE TABLE tx_retrieval_queue(txid BLOB, query_type INTEGER, policy_generation INTEGER, reconfirm_mined INTEGER, UNIQUE(txid,query_type));").unwrap();
        for pool in ["sapling", "orchard", "ironwood"] {
            for suffix in ["received_notes", "received_note_spends"] {
                conn.execute_batch(&format!(
                    "CREATE TABLE {pool}_{suffix}(transaction_id INTEGER)"
                ))
                .unwrap();
            }
        }
        conn.execute_batch(RECEIPT_SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO transactions VALUES(1, ?1, 100, 3)",
            [[9u8; 32]],
        )
        .unwrap();
        conn.execute("INSERT INTO blocks VALUES(100, ?1)", [[7u8; 32]])
            .unwrap();
        conn.execute_batch(&format!("INSERT INTO {table} VALUES(1)"))
            .unwrap();
        let tx = conn.transaction().unwrap();
        capture_before_rewind(&tx, BlockHeight::from_u32(99), BlockHeight::from_u32(99)).unwrap();
        super::super::queue_status_for_unobservable_transactions(
            &tx,
            Some(BlockHeight::from_u32(99)),
        )
        .unwrap();
        assert_eq!(receipts(&tx), 0, "{table}");
        assert_eq!(
            tx.query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "{table}"
        );
    }
}
