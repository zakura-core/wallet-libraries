//! Adds the `tpir_*` transparent ledger schema and classifies existing transparent records.
//!
//! The migration is seedless and purely additive: it records the durable policy as public and
//! backfills projection origins for every existing transparent output and spend. Existing rows
//! are legacy evidence and never private coverage. Recovery tables (scripts, events, coverage,
//! pending work) are added by the migration that introduces candidate recovery.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::{
    add_transparent_receiver_address_index, add_transparent_value_index,
    drop_zip318_pool_migration, ivk_item_cache, v_tx_outputs_transparent_addresses,
};
use crate::wallet::init::WalletMigrationError;

/// Adds the transparent ledger schema and records legacy provenance.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x8f290af0_eb5a_4f1e_88d4_3550fc0ff911);

// The ledger tables reference `accounts`, `addresses`, `transactions`, and
// `transparent_received_outputs`, whose current shapes are established by earlier migrations.
// Depending on every current leaf keeps this migration last in the DAG.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    drop_zip318_pool_migration::MIGRATION_ID,
    v_tx_outputs_transparent_addresses::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    add_transparent_receiver_address_index::MIGRATION_ID,
    add_transparent_value_index::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the transparent ledger schema and records legacy provenance for transparent records."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            CREATE TABLE tpir_meta (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                applied_mode INTEGER NOT NULL CHECK (applied_mode IN (0, 1, 2)),
                policy_generation INTEGER NOT NULL CHECK (policy_generation >= 0),
                min_reader_version INTEGER NOT NULL CHECK (min_reader_version >= 1)
            );
            INSERT INTO tpir_meta (id, applied_mode, policy_generation, min_reader_version)
            VALUES (0, 0, 0, 1);

            CREATE TABLE tpir_output_origins (
                output_id INTEGER NOT NULL
                    REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
                origin INTEGER NOT NULL CHECK (origin IN (0, 1, 2, 3)),
                UNIQUE (output_id, origin)
            );

            CREATE TABLE tpir_spend_origins (
                spending_transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                origin INTEGER NOT NULL CHECK (origin IN (0, 1, 2, 3)),
                UNIQUE (spending_transaction_id, prevout_txid, prevout_output_index, origin)
            );
            "#,
        )?;

        // Every existing record was admitted before the ledger existed, so its provenance
        // cannot be distinguished from public discovery: it is legacy evidence. Records whose
        // transaction carries local creation evidence also keep their local origin. Neither
        // origin is coverage.
        conn.execute_batch(
            r#"
            INSERT INTO tpir_output_origins (output_id, origin)
            SELECT id, 0 FROM transparent_received_outputs;

            INSERT INTO tpir_output_origins (output_id, origin)
            SELECT o.id, 1
            FROM transparent_received_outputs o
            JOIN transactions t ON t.id_tx = o.transaction_id
            WHERE t.created IS NOT NULL OR t.target_height IS NOT NULL;

            INSERT OR IGNORE INTO tpir_spend_origins (
                spending_transaction_id, prevout_txid, prevout_output_index, origin
            )
            SELECT s.transaction_id, prevout_tx.txid, o.output_index, 0
            FROM transparent_received_output_spends s
            JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
            JOIN transactions prevout_tx ON prevout_tx.id_tx = o.transaction_id
            UNION ALL
            SELECT spending_transaction_id, prevout_txid, prevout_output_index, 0
            FROM transparent_spend_map;

            INSERT OR IGNORE INTO tpir_spend_origins (
                spending_transaction_id, prevout_txid, prevout_output_index, origin
            )
            SELECT so.spending_transaction_id, so.prevout_txid, so.prevout_output_index, 1
            FROM tpir_spend_origins so
            JOIN transactions t ON t.id_tx = so.spending_transaction_id
            WHERE so.origin = 0
            AND (t.created IS NOT NULL OR t.target_height IS NOT NULL);
            "#,
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rusqlite::{Connection, types::Value};
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        util::testing::FixedClock,
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    type Db =
        WalletDb<Connection, Network, FixedClock, zcash_client_backend::data_api::testing::TestRng>;

    /// A wallet at the preceding migration state holding a derived account, a hardware-style
    /// imported account without spending keys, and representative transparent history.
    fn pre_migration_wallet(file: &NamedTempFile) -> Db {
        let network = Network::TestNetwork;
        let mut db = WalletDb::for_path(file.path(), network, test_clock(), test_rng()).unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();

        let ufvk = |seed: u8| {
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[seed; 32][..], zip32::AccountId::ZERO)
                    .unwrap();
            let ufvk = usk.to_unified_full_viewing_key();
            (
                ufvk.encode(&network),
                ufvk.to_unified_incoming_viewing_key().encode(&network),
            )
        };
        let (derived_ufvk, derived_uivk) = ufvk(0xab);
        let (hardware_ufvk, hardware_uivk) = ufvk(0xcd);
        let zero_div = vec![0u8; 11];
        db.conn
            .execute_batch(&format!(
                "INSERT INTO accounts (id, uuid, account_kind, hd_seed_fingerprint, hd_account_index,
                     ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (1, X'AA', 0, X'{fp}', 0, '{derived_ufvk}', '{derived_uivk}', 1, 1),
                        (2, X'BB', 1, NULL, NULL, '{hardware_ufvk}', '{hardware_uivk}', 0, 1);
                 INSERT INTO addresses (id, account_id, key_scope, diversifier_index_be, address,
                     transparent_child_index, cached_transparent_receiver_address, receiver_flags)
                 VALUES (1, 1, 0, X'{div}', 'ua-derived', 0, 't-derived', 1),
                        (2, 2, 0, X'{div}', 'ua-hardware', 0, 't-hardware', 1);
                 -- 1: remote receive; 2: local send; 3: coinbase; 4: remote spend of an unknown output.
                 INSERT INTO transactions (id_tx, txid, created, mined_height, tx_index, expiry_height,
                     raw, fee, target_height, min_observed_height)
                 VALUES (1, X'{t1}', NULL, 100, 3, NULL, NULL, NULL, NULL, 100),
                        (2, X'{t2}', '2026-01-01T00:00:00Z', NULL, NULL, 140, X'00', 1000, 120, 0),
                        (3, X'{t3}', NULL, 90, 0, NULL, NULL, NULL, NULL, 90),
                        (4, X'{t4}', NULL, 130, 1, NULL, NULL, NULL, NULL, 130);
                 INSERT INTO transparent_received_outputs (id, transaction_id, output_index,
                     account_id, address, script, value_zat, max_observed_unspent_height,
                     address_id, lock_expiry_height, lock_owner)
                 VALUES (1, 1, 0, 1, 't-derived', X'76', 5000, 100, 1, NULL, NULL),
                        (2, 2, 1, 1, 't-derived', X'76', 3000, 120, 1, 150, X'AA'),
                        (3, 3, 0, 2, 't-hardware', X'76', 7000, 90, 2, NULL, NULL);
                 INSERT INTO transparent_received_output_spends (transparent_received_output_id,
                     transaction_id)
                 VALUES (1, 2);
                 INSERT INTO transparent_spend_map (spending_transaction_id, prevout_txid,
                     prevout_output_index)
                 VALUES (4, X'{t9}', 0);
                 INSERT INTO sent_notes (transaction_id, output_pool, output_index, from_account_id,
                     to_address, value)
                 VALUES (2, 0, 0, 1, 't-external', 1000);",
                fp = hex::encode([0xab; 32]),
                div = hex::encode(&zero_div),
                t1 = hex::encode([1; 32]),
                t2 = hex::encode([2; 32]),
                t3 = hex::encode([3; 32]),
                t4 = hex::encode([4; 32]),
                t9 = hex::encode([9; 32]),
            ))
            .unwrap();
        db
    }

    /// Every row of every table that is not ledger-owned or migration bookkeeping.
    /// Wallet tables are unchanged by the upgrade, except that later migrations may add status
    /// observations to the retrieval queue; every row queued before is kept.
    fn assert_retained(
        mut after: BTreeMap<String, Vec<Vec<Value>>>,
        before: &BTreeMap<String, Vec<Vec<Value>>>,
    ) {
        let mut before = before.clone();
        let queued_before = before.remove("tx_retrieval_queue").unwrap_or_default();
        let queued_after = after.remove("tx_retrieval_queue").unwrap_or_default();
        assert!(queued_before.iter().all(|row| queued_after.contains(row)));
        assert_eq!(after, before);
    }

    fn wallet_tables(conn: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
        let names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name NOT LIKE 'tpir!_%' ESCAPE '!'
                 -- Later migrations' work queue and absence records, not wallet data.
                 AND name NOT IN ('schemer_migrations', 'sqlite_sequence',
                                  'tx_attribution_queue', 'transparent_utxo_absences')",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        names
            .into_iter()
            .map(|name| {
                let mut stmt = conn
                    .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
                    .unwrap();
                let width = stmt.column_count();
                let rows = stmt
                    .query_map([], |row| {
                        (0..width).map(|i| row.get::<_, Value>(i)).collect()
                    })
                    .unwrap()
                    .collect::<Result<Vec<Vec<Value>>, _>>()
                    .unwrap();
                (name, rows)
            })
            .collect()
    }

    fn ledger_table_names(conn: &Connection) -> BTreeSet<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'tpir!_%' ESCAPE '!'",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn output_origins(conn: &Connection) -> BTreeSet<(i64, i64)> {
        conn.prepare("SELECT output_id, origin FROM tpir_output_origins")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn spend_origins(conn: &Connection) -> BTreeSet<(i64, Vec<u8>, i64, i64)> {
        conn.prepare(
            "SELECT spending_transaction_id, prevout_txid, prevout_output_index, origin
             FROM tpir_spend_origins",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    #[test]
    fn seedless_upgrade_is_additive_and_classifies_legacy_rows() {
        let file = NamedTempFile::new().unwrap();
        let mut db = pre_migration_wallet(&file);
        let before = wallet_tables(&db.conn);

        // No seed: imported-only and hardware-first wallets must upgrade.
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();

        // Balances, locks, local sends, and sent-note details are read from these tables only;
        // none changed.
        assert_retained(wallet_tables(&db.conn), &before);

        // Every record is legacy evidence; records with local creation evidence are also local.
        // A mined observation (the coinbase and remote receive) does not make a record local.
        assert_eq!(
            output_origins(&db.conn),
            BTreeSet::from([(1, 0), (2, 0), (2, 1), (3, 0)])
        );
        assert_eq!(
            spend_origins(&db.conn),
            BTreeSet::from([
                (2, vec![1; 32], 0, 0),
                (2, vec![1; 32], 0, 1),
                (4, vec![9; 32], 0, 0),
            ])
        );

        // The durable policy is public, and nothing is fabricated as private evidence.
        let meta: (i64, i64, i64) = db
            .conn
            .query_row(
                "SELECT applied_mode, policy_generation, min_reader_version FROM tpir_meta",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(meta, (0, 0, 1));
        // Later migrations add the recovery tables, empty.
        let ledger_tables = ledger_table_names(&db.conn);
        assert!(ledger_tables.is_superset(&BTreeSet::from([
            "tpir_meta".to_string(),
            "tpir_output_origins".to_string(),
            "tpir_spend_origins".to_string(),
        ])));
        for table in &ledger_tables {
            if !["tpir_meta", "tpir_output_origins", "tpir_spend_origins"].contains(&&**table) {
                assert_eq!(count(&db.conn, table), 0, "{table} must start empty");
            }
        }
    }

    #[test]
    fn interrupted_upgrade_leaves_no_ledger_state() {
        let file = NamedTempFile::new().unwrap();
        let mut db = pre_migration_wallet(&file);
        let before = wallet_tables(&db.conn);

        // An object occupying a later table's name makes the migration fail part-way.
        db.conn
            .execute_batch("CREATE VIEW tpir_spend_origins AS SELECT 1 AS obstacle")
            .unwrap();
        assert!(WalletMigrator::new().init_or_migrate(&mut db).is_err());

        assert_eq!(ledger_table_names(&db.conn), BTreeSet::new());
        let recorded: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM schemer_migrations WHERE id = ?",
                [MIGRATION_ID.as_bytes().to_vec()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recorded, 0);
        assert_retained(wallet_tables(&db.conn), &before);

        // After the obstacle is removed, the migration completes from the untouched state.
        db.conn
            .execute_batch("DROP VIEW tpir_spend_origins")
            .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        assert_retained(wallet_tables(&db.conn), &before);
        assert_eq!(count(&db.conn, "tpir_output_origins"), 4);
    }
}
