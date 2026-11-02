//! Adds the candidate recovery tables of the transparent ledger.
//!
//! Seedless and additive: it creates empty `tpir_*` tables for watched-window progress,
//! revisions, receive and spend events with their observations, coverage, and pending pages,
//! with the indexes their per-event lookups need.
//! Existing rows are untouched; no coverage is inferred for them.
use std::collections::HashSet;

use crate::migration::SqliteMigration as RusqliteMigration;
use uuid::Uuid;

use super::transparent_policy_generation;
use crate::wallet::init::WalletMigrationError;

/// Creates the candidate recovery tables.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x9302bbcf_425a_426b_9074_084d626e45bd);

const DEPENDENCIES: &[Uuid] = &[transparent_policy_generation::MIGRATION_ID];

pub(super) struct Migration;

impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the transparent ledger candidate recovery tables."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            CREATE TABLE tpir_candidate_windows (
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                key_scope INTEGER NOT NULL CHECK (key_scope IN (0, 1, 2)),
                end_index INTEGER NOT NULL CHECK (end_index >= 0 AND end_index <= 2147483648),
                PRIMARY KEY (account_id, key_scope)
            );
            CREATE TABLE tpir_revisions (
                id INTEGER PRIMARY KEY,
                source BLOB NOT NULL,
                revision BLOB NOT NULL,
                lineage INTEGER NOT NULL CHECK (lineage >= 0),
                sealed INTEGER NOT NULL CHECK (sealed IN (0, 1)),
                publication_height INTEGER NOT NULL CHECK (publication_height >= 0),
                publication_hash BLOB NOT NULL,
                UNIQUE (source, revision),
                UNIQUE (source, lineage)
            );
            CREATE TABLE tpir_receive_events (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                txid BLOB NOT NULL,
                output_index INTEGER NOT NULL CHECK (output_index >= 0),
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL CHECK (value_zat >= 0),
                coinbase INTEGER NOT NULL CHECK (coinbase IN (0, 1)),
                mined_height INTEGER CHECK (mined_height >= 0),
                UNIQUE (txid, output_index)
            );
            CREATE TABLE tpir_receive_observations (
                receive_id INTEGER NOT NULL REFERENCES tpir_receive_events(id) ON DELETE CASCADE,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                PRIMARY KEY (receive_id, revision_id)
            );
            CREATE TABLE tpir_spend_events (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                spending_txid BLOB NOT NULL,
                input_index INTEGER NOT NULL CHECK (input_index >= 0),
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL CHECK (prevout_output_index >= 0),
                prevout_script BLOB NOT NULL,
                mined_height INTEGER CHECK (mined_height >= 0),
                UNIQUE (spending_txid, input_index)
            );
            CREATE TABLE tpir_spend_observations (
                spend_id INTEGER NOT NULL REFERENCES tpir_spend_events(id) ON DELETE CASCADE,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                PRIMARY KEY (spend_id, revision_id)
            );
            CREATE TABLE tpir_coverage (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                script BLOB NOT NULL,
                from_height INTEGER NOT NULL CHECK (from_height >= 0),
                through_height INTEGER NOT NULL,
                anchor_height INTEGER NOT NULL,
                anchor_hash BLOB NOT NULL,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                supported INTEGER NOT NULL CHECK (supported IN (0, 1)),
                CHECK (from_height <= through_height AND through_height <= anchor_height)
            );
            CREATE TABLE tpir_pending_pages (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                revision_id INTEGER NOT NULL REFERENCES tpir_revisions(id),
                page BLOB NOT NULL,
                from_height INTEGER NOT NULL CHECK (from_height >= 0),
                through_height INTEGER NOT NULL,
                target_height INTEGER NOT NULL,
                target_hash BLOB NOT NULL,
                UNIQUE (account_id, revision_id, page),
                CHECK (from_height <= through_height AND through_height <= target_height)
            );
            CREATE TABLE tpir_pending_page_scripts (
                page_id INTEGER NOT NULL REFERENCES tpir_pending_pages(id) ON DELETE CASCADE,
                script BLOB NOT NULL,
                PRIMARY KEY (page_id, script)
            );
            CREATE INDEX idx_tpir_coverage_script ON tpir_coverage (account_id, script);
            CREATE INDEX idx_tpir_receive_events_account ON tpir_receive_events (account_id);
            CREATE INDEX idx_tpir_spend_events_account ON tpir_spend_events (account_id);
            CREATE INDEX idx_tpir_spend_events_prevout ON tpir_spend_events (prevout_txid, prevout_output_index);
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
    use std::collections::BTreeSet;

    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    const RECOVERY_TABLES: &[&str] = &[
        "tpir_candidate_windows",
        "tpir_revisions",
        "tpir_receive_events",
        "tpir_receive_observations",
        "tpir_spend_events",
        "tpir_spend_observations",
        "tpir_coverage",
        "tpir_pending_pages",
        "tpir_pending_page_scripts",
    ];

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn seedless_upgrade_creates_only_empty_recovery_tables() {
        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();
        let tables = |db: &WalletDb<rusqlite::Connection, _, _, _>| -> BTreeSet<String> {
            db.conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let before = tables(&db);

        // No seed: imported-only and hardware-first wallets must upgrade.
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, &[MIGRATION_ID])
            .unwrap();

        let added: BTreeSet<String> = tables(&db).difference(&before).cloned().collect();
        assert_eq!(
            added,
            RECOVERY_TABLES.iter().map(|t| t.to_string()).collect()
        );
        for table in RECOVERY_TABLES {
            let rows: i64 = db
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table} must start empty");
        }
    }
}
