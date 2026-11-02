//! Binds queued transparent follow-on work to the durable policy generation and extends
//! Enhance routing for private-unsupported mixed transactions.
//!
//! Additive: existing `tx_retrieval_queue` rows keep generation 0 (the initial policy
//! generation). Route `2` records that transparent details cannot be recovered publicly.
use std::collections::HashSet;

use crate::migration::SqliteMigration as RusqliteMigration;
use uuid::Uuid;

use super::transparent_ledger_schema;
use crate::wallet::init::WalletMigrationError;

/// Stamps retrieval-queue rows with the policy generation and allows route 2.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xb7c4e2a1_9d3f_4e8b_a6c5_1f0e8d7c6b5a);

const DEPENDENCIES: &[Uuid] = &[transparent_ledger_schema::MIGRATION_ID];

pub(super) struct Migration;

impl crate::migration::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tx_retrieval_queue.policy_generation and Enhance route 2 (private details unsupported)."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE tx_retrieval_queue
             ADD COLUMN policy_generation INTEGER NOT NULL DEFAULT 0;",
        )?;

        // `v_transactions` references `ironwood_enhance_routing`; drop it before rebuilding
        // the table so the wider CHECK on `route` can take effect.
        let view: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'v_transactions'",
            [],
            |row| row.get(0),
        )?;
        conn.execute_batch("DROP VIEW v_transactions")?;
        conn.execute_batch(
            r#"
            CREATE TABLE ironwood_enhance_routing_new (
                transaction_id INTEGER PRIMARY KEY
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                route INTEGER NOT NULL CHECK (route IN (0, 1, 2)),
                history_expiry_height INTEGER
                    CHECK (history_expiry_height >= 0 AND history_expiry_height < 500000000)
            );
            INSERT INTO ironwood_enhance_routing_new (
                transaction_id, route, history_expiry_height
            )
            SELECT transaction_id, route, history_expiry_height
            FROM ironwood_enhance_routing;
            DROP TABLE ironwood_enhance_routing;
            ALTER TABLE ironwood_enhance_routing_new RENAME TO ironwood_enhance_routing;
            "#,
        )?;
        conn.execute_batch(&view)?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn existing_queue_rows_keep_generation_zero_and_route_two_is_accepted() {
        use tempfile::NamedTempFile;
        use zcash_protocol::consensus::Network;

        use crate::{
            WalletDb,
            testing::db::{test_clock, test_rng},
            wallet::init::WalletMigrator,
        };

        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();

        db.conn
            .execute_batch(
                "INSERT INTO transactions (id_tx, txid, min_observed_height)
                 VALUES (1, X'01', 1);
                 INSERT INTO tx_retrieval_queue (txid, query_type)
                 VALUES (X'01', 1);
                 INSERT INTO ironwood_enhance_routing (transaction_id, route)
                 VALUES (1, 1);",
            )
            .unwrap();

        WalletMigrator::new().init_or_migrate(&mut db).unwrap();

        let generation: i64 = db
            .conn
            .query_row(
                "SELECT policy_generation FROM tx_retrieval_queue WHERE txid = X'01'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(generation, 0);

        db.conn
            .execute(
                "UPDATE ironwood_enhance_routing SET route = 2 WHERE transaction_id = 1",
                [],
            )
            .unwrap();
        let route: i64 = db
            .conn
            .query_row(
                "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(route, 2);
    }
}
