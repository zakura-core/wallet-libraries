//! Adds durable transparent txid enhancement work and validated display facts, and queues work
//! for existing transactions whose transparent details the wallet cannot otherwise obtain.
use super::ironwood_transparent_output_shape;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Additive: new tables only, plus work rows for transactions without raw bytes.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x73d751a3_dbdc_461a_9154_e061903aae4f);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    fn dependencies(&self) -> HashSet<Uuid> {
        [ironwood_transparent_output_shape::MIGRATION_ID]
            .into_iter()
            .collect()
    }
    fn description(&self) -> &'static str {
        "Adds transparent txid enhancement work and display facts."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            CREATE TABLE transparent_detail_work (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
                reasons INTEGER NOT NULL CHECK (reasons > 0 AND reasons < 8),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                attempted_at INTEGER,
                attempted_height INTEGER CHECK (attempted_height >= 0),
                last_outcome INTEGER CHECK (last_outcome BETWEEN 0 AND 6),
                last_map_sha256 BLOB CHECK (length(last_map_sha256) = 32)
            );
            CREATE TABLE transparent_tx_display (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE,
                coinbase INTEGER NOT NULL CHECK (coinbase IN (0, 1)),
                fee_state INTEGER NOT NULL CHECK (fee_state IN (0, 1, 2)),
                fee_zat INTEGER CHECK (fee_zat >= 0 AND fee_zat <= 2100000000000000),
                input_count INTEGER NOT NULL CHECK (input_count >= 0 AND input_count <= 4294967295),
                shielded INTEGER NOT NULL CHECK (shielded IN (0, 1)),
                shard_id INTEGER NOT NULL,
                revision INTEGER NOT NULL CHECK (revision >= 0),
                map_sha256 BLOB NOT NULL CHECK (length(map_sha256) = 32),
                looked_up_height INTEGER NOT NULL CHECK (looked_up_height >= 0),
                stored_at INTEGER NOT NULL,
                CHECK ((fee_state = 0 AND fee_zat IS NOT NULL) OR (fee_state != 0 AND fee_zat IS NULL)),
                CHECK (fee_state != 2 OR input_count = 0)
            );
            CREATE TABLE transparent_tx_display_outputs (
                transaction_id INTEGER NOT NULL
                    REFERENCES transparent_tx_display(transaction_id) ON DELETE CASCADE,
                output_index INTEGER NOT NULL CHECK (output_index >= 0),
                value_zat INTEGER NOT NULL CHECK (value_zat >= 0 AND value_zat <= 2100000000000000),
                script BLOB NOT NULL,
                PRIMARY KEY (transaction_id, output_index)
            );
            -- Route 2 (private details unsupported) and ledger-origin (2) outputs and spends, of
            -- mined transactions without raw bytes. A ledger-only output whose receive was
            -- withdrawn (no placed receive event) is not the wallet's.
            INSERT INTO transparent_detail_work (transaction_id, reasons)
            SELECT id_tx, reasons FROM (
                SELECT t.id_tx,
                    (CASE WHEN EXISTS (
                         SELECT 1 FROM transparent_received_outputs o
                         JOIN tpir_output_origins oo ON oo.output_id = o.id
                         WHERE o.transaction_id = t.id_tx AND oo.origin = 2
                         AND (
                             EXISTS (SELECT 1 FROM tpir_output_origins x
                                     WHERE x.output_id = o.id AND x.origin != 2)
                             OR EXISTS (SELECT 1 FROM tpir_receive_events re
                                        WHERE re.txid = t.txid
                                        AND re.output_index = o.output_index
                                        AND re.account_id = o.account_id
                                        AND re.mined_height IS NOT NULL)
                         )) THEN 1 ELSE 0 END)
                  | (CASE WHEN EXISTS (
                         SELECT 1 FROM tpir_spend_origins so
                         WHERE so.spending_transaction_id = t.id_tx AND so.origin = 2)
                     THEN 2 ELSE 0 END)
                  | (CASE WHEN EXISTS (
                         SELECT 1 FROM ironwood_enhance_routing r
                         WHERE r.transaction_id = t.id_tx AND r.route = 2) THEN 4 ELSE 0 END)
                    AS reasons
                FROM transactions t
                WHERE t.raw IS NULL AND t.mined_height IS NOT NULL
            )
            WHERE reasons > 0;
            "#,
        )?;
        Ok(())
    }
    fn down(&self, _conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
