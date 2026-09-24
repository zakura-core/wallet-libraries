//! Preserves compact encryption context when upgrading existing Ironwood wallets.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::note_locking;

/// Identifier for the forward migration adding Ironwood compact encryption fields.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x2eac815d_67ca_4fb4_b534_066102a0fba2);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        // Keep column order deterministic for new wallets and released rc5 wallets.
        [note_locking::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds compact encryption context to existing Ironwood notes."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let columns = transaction
            .prepare("PRAGMA table_info(ironwood_received_notes)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<HashSet<_>, _>>()?;
        match (
            columns.contains("ephemeral_key"),
            columns.contains("compact_ciphertext"),
        ) {
            // The unreleased PIR branch included these columns in the original migration.
            (true, true) => return Ok(()),
            (false, false) => {}
            _ => {
                return Err(WalletMigrationError::CorruptedData(
                    "incomplete Ironwood compact encryption schema".into(),
                ));
            }
        }
        // Existing notes retain NULL context until a compact-block rescan supplies it.
        // Keep the pair constraint on the second column so ADD COLUMN preserves every row,
        // foreign key, index, and note-locking field without rebuilding the table.
        transaction.execute_batch(
            "ALTER TABLE ironwood_received_notes ADD COLUMN ephemeral_key BLOB;
             ALTER TABLE ironwood_received_notes ADD COLUMN compact_ciphertext BLOB
                CHECK ((ephemeral_key IS NULL AND compact_ciphertext IS NULL) OR
                       (ephemeral_key IS NOT NULL AND compact_ciphertext IS NOT NULL AND
                        length(ephemeral_key) = 32 AND length(compact_ciphertext) = 52));",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::init::migrations::{ironwood_received_notes, tests::test_migrate};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn rc5_upgrade_preserves_notes_and_spends() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        // Exercise the published rc5 table definition with a preexisting note and spend.
        // Foreign keys are disabled here because their parent tables are outside this fixture.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        let tx = conn.transaction().unwrap();
        ironwood_received_notes::Migration.up(&tx).unwrap();
        tx.execute_batch(
            "ALTER TABLE ironwood_received_notes ADD COLUMN lock_expiry_height INTEGER;
             ALTER TABLE ironwood_received_notes ADD COLUMN lock_owner BLOB;
             INSERT INTO ironwood_received_notes
                (id, transaction_id, action_index, account_id, diversifier, value,
                 rho, rseed, nf, is_change, memo, commitment_tree_position, note_version,
                 lock_expiry_height, lock_owner)
             VALUES (1, 2, 3, 4, X'01', 500, X'02', X'03', X'04', 0, X'05', 6, 3, 700, X'06');
             INSERT INTO ironwood_received_note_spends VALUES (1, 8);",
        )
        .unwrap();
        assert!(
            tx.prepare("SELECT ephemeral_key FROM ironwood_received_notes")
                .is_err()
        );
        let read_note = |tx: &rusqlite::Transaction<'_>| {
            let mut stmt = tx.prepare("SELECT * FROM ironwood_received_notes").unwrap();
            let columns = stmt.column_count();
            stmt.query_row([], |row| {
                (0..columns)
                    .map(|i| row.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
        };
        let before = read_note(&tx);
        Migration.up(&tx).unwrap();
        let after = read_note(&tx);
        assert_eq!(&after[..before.len()], before.as_slice());
        assert_eq!(
            &after[before.len()..],
            &[rusqlite::types::Value::Null, rusqlite::types::Value::Null]
        );
        assert_eq!(
            tx.query_row("SELECT * FROM ironwood_received_note_spends", [], |row| Ok(
                (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)
            ))
            .unwrap(),
            (1, 8)
        );
        for invalid in [
            "ephemeral_key = zeroblob(32)",
            "compact_ciphertext = zeroblob(52)",
            "ephemeral_key = zeroblob(31), compact_ciphertext = zeroblob(52)",
            "ephemeral_key = zeroblob(32), compact_ciphertext = zeroblob(51)",
        ] {
            assert!(
                tx.execute(&format!("UPDATE ironwood_received_notes SET {invalid}"), [])
                    .is_err()
            );
        }
        tx.execute("UPDATE ironwood_received_notes SET ephemeral_key = zeroblob(32), compact_ciphertext = zeroblob(52)", []).unwrap();
        // Reopening a database with compact fields already installed preserves that context.
        Migration.up(&tx).unwrap();
        assert_eq!(tx.query_row("SELECT length(ephemeral_key), length(compact_ciphertext) FROM ironwood_received_notes", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).unwrap(), (32, 52));
        tx.commit().unwrap();
    }
}
