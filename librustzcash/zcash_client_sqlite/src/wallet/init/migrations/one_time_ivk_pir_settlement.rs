//! Adds session-fenced history work without granting authority to legacy pending responses.
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Stable identity of durable block-filter PIR settlement.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x492dab73_330d_469e_8d5f_362345423ea4);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    /// Identifies this additive migration.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    /// Requires the current receiver registry and generation fences.
    fn dependencies(&self) -> HashSet<Uuid> {
        [super::one_time_ivk_issuance_recovery::MIGRATION_ID].into()
    }
    /// Describes the new completion boundary.
    fn description(&self) -> &'static str {
        "Fences receiver history and pending admission to a compatible PIR session."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    /// Preserves existing receipts and legacy obligations for the subsequent caller cutover.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch("CREATE TABLE ironwood_block_lookups (
            one_time_key_id INTEGER PRIMARY KEY REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
            work_generation INTEGER NOT NULL CHECK(work_generation>=0),
            session BLOB NOT NULL CHECK(length(session)=32),
            publication_height INTEGER NOT NULL CHECK(publication_height BETWEEN 0 AND 4294967295),
            publication_hash BLOB NOT NULL CHECK(length(publication_hash)=32),
            tree_size INTEGER NOT NULL CHECK(tree_size BETWEEN 0 AND 4294967296),
            through_height INTEGER NOT NULL CHECK(through_height BETWEEN 0 AND publication_height),
            through_hash BLOB NOT NULL CHECK(length(through_hash)=32),
            applied INTEGER NOT NULL DEFAULT 0 CHECK(applied BETWEEN 0 AND 4294967295),
            last_position INTEGER CHECK(last_position BETWEEN 0 AND 4294967295),
            last_nullifier BLOB CHECK(length(last_nullifier)=32),
            last_height INTEGER CHECK(last_height BETWEEN 0 AND through_height),
            enumerated INTEGER NOT NULL DEFAULT 0 CHECK(enumerated IN(0,1)),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 30),
            next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK(next_attempt_at>=0),
            CHECK((applied=0)=(last_position IS NULL) AND (last_position IS NULL)=(last_nullifier IS NULL) AND (last_nullifier IS NULL)=(last_height IS NULL)));
        CREATE TABLE ironwood_block_payments (
            one_time_key_id INTEGER NOT NULL REFERENCES ironwood_block_lookups(one_time_key_id) ON DELETE CASCADE,
            txid BLOB NOT NULL CHECK(length(txid)=32),
            action_index INTEGER NOT NULL CHECK(action_index BETWEEN 0 AND 4294967295),
            height INTEGER NOT NULL CHECK(height BETWEEN 0 AND 4294967295),
            block_hash BLOB NOT NULL CHECK(length(block_hash)=32),
            tx_index INTEGER NOT NULL CHECK(tx_index BETWEEN 0 AND 65535),
            position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 4294967295),
            encrypted_note BLOB NOT NULL CHECK(length(encrypted_note)=148),
            witness BLOB CHECK(length(witness)=1024),
            witness_height INTEGER CHECK(witness_height BETWEEN 0 AND 4294967295),
            witness_hash BLOB CHECK(length(witness_hash)=32),
            PRIMARY KEY(one_time_key_id,position),
            CHECK((witness IS NULL)=(witness_height IS NULL) AND (witness IS NULL)=(witness_hash IS NULL)));
        CREATE TRIGGER ironwood_pir_generation AFTER UPDATE OF work_generation ON ironwood_block_recovery
            WHEN NEW.work_generation<>OLD.work_generation
            BEGIN DELETE FROM ironwood_block_lookups WHERE one_time_key_id IN
                (SELECT id FROM ironwood_one_time_keys WHERE account_id=NEW.account_id); END;")?;
        Ok(())
    }
    /// Refuses to discard pending recovery work.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    /// Verifies supported predecessor paths and foreign-key integrity.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
