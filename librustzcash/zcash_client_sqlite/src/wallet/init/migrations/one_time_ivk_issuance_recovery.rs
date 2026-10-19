//! Tracks bounded checks of the monotone provider set separately from payment filters.
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Stable identity of the issuance recovery migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x89a9e3ac_0624_45e1_ae86_c942a55100b1);
pub(super) struct Migration;
impl schemerz::Migration<Uuid> for Migration {
    /// Identifies the new schema without rewriting a shipped migration.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    /// Requires the block recovery account and window records.
    fn dependencies(&self) -> HashSet<Uuid> {
        [super::one_time_ivk_block_recovery::MIGRATION_ID].into()
    }
    /// Describes the durable issuance prerequisite.
    fn description(&self) -> &'static str {
        "Tracks checked provider membership for issuance."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    /// Keeps prior keys and exposure facts while initially requiring a provider check.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch("ALTER TABLE ironwood_one_time_keys ADD COLUMN funding_authenticated INTEGER NOT NULL DEFAULT 0 CHECK(funding_authenticated IN(0,1));
            UPDATE ironwood_one_time_keys SET issuance_blocked=1
            WHERE used=1 OR paid_before_birthday=1
               OR (provider_seen=1 AND NOT EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id=ironwood_one_time_keys.id AND o.request IS NOT NULL))
               OR EXISTS(SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id=ironwood_one_time_keys.id AND (o.started=1 OR (purpose=0 AND o.reference IS NOT NULL)));
            UPDATE ironwood_one_time_keys SET authenticated=1 WHERE reserved_at IS NOT NULL OR used=1 OR paid_before_birthday=1;
            CREATE TABLE ironwood_block_seen (
            account_id INTEGER PRIMARY KEY REFERENCES ironwood_block_recovery(account_id) ON DELETE CASCADE,
            digest BLOB NOT NULL CHECK(length(digest)=32), until_unix INTEGER NOT NULL CHECK(until_unix>=0));
            ALTER TABLE ironwood_block_windows ADD COLUMN seen_index BLOB NOT NULL DEFAULT X'00000000000000000000000000000000'
                CHECK(typeof(seen_index)='blob' AND length(seen_index)=16 AND seen_index<=end_index);")?;
        Ok(())
    }
    /// Never silently discard exposure or readiness state on downgrade.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    /// Checks the supported predecessor paths and foreign-key constraints.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
    /// A wallet using the preceding schema may create accepted operations before this upgrade.
    #[test]
    fn backfills_operations_created_after_the_watch_migration() {
        use crate::{
            WalletDb,
            testing::db::{test_clock, test_rng},
            wallet::init::WalletMigrator,
        };
        use secrecy::Secret;
        use zcash_keys::keys::UnifiedSpendingKey;
        use zcash_protocol::consensus::Network;
        let file = tempfile::NamedTempFile::new().unwrap();
        let network = Network::TestNetwork;
        let mut db = WalletDb::for_path(file.path(), network, test_clock(), test_rng()).unwrap();
        let migrate = || {
            WalletMigrator::new()
                .with_seed(Secret::new(vec![0xab; 32]))
                .ignore_seed_relevance()
        };
        migrate()
            .init_or_migrate_to(
                &mut db,
                &[super::super::one_time_ivk_block_recovery::MIGRATION_ID],
            )
            .unwrap();
        let ufvk = UnifiedSpendingKey::from_seed(&network, &[0xab; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        db.conn.execute("INSERT INTO accounts(id,uuid,account_kind,ufvk,uivk,birthday_height) VALUES(1,zeroblob(16),1,?1,?2,1)",[ufvk.encode(&network),ufvk.to_unified_incoming_viewing_key().encode(&network)]).unwrap();
        db.conn.execute_batch("INSERT INTO ironwood_one_time_keys(id,account_id,purpose,key_index,receiver,scan_from,advances_allocation,registered_at,reserved_at) VALUES
            (1,1,0,X'0000000000000000',zeroblob(43),0,1,100,100),
            (2,1,1,X'0000000000000000',X'01000000000000000000000000000000000000000000000000000000000000000000000000000000000000',0,1,100,100),
            (3,1,0,X'0000000000000001',X'02000000000000000000000000000000000000000000000000000000000000000000000000000000000000',0,1,100,100);
            INSERT INTO ironwood_one_time_operations(one_time_key_id,reference,deadline,begun_at,started) VALUES(1,'refund',200,100,0),(2,'receive',200,100,1);").unwrap();
        migrate()
            .init_or_migrate_to(&mut db, &[super::MIGRATION_ID])
            .unwrap();
        let flags: Vec<(i64, bool, bool)> = db
            .conn
            .prepare(
                "SELECT id,issuance_blocked,authenticated FROM ironwood_one_time_keys ORDER BY id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(flags, [(1, true, true), (2, true, true), (3, false, true)]);
        let invented:u32=db.conn.query_row("SELECT COUNT(*) FROM ironwood_one_time_operations WHERE local_watch_deadline IS NOT NULL",[],|r|r.get(0)).unwrap();
        assert_eq!(invented, 0);
    }
}
