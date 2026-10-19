//! Adds per-receiver recovery cursors and exact scan evidence without inventing
//! local-operation provenance for keys or operations created by older versions.
use super::one_time_ivk_discovery;
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Identifier for the permanent block-filter recovery state migration.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x3905d9f9_c6c9_48e0_b201_5bb2ceca5935);
const DEPENDENCIES: &[Uuid] = &[one_time_ivk_discovery::MIGRATION_ID];
pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    /// Returns this migration's stable identity.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    /// Preserves the shipped discovery and spend-journal migration.
    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }
    /// Describes the new state without claiming old scans covered it.
    fn description(&self) -> &'static str {
        "Adds block-filter recovery cursors, scan evidence and local watch provenance."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    /// Creates pending recovery state. Existing notes, keys, operations and spend journal stay intact.
    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch("CREATE TABLE ironwood_block_recovery (
            account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
            needs_prepare INTEGER NOT NULL DEFAULT 1 CHECK(needs_prepare IN(0,1)),
            birthday INTEGER NOT NULL CHECK(birthday BETWEEN 0 AND 4294967295),
            key_generation INTEGER NOT NULL DEFAULT 0 CHECK(typeof(key_generation)='integer' AND key_generation>=0),
            work_generation INTEGER NOT NULL DEFAULT 0 CHECK(typeof(work_generation)='integer' AND work_generation>=0),
            genesis BLOB CHECK(length(genesis)=32), archive BLOB CHECK(length(archive)=32),
            epoch INTEGER CHECK(epoch IS NULL OR (typeof(epoch)='integer' AND epoch>=0)),
            CHECK((genesis IS NULL)=(archive IS NULL) AND (archive IS NULL)=(epoch IS NULL)));
        CREATE TABLE ironwood_block_histories (
            account_id INTEGER NOT NULL REFERENCES ironwood_block_recovery(account_id) ON DELETE CASCADE,
            archive BLOB NOT NULL CHECK(length(archive)=32), epoch INTEGER NOT NULL CHECK(typeof(epoch)='integer' AND epoch>=0),
            PRIMARY KEY(account_id,archive));
        CREATE TABLE ironwood_block_windows (
            account_id INTEGER NOT NULL REFERENCES ironwood_block_recovery(account_id) ON DELETE CASCADE,
            purpose INTEGER NOT NULL CHECK(purpose IN(0,1)),
            end_index BLOB NOT NULL DEFAULT X'00000000000000000000000000000064'
                CHECK(typeof(end_index)='blob' AND length(end_index)=16 AND end_index BETWEEN X'00000000000000000000000000000064' AND X'00000000000000010000000000000000'),
            derived BLOB NOT NULL DEFAULT X'00000000000000000000000000000000'
                CHECK(typeof(derived)='blob' AND length(derived)=16 AND derived<=end_index),
            PRIMARY KEY(account_id,purpose));
        CREATE TABLE ironwood_block_receivers (
            account_id INTEGER NOT NULL REFERENCES ironwood_block_recovery(account_id) ON DELETE CASCADE,
            purpose INTEGER NOT NULL CHECK(purpose IN(0,1)), key_index BLOB NOT NULL CHECK(length(key_index)=8),
            receiver BLOB NOT NULL CHECK(length(receiver)=43),
            next_height INTEGER NOT NULL CHECK(next_height BETWEEN 0 AND 4294967296),
            PRIMARY KEY(account_id,purpose,key_index));
        CREATE TABLE ironwood_block_matches (
            account_id INTEGER NOT NULL, purpose INTEGER NOT NULL, key_index BLOB NOT NULL,
            height INTEGER NOT NULL CHECK(height BETWEEN 0 AND 4294967295), hash BLOB NOT NULL CHECK(length(hash)=32),
            PRIMARY KEY(account_id,purpose,key_index,height),
            FOREIGN KEY(account_id,purpose,key_index) REFERENCES ironwood_block_receivers(account_id,purpose,key_index) ON DELETE CASCADE);
        CREATE TABLE ironwood_key_scans (
            one_time_key_id INTEGER NOT NULL REFERENCES ironwood_one_time_keys(id) ON DELETE CASCADE,
            height INTEGER NOT NULL CHECK(height BETWEEN 0 AND 4294967295), hash BLOB NOT NULL CHECK(length(hash)=32),
            PRIMARY KEY(one_time_key_id,height));
        CREATE TRIGGER ironwood_recovery_allocation AFTER UPDATE OF advances_allocation ON ironwood_one_time_keys
            WHEN NEW.advances_allocation>OLD.advances_allocation
            BEGIN UPDATE ironwood_block_recovery SET needs_prepare=1 WHERE account_id=NEW.account_id; END;
        ALTER TABLE ironwood_one_time_keys ADD COLUMN authenticated INTEGER NOT NULL DEFAULT 0 CHECK(authenticated IN(0,1));
        ALTER TABLE ironwood_one_time_keys ADD COLUMN issuance_blocked INTEGER NOT NULL DEFAULT 0 CHECK(issuance_blocked IN(0,1));
        UPDATE ironwood_one_time_keys SET
            authenticated=(reserved_at IS NOT NULL OR used=1 OR paid_before_birthday=1),
            issuance_blocked=(purpose=0 OR used=1 OR provider_seen=1 OR paid_before_birthday=1 OR EXISTS(
                SELECT 1 FROM ironwood_one_time_operations o WHERE o.one_time_key_id=ironwood_one_time_keys.id AND o.reference IS NOT NULL));
        ALTER TABLE ironwood_one_time_operations ADD COLUMN local_watch_deadline INTEGER CHECK(local_watch_deadline>=0);
        ALTER TABLE ironwood_one_time_operations ADD COLUMN local_watch_accepted INTEGER NOT NULL DEFAULT 0 CHECK(local_watch_accepted IN(0,1));
        ALTER TABLE ironwood_one_time_keys ADD COLUMN watch_closed_height INTEGER CHECK(watch_closed_height BETWEEN 0 AND 4294967295);
        ALTER TABLE ironwood_one_time_keys ADD COLUMN watch_closed_hash BLOB CHECK(length(watch_closed_hash)=32);
        CREATE TRIGGER ironwood_local_watch_bound BEFORE UPDATE OF local_watch_deadline,local_watch_accepted ON ironwood_one_time_operations
            WHEN OLD.local_watch_accepted=1 AND (NEW.local_watch_deadline IS NOT OLD.local_watch_deadline OR NEW.local_watch_accepted<>1)
            BEGIN SELECT RAISE(ABORT,'accepted watch deadline is immutable'); END;")?;
        Ok(())
    }
    /// Recovery state cannot be discarded by a downgrade.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    /// Checks all supported predecessor migration paths and schema integrity.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
    /// Upgrading preserves keys and operation facts without pretending an old operation is local.
    #[test]
    fn preserves_existing_data_without_watch_provenance() {
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
            .init_or_migrate_to(&mut db, super::DEPENDENCIES)
            .unwrap();
        let ufvk = UnifiedSpendingKey::from_seed(&network, &[0xab; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        db.conn.execute("INSERT INTO accounts(id,uuid,account_kind,ufvk,uivk,birthday_height) VALUES(1,zeroblob(16),1,?1,?2,1)",
            [ufvk.encode(&network),ufvk.to_unified_incoming_viewing_key().encode(&network)]).unwrap();
        db.conn.execute_batch("INSERT INTO ironwood_one_time_keys(id,account_id,purpose,key_index,receiver,scan_from,advances_allocation,registered_at,reserved_at,active_from,used,provider_seen)
            VALUES(1,1,1,X'0000000000000000',zeroblob(43),0,1,100,200,0,1,1);
            INSERT INTO ironwood_one_time_operations(one_time_key_id,reference,request,deadline,begun_at,observed_at,funded)
            VALUES(1,'deposit','request',400,150,150,1);").unwrap();
        migrate()
            .init_or_migrate_to(&mut db, &[super::MIGRATION_ID])
            .unwrap();
        let facts:(i64,i64,i64,i64,i64,i64)=db.conn.query_row("SELECT used,provider_seen,reserved_at,advances_allocation,authenticated,issuance_blocked FROM ironwood_one_time_keys",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
        assert_eq!(facts, (1, 1, 200, 1, 1, 1));
        let operation:(String,String,i64,i64,bool,Option<i64>,bool)=db.conn.query_row("SELECT reference,request,deadline,begun_at,funded,local_watch_deadline,local_watch_accepted FROM ironwood_one_time_operations",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).unwrap();
        assert_eq!(
            operation,
            (
                "deposit".into(),
                "request".into(),
                400,
                150,
                true,
                None,
                false
            )
        );
        let count: u64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM ironwood_key_scans", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let violations: u64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(violations, 0);
    }
}
