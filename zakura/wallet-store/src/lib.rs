//! SQLite storage for the Zakura wallet.
//!
//! One concrete type, [`WalletDb`], with inherent methods. There is deliberately
//! no storage trait: genericity over the backend is the single largest source of
//! size in the wallet layer this replaces, and it buys nothing until a second
//! backend exists. If one ever does, the trait can be extracted then, with the
//! benefit of knowing what it actually needs.
//!
//! The wallet lives in two files — see [`schema`] for why — and this type owns
//! both, attaching the derived one so a single connection and a single
//! transaction span them.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod accounts;
mod apply;
mod error;
pub mod gap;
mod hash;
mod report;
pub mod schema;
mod scan_queue;
mod tree;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, named_params};
use zakura_wallet_core::{
    DetectedBatch,
    pool::{PoolId, ShieldedPool},
    scanning::{ScanPriority, ScanRange},
};
use zcash_protocol::consensus::{BlockHeight, Parameters};

pub use accounts::Account;
pub use gap::{GapLimits, GapState};
pub use apply::{StoredNote, SubtreeRoot};
pub use report::{Balance, HistoryEntry};
pub use error::{Error, TreeError, VersionKind};
pub use scan_queue::VERIFY_LOOKAHEAD;
pub use tree::{CommitmentTree, PRUNING_DEPTH, SHARD_HEIGHT, TREE_DEPTH, WalletShardStore};

use schema::{
    CACHE_SCHEMA, DERIVED_DDL, DETECTION_VERSION, DURABLE_DDL, LAYOUT_VERSION, TREE_VERSION,
};

/// A wallet database: the durable file, with the derived file attached.
pub struct WalletDb {
    conn: Connection,
}

impl std::fmt::Debug for WalletDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The contents are the user's transaction history; never render them.
        f.write_str("WalletDb")
    }
}

impl WalletDb {
    /// Opens the wallet at `wallet_path`, with its cache at `cache_path`,
    /// creating and initialising either if it does not exist.
    ///
    /// Returns [`Error::VersionMismatch`] if a schema version does not match
    /// this build's; the error names the remedy, which differs by which version
    /// disagreed. This function never destroys data on its own — deciding to
    /// rebuild the cache is the caller's, because on a phone it is a decision
    /// with a visible cost.
    pub fn open(wallet_path: &Path, cache_path: &Path) -> Result<Self, Error> {
        let conn = Connection::open(wallet_path)?;
        conn.execute(
            "ATTACH DATABASE :path AS cache",
            named_params![":path": cache_path.to_string_lossy()],
        )?;
        Self::from_connection(conn)
    }

    /// Opens a wallet held entirely in memory.
    ///
    /// Both databases are separate in-memory databases, so the durable and
    /// derived halves behave exactly as they do on disk.
    pub fn in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute("ATTACH DATABASE ':memory:' AS cache", [])?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, Error> {
        // Foreign keys are off by default in SQLite, and this schema relies on
        // them: removing a checkpoint depends on the cascade to its marks.
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        // WAL lets the reader connections used by the UI run without blocking
        // the writer. `NORMAL` trades a crash-window fsync for throughput,
        // which is the right trade for a database that can be rebuilt.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let mut db = Self { conn };
        db.create_schema()?;
        db.check_versions()?;
        Ok(db)
    }

    fn create_schema(&mut self) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        for stmt in DURABLE_DDL {
            tx.execute(stmt, [])?;
        }
        for stmt in DERIVED_DDL {
            // The DDL is written unqualified so it reads as ordinary SQL; the
            // derived tables are created in the attached database.
            tx.execute(&qualify(stmt), [])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn check_versions(&mut self) -> Result<(), Error> {
        for (key, expected, kind) in [
            ("detection_version", DETECTION_VERSION, VersionKind::Detection),
            ("layout_version", LAYOUT_VERSION, VersionKind::Layout),
            ("tree_version", TREE_VERSION, VersionKind::Tree),
        ] {
            match self.meta_u32(key)? {
                Some(found) if found != expected => {
                    return Err(Error::VersionMismatch {
                        kind,
                        found,
                        expected,
                    });
                }
                Some(_) => {}
                None => self.set_meta_u32(key, expected)?,
            }
        }
        Ok(())
    }

    /// Reads a `wallet_meta` value as an integer.
    pub fn meta_u32(&self, key: &str) -> Result<Option<u32>, Error> {
        self.conn
            .query_row(
                "SELECT value FROM wallet_meta WHERE key = :key",
                named_params![":key": key],
                |row| row.get::<_, u32>(0),
            )
            .optional()
            .map_err(Error::Query)
    }

    /// Writes a `wallet_meta` value as an integer.
    pub fn set_meta_u32(&mut self, key: &str, value: u32) -> Result<(), Error> {
        self.conn.execute(
            "INSERT INTO wallet_meta (key, value) VALUES (:key, :value)
             ON CONFLICT (key) DO UPDATE SET value = :value",
            named_params![":key": key, ":value": value],
        )?;
        Ok(())
    }

    /// Runs `f` with a mutable handle on one pool's commitment tree.
    ///
    /// The tree is opened inside a transaction that commits only if `f`
    /// succeeds, so a partially applied batch of commitments can never be
    /// observed. That is what lets the sync engine treat one batch as one
    /// all-or-nothing unit of work.
    pub fn with_tree<P, F, A>(&mut self, f: F) -> Result<A, TreeError>
    where
        P: ShieldedPool,
        F: FnOnce(&mut CommitmentTree<'_>) -> Result<A, TreeError>,
    {
        self.with_tree_for(P::ID, f)
    }

    /// As [`Self::with_tree`], but for a pool known only at runtime.
    pub fn with_tree_for<F, A>(&mut self, pool: PoolId, f: F) -> Result<A, TreeError>
    where
        F: FnOnce(&mut CommitmentTree<'_>) -> Result<A, TreeError>,
    {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        let result = {
            let mut t = tree::tree(WalletShardStore::new(&tx, pool));
            f(&mut t)?
        };
        tx.commit().map_err(Error::Query)?;
        Ok(result)
    }

    /// Runs `f` inside a transaction spanning both databases.
    pub fn transactionally<F, A, E>(&mut self, f: F) -> Result<A, E>
    where
        E: From<Error>,
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<A, E>,
    {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        let result = f(&tx)?;
        tx.commit().map_err(Error::Query)?;
        Ok(result)
    }

    /// Creates an account derived from `seed` at ZIP 32 account index
    /// `account_index`.
    ///
    /// The seed is used and dropped: only the viewing key is stored, because a
    /// wallet that kept the seed would hold the ability to spend in the same
    /// place as the ability to see.
    pub fn create_account<P: Parameters>(
        &mut self,
        params: &P,
        seed: &[u8],
        account_index: zip32::AccountId,
        birthday: BlockHeight,
    ) -> Result<zakura_wallet_core::AccountId, Error> {
        self.transactionally(|tx| accounts::create(tx, params, seed, account_index, birthday))
    }

    /// Imports a watch-only account from a unified full viewing key.
    pub fn import_account<P: Parameters>(
        &mut self,
        params: &P,
        ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
        birthday: BlockHeight,
    ) -> Result<zakura_wallet_core::AccountId, Error> {
        self.transactionally(|tx| accounts::import(tx, params, ufvk, birthday))
    }

    /// Returns an account.
    pub fn account<P: Parameters>(
        &self,
        params: &P,
        id: zakura_wallet_core::AccountId,
    ) -> Result<Option<Account>, Error> {
        accounts::get(&self.conn, params, id)
    }

    /// Returns every account, in creation order.
    pub fn accounts<P: Parameters>(&self, params: &P) -> Result<Vec<Account>, Error> {
        accounts::list(&self.conn, params)
    }

    /// Issues the next unused address for an account.
    ///
    /// Two calls return two different addresses: reusing one lets anybody who
    /// has seen it link the payments made to it.
    pub fn next_address<P: Parameters>(
        &mut self,
        params: &P,
        id: zakura_wallet_core::AccountId,
        scope: zakura_wallet_core::KeyScope,
        exposed_at: Option<BlockHeight>,
    ) -> Result<
        (
            zcash_keys::address::UnifiedAddress,
            zip32::DiversifierIndex,
        ),
        Error,
    > {
        self.transactionally(|tx| accounts::next_address(tx, params, id, scope, exposed_at))
    }

    /// Returns the address an account's change is paid to.
    pub fn change_address<P: Parameters>(
        &self,
        params: &P,
        id: zakura_wallet_core::AccountId,
    ) -> Result<orchard::Address, Error> {
        accounts::change_address(&self.conn, params, id)
    }

    /// Returns where an account's transparent addresses stand against the gap
    /// limit.
    pub fn gap_state(
        &self,
        account: zakura_wallet_core::AccountId,
        scope: zakura_wallet_core::KeyScope,
    ) -> Result<GapState, Error> {
        gap::state(&self.conn, account, scope)
    }

    /// Returns the transparent address indices that must be generated to keep a
    /// full gap of unused addresses ahead of the used ones.
    ///
    /// An address a wallet has not generated is one it is not watching, and a
    /// payment to it goes unseen.
    pub fn addresses_to_generate(
        &self,
        account: zakura_wallet_core::AccountId,
        scope: zakura_wallet_core::KeyScope,
        limits: &GapLimits,
    ) -> Result<Vec<u32>, Error> {
        gap::indices_to_generate(&self.conn, account, scope, limits)
    }

    /// Records a transparent address the wallet is watching.
    pub fn record_transparent_address(
        &mut self,
        account: zakura_wallet_core::AccountId,
        scope: zakura_wallet_core::KeyScope,
        index: u32,
        address: &str,
        script: &[u8],
    ) -> Result<(), Error> {
        self.transactionally(|tx| {
            gap::record_address(tx, account, scope, index, address, script)
        })
    }

    /// Returns an account's balance in one pool.
    pub fn balance(
        &self,
        account: zakura_wallet_core::AccountId,
        pool: PoolId,
    ) -> Result<Balance, Error> {
        report::pool_balance(&self.conn, account, pool)
    }

    /// Returns an account's balance across every pool.
    pub fn total_balance(&self, account: zakura_wallet_core::AccountId) -> Result<Balance, Error> {
        let mut total = Balance::default();
        for pool in PoolId::ALL {
            let pool_balance = self.balance(account, pool)?;
            total.spendable = (total.spendable + pool_balance.spendable)
                .ok_or(Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the wallet's balance overflows",
                )))?;
            total.pending = (total.pending + pool_balance.pending).ok_or(Error::Serialization(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "the wallet's balance overflows"),
            ))?;
            total.spent_unconfirmed = (total.spent_unconfirmed + pool_balance.spent_unconfirmed)
                .ok_or(Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the wallet's balance overflows",
                )))?;
        }
        Ok(total)
    }

    /// Returns an account's transactions, most recent first.
    pub fn history(
        &self,
        account: zakura_wallet_core::AccountId,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>, Error> {
        report::history(&self.conn, account, limit)
    }

    /// Records a wallet-wide birthday without creating an account.
    ///
    /// For tests and for a wallet being restored key-first. A real account's
    /// birthday is its own; this is the floor when there are no accounts yet.
    pub fn set_birthday(&mut self, birthday: BlockHeight) -> Result<(), Error> {
        self.set_meta_u32("birthday_height", u32::from(birthday))
    }

    /// Returns the earliest height any account was created at.
    ///
    /// Scanning below it can produce nothing for any account, so it is the
    /// floor for every range the wallet queues.
    pub fn birthday(&self) -> Result<Option<BlockHeight>, Error> {
        Ok(accounts::earliest_birthday(&self.conn)?
            .or(self.meta_u32("birthday_height")?.map(BlockHeight::from)))
    }

    /// Returns the ranges still to be scanned, most urgent first.
    pub fn suggest_scan_ranges(
        &self,
        min_priority: ScanPriority,
    ) -> Result<Vec<ScanRange>, Error> {
        scan_queue::suggest_scan_ranges(&self.conn, min_priority)
    }

    /// Reconciles the scan queue with a newly observed chain tip.
    pub fn update_chain_tip<P: Parameters>(
        &mut self,
        params: &P,
        new_tip: BlockHeight,
    ) -> Result<(), Error> {
        let birthday = self.birthday()?;
        let max_scanned = apply::block_height_extrema(&self.conn)?.map(|(_, hi)| hi);
        self.transactionally(|tx| {
            scan_queue::update_chain_tip(
                tx,
                params,
                birthday,
                max_scanned,
                new_tip,
                PRUNING_DEPTH as u32,
            )
        })
    }

    /// Applies a detected batch and marks its range scanned, atomically.
    ///
    /// The scan queue is updated inside the same transaction as the data, which
    /// is what makes a batch a safe unit of work: whatever the queue reports as
    /// scanned is exactly what is stored.
    pub fn put_batch<P: Parameters>(
        &mut self,
        params: &P,
        batch: &DetectedBatch,
    ) -> Result<(), TreeError> {
        let birthday = self.birthday()?;
        self.transactionally(|tx| apply::put_batch(tx, params, birthday, batch))
    }

    /// Records server-supplied subtree roots for a pool.
    ///
    /// These make notes near the tip witnessable before the history below them
    /// has been downloaded: a witness needs the roots of every other shard, and
    /// a root is orders of magnitude cheaper than the shard it summarises.
    pub fn put_subtree_roots(
        &mut self,
        pool: PoolId,
        start_index: u64,
        roots: &[SubtreeRoot],
    ) -> Result<(), TreeError> {
        self.transactionally(|tx| apply::put_subtree_roots(tx, pool, start_index, roots))
    }

    /// Returns the index of the first shard the wallet has no root for.
    pub fn next_subtree_index(&self, pool: PoolId) -> Result<u64, Error> {
        apply::next_subtree_index(&self.conn, pool)
    }

    /// Rewinds the wallet to `height`, discarding everything above it.
    pub fn truncate_to(&mut self, height: BlockHeight) -> Result<(), TreeError> {
        self.transactionally(|tx| apply::truncate_to(tx, height))
    }

    /// Returns the chain state as of the end of `height`, if that block is
    /// stored.
    pub fn block_anchor(
        &self,
        height: BlockHeight,
    ) -> Result<Option<zakura_wallet_core::BlockAnchor>, Error> {
        apply::block_anchor(&self.conn, height)
    }

    /// Returns the wallet's unspent nullifiers, stamped with an epoch.
    ///
    /// The epoch lets the writer tell whether the wallet moved on while a batch
    /// was in flight; here it is the number of blocks scanned, which changes
    /// exactly when the note set can have changed.
    pub fn unspent_nullifiers(&self) -> Result<zakura_wallet_core::NullifierSnapshot, Error> {
        let epoch = self
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {CACHE_SCHEMA}.blocks"),
                [],
                |row| row.get::<_, u64>(0),
            )
            .map_err(Error::Query)?;
        apply::unspent_nullifiers(&self.conn, epoch)
    }

    /// Returns how many of a pool's commitments the wallet covers, and how many
    /// the chain has.
    pub fn commitment_coverage(&self, pool: PoolId) -> Result<(u64, u64), Error> {
        apply::commitment_coverage(&self.conn, pool)
    }

    /// Returns the notes `account` could spend.
    ///
    /// With `require_stable`, only notes whose witnesses a reorg can no longer
    /// invalidate are returned. Relaxing it is for tests and for callers that
    /// have their own reason to accept the risk; a wallet spending real funds
    /// should not.
    pub fn spendable_notes(
        &self,
        account: zakura_wallet_core::AccountId,
        require_stable: bool,
    ) -> Result<Vec<StoredNote>, Error> {
        apply::spendable_notes(&self.conn, account, require_stable)
    }

    /// Returns the highest checkpoint both pools' trees share.
    ///
    /// A transaction proves every spend against one anchor per pool, and those
    /// anchors must describe the same block or the transaction claims two
    /// different views of the chain. The highest height both trees hold is the
    /// most recent such block.
    pub fn common_anchor_height(&self) -> Result<Option<BlockHeight>, Error> {
        self.conn
            .query_row(
                &format!(
                    "SELECT MAX(a.checkpoint_id) FROM {CACHE_SCHEMA}.tree_checkpoints a
                     JOIN {CACHE_SCHEMA}.tree_checkpoints b
                        ON b.checkpoint_id = a.checkpoint_id
                     WHERE a.pool = :orchard AND b.pool = :ironwood"
                ),
                named_params![
                    ":orchard": PoolId::Orchard.code(),
                    ":ironwood": PoolId::Ironwood.code(),
                ],
                |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
            )
            .map_err(Error::Query)
    }

    /// Returns the lowest and highest scanned block heights.
    pub fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Error> {
        apply::block_height_extrema(&self.conn)
    }

    /// Returns a read-only handle on the underlying connection.
    ///
    /// Exposed so tests and the layers above can run queries this crate does
    /// not yet wrap. It is not a general escape hatch: writes should go through
    /// [`Self::transactionally`] so they inherit its all-or-nothing guarantee.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Rewrites unqualified table names in derived DDL to the attached schema.
///
/// The DDL is authored unqualified so it reads as ordinary SQL and can be
/// checked against a plain SQLite session.
fn qualify(stmt: &str) -> String {
    stmt.replacen("CREATE TABLE IF NOT EXISTS ", &format!("CREATE TABLE IF NOT EXISTS {CACHE_SCHEMA}."), 1)
        .replacen("CREATE INDEX IF NOT EXISTS ", &format!("CREATE INDEX IF NOT EXISTS {CACHE_SCHEMA}."), 1)
}
