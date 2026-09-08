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
pub mod enhance;
mod error;
pub mod gap;
mod hash;
mod report;
pub mod retrieval;
mod scan_queue;
pub mod schema;
pub mod status;
pub mod transparent;
pub mod transparent_keys;
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
pub use apply::{StoredNote, SubtreeRoot};
pub use error::{Error, TreeError, VersionKind};
pub use gap::{GapLimits, GapState};
pub use report::{Balance, HistoryEntry, PoolAmounts, SpendableUtxo, TransparentSpendPolicy};
pub use scan_queue::VERIFY_LOOKAHEAD;
pub use transparent::{ScriptCoverage, TransparentState};

/// How deeply a transparent output must be buried before it is spendable.
///
/// Shielded notes use witness stability for this, which has no transparent
/// analogue: there is no commitment tree and nothing to invalidate. Depth is
/// the whole of the guarantee, so it is stated here rather than implied.
pub const MIN_TRANSPARENT_CONFIRMATIONS: u32 = 10;
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
        //
        // Set on *both* schemas. Journal mode and synchronous are per-database,
        // not per-connection, and `cache` carries essentially all the write
        // traffic — blocks, notes, and the commitment trees. Setting them on
        // `main` alone, which is what an unqualified pragma does, left the busy
        // half of the wallet on the rollback journal.
        //
        // An in-memory database reports `memory` and ignores the request; that
        // is not an error and the tests rely on it.
        for schema in [None, Some(CACHE_SCHEMA)] {
            conn.pragma_update(schema, "journal_mode", "WAL")?;
            conn.pragma_update(schema, "synchronous", "NORMAL")?;
        }

        // A batch rewrites whole shards — up to 2^16 leaves each — so the page
        // cache is doing real work between statements. The default of 2 MiB is
        // sized for a connection that reads a row at a time. Negative means KiB
        // rather than pages, so this is 64 MiB regardless of page size.
        conn.pragma_update(None, "cache_size", -65_536)?;
        // Sorting and the temporary b-trees the shard queries build stay in
        // memory rather than spilling to a file.
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        // Writes are serialised by this type owning the only connection, so
        // nothing here contends today. The timeout is for the reader connection
        // a UI will open: without it, the loser of a lock race gets an immediate
        // `SQLITE_BUSY` rather than waiting the moment the other side needs.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;

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
            (
                "detection_version",
                DETECTION_VERSION,
                VersionKind::Detection,
            ),
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
        let id =
            self.transactionally(|tx| accounts::create(tx, params, seed, account_index, birthday))?;
        // A transparent output is recognised only if its address was derived
        // *before* the block carrying it is scanned — there is no trial
        // decryption to find one afterwards. An account whose window was never
        // filled watches nothing, so this is not an optimisation.
        self.maintain_transparent_addresses(params, id, &GapLimits::default())?;
        Ok(id)
    }

    /// Imports a watch-only account from a unified full viewing key.
    pub fn import_account<P: Parameters>(
        &mut self,
        params: &P,
        ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
        birthday: BlockHeight,
    ) -> Result<zakura_wallet_core::AccountId, Error> {
        let id = self.transactionally(|tx| accounts::import(tx, params, ufvk, birthday))?;
        self.maintain_transparent_addresses(params, id, &GapLimits::default())?;
        Ok(id)
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
    ) -> Result<(zcash_keys::address::UnifiedAddress, zip32::DiversifierIndex), Error> {
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

    /// Derives and records however many transparent addresses are needed to
    /// keep a full window of unused ones ahead of the used ones.
    ///
    /// Must be called before scanning can find anything transparent, and again
    /// whenever an address is used. There is no trial decryption for a
    /// transparent output: the wallet sees one only if it derived the address
    /// first, so an unfilled window is money it will never notice arriving.
    ///
    /// Returns how many addresses were added.
    pub fn maintain_transparent_addresses<P: Parameters>(
        &mut self,
        params: &P,
        account: zakura_wallet_core::AccountId,
        limits: &GapLimits,
    ) -> Result<usize, Error> {
        let Some(stored) = self.account(params, account)? else {
            return Err(Error::UnknownAccount(account));
        };
        let Some(keys) = transparent_keys::TransparentKeys::derive(&stored.ufvk) else {
            // A watch-only shielded account has no transparent addresses to
            // watch, which is a legitimate wallet rather than a failure.
            return Ok(0);
        };

        let mut added = 0;
        for scope in [
            zakura_wallet_core::KeyScope::External,
            zakura_wallet_core::KeyScope::Internal,
        ] {
            let indices = self.addresses_to_generate(account, scope, limits)?;
            for index in indices {
                let Some(derived) = keys.address(params, scope, index)? else {
                    continue;
                };
                self.transactionally(|tx| {
                    gap::record_address(
                        tx,
                        account,
                        scope,
                        index,
                        &derived.encoded,
                        &derived.script,
                    )
                })?;
                added += 1;
            }
        }
        Ok(added)
    }

    /// Builds the transparent watch set from the wallet's stored addresses.
    ///
    /// Every derived address, not just the unused window ahead of them: this
    /// wallet matches scripts locally, so watching more costs nothing that
    /// anybody outside can observe. The narrow window the fork watches exists
    /// because it must *name* its addresses to a server to ask about them, and
    /// every name it gives is one more address that server can group into the
    /// same wallet. That constraint does not apply here, and a wider set cannot
    /// miss what a narrower one would find.
    ///
    /// Rows outside the scopes this wallet issues are refused rather than
    /// skipped. Such a row can only come from a future version, and quietly
    /// ignoring it would present a balance missing whatever it holds.
    pub fn transparent_watch(&self) -> Result<TransparentWatchData, Error> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, account_id, key_scope, transparent_script
             FROM {schema}.addresses
             WHERE transparent_script IS NOT NULL",
            schema = schema::CACHE_SCHEMA,
        ))?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, u8>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut addresses = Vec::new();
        for row in rows {
            let (id, account, scope, script) = row?;
            if zakura_wallet_core::KeyScope::from_code(scope).is_none() {
                return Err(Error::Corrupt(format!(
                    "address {id} is in key scope {scope}, which this wallet does not issue; \
                     treating it as absent would understate the balance"
                )));
            }
            addresses.push(WatchedScript {
                script,
                account: zakura_wallet_core::AccountId(account),
                address_id: id,
            });
        }

        Ok(TransparentWatchData { addresses })
    }

    /// Returns an account's watched transparent addresses, encoded.
    ///
    /// One account's addresses rather than the whole wallet's. Nothing names
    /// them to a server any more, so the separation is no longer a privacy
    /// measure; it is kept because an account is the unit a caller displays and
    /// merging two would misattribute the result.
    pub fn transparent_addresses(
        &self,
        account: zakura_wallet_core::AccountId,
    ) -> Result<Vec<String>, Error> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT transparent_address FROM {schema}.addresses
             WHERE account_id = :account AND transparent_address IS NOT NULL
             ORDER BY key_scope, transparent_child_index",
            schema = schema::CACHE_SCHEMA,
        ))?;
        let rows = stmt.query_map(named_params![":account": account.0], |row| {
            row.get::<_, String>(0)
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
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
        self.transactionally(|tx| gap::record_address(tx, account, scope, index, address, script))
    }

    /// Returns every unspent transparent output an account holds.
    ///
    /// Everything, not only what is spendable: a diagnostic that filtered by
    /// maturity and burial would answer "nothing" for a wallet that holds
    /// funds it simply cannot spend yet, which is the exact confusion it
    /// exists to remove. Address, value, and the mined height where the ledger
    /// knows one.
    pub fn transparent_utxos(
        &self,
        account: zakura_wallet_core::AccountId,
    ) -> Result<Vec<(String, u64, Option<BlockHeight>)>, Error> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT a.transparent_address, o.value, t.mined_height
             FROM {schema}.transparent_received_outputs o
             JOIN {schema}.addresses a ON a.id = o.address_id
             JOIN {schema}.transactions t ON t.id = o.transaction_id
             WHERE o.account_id = :account
               AND o.id NOT IN (
                   SELECT output_id FROM {schema}.transparent_received_output_spends)
             ORDER BY o.value DESC",
            schema = schema::CACHE_SCHEMA,
        ))?;
        let rows = stmt.query_map(named_params![":account": account.0], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<u32>>(2)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (address, value, height) = row?;
            out.push((
                address.unwrap_or_default(),
                value as u64,
                height.map(BlockHeight::from_u32),
            ));
        }
        Ok(out)
    }

    /// Returns the transparent outputs an account can spend, largest first.
    pub fn spendable_utxos(
        &self,
        account: zakura_wallet_core::AccountId,
        policy: report::TransparentSpendPolicy,
    ) -> Result<Vec<report::SpendableUtxo>, Error> {
        let Some(tip) = self.chain_tip()? else {
            // Without a tip nothing can be shown to be buried, and spending an
            // output that is not is how a reorg turns a payment into a
            // double spend.
            return Ok(Vec::new());
        };
        report::spendable_utxos(
            &self.conn,
            account,
            policy,
            MIN_TRANSPARENT_CONFIRMATIONS,
            tip,
        )
    }

    /// Returns an account's transparent balance.
    ///
    /// Confirmations are measured against the last tip the wallet was told
    /// about; without one, nothing is treated as confirmed, which understates
    /// rather than overstates.
    pub fn transparent_balance(
        &self,
        account: zakura_wallet_core::AccountId,
    ) -> Result<Balance, Error> {
        report::transparent_balance(
            &self.conn,
            account,
            MIN_TRANSPARENT_CONFIRMATIONS,
            self.chain_tip()?,
        )
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
        // The shielded pools, then transparent. Leaving transparent out — which
        // this did — reports a wallet holding transparent funds as empty.
        let transparent = self.transparent_balance(account)?;
        for pool_balance in PoolId::ALL
            .into_iter()
            .map(|pool| self.balance(account, pool))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .chain(std::iter::once(transparent))
        {
            total.spendable = (total.spendable + pool_balance.spendable).ok_or(
                Error::Serialization(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the wallet's balance overflows",
                )),
            )?;
            total.pending = (total.pending + pool_balance.pending).ok_or(Error::Serialization(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the wallet's balance overflows",
                ),
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
    pub fn suggest_scan_ranges(&self, min_priority: ScanPriority) -> Result<Vec<ScanRange>, Error> {
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
            // Recorded, not just used: whether a note's witness is beyond a
            // reorg's reach is measured against the tip of the *chain*, and the
            // apply stage has no other way to know where that is. Measuring it
            // against the batch instead would make spend eligibility depend on
            // which range happened to be scanned last.
            tx.execute(
                "INSERT INTO wallet_meta (key, value) VALUES ('chain_tip', :tip)
                 ON CONFLICT (key) DO UPDATE SET value = max(value, :tip)",
                named_params![":tip": u32::from(new_tip)],
            )?;
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

    /// Returns the hash the wallet accepted at `height`, if it scanned it.
    ///
    /// The wallet's own view of the chain, and the only one it may use to
    /// decide where something it was handed sits. A service that supplied both
    /// a range of history and the block hashes that range claims to be on could
    /// place any history anywhere; this is the other side of that check, and it
    /// answers `None` rather than guessing when the wallet has not scanned the
    /// height in question.
    pub fn accepted_block_hash(
        &self,
        height: BlockHeight,
    ) -> Result<Option<zakura_wallet_core::BlockHash>, Error> {
        let hash: Option<Vec<u8>> = self
            .conn
            .query_row(
                &format!(
                    "SELECT hash FROM {schema}.blocks WHERE height = :height",
                    schema = schema::CACHE_SCHEMA,
                ),
                named_params![":height": u32::from(height)],
                |row| row.get(0),
            )
            .optional()?;
        hash.map(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::Corrupt("a stored block hash was not 32 bytes".into()))?;
            Ok(zakura_wallet_core::BlockHash(bytes))
        })
        .transpose()
    }

    /// Returns the highest chain tip the wallet has been told about.
    ///
    /// This is the source's view of the chain, not the wallet's own scan
    /// progress, and it is what burial depth is measured against.
    pub fn chain_tip(&self) -> Result<Option<BlockHeight>, Error> {
        Ok(self.meta_u32("chain_tip")?.map(BlockHeight::from))
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
        // The tip the source last reported, which is what burial is measured
        // against. A wallet that has never been told a tip — a test applying a
        // batch directly — falls back to the batch's own end, which is
        // conservative rather than wrong: it can only under-report stability.
        let chain_tip = self.chain_tip()?;
        self.transactionally(|tx| apply::put_batch(tx, params, birthday, chain_tip, batch))
    }

    /// Folds a decrypted full transaction into the wallet.
    ///
    /// This is what recovers the two things scanning cannot: the memos on
    /// received notes, and what an outgoing payment paid and to whom. It is
    /// safe to call on a transaction the wallet has already scanned — every
    /// write fills a gap rather than replacing what is there — and safe to call
    /// on a transaction that turns out to be nothing to do with the wallet,
    /// which is stored nowhere at all.
    pub fn put_enhanced_tx<P: Parameters>(
        &mut self,
        params: &P,
        tx: &zakura_wallet_core::enhanced::EnhancedTx,
        meta: enhance::TxMeta,
    ) -> Result<enhance::PutOutcome, Error> {
        let chain_tip = self.chain_tip()?;
        self.transactionally(|conn| enhance::put_enhanced_tx(conn, params, chain_tip, tx, meta))
    }

    /// Records a transaction this wallet built, before it is broadcast.
    ///
    /// Call this *before* handing the bytes to a server, never after. A crash
    /// in between leaves a transaction spending notes the wallet still believes
    /// are free, and the next payment it builds will spend them again.
    ///
    /// It goes through the same write path enhancement uses, rather than a
    /// parallel one. The wallet can decrypt its own transaction with its own
    /// keys, so the change note and the payment out fall out of the same three
    /// arms that an enhanced transaction does — one write path, not two that
    /// have to be kept agreeing.
    ///
    /// `typed_recipient` is the address the user actually entered, which is not
    /// necessarily the one the protocol saw: a unified address carrying several
    /// receivers is recorded by the receiver that was paid. Keeping what they
    /// typed is the only way history can show them back what they asked for.
    pub fn store_sent_transaction<P: Parameters>(
        &mut self,
        params: &P,
        tx: &zakura_wallet_core::enhanced::EnhancedTx,
        fee: zcash_protocol::value::Zatoshis,
        target_height: BlockHeight,
        created_time: u32,
        typed_recipient: Option<&str>,
    ) -> Result<(), Error> {
        let chain_tip = self.chain_tip()?;
        let meta = enhance::TxMeta {
            // Not mined: it has not even been sent yet.
            mined_height: None,
            // The marker that says this installation created it. Nothing else
            // sets it, so it is what tells a payment somebody is waiting on
            // apart from one merely observed on the chain.
            target_height: Some(target_height),
            created_time: Some(created_time),
            // Exact, because the wallet chose it rather than inferring it.
            fee: Some(fee),
        };

        self.transactionally(|conn| {
            enhance::put_enhanced_tx(conn, params, chain_tip, tx, meta)?;
            if let Some(recipient) = typed_recipient {
                conn.execute(
                    "INSERT INTO main.user_metadata (txid, key, value)
                     VALUES (:txid, 'recipient', :value)
                     ON CONFLICT (txid, key) DO UPDATE SET value = :value",
                    rusqlite::named_params![
                        ":txid": tx.txid.as_ref(),
                        ":value": recipient.as_bytes(),
                    ],
                )
                .map_err(Error::Query)?;
            }
            Ok(())
        })
    }

    /// Returns outstanding retrieval requests, most urgent first.
    /// `kinds` is what the backend that will answer them can serve. Rows of
    /// any other kind are not returned, so they cannot fill the batch and
    /// starve the ones that can be answered.
    pub fn pending_requests(
        &self,
        scope: retrieval::RequestScope,
        kinds: zakura_wallet_core::retrieval::LocatorKinds,
        tip: BlockHeight,
        limit: usize,
    ) -> Result<Vec<retrieval::QueuedRequest>, Error> {
        retrieval::pending(&self.conn, scope, kinds, tip, limit)
    }

    /// Records that a request was asked at this tip, so it is not re-asked
    /// until the chain has moved.
    pub fn mark_polled(
        &self,
        locator: zakura_wallet_core::retrieval::Locator,
        tip: BlockHeight,
    ) -> Result<(), Error> {
        retrieval::mark_polled(&self.conn, locator, tip)
    }

    /// Records an attempt that produced nothing usable, bounding retries.
    pub fn mark_attempted(
        &self,
        locator: zakura_wallet_core::retrieval::Locator,
    ) -> Result<(), Error> {
        retrieval::mark_attempted(&self.conn, locator)
    }

    /// Records that a transaction can never be served privately again.
    ///
    /// Sticky by design: the disclosure this represents cannot be undone, so a
    /// later response claiming the transaction is private after all must not be
    /// able to re-protect it.
    pub fn bar_fallback(&mut self, subject: zcash_protocol::TxId) -> Result<(), Error> {
        self.transactionally(|conn| retrieval::bar_fallback(conn, subject))
    }

    /// Whether a transaction has been barred from private retrieval.
    pub fn is_fallback_barred(&self, subject: zcash_protocol::TxId) -> Result<bool, Error> {
        retrieval::is_barred(&self.conn, subject)
    }

    /// Applies what a source said about a transaction.
    ///
    /// Only ever call this with an answer a source actually gave. A transport
    /// failure is not an answer: recording one as `NotFound` would start the
    /// transaction expiring and eventually hand back the notes it spends.
    pub fn set_transaction_status(
        &mut self,
        txid: zcash_protocol::TxId,
        status: zakura_wallet_core::enhanced::TransactionStatus,
        tip: BlockHeight,
    ) -> Result<(), Error> {
        self.transactionally(|conn| status::set_transaction_status(conn, txid, status, tip))
    }

    /// Whether the wallet is waiting on a transaction it created.
    ///
    /// A cache rebuild while this is true loses the pending transaction's
    /// expiry and the record of what it spent, after which the wallet will
    /// happily spend those notes again.
    pub fn has_outstanding_sent_transaction(&self) -> Result<bool, Error> {
        let sql = format!(
            "SELECT EXISTS (
                SELECT 1 FROM {schema}.transactions t
                 WHERE t.target_height IS NOT NULL
                   AND t.mined_height IS NULL
                   AND {unexpired}
             )",
            schema = schema::CACHE_SCHEMA,
            unexpired = status::UNEXPIRED,
        );
        self.conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(Error::Query)
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

    /// Stores the enhance candidates a re-detection of one block produced.
    ///
    /// Used to recover the candidates descending recovery could not record,
    /// once the funding that makes a transaction the wallet's is known. It
    /// applies candidates and nothing else, and refuses a block that is not the
    /// one the wallet scanned at that height.
    pub fn put_rediscovered_candidates(
        &mut self,
        height: BlockHeight,
        hash: &zakura_wallet_core::BlockHash,
        block: &zakura_wallet_core::DetectedBlock,
    ) -> Result<usize, Error> {
        self.transactionally(|conn| apply::put_rediscovered_candidates(conn, height, hash, block))
    }

    /// Removes an outstanding retrieval request that has been answered.
    pub fn resolve_request(
        &mut self,
        locator: zakura_wallet_core::retrieval::Locator,
    ) -> Result<(), Error> {
        self.transactionally(|conn| retrieval::delete(conn, locator))
    }

    /// Returns every nullifier the wallet holds a note for, spent or not.
    ///
    /// Only for rediscovery. Ordinary detection must use
    /// [`Self::unspent_nullifiers`]: a spent note offered to the scanner would
    /// match a spend that already happened.
    pub fn all_nullifiers(&self) -> Result<zakura_wallet_core::NullifierSnapshot, Error> {
        apply::all_nullifiers(&self.conn)
    }

    /// Returns the wallet's unspent nullifiers, for the scanner to match spends
    /// against.
    pub fn unspent_nullifiers(&self) -> Result<zakura_wallet_core::NullifierSnapshot, Error> {
        apply::unspent_nullifiers(&self.conn)
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

    /// Returns the highest ZIP 318 anchor-grid boundary both pools can prove
    /// against.
    ///
    /// Distinct from [`Self::common_anchor_height`], which returns the most
    /// recent shared checkpoint and is what an ordinary spend wants. A pool
    /// crossing may not anchor there: the anonymity set a crossing gets is the
    /// set of transfers that chose the same boundary, so anchoring anywhere
    /// else — including somewhere more recent — is what singles a wallet out.
    ///
    /// Only retained boundaries qualify. An unretained one is inside the
    /// pruning window and will be discarded, and a crossing is often built long
    /// after its anchor height has passed.
    pub fn grid_anchor_height(&self) -> Result<Option<BlockHeight>, Error> {
        let interval = u32::from(zakura_wallet_core::ANCHOR_GRID.block_count());
        self.conn
            .query_row(
                &format!(
                    "SELECT MAX(a.checkpoint_id)
                     FROM {CACHE_SCHEMA}.tree_checkpoints a
                     JOIN {CACHE_SCHEMA}.tree_checkpoints b
                        ON b.checkpoint_id = a.checkpoint_id
                     WHERE a.pool = :orchard AND b.pool = :ironwood
                       AND a.retained_for IS NOT NULL
                       AND b.retained_for IS NOT NULL
                       AND a.checkpoint_id % :interval = 0"
                ),
                named_params![
                    ":orchard": PoolId::Orchard.code(),
                    ":ironwood": PoolId::Ironwood.code(),
                    ":interval": interval,
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
    // Every form the derived DDL uses must appear here. A statement that
    // matches none of them is not rejected — it is silently created in the
    // durable database instead, where it references tables that do not exist
    // there, and the failure surfaces much later as a confusing "no such
    // table: main.…" from an unrelated query.
    const PREFIXES: &[&str] = &[
        "CREATE TABLE IF NOT EXISTS ",
        "CREATE UNIQUE INDEX IF NOT EXISTS ",
        "CREATE INDEX IF NOT EXISTS ",
    ];

    for prefix in PREFIXES {
        if let Some(rest) = stmt.strip_prefix(prefix) {
            return format!("{prefix}{CACHE_SCHEMA}.{rest}");
        }
    }

    panic!("derived DDL statement has an unrecognised form: {stmt}");
}

/// One address the wallet watches, as plain data.
///
/// Deliberately not a scanning type: the store describes what it holds and the
/// sync engine assembles it into whatever detection wants, so storage does not
/// depend on the scanner.
#[derive(Debug, Clone)]
pub struct WatchedScript {
    /// The `scriptPubKey` that pays this address.
    pub script: Vec<u8>,
    /// Whose address it is.
    pub account: zakura_wallet_core::AccountId,
    /// The stored row, handed back on a hit so attribution needs no re-derivation.
    pub address_id: i64,
}

/// Every script the wallet watches, and whose it is.
#[derive(Debug, Clone, Default)]
pub struct TransparentWatchData {
    /// Every address the wallet has derived.
    pub addresses: Vec<WatchedScript>,
}

/// One transparent output the private ledger recovered.
#[derive(Debug, Clone)]
pub struct RecoveredOutput {
    /// The transaction that created it.
    pub txid: zcash_protocol::TxId,
    /// Its index in that transaction's outputs.
    pub output_index: u32,
    /// The `scriptPubKey` the event was indexed under.
    ///
    /// The exact raw script, not an address and not a hash of one: it is the
    /// key the event was stored under, and it is what resolves the output back
    /// to the address row that owns it.
    pub script: Vec<u8>,
    /// Its value in zatoshis.
    pub value: u64,
    /// The height the creating transaction was mined at, when the run knows it.
    ///
    /// `None` for an output the run only ever saw *spent*. A recovered spend
    /// carries the value and script of what it consumed but not the height at
    /// which that was created, and writing the spend's own height there would
    /// put a wrong number into the wallet's history in a field nothing could
    /// later contradict. The row is still written, so the spend has an output
    /// to attach to and the history shows both halves; what is not written is
    /// the height nobody knows.
    pub mined_height: Option<BlockHeight>,
    /// A height at which this output is known to have existed.
    ///
    /// Always known, even when [`Self::mined_height`] is not: an output that
    /// was spent at some height existed at that height. Used for the gap limit,
    /// where being late is harmless and being absent is not.
    pub observed_at: BlockHeight,
    /// Whether it is a coinbase output, when the run knows.
    ///
    /// `None` is *unknown*, and unknown is treated as coinbase downstream: the
    /// cost of that is a mature output the wallet declines to spend, where the
    /// opposite error builds a transaction consensus rejects.
    pub coinbase: Option<bool>,
}

/// One spend of a recovered output.
#[derive(Debug, Clone)]
pub struct RecoveredSpend {
    /// The transaction that consumed it.
    pub spending_txid: zcash_protocol::TxId,
    /// The height that transaction was mined at.
    pub height: BlockHeight,
    /// The outpoint consumed.
    pub spent_txid: zcash_protocol::TxId,
    /// The index of the consumed output.
    pub spent_output_index: u32,
}
