//! Reading the chain from the node's own database instead of over its RPC.
//!
//! The ingest path this replaces asked the node, over JSON-RPC, for a block and
//! then for every previous transaction the block's inputs spend. The node
//! answers those from its transaction index, so the work was already a database
//! read; the RPC only added a round trip, a hex encoding and a re-parse to it.
//! That cost was real: at height 344,000 a block needed 387 `getrawtransaction`
//! lookups, and the machinery built to avoid them — a bounded output cache, a
//! batching pre-pass, a pipelined fetch — existed only to hide the round trip.
//!
//! Zakura's state crate opens the same RocksDB as a **secondary instance**, so
//! this reads a running node's database without stopping it and without a copy.
//! `ZakuraDb::transaction` resolves a previous output through `tx_loc_by_hash`
//! and `tx_by_loc` as two local point lookups, which is the whole of what the
//! cache was standing in for. A block-local cache now retains validated full
//! outputs: dense early mining transactions otherwise require repeatedly
//! parsing and hashing the same large parent for different referenced outputs.
//! Its output, byte and entry bounds are independent of RocksDB's page cache.
//!
//! # What this deliberately does not read
//!
//! Zakura also maintains `tx_loc_by_transparent_addr_loc`, which is already
//! grouped by address and ordered by height — the shape a shard wants. It is
//! not usable here. That index is built with
//! `filter_map(|utxo| utxo.output.address(network))`, so it holds only P2PKH
//! and P2SH, while the transparent services index every nonempty output script that
//! does not begin with `OP_RETURN`, raw. Sourcing transactions from the address index
//! would silently drop every nonstandard script, and a wallet told it has no
//! activity does not look again.
//!
//! # Coverage: a snapshot taken at open
//!
//! A secondary instance sees what the primary had written when it opens —
//! RocksDB replays the primary's write-ahead log at open, so a block committed
//! but not yet flushed is included — and this reader never catches up
//! afterwards: it reads one fixed finalized snapshot, and a block the node
//! commits later is [`StateError::MissingBlock`] until a new reader is opened.
//! It does not see the non-finalized state at all. For a backfill of buried
//! history, bounded by [`StateReader::tip_height`], that is irrelevant; near the
//! tip a height is absent rather than wrong.
//!
//! The snapshot is not indefinitely valid. The primary keeps compacting, and a
//! secondary that has closed a table file the primary has since deleted cannot
//! reopen it; the node's reads treat that as a broken database and panic. A long
//! backfill should therefore open a fresh reader periodically, say every few
//! thousand blocks, rather than hold one for the whole run.
//!
//! # Archive databases only
//!
//! Previous outputs resolve from raw transactions, which only an archive node
//! keeps for the whole chain. A database that has pruned raw transactions, or
//! that stopped maintaining its transparent indexes as a pruned checkpoint-syncing
//! node does, is refused at open with [`StateError::NotArchive`]; the node's own
//! archive-mode open would refuse both (the first by panicking).

use super::{
    BoxError, ExtractError, FetchedBlock, Output as ChainOutput, PreviousOutputs, TransparentBlock,
};
use crate::Network;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use zakura_chain::transparent::{OutPoint, Output};
use zakura_state::{Config, HashOrHeight, PruningConfig, ReadStateService, StorageMode, ZakuraDb};

/// Why the node's database could not be read. Every field is this crate's own: the
/// node's error is carried as its message.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("could not open the Zakura state database at {path}: {reason}")]
    Open { path: PathBuf, reason: String },
    #[error("the Zakura state database at {path} is not an archive database: {reason}")]
    NotArchive { path: PathBuf, reason: &'static str },
    #[error("the state database holds no block at height {0}")]
    MissingBlock(u64),
    #[error("the state database holds no finalized tip")]
    NoTip,
    #[error("height {0} does not fit a block height")]
    HeightRange(u64),
}

/// A read-only view of a running node's finalized state.
///
/// Holds the `ReadStateService` and the non-finalized sender that
/// [`zakura_state::init_read_only`] returns even though neither is used: the
/// secondary instance's workspace is torn down when its handles drop, so
/// dropping them early would close the database this reads.
pub struct StateReader {
    db: ZakuraDb,
    _read_service: ReadStateService,
    _non_finalized: tokio::sync::watch::Sender<zakura_state::NonFinalizedState>,
}

impl StateReader {
    /// Opens a snapshot of the node's finalized state, read-only; see the module
    /// documentation for what it covers.
    ///
    /// `cache_dir` is the node's `[state] cache_dir` — the directory holding
    /// `state/vN/<network>`, not that inner path. Resolving previous outputs needs
    /// `tx_by_loc`, which only an archive node retains for the whole chain, so any
    /// other database is [`StateError::NotArchive`].
    pub fn open(cache_dir: impl AsRef<Path>, network: Network) -> Result<Self, StateError> {
        let network = network.node();
        let cache_dir = cache_dir.as_ref().to_path_buf();
        let config = Config {
            cache_dir: cache_dir.clone(),
            ephemeral: false,
            // A reader must never delete a database, and the node's own older
            // format directories are not ours to collect.
            delete_old_database: false,
            should_backup_non_finalized_state: false,
            // Opened as pruned so that the node's archive-mode checks, one of which
            // panics, do not run: this reader makes them itself, below, and refuses
            // with an error. A read-only secondary never prunes or writes, so the
            // retention window is never applied.
            storage_mode: StorageMode::Pruned(PruningConfig::default()),
            ..Config::default()
        };
        let (read_service, db, non_finalized) = zakura_state::init_read_only(config, &network)
            .map_err(|error| StateError::Open {
                path: cache_dir.clone(),
                reason: error.to_string(),
            })?;
        if let Some(reason) = archive_refusal(
            db.lowest_retained_height().is_some(),
            db.transparent_indexes_skipped_from().is_some(),
        ) {
            return Err(StateError::NotArchive {
                path: cache_dir,
                reason,
            });
        }
        Ok(Self {
            db,
            _read_service: read_service,
            _non_finalized: non_finalized,
        })
    }

    /// The highest finalized height the secondary can see.
    pub fn tip_height(&self) -> Result<u64, StateError> {
        self.db
            .finalized_tip_height()
            .map(|height| u64::from(height.0))
            .ok_or(StateError::NoTip)
    }

    /// The hash of a finalized block, in protocol byte order.
    pub fn block_hash(&self, height: u64) -> Result<[u8; 32], StateError> {
        let height = to_height(height)?;
        self.db
            .hash(height)
            .map(|hash| hash.0)
            .ok_or(StateError::MissingBlock(u64::from(height.0)))
    }

    /// The full finalized block at `height`.
    pub fn fetch_block(&self, height: u64) -> Result<FetchedBlock, StateError> {
        self.db
            .block(HashOrHeight::Height(to_height(height)?))
            .map(FetchedBlock)
            .ok_or(StateError::MissingBlock(height))
    }

    /// The header time of a finalized block, as the miner stamped it.
    ///
    /// Block times are not monotone — consensus only requires each to exceed
    /// the median of the eleven before it — so a caller deriving a calendar
    /// boundary must search a window, not a single crossing.
    /// Returned in Unix seconds.
    pub fn block_time(&self, height: u64) -> Result<i64, StateError> {
        let block_height = to_height(height)?;
        self.db
            .block_header(HashOrHeight::Height(block_height))
            .map(|header| header.time.timestamp())
            .ok_or(StateError::MissingBlock(height))
    }

    /// One block's transparent parts, resolving spent outputs from the same database.
    ///
    /// Synchronous and self-contained: it holds no state that another height's work
    /// depends on, which is what lets a caller read several heights at once and
    /// append them in order. The RPC path cannot, because every block writes the
    /// output cache the next one reads.
    pub fn transparent_block(&self, height: u64) -> Result<TransparentBlock, ExtractError> {
        let block = self.fetch_block(height).map_err(|error| match error {
            StateError::HeightRange(height) => ExtractError::Height(height),
            _ => ExtractError::MissingBlock(height),
        })?;
        let event_height = u32::try_from(height).map_err(|_| ExtractError::Height(height))?;
        let mut previous = StatePreviousOutputs {
            db: &self.db,
            lookups: 0,
            cache_hits: 0,
            cache: BlockOutputCache::new(32_768, 8 * 1024 * 1024, 1_024),
        };
        let transactions = block.transparent(event_height, &mut previous)?;
        Ok(TransparentBlock {
            height: event_height,
            hash: block.hash(),
            parent: block.parent(),
            transactions,
            // Local database reads, not network traffic.
            lookups: previous.lookups,
            cache_hits: previous.cache_hits,
        })
    }
}

/// Why a database with these markers cannot serve every previous output, if it
/// cannot: `pruned` when it has deleted raw transactions below some height, and
/// `indexes_skipped` when a pruned checkpoint-syncing node stopped its transparent
/// indexes in it. Both are the node's own reasons for refusing an archive-mode open.
fn archive_refusal(pruned: bool, indexes_skipped: bool) -> Option<&'static str> {
    if pruned {
        Some("it has pruned raw transactions, which previous outputs resolve from")
    } else if indexes_skipped {
        Some("it was written by a pruned checkpoint-syncing node")
    } else {
        None
    }
}

fn to_height(height: u64) -> Result<zakura_chain::block::Height, StateError> {
    u32::try_from(height)
        .ok()
        .filter(|height| *height <= zakura_chain::block::Height::MAX.0)
        .map(zakura_chain::block::Height)
        .ok_or(StateError::HeightRange(height))
}

/// Resolves a spent output's locking script from the node's transaction index.
///
/// Not from `utxo_by_out_loc`: the node deletes an output from the UTXO set
/// when it is spent, and every output this resolver is asked about is one that
/// is being spent. The creating transaction is still in `tx_by_loc` on an
/// archive node, which is why the storage mode is checked when opening.
struct StatePreviousOutputs<'a> {
    db: &'a ZakuraDb,
    /// Previous-output resolutions that reached the database.
    lookups: u64,
    cache_hits: u64,
    cache: BlockOutputCache,
}

/// Full outputs of identity-checked parents, scoped to one independently
/// extracted block. Oversized parents bypass the cache; they are still resolved.
struct BlockOutputCache {
    entries: HashMap<zakura_chain::transaction::Hash, (Vec<Output>, usize)>,
    order: VecDeque<zakura_chain::transaction::Hash>,
    outputs: usize,
    bytes: usize,
    max_outputs: usize,
    max_bytes: usize,
    max_entries: usize,
}

impl BlockOutputCache {
    fn new(max_outputs: usize, max_bytes: usize, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            outputs: 0,
            bytes: 0,
            max_outputs,
            max_bytes,
            max_entries,
        }
    }

    fn get(&self, outpoint: &OutPoint) -> Option<Option<Output>> {
        self.entries
            .get(&outpoint.hash)
            .map(|(outputs, _)| outputs.get(outpoint.index as usize).cloned())
    }

    fn insert(&mut self, hash: zakura_chain::transaction::Hash, outputs: &[Output]) {
        if outputs.is_empty()
            || outputs.len() > self.max_outputs
            || self.entries.contains_key(&hash)
            || self.max_entries == 0
        {
            return;
        }
        // Charge inline outputs, script payloads, and conservative per-entry
        // bookkeeping. There is no exception for a single oversized parent.
        let Some(bytes) = outputs.iter().try_fold(128usize, |sum, output| {
            sum.checked_add(std::mem::size_of::<Output>())?
                .checked_add(output.lock_script.as_raw_bytes().len())
        }) else {
            return;
        };
        if bytes > self.max_bytes {
            return;
        }
        while self.outputs > self.max_outputs - outputs.len()
            || self.bytes > self.max_bytes - bytes
            || self.entries.len() >= self.max_entries
        {
            let oldest = self
                .order
                .pop_front()
                .expect("charged entry has eviction order");
            let (evicted, cost) = self
                .entries
                .remove(&oldest)
                .expect("ordered cache entry exists");
            self.outputs -= evicted.len();
            self.bytes -= cost;
        }
        self.outputs += outputs.len();
        self.bytes += bytes;
        self.entries.insert(hash, (outputs.to_vec(), bytes));
        self.order.push_back(hash);
    }
}

impl StatePreviousOutputs<'_> {
    fn resolve(&mut self, outpoint: &OutPoint) -> Result<Option<Output>, BoxError> {
        if let Some(output) = self.cache.get(outpoint) {
            self.cache_hits += 1;
            return Ok(output);
        }
        self.lookups += 1;
        let Some((transaction, _height, _time)) = self.db.transaction(outpoint.hash) else {
            return Ok(None);
        };
        if transaction.hash() != outpoint.hash {
            return Err("previous transaction identity mismatch".into());
        }
        self.cache.insert(outpoint.hash, transaction.outputs());
        let output = transaction.outputs().get(outpoint.index as usize).cloned();
        if output.is_none() {
            tracing::warn!(
                outpoint = %super::label(outpoint),
                outputs = transaction.outputs().len(),
                "previous transaction has no output at this index"
            );
        }
        Ok(output)
    }
}

impl PreviousOutputs for StatePreviousOutputs<'_> {
    fn previous_output(
        &mut self,
        txid: [u8; 32],
        index: u32,
    ) -> Result<Option<ChainOutput>, BoxError> {
        let outpoint = OutPoint {
            hash: zakura_chain::transaction::Hash(txid),
            index,
        };
        Ok(self.resolve(&outpoint)?.map(|output| ChainOutput {
            value: u64::from(output.value),
            script: output.lock_script.as_raw_bytes().to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::{
        amount::Amount,
        transaction::{LockTime, Transaction},
        transparent::Script,
    };

    fn transaction(tag: u8, count: usize) -> Transaction {
        Transaction::V1 {
            inputs: vec![],
            outputs: (0..count)
                .map(|n| Output {
                    value: Amount::try_from(n as i64 + 1).unwrap(),
                    lock_script: Script::new(&[0x76, tag, n as u8]),
                })
                .collect(),
            lock_time: LockTime::unlocked(),
        }
    }
    fn point(tx: &Transaction, index: u32) -> OutPoint {
        OutPoint {
            hash: tx.hash(),
            index,
        }
    }

    #[test]
    fn only_a_database_with_neither_pruning_marker_is_an_archive() {
        assert_eq!(archive_refusal(false, false), None);
        assert!(archive_refusal(true, false).is_some());
        assert!(archive_refusal(false, true).is_some());
        assert!(archive_refusal(true, true).is_some());
    }

    #[test]
    fn full_parent_outputs_preserve_values_scripts_and_missing_index() {
        let tx = transaction(1, 3);
        let mut cache = BlockOutputCache::new(10, 4096, 10);
        cache.insert(tx.hash(), tx.outputs());
        for n in 0..3 {
            assert_eq!(
                cache.get(&point(&tx, n)),
                Some(Some(tx.outputs()[n as usize].clone()))
            );
        }
        assert_eq!(cache.get(&point(&tx, 3)), Some(None));
        let missing = transaction(2, 1);
        assert_eq!(cache.get(&point(&missing, 0)), None);
        cache.insert(tx.hash(), tx.outputs());
        assert_eq!(cache.outputs, 3);
        assert_eq!(cache.order.len(), 1);
    }

    #[test]
    fn dense_parents_and_script_bytes_obey_strict_admission_bounds() {
        let tx = transaction(1, 3);
        let mut cache = BlockOutputCache::new(2, 4096, 10);
        cache.insert(tx.hash(), tx.outputs());
        assert!(cache.entries.is_empty());
        let cost = 128 + std::mem::size_of::<Output>() + 3;
        let small = transaction(2, 1);
        let mut cache = BlockOutputCache::new(10, cost, 10);
        cache.insert(small.hash(), small.outputs());
        assert_eq!(cache.bytes, cost);
        cache.insert(tx.hash(), tx.outputs());
        assert_eq!(
            cache.get(&point(&small, 0)),
            Some(Some(small.outputs()[0].clone()))
        );
        assert_eq!(cache.get(&point(&tx, 0)), None);
    }

    #[test]
    fn eviction_respects_output_byte_and_entry_limits_independently() {
        for (outputs, bytes, entries) in [
            (2, 4096, 10),
            (10, 128 + std::mem::size_of::<Output>() + 3, 10),
            (10, 4096, 1),
        ] {
            let mut cache = BlockOutputCache::new(outputs, bytes, entries);
            let first = transaction(1, 1);
            cache.insert(first.hash(), first.outputs());
            for tag in 2..20 {
                let tx = transaction(tag, 1);
                cache.insert(tx.hash(), tx.outputs());
                assert!(
                    cache.outputs <= outputs
                        && cache.bytes <= bytes
                        && cache.entries.len() <= entries
                );
                assert_eq!(
                    cache.get(&point(&tx, 0)),
                    Some(Some(tx.outputs()[0].clone()))
                );
            }
            assert_eq!(cache.get(&point(&first, 0)), None);
        }
    }
}
