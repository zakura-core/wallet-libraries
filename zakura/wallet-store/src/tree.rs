//! Note commitment tree storage, for both pools, in one implementation.
//!
//! `shardtree` persists a tree as a set of fixed-height *shards* plus a *cap*
//! (the tree above the shards), and a set of *checkpoints* recording the tree's
//! state at each block height. This module implements its
//! [`ShardStore`] interface over four tables.
//!
//! The one design decision here is that `pool` is a **column**, not part of a
//! table name. The fork carries five tables per pool across three pools and
//! reaches them by formatting the prefix into every statement; that is fifteen
//! tables and a string-templated query at every call site. Because Orchard and
//! Ironwood share their hash type and shard geometry exactly, one set of tables
//! keyed by `(pool, …)` serves both, and the pool becomes an ordinary bound
//! parameter.
//!
//! Ported from `zcash_client_sqlite::wallet::commitment_tree`, whose SQL and
//! error semantics this follows closely.

use std::{
    collections::BTreeSet,
    io::{self, Cursor},
    ops::Range,
    sync::Arc,
};

use incrementalmerkletree::{Address, Level, Position};
use rusqlite::{OptionalExtension, named_params};
use shardtree::{
    LocatedPrunableTree, PrunableTree, ShardTree,
    store::{Checkpoint, ShardStore, TreeState},
};
use zakura_wallet_core::pool::PoolId;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    error::Error,
    hash::{HashSer, read_shard, write_shard},
    schema::CACHE_SCHEMA,
};

/// The depth of an Orchard-family note commitment tree.
pub const TREE_DEPTH: u8 = 32;

/// The height of one shard, in levels.
///
/// Both pools use Orchard's geometry, so a shard holds `2^16` commitments.
pub const SHARD_HEIGHT: u8 = TREE_DEPTH / 2;

/// How many blocks of history the tree keeps checkpoints for.
///
/// A rewind can go back at most this far; beyond it, recovery is a rescan.
pub const PRUNING_DEPTH: usize = 100;

/// The commitment tree type this wallet uses, for either pool.
pub type CommitmentTree<'a> =
    ShardTree<WalletShardStore<'a>, TREE_DEPTH, SHARD_HEIGHT>;

/// A `shardtree` store backed by the wallet's unified tree tables.
///
/// Holds the pool it is reading and writing, rather than being generic over it,
/// because `shardtree` needs a concrete store type and nothing in the storage
/// layer differs between the pools.
pub struct WalletShardStore<'a> {
    conn: &'a rusqlite::Transaction<'a>,
    pool: PoolId,
}

impl<'a> WalletShardStore<'a> {
    /// Opens the store for one pool over an existing transaction.
    pub fn new(conn: &'a rusqlite::Transaction<'a>, pool: PoolId) -> Self {
        Self { conn, pool }
    }

    fn code(&self) -> u8 {
        self.pool.code()
    }
}

/// Wraps `store` in a tree that prunes checkpoints beyond [`PRUNING_DEPTH`].
pub fn tree(store: WalletShardStore<'_>) -> CommitmentTree<'_> {
    ShardTree::new(store, PRUNING_DEPTH)
}

impl ShardStore for WalletShardStore<'_> {
    type H = orchard::tree::MerkleHashOrchard;
    type CheckpointId = BlockHeight;
    type Error = Error;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        // Cached: a single `batch_insert` walks many shards, and this is the
        // read half of every one of those visits.
        self.conn
            .prepare_cached(&format!(
                "SELECT shard_data, root_hash FROM {CACHE_SCHEMA}.tree_shards
                 WHERE pool = :pool AND shard_index = :shard_index"
            ))?
            .query_row(
                named_params![":pool": self.code(), ":shard_index": shard_root.index()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?
            .map(|(shard_data, root_hash)| {
                // A shard whose contents have not been scanned is still stored
                // as a real tree: backfill records it as a single ephemeral leaf
                // holding the server-supplied root hash, so this never has to
                // reconstruct one from nothing.
                let shard_tree = read_shard(&mut Cursor::new(shard_data))?;
                let located = LocatedPrunableTree::from_parts(shard_root, shard_tree)
                    .map_err(|addr| {
                        Error::Serialization(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("stored shard contains invalid data at address {addr:?}"),
                        ))
                    })?;
                Ok(match root_hash {
                    Some(bytes) => {
                        located.reannotate_root(Some(Arc::new(Self::H::read(Cursor::new(bytes))?)))
                    }
                    None => located,
                })
            })
            .transpose()
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        self.conn
            .query_row(
                &format!(
                    "SELECT shard_index, shard_data FROM {CACHE_SCHEMA}.tree_shards
                     WHERE pool = :pool
                     ORDER BY shard_index DESC
                     LIMIT 1"
                ),
                named_params![":pool": self.code()],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(shard_index, shard_data)| {
                let shard_root = Address::from_parts(Level::from(SHARD_HEIGHT), shard_index);
                let shard_tree = read_shard(&mut Cursor::new(shard_data))?;
                LocatedPrunableTree::from_parts(shard_root, shard_tree).map_err(|addr| {
                    Error::Serialization(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("stored shard contains invalid data at address {addr:?}"),
                    ))
                })
            })
            .transpose()
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        let root_hash = subtree
            .root()
            .annotation()
            .and_then(|ann| {
                ann.as_ref().map(|rc| {
                    let mut bytes = vec![];
                    rc.write(&mut bytes)?;
                    Ok::<_, io::Error>(bytes)
                })
            })
            .transpose()
            .map_err(Error::Serialization)?;

        let mut shard_data = vec![];
        write_shard(&mut shard_data, subtree.root())?;

        let shard_index = subtree.root_addr().index();
        self.check_shard_continuity(shard_index..shard_index + 1)?;

        self.conn
            .prepare_cached(&format!(
                "INSERT INTO {CACHE_SCHEMA}.tree_shards (pool, shard_index, root_hash, shard_data)
                 VALUES (:pool, :shard_index, :root_hash, :shard_data)
                 ON CONFLICT (pool, shard_index) DO UPDATE
                 SET root_hash = :root_hash, shard_data = :shard_data"
            ))?
            .execute(named_params![
                ":pool": self.code(),
                ":shard_index": shard_index,
                ":root_hash": root_hash,
                ":shard_data": shard_data,
            ])?;

        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT shard_index FROM {CACHE_SCHEMA}.tree_shards
             WHERE pool = :pool ORDER BY shard_index"
        ))?;
        let rows = stmt.query(named_params![":pool": self.code()])?;
        rows.mapped(|row| {
            row.get::<_, u64>(0)
                .map(|i| Address::from_parts(Level::from(SHARD_HEIGHT), i))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::Query)
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Self::Error> {
        self.conn.execute(
            &format!(
                "DELETE FROM {CACHE_SCHEMA}.tree_shards
                 WHERE pool = :pool AND shard_index >= :shard_index"
            ),
            named_params![":pool": self.code(), ":shard_index": shard_index],
        )?;
        Ok(())
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        self.conn
            .query_row(
                &format!("SELECT cap_data FROM {CACHE_SCHEMA}.tree_cap WHERE pool = :pool"),
                named_params![":pool": self.code()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map_or_else(
                || Ok(PrunableTree::empty()),
                |data| read_shard(&mut Cursor::new(data)),
            )
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        let mut cap_data = vec![];
        write_shard(&mut cap_data, &cap)?;
        self.conn
            .prepare_cached(&format!(
                "INSERT INTO {CACHE_SCHEMA}.tree_cap (pool, cap_data) VALUES (:pool, :cap_data)
                 ON CONFLICT (pool) DO UPDATE SET cap_data = :cap_data"
            ))?
            .execute(named_params![":pool": self.code(), ":cap_data": cap_data])?;
        Ok(())
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        self.checkpoint_extremum("MIN")
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        self.checkpoint_extremum("MAX")
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        let existing = self.read_checkpoint(checkpoint_id)?;

        if let Some(current) = existing {
            // A checkpoint at a height we already know must describe the same
            // tree. If it does not, the chain moved and the wallet failed to
            // rewind first; overwriting would leave the tree describing a chain
            // that never existed. `Checkpoint` is not `PartialEq`, so the two
            // components it is made of are compared directly.
            let same = current.tree_state() == checkpoint.tree_state()
                && current.marks_removed() == checkpoint.marks_removed();
            return if same {
                Ok(())
            } else {
                Err(Error::CheckpointConflict { checkpoint_id })
            };
        }

        self.conn
            .prepare_cached(&format!(
                "INSERT INTO {CACHE_SCHEMA}.tree_checkpoints (pool, checkpoint_id, position)
                 VALUES (:pool, :checkpoint_id, :position)"
            ))?
            .execute(named_params![
                ":pool": self.code(),
                ":checkpoint_id": u32::from(checkpoint_id),
                ":position": checkpoint.position().map(u64::from),
            ])?;

        let mut stmt = self.conn.prepare_cached(&format!(
            "INSERT INTO {CACHE_SCHEMA}.tree_checkpoint_marks_removed
                (pool, checkpoint_id, mark_removed_position)
             VALUES (:pool, :checkpoint_id, :position)"
        ))?;
        for position in checkpoint.marks_removed() {
            stmt.execute(named_params![
                ":pool": self.code(),
                ":checkpoint_id": u32::from(checkpoint_id),
                ":position": u64::from(*position),
            ])?;
        }

        Ok(())
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        self.conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {CACHE_SCHEMA}.tree_checkpoints WHERE pool = :pool"
                ),
                named_params![":pool": self.code()],
                |row| row.get(0),
            )
            .map_err(Error::Query)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        let found = self
            .conn
            .query_row(
                &format!(
                    "SELECT checkpoint_id FROM {CACHE_SCHEMA}.tree_checkpoints
                     WHERE pool = :pool
                     ORDER BY checkpoint_id DESC
                     LIMIT 1 OFFSET :offset"
                ),
                named_params![":pool": self.code(), ":offset": checkpoint_depth],
                |row| row.get::<_, u32>(0).map(BlockHeight::from),
            )
            .optional()?;

        found
            .map(|id| {
                Ok((
                    id,
                    self.read_checkpoint(id)?
                        .expect("the checkpoint just found is still present"),
                ))
            })
            .transpose()
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        self.read_checkpoint(*checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        self.for_each_checkpoint(limit, callback)
    }

    fn for_each_checkpoint<F>(&self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT checkpoint_id FROM {CACHE_SCHEMA}.tree_checkpoints
             WHERE pool = :pool
             ORDER BY checkpoint_id
             LIMIT :limit"
        ))?;
        let ids = stmt
            .query(named_params![":pool": self.code(), ":limit": limit])?
            .mapped(|row| row.get::<_, u32>(0).map(BlockHeight::from))
            .collect::<Result<Vec<_>, _>>()?;

        for id in ids {
            let checkpoint = self
                .read_checkpoint(id)?
                .expect("the checkpoint just listed is still present");
            callback(&id, &checkpoint)?;
        }
        Ok(())
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        match self.read_checkpoint(*checkpoint_id)? {
            Some(mut checkpoint) => {
                update(&mut checkpoint)?;
                self.remove_checkpoint(checkpoint_id)?;
                self.add_checkpoint(*checkpoint_id, checkpoint)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn remove_checkpoint(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        // The cascade on `tree_checkpoint_marks_removed` clears the marks, but
        // only if foreign keys are enforced; the connection enables them.
        self.conn.execute(
            &format!(
                "DELETE FROM {CACHE_SCHEMA}.tree_checkpoints
                 WHERE pool = :pool AND checkpoint_id = :checkpoint_id"
            ),
            named_params![":pool": self.code(), ":checkpoint_id": u32::from(*checkpoint_id)],
        )?;
        Ok(())
    }

    fn add_retained_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        // Retention is a column on the checkpoint rather than a separate table.
        // A retained checkpoint must exist first: retaining a height the tree
        // does not know about would silently do nothing.
        let updated = self.conn.execute(
            &format!(
                "UPDATE {CACHE_SCHEMA}.tree_checkpoints SET retained_for = 1
                 WHERE pool = :pool AND checkpoint_id = :checkpoint_id"
            ),
            named_params![":pool": self.code(), ":checkpoint_id": u32::from(checkpoint_id)],
        )?;

        if updated == 0 {
            // Record the intent anyway, with no position: the tree does not yet
            // reach this height, and the retention must not be forgotten before
            // it does.
            self.conn.execute(
                &format!(
                    "INSERT INTO {CACHE_SCHEMA}.tree_checkpoints
                        (pool, checkpoint_id, position, retained_for)
                     VALUES (:pool, :checkpoint_id, NULL, 1)
                     ON CONFLICT (pool, checkpoint_id) DO UPDATE SET retained_for = 1"
                ),
                named_params![":pool": self.code(), ":checkpoint_id": u32::from(checkpoint_id)],
            )?;
        }
        Ok(())
    }

    fn remove_retained_checkpoint(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        self.conn.execute(
            &format!(
                "UPDATE {CACHE_SCHEMA}.tree_checkpoints SET retained_for = NULL
                 WHERE pool = :pool AND checkpoint_id = :checkpoint_id"
            ),
            named_params![":pool": self.code(), ":checkpoint_id": u32::from(*checkpoint_id)],
        )?;
        Ok(())
    }

    fn retained_checkpoints(&self) -> Result<BTreeSet<Self::CheckpointId>, Self::Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT checkpoint_id FROM {CACHE_SCHEMA}.tree_checkpoints
             WHERE pool = :pool AND retained_for IS NOT NULL"
        ))?;
        let rows = stmt.query(named_params![":pool": self.code()])?;
        rows.mapped(|row| row.get::<_, u32>(0).map(BlockHeight::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Error::Query)
    }

    fn truncate_checkpoints_retaining(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        self.conn.execute(
            &format!(
                "DELETE FROM {CACHE_SCHEMA}.tree_checkpoints
                 WHERE pool = :pool AND checkpoint_id > :checkpoint_id"
            ),
            named_params![":pool": self.code(), ":checkpoint_id": u32::from(*checkpoint_id)],
        )?;

        // The retained checkpoint itself survives, but its marks do not: the
        // notes whose marks were removed after it are being restored.
        self.conn.execute(
            &format!(
                "DELETE FROM {CACHE_SCHEMA}.tree_checkpoint_marks_removed
                 WHERE pool = :pool AND checkpoint_id = :checkpoint_id"
            ),
            named_params![":pool": self.code(), ":checkpoint_id": u32::from(*checkpoint_id)],
        )?;

        Ok(())
    }
}

impl WalletShardStore<'_> {
    fn checkpoint_extremum(&self, agg: &str) -> Result<Option<BlockHeight>, Error> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {agg}(checkpoint_id) FROM {CACHE_SCHEMA}.tree_checkpoints
                     WHERE pool = :pool"
                ),
                named_params![":pool": self.code()],
                |row| {
                    row.get::<_, Option<u32>>(0)
                        .map(|opt| opt.map(BlockHeight::from))
                },
            )
            .map_err(Error::Query)
    }

    fn read_checkpoint(&self, checkpoint_id: BlockHeight) -> Result<Option<Checkpoint>, Error> {
        let position = self
            .conn
            .query_row(
                &format!(
                    "SELECT position FROM {CACHE_SCHEMA}.tree_checkpoints
                     WHERE pool = :pool AND checkpoint_id = :checkpoint_id"
                ),
                named_params![":pool": self.code(), ":checkpoint_id": u32::from(checkpoint_id)],
                |row| {
                    row.get::<_, Option<u64>>(0)
                        .map(|opt| opt.map(Position::from))
                },
            )
            .optional()?;

        position
            .map(|position| {
                Ok(Checkpoint::from_parts(
                    position.map_or(TreeState::Empty, TreeState::AtPosition),
                    self.read_marks_removed(checkpoint_id)?,
                ))
            })
            .transpose()
    }

    fn read_marks_removed(
        &self,
        checkpoint_id: BlockHeight,
    ) -> Result<BTreeSet<Position>, Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT mark_removed_position FROM {CACHE_SCHEMA}.tree_checkpoint_marks_removed
             WHERE pool = :pool AND checkpoint_id = :checkpoint_id"
        ))?;
        let rows = stmt.query(named_params![
            ":pool": self.code(),
            ":checkpoint_id": u32::from(checkpoint_id),
        ])?;
        rows.mapped(|row| row.get::<_, u64>(0).map(Position::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Error::Query)
    }

    /// Rejects an insertion that would leave a hole in the shard sequence.
    ///
    /// Shards must be contiguous: a gap means the region beyond it cannot be
    /// reached from the tree's root, and every witness past the gap would be
    /// unbuildable.
    fn check_shard_continuity(&self, proposed: Range<u64>) -> Result<(), Error> {
        // Cached: this runs on *every* `put_shard`, so a batch that touches many
        // shards re-prepares an aggregate query once per shard written. The
        // aggregate itself is served from the primary key index.
        let bounds = self
            .conn
            .prepare_cached(&format!(
                "SELECT MIN(shard_index), MAX(shard_index) FROM {CACHE_SCHEMA}.tree_shards
                 WHERE pool = :pool"
            ))?
            .query_row(named_params![":pool": self.code()], |row| {
                Ok((row.get::<_, Option<u64>>(0)?, row.get::<_, Option<u64>>(1)?))
            })?;

        if let (Some(min), Some(max)) = bounds {
            let existing = min..(max + 1);
            // Overlapping or directly adjacent ranges are fine; only a gap on
            // either side is a discontinuity.
            if existing.start > proposed.end || proposed.start > existing.end {
                return Err(Error::ShardDiscontinuity {
                    attempted: proposed,
                    existing,
                });
            }
        }

        Ok(())
    }
}
