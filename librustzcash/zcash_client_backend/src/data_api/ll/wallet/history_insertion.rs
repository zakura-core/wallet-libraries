//! Inserting a history range scanned after the chain tip. Most of the tree work `put_blocks` would
//! do there leaves nothing behind: checkpoints its trees prune in the same call, and note-free
//! shards already stored as their downloaded roots. This module decides what to leave out and
//! checks a sample of those roots; `put_blocks` calls into it where it decides what to insert and
//! after the update.

use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    ops::RangeInclusive,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use incrementalmerkletree::{Address, Level};
use shardtree::RetentionFlags;

use super::*;

/// Whether every pool's tree would prune checkpoints at `heights` as soon as [`update_tree`]
/// inserted them; see [`checkpoints_pruned_on_insert`]. Anchor retention keeps the checkpoints it
/// retains, so a range containing one of its heights never qualifies.
pub(super) fn checkpoints_pruned_on_insert_in_all_pools<DbT, SE, TE>(
    wallet_db: &mut DbT,
    anchor_retention: Option<&AnchorRetention>,
    heights: &RangeInclusive<BlockHeight>,
) -> Result<bool, PutBlocksError<SE, TE>>
where
    DbT: WalletCommitmentTrees<Error = TE>,
{
    if anchor_retention
        .is_some_and(|retention| !retention.retained_in_range(heights.clone()).is_empty())
    {
        return Ok(false);
    }
    if !wallet_db.with_sapling_tree_mut(|tree| {
        checkpoints_pruned_on_insert(tree, heights).map_err(PutBlocksError::ShardTree)
    })? {
        return Ok(false);
    }
    #[cfg(feature = "orchard")]
    {
        if !wallet_db.with_orchard_tree_mut(|tree| {
            checkpoints_pruned_on_insert(tree, heights).map_err(PutBlocksError::ShardTree)
        })? {
            return Ok(false);
        }
        if wallet_db.with_ironwood_tree_mut(|tree| {
            checkpoints_pruned_on_insert(tree, heights).map_err(PutBlocksError::ShardTree)
        })? == Some(false)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether [`ShardTree::insert_tree`] would prune checkpoints at `heights` as soon as it added
/// them: none of `heights` is retained, and the tree already holds `max_checkpoints` unretained
/// checkpoints above them, which pruning keeps in preference to older ones.
fn checkpoints_pruned_on_insert<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    heights: &RangeInclusive<BlockHeight>,
) -> Result<bool, ShardTreeError<S::Error>>
where
    S: ShardStore<CheckpointId = BlockHeight>,
    S::H: Clone + PartialEq + Hashable,
{
    let store = tree.store();
    let retained = store
        .retained_checkpoints()
        .map_err(ShardTreeError::Storage)?;
    if retained.range(heights.clone()).next().is_some() {
        return Ok(false);
    }
    let checkpoint_count = store.checkpoint_count().map_err(ShardTreeError::Storage)?;
    if checkpoint_count < tree.max_checkpoints() {
        return Ok(false);
    }
    let mut newer = 0;
    store
        .for_each_checkpoint(checkpoint_count, |id, _| {
            if id > heights.end() && !retained.contains(id) {
                newer += 1;
            }
            Ok(())
        })
        .map_err(ShardTreeError::Storage)?;
    Ok(newer >= tree.max_checkpoints())
}

/// How often [`put_blocks`] builds a shard it could leave out, to check the root stored for it:
/// about one shard in this many.
const STORED_ROOT_AUDIT_RATE: u64 = 16;

/// See [`stored_root_mismatches`].
pub(super) static STORED_ROOT_MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// The number of shards, since the process started, whose root computed from scanned note
/// commitments differed from the root the tree stored for them, such as a downloaded subtree root.
///
/// Once this is nonzero, [`put_blocks`] leaves no more shards out of the tree update for the rest
/// of the process, for every wallet database, and builds them as it otherwise would. A mismatch
/// neither fails the scan nor replaces the stored root.
pub fn stored_root_mismatches() -> u64 {
    STORED_ROOT_MISMATCHES.load(Ordering::Relaxed)
}

/// Whether [`put_blocks`] builds and checks the shard at `index` although it could leave it out:
/// about one shard in [`STORED_ROOT_AUDIT_RATE`], chosen with a key drawn once per process, so that
/// a server cannot tell which shards will be checked.
pub(super) fn audit_sample(index: u64) -> bool {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    KEY.get_or_init(RandomState::new)
        .hash_one(index)
        .is_multiple_of(STORED_ROOT_AUDIT_RATE)
}

/// The shards of a range that the tree stores as their roots alone; see [`shards_stored_as_root`].
pub(super) struct StoredRootShards<H> {
    /// Indices of the shards left out of the insertion.
    pub(super) left_out: Vec<u64>,
    /// The shards built anyway, each with the root stored for it, to check once they are inserted.
    pub(super) audited: Vec<(u64, H)>,
}

impl<H> Default for StoredRootShards<H> {
    fn default() -> Self {
        Self {
            left_out: vec![],
            audited: vec![],
        }
    }
}

/// Finds the shards that [`shards_stored_as_root`] allows to be left out of inserting
/// `commitments`, writes each back to the store unchanged, and returns them with the shards to
/// check after the insertion.
///
/// Inserting such a shard would write it as the same single leaf, and a store may record that
/// write; the SQLite store, for one, keeps a separate root hash only for a shard whose root is a
/// parent node. Writing the shard back leaves the store as inserting it would have.
pub(super) fn leave_out_shards_stored_as_root<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
    start: Position,
    commitments: &[Option<(S::H, Retention<BlockHeight>)>],
    leave_out_allowed: bool,
    audited: impl Fn(u64) -> bool,
) -> Result<StoredRootShards<S::H>, ShardTreeError<S::Error>>
where
    S: ShardStore<CheckpointId = BlockHeight>,
    S::H: Clone + PartialEq + Hashable,
{
    let (left_out, audited) =
        shards_stored_as_root(tree, start, commitments, leave_out_allowed, audited)?;
    let mut indices = Vec::with_capacity(left_out.len());
    for shard in left_out {
        indices.push(shard.root_addr().index());
        tree.store_mut()
            .put_shard(shard)
            .map_err(ShardTreeError::Storage)?;
    }
    Ok(StoredRootShards {
        left_out: indices,
        audited,
    })
}

/// The shards that lie wholly inside `commitments`, which start at `start`, and are stored in
/// `tree` as a single ephemeral leaf: their root alone. Returns the shards that can be left out of
/// the insertion, and the others with their stored roots.
///
/// A shard holding only `Ephemeral` leaves can be left out: inserting its commitments would
/// compute its root and leave the shard collapsed to a single leaf again. Insertion does not check
/// the computed root against the stored one, and the tree computes its root above the shards from
/// the roots `put_*_subtree_roots` caches there either way, so leaving the shard out trusts the
/// stored root no more than inserting it does.
///
/// The others are built: shards holding a leaf to keep, the shards for which `audited` returns
/// true, and every shard unless `leave_out_allowed`. [`count_stored_root_mismatches`] checks their
/// stored roots after the insertion.
#[allow(clippy::type_complexity)]
fn shards_stored_as_root<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    start: Position,
    commitments: &[Option<(S::H, Retention<BlockHeight>)>],
    leave_out_allowed: bool,
    audited: impl Fn(u64) -> bool,
) -> Result<(Vec<LocatedPrunableTree<S::H>>, Vec<(u64, S::H)>), ShardTreeError<S::Error>>
where
    S: ShardStore<CheckpointId = BlockHeight>,
    S::H: Clone + PartialEq + Hashable,
{
    let shard_size = 1u64 << SHARD_HEIGHT;
    let start = u64::from(start);
    let end = start + commitments.len() as u64;
    let mut left_out = vec![];
    let mut checked = vec![];
    for index in start.div_ceil(shard_size)..end / shard_size {
        let Some(shard) = tree
            .store()
            .get_shard(Address::from_parts(Level::from(SHARD_HEIGHT), index))
            .map_err(ShardTreeError::Storage)?
        else {
            continue;
        };
        let stored_root = match (**shard.root()).leaf_value() {
            Some((root, flags)) if *flags == RetentionFlags::EPHEMERAL => root.clone(),
            _ => continue,
        };
        let first = usize::try_from(index * shard_size - start).expect("within commitments");
        let note_free = commitments[first..first + shard_size as usize]
            .iter()
            .all(|leaf| matches!(leaf, Some((_, Retention::Ephemeral))));
        if note_free && leave_out_allowed && !audited(index) {
            left_out.push(shard);
        } else {
            checked.push((index, stored_root));
        }
    }
    Ok((left_out, checked))
}

/// Compares each shard's root, computed from the commitments just inserted, with the root that was
/// stored for it, and counts a mismatch in `mismatches`.
///
/// Insertion keeps a stored root as the annotation of a shard that does not collapse to a leaf, so
/// the root is computed without it.
pub(super) fn count_stored_root_mismatches<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<S, DEPTH, SHARD_HEIGHT>,
    shards: &[(u64, S::H)],
    mismatches: &AtomicU64,
) -> Result<(), ShardTreeError<S::Error>>
where
    S: ShardStore<CheckpointId = BlockHeight>,
    S::H: Clone + PartialEq + Hashable,
{
    for (index, stored_root) in shards {
        let shard = tree
            .store()
            .get_shard(Address::from_parts(Level::from(SHARD_HEIGHT), *index))
            .map_err(ShardTreeError::Storage)?;
        let computed = shard.and_then(|shard| {
            shard
                .reannotate_root(None)
                .root_hash(Position::from((index + 1) << SHARD_HEIGHT))
                .ok()
        });
        if computed.is_some_and(|computed| &computed != stored_root) {
            mismatches.fetch_add(1, Ordering::Relaxed);
            warn!(
                "The root of shard {index} computed from scanned note commitments differs from the \
                 root stored for it; no more shards will be left out of note commitment tree updates"
            );
        }
    }
    Ok(())
}

/// [`build_subtrees`] for the commitments outside the shards in `left_out`: ascending indices of
/// shards that lie wholly inside `commitments`, which start at `start`.
pub(super) fn build_subtrees_except<H, const SHARD_HEIGHT: u8>(
    start: Position,
    commitments: &mut [Option<(H, Retention<BlockHeight>)>],
    chunk_size: usize,
    left_out: &[u64],
) -> Vec<(LocatedPrunableTree<H>, BTreeMap<BlockHeight, Position>)>
where
    H: Clone + PartialEq + Hashable + Send + Sync,
{
    let shard_size = 1u64 << SHARD_HEIGHT;
    let start = u64::from(start);
    let end = start + commitments.len() as u64;
    let mut segments = vec![];
    let mut from = start;
    for index in left_out {
        segments.push(from..index * shard_size);
        from = (index + 1) * shard_size;
    }
    segments.push(from..end);
    segments
        .into_iter()
        .filter(|segment| !segment.is_empty())
        .flat_map(|segment| {
            let first = usize::try_from(segment.start - start).expect("within commitments");
            let last = usize::try_from(segment.end - start).expect("within commitments");
            build_subtrees::<H, SHARD_HEIGHT>(
                Position::from(segment.start),
                &mut commitments[first..last],
                chunk_size,
            )
        })
        .collect()
}

/// Replaces `Checkpoint` retention with the retention the leaf has once its checkpoint is removed.
pub(super) fn drop_checkpoint_retention<H>(
    commitments: &mut [Option<(H, Retention<BlockHeight>)>],
) {
    for (_, retention) in commitments.iter_mut().flatten() {
        if let Retention::Checkpoint { marking, .. } = retention {
            *retention = match marking {
                Marking::Marked => Retention::Marked,
                Marking::Reference => Retention::Reference,
                Marking::None => Retention::Ephemeral,
            };
        }
    }
}

#[cfg(test)]
mod tests;
