//! Lower inclusion paths for companion witness tables.
//!
//! A payload holds a payment's siblings inside its Ironwood shard of `2^16` leaves, supplied
//! only where they are complete at the payload's construction tree size (see
//! [`crate::wire::supplied`]). Paths authenticate inclusion only against a root the wallet
//! accepted from its own chain, never against a root the service supplies.
use crate::{
    Error, Hash,
    wire::{LOWER_LEVELS, PAYLOAD_BYTES, encode_payload},
};
use incrementalmerkletree::Hashable;
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};

/// Combine two canonical note-tree nodes at a level counted from the leaves.
///
/// Level 0 combines leaves; level 31 produces the depth-32 tree root. Returns
/// [`Error::Malformed`] for a level outside `0..32` or a noncanonical node.
/// Hashing uses the protocol's Orchard Sinsemilla operation without changing its
/// level domain separation. The returned bytes alone do not authenticate a tree.
pub fn combine(level: u8, left: &Hash, right: &Hash) -> Result<Hash, Error> {
    if level >= 32 {
        return Err(Error::Malformed);
    }
    let left = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(left))
        .ok_or(Error::Malformed)?;
    let right = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(right))
        .ok_or(Error::Malformed)?;
    Ok(MerkleHashOrchard::combine(level.into(), &left, &right).to_bytes())
}

/// The empty subtree root at a height counted from the leaves.
///
/// Height 0 is the uncommitted leaf; height 32 is the empty full-tree root.
/// Returns [`Error::Malformed`] for a height greater than 32.
pub fn empty_root(height: u8) -> Result<Hash, Error> {
    if height > 32 {
        return Err(Error::Malformed);
    }
    Ok(MerkleHashOrchard::empty_root(height.into()).to_bytes())
}

/// Leaves in one Ironwood shard.
pub const SHARD_LEAVES: u64 = 1 << LOWER_LEVELS;

/// The complete nodes of one Ironwood shard's commitments, from which every payment in it
/// gets its lower path. Appending leaves only adds nodes, so a publisher extends the filling
/// shard incrementally and keeps completed shards' paths final. About 64 bytes per leaf.
pub struct ShardPaths {
    shard: u32,
    /// `levels[l]` holds the shard's complete subtree roots at level `l`, left to right.
    levels: Vec<Vec<MerkleHashOrchard>>,
}

impl ShardPaths {
    /// An empty Ironwood shard `shard`, which starts at position `shard << 16`.
    pub fn new(shard: u32) -> Self {
        Self {
            shard,
            levels: vec![Vec::new(); usize::from(LOWER_LEVELS) + 1],
        }
    }

    /// Appends the shard's next commitments in chain order. Fails without changing the
    /// shard for a noncanonical commitment or more than [`SHARD_LEAVES`] leaves in total.
    pub fn extend(&mut self, commitments: &[Hash]) -> Result<(), Error> {
        if self.levels[0].len() as u64 + commitments.len() as u64 > SHARD_LEAVES {
            return Err(Error::Capacity);
        }
        let leaves = commitments
            .iter()
            .map(|cmx| {
                Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(cmx))
                    .map(|c| MerkleHashOrchard::from_cmx(&c))
                    .ok_or(Error::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.levels[0].extend(leaves);
        for level in 0..usize::from(LOWER_LEVELS) {
            let (lower, upper) = self.levels.split_at_mut(level + 1);
            let (children, parents) = (&lower[level], &mut upper[0]);
            while children.len() >= 2 * (parents.len() + 1) {
                let i = parents.len() * 2;
                parents.push(MerkleHashOrchard::combine(
                    (level as u8).into(),
                    &children[i],
                    &children[i + 1],
                ));
            }
        }
        Ok(())
    }

    /// The global tree size these leaves describe: the shard's start plus its leaves.
    pub fn tree_size(&self) -> u64 {
        (u64::from(self.shard) << LOWER_LEVELS) + self.levels[0].len() as u64
    }

    /// The full shard's root once all [`SHARD_LEAVES`] leaves are present.
    pub fn root(&self) -> Option<Hash> {
        self.levels[usize::from(LOWER_LEVELS)]
            .first()
            .map(|h| h.to_bytes())
    }

    /// The encoded lower path of `position` at [`Self::tree_size`], supplying exactly its
    /// complete siblings. [`Error::Coverage`] for a position outside these leaves.
    pub fn payload(&self, position: u64) -> Result<[u8; PAYLOAD_BYTES], Error> {
        let start = u64::from(self.shard) << LOWER_LEVELS;
        let local = position
            .checked_sub(start)
            .filter(|local| *local < self.levels[0].len() as u64)
            .ok_or(Error::Coverage)?;
        let siblings = std::array::from_fn(|level| {
            self.levels[level]
                .get(((local >> level) ^ 1) as usize)
                .map(|h| h.to_bytes())
        });
        encode_payload(&siblings, position, self.tree_size()).map_err(|_| Error::Malformed)
    }
}

/// The lower paths of `positions`, in order, in a tree of exactly `commitments`, rebuilding
/// each referenced Ironwood shard. Publishers that keep shards between publications extend
/// [`ShardPaths`] instead. [`Error::Coverage`] for a position outside the tree.
pub fn payloads(
    commitments: &[Hash],
    positions: &[u64],
) -> Result<Vec<[u8; PAYLOAD_BYTES]>, Error> {
    let mut shards = std::collections::BTreeMap::new();
    positions
        .iter()
        .map(|&position| {
            if position >= commitments.len() as u64 {
                return Err(Error::Coverage);
            }
            let shard = position >> LOWER_LEVELS;
            let paths = match shards.entry(shard) {
                std::collections::btree_map::Entry::Occupied(found) => found.into_mut(),
                std::collections::btree_map::Entry::Vacant(slot) => {
                    let start = (shard << LOWER_LEVELS) as usize;
                    let end = commitments.len().min(start + SHARD_LEAVES as usize);
                    let mut paths = ShardPaths::new(shard as u32);
                    paths.extend(&commitments[start..end])?;
                    slot.insert(paths)
                }
            };
            paths.payload(position)
        })
        .collect()
}
