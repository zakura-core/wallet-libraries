//! Witness reconstruction from two PIR rows and the public cap, and local
//! witness updates from the per-block frontier.
//!
//! A note's authentication path has three tiers: levels 0 to 8 from the
//! `witness` row of its sub-shard (256 leaves), levels 8 to 16 from the
//! `witness-roots` row of its shard (256 completed sub-shard roots, the
//! frontier sub-shard's root coming from the cap), and levels 16 to 32 from
//! the cap's shard roots. A note in a sealed shard fetches its rows once;
//! frontier updates move the path to newer anchors locally.

use crate::{FrontierUpdate, WitnessCap};
use incrementalmerkletree::{Hashable, Level, MerklePath, Position};
use orchard::tree::MerkleHashOrchard;

pub type Hash = [u8; 32];

pub const TREE_DEPTH: usize = 32;
pub const SUBSHARD_HEIGHT: u8 = 8;
pub const SHARD_HEIGHT: u8 = 16;
pub const SUBSHARD_LEAVES: usize = 1 << SUBSHARD_HEIGHT;
pub const SUBSHARDS_PER_SHARD: usize = 1 << (SHARD_HEIGHT - SUBSHARD_HEIGHT);

/// Failures while reconstructing or updating a witness.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// The cap or a row was malformed.
    #[error("malformed witness material: {0}")]
    Malformed(&'static str),
    /// The position is beyond the anchor's tree size.
    #[error("position is beyond the anchor's tree size")]
    OutsideTree,
    /// The reconstructed path does not reach the cap's tree root.
    #[error("reconstructed path does not reach the cap's tree root")]
    RootMismatch,
    /// The witness shares the last leaf's sub-shard; levels below 8 are not
    /// in an update, so it needs the cached leaves spliced or a fresh fetch.
    #[error("witness shares the last leaf's sub-shard; re-fetch or splice new leaves")]
    NeedsLeaves,
    /// The update moves the tree backwards.
    #[error("frontier update moves the tree backwards")]
    Backwards,
}

/// A full authentication path bound to one anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirWitness {
    pub position: u64,
    pub leaf: Hash,
    /// Level 0 first.
    pub siblings: [Hash; TREE_DEPTH],
    pub anchor_height: u64,
    pub tree_size: u64,
    /// Depth-32 root the path reaches.
    pub root: Hash,
}

impl PirWitness {
    /// Converts to the wallet's Merkle path type for the Ironwood tree.
    pub fn to_merkle_path(&self) -> Option<MerklePath<MerkleHashOrchard, 32>> {
        let siblings: Option<Vec<MerkleHashOrchard>> =
            self.siblings.iter().map(bytes_to_node).collect();
        MerklePath::from_parts(siblings?, Position::from(self.position)).ok()
    }
}

/// Shard, sub-shard, and leaf index of a position.
pub fn decompose(position: u64) -> (u64, u64, usize) {
    (
        position >> SHARD_HEIGHT,
        position >> SUBSHARD_HEIGHT,
        (position % SUBSHARD_LEAVES as u64) as usize,
    )
}

fn bytes_to_node(hash: &Hash) -> Option<MerkleHashOrchard> {
    Option::from(MerkleHashOrchard::from_bytes(hash))
}

/// Sinsemilla parent of two nodes at `level`.
pub fn hash_combine(level: u8, left: &Hash, right: &Hash) -> Hash {
    let l = bytes_to_node(left).expect("valid node bytes");
    let r = bytes_to_node(right).expect("valid node bytes");
    <MerkleHashOrchard as Hashable>::combine(Level::from(level), &l, &r).to_bytes()
}

/// Root of an empty subtree at `level`.
pub fn empty_root(level: u8) -> Hash {
    <MerkleHashOrchard as Hashable>::empty_root(Level::from(level)).to_bytes()
}

/// Root of a complete subtree from exactly `2^k` nodes at `base_level`.
pub fn complete_subtree_root(nodes: &[Hash], base_level: u8) -> Hash {
    debug_assert!(nodes.len().is_power_of_two());
    let mut current = nodes.to_vec();
    let mut level = base_level;
    while current.len() > 1 {
        current = current
            .chunks_exact(2)
            .map(|pair| hash_combine(level, &pair[0], &pair[1]))
            .collect();
        level += 1;
    }
    current[0]
}

/// Given a complete `2^k`-node array at `base_level`, records the siblings
/// along the path to `index` into `siblings[base_level..base_level + k]`.
fn extract_siblings(
    nodes: &[Hash],
    index: usize,
    base_level: u8,
    siblings: &mut [Hash; TREE_DEPTH],
) {
    let mut current = nodes.to_vec();
    let mut idx = index;
    let levels = current.len().trailing_zeros() as usize;
    for offset in 0..levels {
        let level = base_level as usize + offset;
        let sibling = idx ^ 1;
        siblings[level] = if sibling < current.len() {
            current[sibling]
        } else {
            empty_root(level as u8)
        };
        current = current
            .chunks(2)
            .map(|pair| {
                let right = if pair.len() > 1 {
                    pair[1]
                } else {
                    empty_root(level as u8)
                };
                hash_combine(level as u8, &pair[0], &right)
            })
            .collect();
        idx /= 2;
    }
}

/// Root implied by a leaf and its 32 siblings.
pub fn root_from_path(position: u64, leaf: &Hash, siblings: &[Hash; TREE_DEPTH]) -> Hash {
    let mut current = *leaf;
    let mut pos = position;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if pos & 1 == 0 {
            hash_combine(level as u8, &current, sibling)
        } else {
            hash_combine(level as u8, sibling, &current)
        };
        pos >>= 1;
    }
    current
}

fn hex_hash(text: &str) -> Result<Hash, WitnessError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(WitnessError::Malformed("hash is not 32 hex bytes"))
}

fn parse_hashes(bytes: &[u8], count: usize) -> Result<Vec<Hash>, WitnessError> {
    let bytes = bytes
        .get(..count * 32)
        .ok_or(WitnessError::Malformed("row is too short"))?;
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("32-byte chunk"))
        .collect())
}

/// Reconstructs the path for `position` from its sub-shard's `witness` row,
/// its shard's `witness-roots` row, and the cap, and verifies it reaches the
/// cap's tree root.
pub fn reconstruct(
    position: u64,
    leaves_row: &[u8],
    roots_row: &[u8],
    cap: &WitnessCap,
) -> Result<PirWitness, WitnessError> {
    if position >= cap.tree_size {
        return Err(WitnessError::OutsideTree);
    }
    let (shard, subshard, leaf_index) = decompose(position);
    let mut leaves = parse_hashes(leaves_row, SUBSHARD_LEAVES)?;
    let populated =
        (cap.tree_size - subshard * SUBSHARD_LEAVES as u64).min(SUBSHARD_LEAVES as u64) as usize;
    for leaf in leaves.iter_mut().skip(populated) {
        *leaf = empty_root(0);
    }
    let leaf = leaves[leaf_index];
    let mut siblings = [[0u8; 32]; TREE_DEPTH];
    extract_siblings(&leaves, leaf_index, 0, &mut siblings);

    let mut roots = parse_hashes(roots_row, SUBSHARDS_PER_SHARD)?;
    let completed_subshards = (cap.tree_size as usize) / SUBSHARD_LEAVES;
    let first_subshard = (shard as usize) * SUBSHARDS_PER_SHARD;
    let completed_in_shard = completed_subshards
        .saturating_sub(first_subshard)
        .min(SUBSHARDS_PER_SHARD);
    for (index, root) in roots.iter_mut().enumerate().skip(completed_in_shard) {
        *root = match &cap.frontier_subshard_root {
            Some(frontier)
                if index == completed_in_shard && first_subshard + index == completed_subshards =>
            {
                hex_hash(frontier)?
            }
            _ => empty_root(SUBSHARD_HEIGHT),
        };
    }
    extract_siblings(
        &roots,
        (subshard as usize) % SUBSHARDS_PER_SHARD,
        SUBSHARD_HEIGHT,
        &mut siblings,
    );

    let mut shard_roots: Vec<Hash> = cap
        .shard_roots
        .iter()
        .map(|root| hex_hash(root))
        .collect::<Result<_, _>>()?;
    shard_roots.resize(
        1 << (TREE_DEPTH as u8 - SHARD_HEIGHT),
        empty_root(SHARD_HEIGHT),
    );
    extract_siblings(&shard_roots, shard as usize, SHARD_HEIGHT, &mut siblings);

    let root = root_from_path(position, &leaf, &siblings);
    if hex::encode(root) != cap.tree_root {
        return Err(WitnessError::RootMismatch);
    }
    Ok(PirWitness {
        position,
        leaf,
        siblings,
        anchor_height: cap.anchor_height,
        tree_size: cap.tree_size,
        root,
    })
}

/// Moves a held path to the anchor of `update`. Levels whose sibling subtree
/// is fully populated are final; a sibling on the rightmost path takes the
/// update's node; a sibling beyond the tree is the empty root.
pub fn apply_frontier_update(
    witness: &mut PirWitness,
    update: &FrontierUpdate,
) -> Result<(), WitnessError> {
    if update.tree_size < witness.tree_size {
        return Err(WitnessError::Backwards);
    }
    if update.tree_size == witness.tree_size {
        witness.anchor_height = update.height;
        return Ok(());
    }
    let nodes: Vec<Hash> = update
        .rightmost_nodes
        .iter()
        .map(|node| hex_hash(node))
        .collect::<Result<_, _>>()?;
    if nodes.len() != TREE_DEPTH {
        return Err(WitnessError::Malformed("frontier update needs 32 nodes"));
    }
    let last = update.tree_size - 1;
    if (witness.position >> SUBSHARD_HEIGHT) == (last >> SUBSHARD_HEIGHT) {
        return Err(WitnessError::NeedsLeaves);
    }
    for (level, node) in nodes.iter().enumerate() {
        let sibling_pos = (witness.position >> level) ^ 1;
        let rightmost_pos = last >> level;
        if sibling_pos == rightmost_pos {
            witness.siblings[level] = *node;
        } else if sibling_pos > rightmost_pos {
            witness.siblings[level] = empty_root(level as u8);
        }
    }
    witness.tree_size = update.tree_size;
    witness.anchor_height = update.height;
    witness.root = root_from_path(witness.position, &witness.leaf, &witness.siblings);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u64) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(i + 1).to_le_bytes());
        bytes
    }

    /// Builds the cap and the two rows for `position` exactly as the server
    /// journals them for a tree of `n` leaves.
    fn material(n: u64, position: u64) -> (WitnessCap, Vec<u8>, Vec<u8>) {
        let completed = (n as usize) / SUBSHARD_LEAVES;
        let mut subshard_roots: Vec<Hash> = (0..completed)
            .map(|s| {
                let leaves: Vec<Hash> = (0..SUBSHARD_LEAVES)
                    .map(|i| leaf((s * SUBSHARD_LEAVES + i) as u64))
                    .collect();
                complete_subtree_root(&leaves, 0)
            })
            .collect();
        let frontier_leaves: Vec<Hash> = ((completed * SUBSHARD_LEAVES) as u64..n)
            .map(leaf)
            .collect();
        let frontier_root = (!frontier_leaves.is_empty()).then(|| {
            let mut padded = frontier_leaves.clone();
            padded.resize(SUBSHARD_LEAVES, empty_root(0));
            complete_subtree_root(&padded, 0)
        });
        let mut all_roots = subshard_roots.clone();
        if let Some(root) = frontier_root {
            all_roots.push(root);
        }
        let shard_roots: Vec<Hash> = all_roots
            .chunks(SUBSHARDS_PER_SHARD)
            .map(|chunk| {
                let mut padded = chunk.to_vec();
                padded.resize(SUBSHARDS_PER_SHARD, empty_root(SUBSHARD_HEIGHT));
                complete_subtree_root(&padded, SUBSHARD_HEIGHT)
            })
            .collect();
        let mut padded_shards = shard_roots.clone();
        padded_shards.resize(1 << 16, empty_root(SHARD_HEIGHT));
        let tree_root = complete_subtree_root(&padded_shards, SHARD_HEIGHT);
        let cap = WitnessCap {
            anchor_height: 100,
            tree_size: n,
            shard_roots: shard_roots.iter().map(hex::encode).collect(),
            frontier_subshard_root: frontier_root.map(hex::encode),
            tree_root: hex::encode(tree_root),
        };
        let (shard, subshard, _) = decompose(position);
        let mut leaves_row = vec![0u8; SUBSHARD_LEAVES * 32];
        for i in 0..SUBSHARD_LEAVES as u64 {
            let p = subshard * SUBSHARD_LEAVES as u64 + i;
            if p < n {
                leaves_row[i as usize * 32..(i as usize + 1) * 32].copy_from_slice(&leaf(p));
            }
        }
        let mut roots_row = vec![0u8; SUBSHARDS_PER_SHARD * 32];
        let start = shard as usize * SUBSHARDS_PER_SHARD;
        for (i, root) in subshard_roots
            .drain(..)
            .enumerate()
            .skip(start)
            .take(SUBSHARDS_PER_SHARD)
        {
            roots_row[(i - start) * 32..(i - start + 1) * 32].copy_from_slice(&root);
        }
        (cap, leaves_row, roots_row)
    }

    #[test]
    fn reconstructs_and_converts_across_frontiers() {
        for n in [1u64, 255, 256, 257, 65_536, 65_537, 66_000] {
            for position in [0, n / 2, n - 1] {
                let (cap, leaves_row, roots_row) = material(n, position);
                let witness = reconstruct(position, &leaves_row, &roots_row, &cap)
                    .unwrap_or_else(|e| panic!("n={n} position={position}: {e}"));
                assert_eq!(witness.leaf, leaf(position));
                let path = witness.to_merkle_path().expect("merkle path");
                assert_eq!(u64::from(path.position()), position);
                let root = path.root(bytes_to_node(&witness.leaf).unwrap()).to_bytes();
                assert_eq!(hex::encode(root), cap.tree_root);
            }
        }
    }

    #[test]
    fn rejects_a_position_past_the_tree_and_a_tampered_row() {
        let (cap, leaves_row, roots_row) = material(300, 10);
        assert!(matches!(
            reconstruct(300, &leaves_row, &roots_row, &cap),
            Err(WitnessError::OutsideTree)
        ));
        let mut tampered = leaves_row.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            reconstruct(10, &tampered, &roots_row, &cap),
            Err(WitnessError::RootMismatch)
        ));
    }

    #[test]
    fn frontier_updates_refuse_the_frontier_subshard_and_move_others() {
        let (cap, leaves_row, roots_row) = material(65_536 + 300, 12_345);
        let mut witness = reconstruct(12_345, &leaves_row, &roots_row, &cap).unwrap();
        let update = FrontierUpdate {
            height: 101,
            tree_size: 65_536 + 300,
            rightmost_nodes: vec![hex::encode([0u8; 32]); 32],
        };
        apply_frontier_update(&mut witness, &update).unwrap();
        assert_eq!(witness.anchor_height, 101);

        let (cap2, lr2, rr2) = material(65_536 + 300, 65_536 + 299);
        let mut frontier_witness = reconstruct(65_536 + 299, &lr2, &rr2, &cap2).unwrap();
        let grown = FrontierUpdate {
            height: 102,
            tree_size: 65_536 + 301,
            rightmost_nodes: vec![hex::encode([0u8; 32]); 32],
        };
        assert!(matches!(
            apply_frontier_update(&mut frontier_witness, &grown),
            Err(WitnessError::NeedsLeaves)
        ));
        let back = FrontierUpdate {
            height: 99,
            tree_size: 10,
            rightmost_nodes: vec![],
        };
        assert!(matches!(
            apply_frontier_update(&mut witness, &back),
            Err(WitnessError::Backwards)
        ));
    }
}
