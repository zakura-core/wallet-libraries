//! Common inclusion proofs for one publication. Every wallet downloads the same bytes.
//! Proofs authenticate inclusion only against a root independently accepted by the wallet.
use crate::{Error, Hash};
use incrementalmerkletree::Hashable;
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

mod cache;
pub use cache::WitnessCache;

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

const HEADER: usize = 152;
const NODE: usize = 37;
/// Bound allocations before parsing an untrusted common snapshot.
pub const MAX_WITNESS_BYTES: usize = 64 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"IWPROOF1";
/// Leaves in a full depth-32 note commitment tree.
const TREE_SIZE: u64 = 1 << 32;

/// The publication a proof file binds to: the fields of a receiver directory manifest
/// that a proof commits to or is checked against. The caller validates the manifest
/// these come from, and computes its revision, with the receiver protocol package;
/// this crate does not interpret manifests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    /// The network's genesis block hash.
    pub genesis: Hash,
    /// The manifest's revision, which commits to every manifest field.
    pub directory_revision: Hash,
    /// The publication's last covered height and its block hash.
    pub end_height: u32,
    pub end_hash: Hash,
    /// The first and one past the last note position the publication covers.
    pub start_position: u64,
    pub end_position: u64,
    /// The records the publication holds, each at its own note position.
    pub records: u64,
}

impl Publication {
    /// Refuse coverage no manifest can declare: a span that runs backwards or past the
    /// tree, or more records than covered positions.
    fn validate(&self) -> Result<(), Error> {
        if self.start_position > self.end_position
            || self.end_position > TREE_SIZE
            || self.records > self.end_position - self.start_position
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// Sibling nodes for every payment position in one publication, bound to its revision.
pub struct WitnessSnapshot {
    genesis: Hash,
    directory_revision: Hash,
    height: u32,
    block_hash: Hash,
    tree_size: u64,
    root: Hash,
    nodes: BTreeMap<(u8, u32), MerkleHashOrchard>,
}

impl WitnessSnapshot {
    /// Build from every commitment since the pool's empty tree, including coinbase.
    pub fn build(
        publication: &Publication,
        commitments: &[Hash],
        positions: &BTreeSet<u32>,
    ) -> Result<Self, Error> {
        WitnessCache::default().build(publication, commitments, positions)
    }

    /// The file's tree root. Like every path, it is untrusted until checked against the
    /// wallet's own chain.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// A snapshot of `nodes` under `root` at `publication`'s end.
    fn from_nodes(
        publication: &Publication,
        root: Hash,
        nodes: BTreeMap<(u8, u32), MerkleHashOrchard>,
    ) -> Self {
        Self {
            genesis: publication.genesis,
            directory_revision: publication.directory_revision,
            height: publication.end_height,
            block_hash: publication.end_hash,
            tree_size: publication.end_position,
            root,
            nodes,
        }
    }

    /// Serialize as the `IWPROOF1` file that every wallet downloads.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + NODE * self.nodes.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.genesis);
        out.extend_from_slice(&self.directory_revision);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.tree_size.to_le_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for ((level, index), hash) in &self.nodes {
            out.push(*level);
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&hash.to_bytes());
        }
        out
    }

    /// Binds the proof file to one directory publication. Its root is still untrusted.
    pub fn decode(bytes: &[u8], publication: &Publication) -> Result<Self, Error> {
        publication.validate()?;
        if bytes.len() < HEADER || bytes.len() > MAX_WITNESS_BYTES || &bytes[..8] != MAGIC {
            return Err(Error::Malformed);
        }
        let count = u32::from_le_bytes(bytes[148..152].try_into().unwrap()) as usize;
        if count != (bytes.len() - HEADER) / NODE || !(bytes.len() - HEADER).is_multiple_of(NODE) {
            return Err(Error::Malformed);
        }
        let mut result = Self {
            genesis: bytes[8..40].try_into().unwrap(),
            directory_revision: bytes[40..72].try_into().unwrap(),
            height: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
            block_hash: bytes[76..108].try_into().unwrap(),
            tree_size: u64::from_le_bytes(bytes[108..116].try_into().unwrap()),
            root: bytes[116..148].try_into().unwrap(),
            nodes: BTreeMap::new(),
        };
        if result.genesis != publication.genesis
            || result.directory_revision != publication.directory_revision
            || result.height != publication.end_height
            || result.block_hash != publication.end_hash
            || result.tree_size != publication.end_position
        {
            return Err(Error::Coverage);
        }
        let mut previous = None;
        for node in bytes[HEADER..].as_chunks::<NODE>().0 {
            let key = (node[0], u32::from_le_bytes(node[1..5].try_into().unwrap()));
            if key.0 >= 32
                || (u64::from(key.1) << key.0) >= result.tree_size
                || previous.is_some_and(|p| p >= key)
            {
                return Err(Error::Malformed);
            }
            let hash = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(
                node[5..37].try_into().unwrap(),
            ))
            .ok_or(Error::Malformed)?;
            result.nodes.insert(key, hash);
            previous = Some(key);
        }
        Ok(result)
    }

    /// Returns a path bound to the requested commitment. The caller must additionally
    /// verify it against local chain state, never just against this file's root.
    pub fn path(&self, position: u32, cmx: Hash) -> Result<[[u8; 32]; 32], Error> {
        let path = self.siblings(position)?;
        if MerklePath::from_parts(position, path)
            .root(leaf(cmx)?)
            .to_bytes()
            != self.root
        {
            return Err(Error::Malformed);
        }
        Ok(path.map(|h| h.to_bytes()))
    }

    /// Checks [`Self::path`] for every `(position, cmx)` in order, failing as the first
    /// failing call would. An ancestor that already reached the root with the same
    /// value is not hashed again, so leaves that share subtrees share that work.
    pub fn check_paths(&self, leaves: impl IntoIterator<Item = (u32, Hash)>) -> Result<(), Error> {
        let mut verified = HashMap::<(u8, u32), MerkleHashOrchard>::new();
        let mut visited = Vec::with_capacity(32);
        for (position, cmx) in leaves {
            let path = self.siblings(position)?;
            let mut node = MerkleHashOrchard::from_cmx(&leaf(cmx)?);
            visited.clear();
            let mut depth = 0;
            while depth < 32 {
                let key = (depth, position >> depth);
                if verified.get(&key) == Some(&node) {
                    break;
                }
                visited.push((key, node));
                let sibling = &path[depth as usize];
                node = if key.1 & 1 == 0 {
                    MerkleHashOrchard::combine(depth.into(), &node, sibling)
                } else {
                    MerkleHashOrchard::combine(depth.into(), sibling, &node)
                };
                depth += 1;
            }
            if depth == 32 && node.to_bytes() != self.root {
                return Err(Error::Malformed);
            }
            verified.extend(visited.drain(..));
        }
        Ok(())
    }

    /// The sibling of each of `position`'s ancestors, failing with [`Error::Coverage`]
    /// for a position outside the tree or a sibling missing from the file.
    fn siblings(&self, position: u32) -> Result<[MerkleHashOrchard; 32], Error> {
        if u64::from(position) >= self.tree_size {
            return Err(Error::Coverage);
        }
        let mut path = [MerkleHashOrchard::empty_leaf(); 32];
        for depth in 0..32u8 {
            let index = (position >> depth) ^ 1;
            path[depth as usize] = if (u64::from(index) << depth) >= self.tree_size {
                MerkleHashOrchard::empty_root(depth.into())
            } else {
                *self.nodes.get(&(depth, index)).ok_or(Error::Coverage)?
            };
        }
        Ok(path)
    }
}

/// The commitment `cmx`, failing with [`Error::Malformed`] when it is not a field element.
fn leaf(cmx: Hash) -> Result<ExtractedNoteCommitment, Error> {
    Option::from(ExtractedNoteCommitment::from_bytes(&cmx)).ok_or(Error::Malformed)
}
