//! Checked note-tree hashing for lower inclusion paths.
//!
//! Paths authenticate inclusion only against a root the wallet accepted from its own
//! chain, never against a root the service supplies. Publishers build the paths
//! themselves, with `zakura-pir-publisher`'s `receiver::witness::ShardPaths`.
use super::{Error, Hash};
use incrementalmerkletree::Hashable;
use orchard::tree::MerkleHashOrchard;

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
