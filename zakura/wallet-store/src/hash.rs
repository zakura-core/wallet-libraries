//! Serialization of note commitment tree nodes and shards.
//!
//! The wire format is byte-identical to the one `zcash_client_backend` uses, so
//! a database written by either implementation can be read by the other. That
//! matters for one specific reason: the differential test that validates this
//! wallet against the existing fork needs both to agree on what is in the
//! trees, not merely on the balances derived from them.
//!
//! Unlike the fork's version this is not generic over a `HashSer` trait. The
//! store's node type is always [`MerkleHashOrchard`] — both pools use Orchard's
//! tree — so the trait would have exactly one implementor and would only serve
//! to spread a bound across every signature.

use std::{
    io::{self, Read, Write},
    ops::Deref,
    sync::Arc,
};

use orchard::tree::MerkleHashOrchard;
use shardtree::{Node, PrunableTree, RetentionFlags, Tree};

use crate::error::Error;

const SER_V1: u8 = 1;

const NIL_TAG: u8 = 0;
const LEAF_TAG: u8 = 1;
const PARENT_TAG: u8 = 2;

/// Reading and writing a tree node.
///
/// Named to mirror `zcash_primitives::merkle_tree::HashSer`, whose encoding
/// this reproduces, but implemented only for the one type this wallet stores.
pub(crate) trait HashSer: Sized {
    /// Parses a node from `reader`.
    fn read<R: Read>(reader: R) -> Result<Self, Error>;
    /// Writes this node to `writer`.
    fn write<W: Write>(&self, writer: W) -> io::Result<()>;
}

impl HashSer for MerkleHashOrchard {
    fn read<R: Read>(mut reader: R) -> Result<Self, Error> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr).map_err(Error::Serialization)?;
        Option::from(Self::from_bytes(&repr)).ok_or_else(|| {
            Error::Serialization(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-canonical encoding of a Pallas base field element",
            ))
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

/// Writes a shard, prefixed by a one-byte format version.
pub(crate) fn write_shard<W: Write>(
    writer: &mut W,
    tree: &PrunableTree<MerkleHashOrchard>,
) -> Result<(), Error> {
    fn write_inner<W: Write>(
        writer: &mut W,
        tree: &PrunableTree<MerkleHashOrchard>,
    ) -> io::Result<()> {
        match tree.deref() {
            Node::Parent { ann, left, right } => {
                writer.write_all(&[PARENT_TAG])?;
                match ann.as_ref() {
                    Some(hash) => {
                        writer.write_all(&[1])?;
                        hash.write(&mut *writer)?;
                    }
                    None => writer.write_all(&[0])?,
                }
                write_inner(writer, left)?;
                write_inner(writer, right)
            }
            Node::Leaf { value } => {
                writer.write_all(&[LEAF_TAG])?;
                value.0.write(&mut *writer)?;
                writer.write_all(&[value.1.bits()])
            }
            Node::Nil => writer.write_all(&[NIL_TAG]),
        }
    }

    writer.write_all(&[SER_V1]).map_err(Error::Serialization)?;
    write_inner(writer, tree).map_err(Error::Serialization)
}

/// Reads a shard written by [`write_shard`].
pub(crate) fn read_shard<R: Read>(
    reader: &mut R,
) -> Result<PrunableTree<MerkleHashOrchard>, Error> {
    match read_u8(reader)? {
        SER_V1 => read_shard_v1(reader),
        other => Err(Error::Serialization(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("shard serialization version {other} is not recognised"),
        ))),
    }
}

fn read_shard_v1<R: Read>(reader: &mut R) -> Result<PrunableTree<MerkleHashOrchard>, Error> {
    match read_u8(reader)? {
        PARENT_TAG => {
            let ann = match read_u8(reader)? {
                0 => None,
                1 => Some(Arc::new(MerkleHashOrchard::read(&mut *reader)?)),
                other => {
                    return Err(Error::Serialization(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{other} is not a valid presence flag"),
                    )));
                }
            };
            let left = read_shard_v1(reader)?;
            let right = read_shard_v1(reader)?;
            Ok(Tree::parent(ann, left, right))
        }
        LEAF_TAG => {
            let value = MerkleHashOrchard::read(&mut *reader)?;
            let bits = read_u8(reader)?;
            let flags = RetentionFlags::from_bits(bits).ok_or_else(|| {
                Error::Serialization(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("byte {bits} is not a valid set of retention flags"),
                ))
            })?;
            Ok(Tree::leaf((value, flags)))
        }
        NIL_TAG => Ok(Tree::empty()),
        other => Err(Error::Serialization(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("node tag {other} is not recognised"),
        ))),
    }
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, Error> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).map_err(Error::Serialization)?;
    Ok(byte[0])
}
