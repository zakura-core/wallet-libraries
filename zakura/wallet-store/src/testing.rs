//! Helpers for exercising the store.

use orchard::tree::MerkleHashOrchard;
use shardtree::PrunableTree;

use crate::{
    Error, WalletDb,
    hash::{read_shard, write_shard},
};

/// Opens a throwaway wallet held entirely in memory.
pub fn test_db() -> Result<WalletDb, Error> {
    WalletDb::in_memory()
}

/// Returns whether `tree` survives a write-read round trip byte-identically.
///
/// Exposed so the encoding can be property-tested against trees the store
/// actually produced, rather than against synthetic ones.
pub fn roundtrip_shard(tree: &PrunableTree<MerkleHashOrchard>) -> Result<bool, Error> {
    let mut written = vec![];
    write_shard(&mut written, tree)?;

    let read_back = read_shard(&mut std::io::Cursor::new(written.clone()))?;

    let mut rewritten = vec![];
    write_shard(&mut rewritten, &read_back)?;

    Ok(written == rewritten && read_back == *tree)
}
