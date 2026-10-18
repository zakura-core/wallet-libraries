//! Status's chain reads: a canonical block's transaction IDs and the mempool's.
use crate::chain::Block;
use serde_json::json;

use crate::{NodeClient, NodeError};

/// A canonical block's identity and the IDs of every transaction in it, of every
/// type, in block order. Hashes use protocol byte order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub parent: [u8; 32],
    pub txids: Vec<[u8; 32]>,
}

impl NodeClient {
    /// The block at `height`, decoded from its raw bytes and checked against the
    /// node's canonical hash at that height.
    pub async fn status_block(&self, height: u64) -> Result<StatusBlock, NodeError> {
        let raw = self.raw_block(height.to_string()).await?;
        let block = Block::zcash_deserialize(raw.as_slice())
            .map_err(|error| NodeError::Block(error.to_string()))?;
        let hash = block.hash();
        let canonical = self
            .block_hash_display(height)
            .await?
            .parse::<crate::chain::Hash>()
            .map_err(|error| NodeError::Block(format!("invalid canonical hash: {error}")))?
            .0;
        if hash.0 != canonical {
            return Err(NodeError::Block("raw block is not canonical".into()));
        }
        Ok(StatusBlock {
            height: u32::try_from(height)
                .map_err(|_| NodeError::Block("height exceeds Status encoding".into()))?,
            hash: hash.0,
            parent: block.header.previous_block_hash.0,
            txids: block.transactions.iter().map(|tx| tx.hash().0).collect(),
        })
    }

    /// The mempool's transaction IDs, parsed from RPC display order into protocol byte
    /// order.
    pub async fn status_mempool(&self) -> Result<Vec<[u8; 32]>, NodeError> {
        let displayed: Vec<String> = self.call("getrawmempool", json!([false])).await?;
        displayed
            .into_iter()
            .map(|id| {
                id.parse::<crate::chain::Hash>()
                    .map(|hash| hash.0)
                    .map_err(|error| NodeError::Block(format!("invalid mempool txid: {error}")))
            })
            .collect()
    }
}
