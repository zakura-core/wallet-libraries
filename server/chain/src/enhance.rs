//! Enhance's chain reads: each Ironwood Action's ciphertext parts with its
//! transaction's transparent flags, expiry height and exact fee.
//!
//! A fee needs the values of the outputs a transaction spends, which are not in the
//! transaction. They are resolved from the same block, then a bounded cross-block
//! cache, then batched `getrawtransaction` reads; an unresolved spent output fails
//! the block rather than publishing an absent or partial fee.
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use serde_json::json;
use zakura_chain::amount::{Amount, NonNegative};
use zakura_chain::block::Block;
use zakura_chain::serialization::ZcashDeserialize;
use zakura_chain::transaction::{self, Transaction};
use zakura_chain::transparent::{Input, OutPoint, Utxo};

use crate::fee::{self, OutputCache};
use crate::{Network, NodeClient, NodeError};

/// Previous transactions requested per JSON-RPC batch.
pub const PREVOUT_BATCH: usize = 256;

/// One Ironwood Action's Enhance fields and its transaction's metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhanceAction {
    /// The encrypted note ciphertext after its 52-byte compact prefix.
    pub enc_ciphertext_suffix: [u8; 528],
    pub cv_net: [u8; 32],
    pub out_ciphertext: [u8; 80],
    pub has_transparent_inputs: bool,
    pub has_transparent_outputs: bool,
    /// The transaction's expiry height; zero for none.
    pub expiry_height: u32,
    /// The transaction's exact fee, or `None` for a coinbase transaction.
    pub fee_zatoshis: Option<u64>,
}

/// One block's Enhance actions in block order and the node's Ironwood tree size
/// after it (zero before activation). The hash is in protocol byte order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhanceBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub actions: Vec<EnhanceAction>,
    pub tree_size: u64,
}

/// Spent-output resolution shared across blocks: a bounded cache and counters.
pub struct Prevouts {
    cache: Mutex<OutputCache>,
    counts: PrevoutCounters,
}

#[derive(Default)]
struct PrevoutCounters {
    same_block_hits: AtomicU64,
    cache_hits: AtomicU64,
    fetched_transactions: AtomicU64,
    batches: AtomicU64,
}

/// Cumulative spent-output resolution counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrevoutCounts {
    pub same_block_hits: u64,
    pub cache_hits: u64,
    pub fetched_transactions: u64,
    pub batches: u64,
}

impl Prevouts {
    /// A cache holding at most about `outputs` transparent outputs; see
    /// [`crate::DEFAULT_CACHE_OUTPUTS`].
    pub fn new(outputs: usize) -> Self {
        Self {
            cache: Mutex::new(OutputCache::new(outputs)),
            counts: PrevoutCounters::default(),
        }
    }

    pub fn counts(&self) -> PrevoutCounts {
        PrevoutCounts {
            same_block_hits: self.counts.same_block_hits.load(Ordering::Relaxed),
            cache_hits: self.counts.cache_hits.load(Ordering::Relaxed),
            fetched_transactions: self.counts.fetched_transactions.load(Ordering::Relaxed),
            batches: self.counts.batches.load(Ordering::Relaxed),
        }
    }
}

#[derive(Deserialize)]
struct VerboseBlock {
    trees: BlockTrees,
}

#[derive(Deserialize)]
struct BlockTrees {
    ironwood: Option<TreeSize>,
}

#[derive(Deserialize)]
struct TreeSize {
    size: u64,
}

impl NodeClient {
    /// The node's Ironwood tree size after the block at `height`.
    pub async fn tree_size(&self, height: u64) -> Result<u64, NodeError> {
        self.tree_size_at(height.to_string(), height).await
    }

    /// Read by block identity when another read already selected that block.
    async fn tree_size_at(&self, block: String, height: u64) -> Result<u64, NodeError> {
        let block: VerboseBlock = self.call("getblock", json!([block, 2])).await?;
        block
            .trees
            .ironwood
            .map(|tree| tree.size)
            .ok_or(NodeError::MissingTreeSize(height))
    }

    /// A mainnet block's Enhance actions and the Ironwood tree size after that
    /// same block, read by hash so a height reorg cannot mix two blocks.
    /// This method uses mainnet activation rules; Testnet backfill is unsupported.
    ///
    /// Fails, rather than publishing an absent or partial fee, when a spent
    /// output cannot be resolved; the caller retries the block later.
    pub async fn enhance_block(
        &self,
        height: u64,
        prevouts: &Prevouts,
    ) -> Result<EnhanceBlock, NodeError> {
        let (hash, actions) = self.enhance_actions(height, prevouts).await?;
        let tree_size = if height >= u64::from(Network::Mainnet.ironwood_activation()) {
            self.tree_size_at(crate::hash::display(&hash), height)
                .await?
        } else {
            0
        };
        Ok(EnhanceBlock {
            height,
            hash,
            actions,
            tree_size,
        })
    }

    /// The block's hash (protocol byte order) and Enhance actions, without the tree
    /// size.
    pub async fn enhance_actions(
        &self,
        height: u64,
        prevouts: &Prevouts,
    ) -> Result<([u8; 32], Vec<EnhanceAction>), NodeError> {
        let raw = self.raw_block(height.to_string()).await?;
        let block = Block::zcash_deserialize(raw.as_slice())
            .map_err(|error| NodeError::Block(error.to_string()))?;
        let actions = self.block_actions(&block, prevouts).await?;
        Ok((block.hash().0, actions))
    }

    /// Actions of every Ironwood action in block order.
    ///
    /// Spent outputs are resolved only for non-coinbase transactions with
    /// Ironwood actions and transparent inputs: from this block, then the
    /// cross-block cache, then one batched `getrawtransaction` per 256 missing
    /// transactions. A block without such a transaction issues no extra RPC.
    async fn block_actions(
        &self,
        block: &Block,
        prevouts: &Prevouts,
    ) -> Result<Vec<EnhanceAction>, NodeError> {
        let wanted: Vec<OutPoint> = block
            .transactions
            .iter()
            .filter(|tx| tx.ironwood_actions().next().is_some() && fee::needs_prevouts(tx))
            .flat_map(|tx| tx.inputs().iter().filter_map(Input::outpoint))
            .collect();
        let mut values: HashMap<OutPoint, Amount<NonNegative>> = HashMap::new();
        if !wanted.is_empty() {
            let in_block: HashMap<_, _> = block
                .transactions
                .iter()
                .map(|tx| (tx.hash(), tx.as_ref()))
                .collect();
            let mut missing = Vec::new();
            let mut requested = std::collections::HashSet::new();
            {
                let cache = prevouts.cache.lock().expect("prevout cache");
                for outpoint in &wanted {
                    if let Some(tx) = in_block.get(&outpoint.hash) {
                        values.insert(*outpoint, output_value(outpoint, tx.outputs())?);
                        prevouts
                            .counts
                            .same_block_hits
                            .fetch_add(1, Ordering::Relaxed);
                    } else if let Some(value) = cache.get(outpoint) {
                        values.insert(*outpoint, value);
                        prevouts.counts.cache_hits.fetch_add(1, Ordering::Relaxed);
                    } else if requested.insert(outpoint.hash) {
                        missing.push(outpoint.hash);
                    }
                }
            }
            for chunk in missing.chunks(PREVOUT_BATCH) {
                let fetched = self.transactions(chunk).await?;
                prevouts.counts.batches.fetch_add(1, Ordering::Relaxed);
                prevouts
                    .counts
                    .fetched_transactions
                    .fetch_add(fetched.len() as u64, Ordering::Relaxed);
                let mut cache = prevouts.cache.lock().expect("prevout cache");
                for tx in &fetched {
                    for outpoint in wanted.iter().filter(|o| o.hash == tx.hash()) {
                        values.insert(*outpoint, output_value(outpoint, tx.outputs())?);
                    }
                    cache.insert_transaction(tx);
                }
            }
        }
        let mut actions = Vec::new();
        for transaction in &block.transactions {
            let utxos = transaction
                .inputs()
                .iter()
                .filter_map(Input::outpoint)
                .filter_map(|o| values.get(&o).map(|v| (o, fee::spent_output(*v))))
                .collect();
            actions.extend(transaction_actions(transaction, &utxos)?);
        }
        let mut cache = prevouts.cache.lock().expect("prevout cache");
        for transaction in &block.transactions {
            cache.insert_transaction(transaction);
        }
        Ok(actions)
    }

    /// Protocol-order hashes of `heights`, in JSON-RPC 2.0 batches.
    pub async fn block_hashes(&self, heights: &[u64]) -> Result<Vec<[u8; 32]>, NodeError> {
        let mut hashes = Vec::with_capacity(heights.len());
        for chunk in heights.chunks(PREVOUT_BATCH) {
            for entry in self
                .batch::<String>("getblockhash", chunk.iter().map(|h| json!([h])).collect())
                .await?
            {
                let displayed = entry.map_err(|(code, message)| NodeError::Rpc(code, message))?;
                hashes.push(crate::hash::parse_display(&displayed)?);
            }
        }
        Ok(hashes)
    }

    /// Transactions by id in one JSON-RPC 2.0 batch, each identity verified.
    ///
    /// A transaction the node does not have (-5) is an error, never an
    /// absent input value.
    async fn transactions(
        &self,
        txids: &[transaction::Hash],
    ) -> Result<Vec<Transaction>, NodeError> {
        let entries = self
            .batch::<String>(
                "getrawtransaction",
                txids
                    .iter()
                    .map(|txid| json!([txid.to_string(), 0]))
                    .collect(),
            )
            .await?;
        txids
            .iter()
            .zip(entries)
            .map(|(txid, entry)| {
                let raw_hex = entry.map_err(|(code, message)| match code {
                    -5 => NodeError::MissingTransaction(txid.to_string()),
                    _ => NodeError::Rpc(code, message),
                })?;
                let raw = hex::decode(raw_hex)?;
                let tx = Transaction::zcash_deserialize(raw.as_slice())
                    .map_err(|error| NodeError::Transaction(txid.to_string(), error.to_string()))?;
                if tx.hash() != *txid {
                    return Err(NodeError::Transaction(
                        txid.to_string(),
                        "returned transaction identity differs".into(),
                    ));
                }
                Ok(tx)
            })
            .collect()
    }
}

/// The Enhance actions of the serialized transaction `raw`, whose transparent inputs
/// spend the outputs valued in `spent`, keyed by protocol-order txid and index.
/// `spent` must hold every output a non-coinbase transaction spends; see
/// [`EnhanceAction::fee_zatoshis`]. A transaction without Ironwood actions yields
/// none.
pub fn raw_transaction_actions(
    raw: &[u8],
    spent: &HashMap<([u8; 32], u32), u64>,
) -> Result<Vec<EnhanceAction>, NodeError> {
    let transaction = Transaction::zcash_deserialize(raw)
        .map_err(|error| NodeError::Transaction(String::new(), error.to_string()))?;
    let mut utxos = HashMap::new();
    for (&(txid, index), &value) in spent {
        let value = Amount::try_from(value).map_err(|error| {
            NodeError::Transaction(transaction.hash().to_string(), error.to_string())
        })?;
        utxos.insert(
            OutPoint {
                hash: transaction::Hash(txid),
                index,
            },
            fee::spent_output(value),
        );
    }
    transaction_actions(&transaction, &utxos)
}

/// One action per Ironwood action, with the transaction's exact fee.
///
/// `utxos` must hold every output a non-coinbase transaction spends.
/// Transactions without Ironwood actions yield none.
fn transaction_actions(
    transaction: &Transaction,
    utxos: &HashMap<OutPoint, Utxo>,
) -> Result<Vec<EnhanceAction>, NodeError> {
    if transaction.ironwood_actions().next().is_none() {
        return Ok(Vec::new());
    }
    let has_transparent_inputs = transaction.has_transparent_inputs();
    let has_transparent_outputs = transaction.has_transparent_outputs();
    // Derive metadata from canonical transaction data, never from a fee estimate.
    let fee_zatoshis = fee::transaction_fee(transaction, utxos)
        .map_err(|error| NodeError::Fee(transaction.hash().to_string(), error))?;
    // For Ironwood's v6 format, None from this accessor means encoded zero.
    let expiry_height = transaction.expiry_height().map_or(0, |height| height.0);
    Ok(transaction
        .ironwood_actions()
        .map(|action| EnhanceAction {
            enc_ciphertext_suffix: <[u8; 580]>::from(action.enc_ciphertext)[52..]
                .try_into()
                .expect("fixed ciphertext suffix"),
            cv_net: action.cv.into(),
            out_ciphertext: action.out_ciphertext.into(),
            has_transparent_inputs,
            has_transparent_outputs,
            expiry_height,
            fee_zatoshis,
        })
        .collect())
}

fn output_value(
    outpoint: &OutPoint,
    outputs: &[zakura_chain::transparent::Output],
) -> Result<Amount<NonNegative>, NodeError> {
    outputs
        .get(outpoint.index as usize)
        .map(|output| output.value)
        .ok_or_else(|| NodeError::PrevoutIndex {
            outpoint: fee::outpoint_label(outpoint),
            outputs: outputs.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ironwood_transaction_has_actual_fee_and_expiry() {
        let bytes =
            hex::decode(include_str!("../tests/fixtures/ironwood-fee-expiry.hex").trim()).unwrap();
        let tx = Transaction::zcash_deserialize(bytes.as_slice()).unwrap();
        assert_eq!(
            tx.hash().to_string(),
            "f337d9675817668120ae626021f61e5350ff5412beeb5e42b67bd412452b8d13"
        );
        let actions = raw_transaction_actions(&bytes, &HashMap::new()).unwrap();
        assert!(!actions.is_empty());
        for action in actions {
            assert_eq!(action.expiry_height, 3483371);
            assert_eq!(action.fee_zatoshis, Some(10000));
        }
    }
}
