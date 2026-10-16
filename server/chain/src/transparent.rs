//! Transparent's chain reads: every transaction's transparent outputs and the
//! outputs its inputs spend, raw, with its exact fee.
//!
//! A block is read either over the node's RPC or, with the `rocksdb` feature,
//! straight from the node's database ([`state::StateReader`]); both give the same
//! [`FetchedBlock`] and the same [`TransparentBlock`]. Scripts are the raw bytes on
//! chain, never the node's notion of a standard script: a filter that silently
//! omitted unusual scripts would report "no activity" to a wallet that has some.
//!
//! An input's spent output resolves from earlier transactions in the same block
//! first, then from the caller's resolver; an output that cannot be resolved fails
//! the block. It is never treated as an empty script.
//!
//! Which scripts become filter elements and events, and how display records are
//! encoded, is the PIR services' business; this module only reads the chain.
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use serde_json::json;
use zakura_chain::block::Block;
use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};
use zakura_chain::transaction::{self, Transaction};
use zakura_chain::transparent::{Input as ChainInput, OutPoint, Utxo};

use crate::{NodeClient, NodeError};

mod compact;
#[cfg(feature = "rocksdb")]
pub mod state;

pub use compact::{
    CompactAction, CompactBlock, CompactInput, CompactSaplingOutput, CompactTransaction,
};

/// Previous transactions requested per JSON-RPC batch.
pub const PREVOUT_BATCH: usize = 256;

/// Default cross-block budget of an [`OutputCache`], in transparent outputs.
pub const DEFAULT_CACHE_OUTPUTS: usize = 8_000_000;

/// A boxed error from a [`PreviousOutputs`] resolver.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A transparent output: its value and its raw locking script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub script: Vec<u8>,
}

impl Output {
    /// The output in its consensus encoding, as a transaction carries it: the
    /// value, then the script with its length prefix.
    pub fn consensus_bytes(&self) -> Result<Vec<u8>, NodeError> {
        node_output(self)
            .map_err(|error| NodeError::Transaction("<output>".into(), error))?
            .zcash_serialize_to_vec()
            .map_err(|error| NodeError::Transaction("<output>".into(), error.to_string()))
    }

    /// The output whose consensus encoding is `raw`.
    pub fn from_consensus_bytes(raw: &[u8]) -> Result<Self, NodeError> {
        zakura_chain::transparent::Output::zcash_deserialize(raw)
            .map(|output| chain_output(&output))
            .map_err(|error| NodeError::Transaction("<output>".into(), error.to_string()))
    }
}

/// `output` as this crate returns it.
fn chain_output(output: &zakura_chain::transparent::Output) -> Output {
    Output {
        value: u64::from(output.value),
        script: output.lock_script.as_raw_bytes().to_vec(),
    }
}

/// `output` as the node represents it, refusing a value outside the money range.
fn node_output(output: &Output) -> Result<zakura_chain::transparent::Output, String> {
    Ok(zakura_chain::transparent::Output {
        value: zakura_chain::amount::Amount::try_from(output.value)
            .map_err(|error| error.to_string())?,
        lock_script: zakura_chain::transparent::Script::new(&output.script),
    })
}

/// A transparent input that spends an earlier output, with that output resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    /// The input's position among all of the transaction's inputs.
    pub input_index: u32,
    /// The spent output's transaction ID, in protocol byte order, and index.
    pub prevout_txid: [u8; 32],
    pub prevout_index: u32,
    /// The output it spends.
    pub spent: Output,
}

/// A transaction's fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fee {
    /// A coinbase transaction has no fee of its own.
    NotApplicable,
    /// The remaining value of the transaction's value pool, in zatoshis.
    Exact(u64),
}

/// One transaction's transparent parts. Hashes use protocol byte order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentTransaction {
    pub txid: [u8; 32],
    /// The transaction's position in its block.
    pub transaction_index: u16,
    pub coinbase: bool,
    pub fee: Fee,
    /// How many inputs spend an earlier output; a coinbase input does not.
    pub transparent_input_count: u32,
    /// Whether the transaction has Sprout, Sapling, Orchard or Ironwood parts.
    pub has_shielded_components: bool,
    /// Every transparent output, in order.
    pub outputs: Vec<Output>,
    /// Every input that spends an earlier output, in input order.
    pub inputs: Vec<Input>,
}

/// One block's transparent transactions, in block order, and how many spent outputs
/// its resolver looked up and found cached. Hashes use protocol byte order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub parent: [u8; 32],
    pub transactions: Vec<TransparentTransaction>,
    pub lookups: u64,
    pub cache_hits: u64,
}

/// Why a block's transparent parts could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("transaction metadata: {0}")]
    Metadata(String),
    #[error("previous output {0} is unavailable; refusing to build a partial block")]
    MissingPreviousOutput(String),
    #[error("block has {0} transactions, more than the event encoding can index")]
    BlockTooLarge(usize),
    #[error("previous output lookup failed for {outpoint}: {source}")]
    Lookup {
        outpoint: String,
        #[source]
        source: BoxError,
    },
    #[error("height {0} does not fit a block height")]
    Height(u64),
    /// The node's database holds no finalized block at this height (yet).
    #[error("the node holds no finalized block at height {0}")]
    MissingBlock(u64),
    /// The node's database could not be read, so whether the block exists is unknown.
    #[error("the node's database could not be read: {0}")]
    Database(#[source] BoxError),
    #[error(transparent)]
    Node(#[from] NodeError),
}

/// Renders an outpoint for diagnostics: display-order txid and index, as a person
/// would look it up.
pub fn outpoint_label(txid: &[u8; 32], index: u32) -> String {
    format!("{}:{index}", crate::hash::display(txid))
}

fn label(outpoint: &OutPoint) -> String {
    outpoint_label(&outpoint.hash.0, outpoint.index)
}

/// Supplies the value and locking script of an output created before a block.
pub trait PreviousOutputs {
    /// The output `index` of the transaction `txid` (protocol byte order), or `None`
    /// if it is not known. `None` aborts the block; it must never be treated as an
    /// empty script.
    fn previous_output(&mut self, txid: [u8; 32], index: u32) -> Result<Option<Output>, BoxError>;
}

/// A transaction's identity and transparent parts as it appears on chain, with
/// nothing resolved: what can be read from the transaction alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionView {
    /// The transaction ID in protocol byte order.
    pub txid: [u8; 32],
    /// Whether it has a coinbase input.
    pub coinbase: bool,
    /// The outputs its other inputs spend, in input order: a txid in protocol byte
    /// order and an output index.
    pub spends: Vec<([u8; 32], u32)>,
    /// Every transparent output, in order, scripts raw.
    pub outputs: Vec<Output>,
    /// Whether the transaction has Sprout, Sapling, Orchard or Ironwood parts.
    pub has_shielded_components: bool,
}

impl TransactionView {
    fn of(transaction: &Transaction) -> Self {
        Self {
            txid: transaction.hash().0,
            coinbase: transaction
                .inputs()
                .iter()
                .any(|input| matches!(input, ChainInput::Coinbase { .. })),
            spends: transaction
                .inputs()
                .iter()
                .filter_map(|input| match input {
                    ChainInput::PrevOut { outpoint, .. } => Some((outpoint.hash.0, outpoint.index)),
                    ChainInput::Coinbase { .. } => None,
                })
                .collect(),
            outputs: transaction.outputs().iter().map(chain_output).collect(),
            has_shielded_components: transaction.has_shielded_data(),
        }
    }
}

/// The transaction serialized in `raw`, which must hold exactly one transaction.
pub fn read_transaction(raw: &[u8]) -> Result<TransactionView, NodeError> {
    let mut cursor = raw;
    let transaction = Transaction::zcash_deserialize(&mut cursor)
        .map_err(|error| NodeError::Transaction("<raw>".into(), error.to_string()))?;
    if !cursor.is_empty() {
        return Err(NodeError::Transaction(
            crate::hash::display(&transaction.hash().0),
            "trailing bytes after the transaction".into(),
        ));
    }
    Ok(TransactionView::of(&transaction))
}

/// A decoded block, read over RPC or from the node's database.
#[derive(Clone, Debug)]
pub struct FetchedBlock(Arc<Block>);

impl FetchedBlock {
    /// The block serialized in `raw`.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, NodeError> {
        Block::zcash_deserialize(raw)
            .map(|block| Self(Arc::new(block)))
            .map_err(|error| NodeError::Block(error.to_string()))
    }

    /// The block serialized in `raw`, which must hold exactly one block.
    pub fn from_exact_bytes(raw: &[u8]) -> Result<Self, NodeError> {
        let mut cursor = raw;
        let block = Block::zcash_deserialize(&mut cursor)
            .map_err(|error| NodeError::Block(error.to_string()))?;
        if !cursor.is_empty() {
            return Err(NodeError::Block("trailing bytes after the block".into()));
        }
        Ok(Self(Arc::new(block)))
    }

    /// The block hash in protocol byte order.
    pub fn hash(&self) -> [u8; 32] {
        self.0.hash().0
    }

    /// The parent block's hash in protocol byte order.
    pub fn parent(&self) -> [u8; 32] {
        self.0.header.previous_block_hash.0
    }

    /// The header time the miner stamped, in Unix seconds.
    pub fn time(&self) -> i64 {
        self.0.header.time.timestamp()
    }

    /// The height the coinbase transaction commits to, if it has one.
    pub fn coinbase_height(&self) -> Option<u32> {
        self.0.coinbase_height().map(|height| height.0)
    }

    /// Every transaction as it appears on chain, in block order.
    pub fn transactions(&self) -> Vec<TransactionView> {
        self.0
            .transactions
            .iter()
            .map(|transaction| TransactionView::of(transaction))
            .collect()
    }

    /// The transaction at `position` read alone, as if it were the only one in a
    /// block at `height`: every output it spends resolves through `previous`, even
    /// one created earlier in this block, and its transaction index is 0. For
    /// analysis that reads transactions independently; ingest reads whole blocks
    /// with [`Self::transparent`].
    pub fn transparent_transaction(
        &self,
        position: usize,
        height: u32,
        previous: &mut impl PreviousOutputs,
    ) -> Result<TransparentTransaction, ExtractError> {
        let transaction = self.0.transactions.get(position).ok_or_else(|| {
            ExtractError::Metadata(format!("block has no transaction at position {position}"))
        })?;
        Ok(extract(std::slice::from_ref(transaction), previous, height)?.remove(0))
    }

    /// The transaction IDs, in block order and protocol byte order.
    pub fn txids(&self) -> Vec<[u8; 32]> {
        self.0.transactions.iter().map(|tx| tx.hash().0).collect()
    }

    /// This block's transparent parts at `height`, resolving spent outputs not
    /// created in this block through `previous`.
    pub fn transparent(
        &self,
        height: u32,
        previous: &mut impl PreviousOutputs,
    ) -> Result<Vec<TransparentTransaction>, ExtractError> {
        extract(&self.0.transactions, previous, height)
    }
}

/// Every transaction's transparent parts. Same-block spends resolve from this
/// block's own outputs before `previous` is consulted.
pub(crate) fn extract(
    transactions: &[Arc<Transaction>],
    previous: &mut impl PreviousOutputs,
    height: u32,
) -> Result<Vec<TransparentTransaction>, ExtractError> {
    // Every output this block creates, keyed by outpoint, for same-block spends.
    let mut created: HashMap<OutPoint, zakura_chain::transparent::Output> = HashMap::new();
    for transaction in transactions {
        let txid = transaction.hash();
        for (index, output) in transaction.outputs().iter().enumerate() {
            created.insert(
                OutPoint {
                    hash: txid,
                    index: index as u32,
                },
                output.clone(),
            );
        }
    }
    let mut extracted = Vec::with_capacity(transactions.len());
    for (transaction_index, transaction) in transactions.iter().enumerate() {
        // A transaction index beyond u16 would silently alias another transaction's
        // events. No Zcash block comes close, which is why it is checked.
        let transaction_index = u16::try_from(transaction_index)
            .map_err(|_| ExtractError::BlockTooLarge(transactions.len()))?;
        let coinbase = transaction
            .inputs()
            .iter()
            .any(|input| matches!(input, ChainInput::Coinbase { .. }));
        let mut prevouts = HashMap::new();
        let mut inputs = Vec::new();
        for (input_index, input) in transaction.inputs().iter().enumerate() {
            let ChainInput::PrevOut { outpoint, .. } = input else {
                continue;
            };
            let output = match created.get(outpoint) {
                Some(output) => output.clone(),
                None => {
                    let found = previous
                        .previous_output(outpoint.hash.0, outpoint.index)
                        .map_err(|source| ExtractError::Lookup {
                            outpoint: label(outpoint),
                            source,
                        })?
                        .ok_or_else(|| ExtractError::MissingPreviousOutput(label(outpoint)))?;
                    zakura_chain::transparent::Output {
                        value: zakura_chain::amount::Amount::try_from(found.value)
                            .map_err(|e| ExtractError::Metadata(e.to_string()))?,
                        lock_script: zakura_chain::transparent::Script::new(&found.script),
                    }
                }
            };
            inputs.push(Input {
                input_index: input_index as u32,
                prevout_txid: outpoint.hash.0,
                prevout_index: outpoint.index,
                spent: Output {
                    value: u64::from(output.value),
                    script: output.lock_script.as_raw_bytes().to_vec(),
                },
            });
            if prevouts
                .insert(
                    *outpoint,
                    Utxo {
                        output,
                        height: zakura_chain::block::Height(height),
                        from_coinbase: false,
                    },
                )
                .is_some()
            {
                return Err(ExtractError::Metadata("duplicate transaction input".into()));
            }
        }
        let transparent_input_count = u32::try_from(prevouts.len())
            .map_err(|_| ExtractError::Metadata("input count exceeds u32".into()))?;
        let fee = if coinbase {
            Fee::NotApplicable
        } else {
            let balance = transaction
                .value_balance(&prevouts)
                .map_err(|e| ExtractError::Metadata(e.to_string()))?;
            let fee = balance
                .remaining_transaction_value()
                .map_err(|e| ExtractError::Metadata(e.to_string()))?;
            Fee::Exact(u64::from(fee))
        };
        extracted.push(TransparentTransaction {
            txid: transaction.hash().0,
            transaction_index,
            coinbase,
            fee,
            transparent_input_count,
            has_shielded_components: transaction.has_shielded_data(),
            outputs: transaction
                .outputs()
                .iter()
                .map(|o| Output {
                    value: u64::from(o.value),
                    script: o.lock_script.as_raw_bytes().to_vec(),
                })
                .collect(),
            inputs,
        });
    }
    Ok(extracted)
}

/// Spent-output values and scripts of recently seen transactions, evicted oldest
/// first, shared across blocks read over RPC.
///
/// Entries are keyed by outpoint, and a txid commits to its outputs, so an entry
/// stays correct across reorganizations; a reorganized-out transaction is only a
/// wasted entry. Eviction removes whole transactions; the budget counts outputs.
pub struct OutputCache {
    outputs: HashMap<OutPoint, zakura_chain::transparent::Output>,
    order: VecDeque<(transaction::Hash, u32)>,
    count: usize,
    capacity: usize,
}

impl OutputCache {
    /// A cache holding at most about `capacity` transparent outputs; see
    /// [`DEFAULT_CACHE_OUTPUTS`].
    pub fn new(capacity: usize) -> Self {
        Self {
            outputs: HashMap::new(),
            order: VecDeque::new(),
            count: 0,
            capacity: capacity.max(1),
        }
    }

    fn insert_transaction(&mut self, transaction: &Transaction) {
        let txid = transaction.hash();
        let outputs = transaction.outputs();
        // Eviction removes a transaction's outputs together, so a held first output
        // means the whole transaction is held and already charged once.
        if self.outputs.contains_key(&OutPoint {
            hash: txid,
            index: 0,
        }) {
            return;
        }
        for (index, output) in outputs.iter().enumerate() {
            self.outputs.insert(
                OutPoint {
                    hash: txid,
                    index: index as u32,
                },
                output.clone(),
            );
        }
        if !outputs.is_empty() {
            self.order.push_back((txid, outputs.len() as u32));
            self.count += outputs.len();
            // A transaction larger than the budget is kept until another arrives, so
            // the block being processed can still resolve it.
            while self.count > self.capacity && self.order.len() > 1 {
                if let Some((evicted, count)) = self.order.pop_front() {
                    for index in 0..count {
                        self.outputs.remove(&OutPoint {
                            hash: evicted,
                            index,
                        });
                    }
                    self.count = self.count.saturating_sub(count as usize);
                }
            }
        }
    }

    fn get(&self, outpoint: &OutPoint) -> Option<&zakura_chain::transparent::Output> {
        self.outputs.get(outpoint)
    }

    /// The outputs held.
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }
}

/// Resolves spent outputs from an [`OutputCache`], then from the node one
/// transaction at a time, blocking on `runtime`.
struct RpcPreviousOutputs<'a> {
    client: &'a NodeClient,
    runtime: tokio::runtime::Handle,
    cache: &'a mut OutputCache,
    lookups: u64,
    cache_hits: u64,
}

impl PreviousOutputs for RpcPreviousOutputs<'_> {
    fn previous_output(&mut self, txid: [u8; 32], index: u32) -> Result<Option<Output>, BoxError> {
        let outpoint = OutPoint {
            hash: transaction::Hash(txid),
            index,
        };
        if let Some(output) = self.cache.get(&outpoint) {
            self.cache_hits += 1;
            return Ok(Some(Output {
                value: u64::from(output.value),
                script: output.lock_script.as_raw_bytes().to_vec(),
            }));
        }
        self.lookups += 1;
        let found = self
            .runtime
            .block_on(self.client.transparent_transactions(&[txid]))?
            .pop()
            .flatten();
        let Some(transaction) = found else {
            return Ok(None);
        };
        self.cache.insert_transaction(&transaction);
        let output = transaction.outputs().get(index as usize).map(|o| Output {
            value: u64::from(o.value),
            script: o.lock_script.as_raw_bytes().to_vec(),
        });
        if output.is_none() {
            tracing::warn!(
                outpoint = %label(&outpoint),
                outputs = transaction.outputs().len(),
                "previous transaction has no output at this index"
            );
        }
        Ok(output)
    }
}

impl NodeClient {
    /// The block at `height`, from its raw serialization.
    pub async fn fetch_block(&self, height: u64) -> Result<FetchedBlock, NodeError> {
        FetchedBlock::from_bytes(&self.raw_block(height.to_string()).await?)
    }

    /// `fetched`'s transparent parts at `height`, resolving spent outputs from the
    /// block itself, then `cache`, then the node in batches of [`PREVOUT_BATCH`].
    /// The block's own transactions enter the cache first, so a later block spending
    /// them needs no lookup.
    pub async fn transparent_block(
        &self,
        height: u64,
        fetched: FetchedBlock,
        cache: &mut OutputCache,
    ) -> Result<TransparentBlock, ExtractError> {
        let event_height = u32::try_from(height).map_err(|_| ExtractError::Height(height))?;
        for transaction in &fetched.0.transactions {
            cache.insert_transaction(transaction);
        }
        let batched = self.prefetch(cache, &fetched.0.transactions).await?;
        let runtime = tokio::runtime::Handle::current();
        let client = self.clone();
        let block = fetched.clone();
        // Extraction is synchronous and may block on straggler lookups, so it must
        // not run on an async worker thread.
        let mut owned = std::mem::replace(cache, OutputCache::new(1));
        let (result, lookups, cache_hits, owned) = tokio::task::spawn_blocking(move || {
            let mut previous = RpcPreviousOutputs {
                client: &client,
                runtime,
                cache: &mut owned,
                lookups: 0,
                cache_hits: 0,
            };
            let result = extract(&block.0.transactions, &mut previous, event_height);
            let counts = (previous.lookups, previous.cache_hits);
            (result, counts.0, counts.1, owned)
        })
        .await
        .map_err(|e| ExtractError::Metadata(e.to_string()))?;
        *cache = owned;
        Ok(TransparentBlock {
            height: event_height,
            hash: fetched.hash(),
            parent: fetched.parent(),
            transactions: result?,
            // The pre-pass did the fetching; stragglers are counted with it.
            lookups: lookups + batched,
            cache_hits,
        })
    }

    /// Fetches, in batches, every transaction `transactions` spend from that is not
    /// in `cache`, and caches it. Returns how many it fetched.
    async fn prefetch(
        &self,
        cache: &mut OutputCache,
        transactions: &[Arc<Transaction>],
    ) -> Result<u64, NodeError> {
        let mut wanted = Vec::new();
        let mut seen = HashSet::new();
        for transaction in transactions {
            for input in transaction.inputs() {
                let ChainInput::PrevOut { outpoint, .. } = input else {
                    continue;
                };
                if cache.get(outpoint).is_some() || !seen.insert(outpoint.hash) {
                    continue;
                }
                wanted.push(outpoint.hash.0);
            }
        }
        let mut fetched = 0u64;
        for chunk in wanted.chunks(PREVOUT_BATCH) {
            for transaction in self
                .transparent_transactions(chunk)
                .await?
                .into_iter()
                .flatten()
            {
                cache.insert_transaction(&transaction);
                fetched += 1;
            }
        }
        Ok(fetched)
    }

    /// Transactions by protocol-order ID in one JSON-RPC 2.0 batch, each identity
    /// verified, `None` where the node does not have one (-5).
    async fn transparent_transactions(
        &self,
        txids: &[[u8; 32]],
    ) -> Result<Vec<Option<Transaction>>, NodeError> {
        let entries = self
            .batch::<String>(
                "getrawtransaction",
                txids
                    .iter()
                    .map(|txid| json!([crate::hash::display(txid), 0]))
                    .collect(),
            )
            .await?;
        txids
            .iter()
            .zip(entries)
            .map(|(txid, entry)| {
                let displayed = crate::hash::display(txid);
                let raw_hex = match entry {
                    Ok(raw) => raw,
                    // "No information available about transaction".
                    Err((-5, _)) => return Ok(None),
                    Err((code, message)) => return Err(NodeError::Rpc(code, message)),
                };
                let raw = hex::decode(raw_hex)?;
                let transaction =
                    Transaction::zcash_deserialize(raw.as_slice()).map_err(|error| {
                        NodeError::Transaction(displayed.clone(), error.to_string())
                    })?;
                if transaction.hash().0 != *txid {
                    return Err(NodeError::Transaction(
                        displayed,
                        "returned transaction identity differs".into(),
                    ));
                }
                Ok(Some(transaction))
            })
            .collect()
    }

    /// Whether the node has the transaction `txid` (protocol byte order), checking
    /// the identity of what it returns.
    pub async fn has_transaction(&self, txid: [u8; 32]) -> Result<bool, NodeError> {
        Ok(self
            .transparent_transactions(&[txid])
            .await?
            .pop()
            .flatten()
            .is_some())
    }

    /// One JSON-RPC call whose result is returned as raw JSON, for tools that
    /// deliberately read the node's verbose answers instead of this crate's parser.
    pub async fn call_value(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, NodeError> {
        self.call(method, params).await
    }

    /// Several JSON-RPC calls in one JSON-RPC 2.0 batch, results positional and raw.
    /// A call answered with an RPC error fails the whole batch, since a positional
    /// hole would be indistinguishable from a null result.
    pub async fn call_batch_values(
        &self,
        calls: &[(&str, serde_json::Value)],
    ) -> Result<Vec<serde_json::Value>, NodeError> {
        let mut results = Vec::with_capacity(calls.len());
        let requests: Vec<serde_json::Value> = calls
            .iter()
            .map(|(method, params)| json!({"method": method, "params": params}))
            .collect();
        for entry in self.batch_mixed(requests).await? {
            results.push(entry.map_err(|(code, message)| NodeError::Rpc(code, message))?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Map(HashMap<([u8; 32], u32), Output>, u64);

    impl PreviousOutputs for Map {
        fn previous_output(
            &mut self,
            txid: [u8; 32],
            index: u32,
        ) -> Result<Option<Output>, BoxError> {
            self.1 += 1;
            Ok(self.0.get(&(txid, index)).cloned())
        }
    }

    fn output(value: i64, script: &[u8]) -> zakura_chain::transparent::Output {
        zakura_chain::transparent::Output {
            value: zakura_chain::amount::Amount::try_from(value).unwrap(),
            lock_script: zakura_chain::transparent::Script::new(script),
        }
    }

    fn spend(txid: [u8; 32], index: u32) -> zakura_chain::transparent::Input {
        zakura_chain::transparent::Input::PrevOut {
            outpoint: OutPoint {
                hash: transaction::Hash(txid),
                index,
            },
            unlock_script: zakura_chain::transparent::Script::new(&[0x47, 0x30]),
            sequence: 0,
        }
    }

    fn tx(
        inputs: Vec<zakura_chain::transparent::Input>,
        outputs: Vec<zakura_chain::transparent::Output>,
    ) -> Arc<Transaction> {
        Arc::new(Transaction::V1 {
            inputs,
            outputs,
            lock_time: zakura_chain::transaction::LockTime::unlocked(),
        })
    }

    /// The exact fee counts every input, including one whose spent script is empty,
    /// and an overspend fails the block.
    #[test]
    fn exact_fee_counts_all_inputs() {
        let mut previous = Map::default();
        previous.0.insert(
            ([10; 32], 0),
            Output {
                value: 1000,
                script: vec![0x51],
            },
        );
        previous.0.insert(
            ([11; 32], 1),
            Output {
                value: 2000,
                script: vec![],
            },
        );
        let t = tx(
            vec![spend([10; 32], 0), spend([11; 32], 1)],
            vec![output(2500, &[0x52])],
        );
        let read = extract(std::slice::from_ref(&t), &mut previous, 100).unwrap();
        assert_eq!(read[0].fee, Fee::Exact(500));
        assert_eq!(read[0].transparent_input_count, 2);
        assert_eq!(
            read[0].inputs[1].spent,
            Output {
                value: 2000,
                script: vec![]
            }
        );
        assert_eq!(read[0].inputs[1].input_index, 1);
        assert_eq!(previous.1, 2);
        previous.0.insert(
            ([10; 32], 0),
            Output {
                value: 0,
                script: vec![0x51],
            },
        );
        assert!(extract(&[t], &mut previous, 100).is_err());
    }

    /// A same-block spend resolves without a lookup; a missing output and a lookup
    /// failure fail the block; a duplicated input is refused.
    #[test]
    fn same_block_spends_resolve_locally_and_missing_outputs_fail() {
        let funding = tx(vec![spend([1; 32], 0)], vec![output(5000, &[0x76, 0xa9])]);
        let spender = tx(
            vec![spend(funding.hash().0, 0)],
            vec![output(4000, &[0x51])],
        );
        let mut previous = Map::default();
        previous.0.insert(
            ([1; 32], 0),
            Output {
                value: 6000,
                script: vec![0x53],
            },
        );
        let read = extract(&[funding.clone(), spender.clone()], &mut previous, 7).unwrap();
        assert_eq!(previous.1, 1, "only the outside parent is looked up");
        assert_eq!(read[1].inputs[0].spent.script, vec![0x76, 0xa9]);
        assert_eq!(read[1].fee, Fee::Exact(1000));
        assert!(matches!(
            extract(std::slice::from_ref(&spender), &mut Map::default(), 7),
            Err(ExtractError::MissingPreviousOutput(_))
        ));
        struct Failing;
        impl PreviousOutputs for Failing {
            fn previous_output(&mut self, _: [u8; 32], _: u32) -> Result<Option<Output>, BoxError> {
                Err("node unavailable".into())
            }
        }
        assert!(matches!(
            extract(&[spender], &mut Failing, 7),
            Err(ExtractError::Lookup { .. })
        ));
        let twice = tx(vec![spend([1; 32], 0), spend([1; 32], 0)], vec![]);
        assert!(matches!(
            extract(&[twice], &mut previous, 7),
            Err(ExtractError::Metadata(_))
        ));
    }

    /// The cross-block cache evicts whole transactions by its output budget.
    #[test]
    fn the_cache_evicts_whole_transactions_by_output_budget() {
        let first = tx(
            vec![spend([1; 32], 0)],
            (0..4).map(|i| output(i + 1, &[0x51])).collect(),
        );
        let second = tx(
            vec![spend([2; 32], 0)],
            (0..3).map(|i| output(i + 1, &[0x52])).collect(),
        );
        let mut cache = OutputCache::new(5);
        cache.insert_transaction(&first);
        let out = OutPoint {
            hash: first.hash(),
            index: 3,
        };
        assert!(cache.get(&out).is_some());
        cache.insert_transaction(&second);
        assert!(cache.get(&out).is_none());
        assert_eq!(cache.len(), 3);
    }

    // The transparent filter service's cache tests, moved with the cache.

    /// A transaction with `outputs` outputs, standing in for the early-chain
    /// mining-pool coinbases that made a transaction-bounded cache unbounded.
    fn wide_transaction(tag: u8, outputs: usize) -> Arc<Transaction> {
        tx(
            Vec::new(),
            (0..outputs)
                .map(|index| output(1, &[0x76, 0xa9, 0x14, tag, index as u8]))
                .collect(),
        )
    }

    fn outpoint_of(transaction: &Transaction, index: u32) -> OutPoint {
        OutPoint {
            hash: transaction.hash(),
            index,
        }
    }

    /// The budget is outputs, not transactions. A transaction-bounded cache
    /// grew without limit over early-chain blocks, whose mining-pool coinbases
    /// carry thousands of outputs each, and a genesis backfill was killed by
    /// the OOM killer partway through because of it.
    #[test]
    fn one_huge_transaction_counts_for_all_its_outputs() {
        let mut cache = OutputCache::new(100);
        let wide = wide_transaction(0, 250);
        cache.insert_transaction(&wide);
        // A transaction larger than the whole budget is kept: evicting it would
        // leave the block being extracted unable to resolve its own outputs.
        assert!(cache.get(&outpoint_of(&wide, 0)).is_some());

        // The next insert evicts it, because the budget is now exceeded by a
        // transaction that is not the only one held.
        let next = wide_transaction(1, 10);
        cache.insert_transaction(&next);
        assert!(
            cache.get(&outpoint_of(&wide, 0)).is_none(),
            "the oversized transaction should be evicted once another arrives"
        );
        assert!(cache.get(&outpoint_of(&next, 0)).is_some());
    }

    /// Many small transactions evict by output count rather than by count of
    /// transactions, so a fixed budget holds a predictable amount of memory
    /// whatever the shape of the blocks.
    #[test]
    fn eviction_is_by_output_count_not_transaction_count() {
        let mut cache = OutputCache::new(20);
        let first = wide_transaction(0, 8);
        cache.insert_transaction(&first);
        for tag in 1..4u8 {
            cache.insert_transaction(&wide_transaction(tag, 8));
        }
        // Four transactions of eight outputs is 32, past a 20-output budget, so
        // the earliest are gone even though only four transactions were seen.
        assert!(cache.get(&outpoint_of(&first, 0)).is_none());
        assert!(cache.len() <= 24, "held {} outputs", cache.len());
    }

    #[test]
    fn an_empty_cache_answers_nothing() {
        let cache = OutputCache::new(4);
        assert!(cache.is_empty());
        assert!(
            cache
                .get(&OutPoint {
                    hash: transaction::Hash([1; 32]),
                    index: 0,
                })
                .is_none()
        );
    }

    #[test]
    fn eviction_bounds_the_cache_without_losing_recent_entries() {
        let make = |tag: u8| tx(vec![], vec![output(i64::from(tag) + 1, &[0x76, 0xa9, tag])]);

        let mut cache = OutputCache::new(2);
        let first = make(1);
        let second = make(2);
        let third = make(3);
        cache.insert_transaction(&first);
        cache.insert_transaction(&second);
        cache.insert_transaction(&third);

        // The oldest was evicted.
        assert_eq!(cache.len(), 2);
        assert!(
            cache.get(&outpoint_of(&first, 0)).is_none(),
            "oldest entry should be evicted"
        );
        assert_eq!(
            cache.get(&outpoint_of(&third, 0)),
            Some(&third.outputs()[0])
        );
    }

    /// Seeing a held transaction again, as a retried block or a prefetch of a
    /// transaction the block itself created does, charges it only once.
    #[test]
    fn a_repeated_transaction_is_charged_once() {
        let mut cache = OutputCache::new(5);
        let first = wide_transaction(0, 3);
        cache.insert_transaction(&first);
        cache.insert_transaction(&first);
        assert_eq!((cache.count, cache.order.len()), (3, 1));
        let second = wide_transaction(1, 2);
        cache.insert_transaction(&second);
        assert_eq!((cache.count, cache.len()), (5, 5));
        assert!(cache.get(&outpoint_of(&first, 2)).is_some());
        assert!(cache.get(&outpoint_of(&second, 1)).is_some());
    }
}
