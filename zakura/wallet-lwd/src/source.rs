//! The gRPC chain source.

use std::{fmt, ops::Range, sync::Arc};

use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zakura_wallet_core::{BlockAnchor, CompactBlock};
use zakura_wallet_sync::{
    ByteBudget, ChainSource, ChainTip, Direction, FetchedTransaction,
    SubtreeRoot as SyncSubtreeRoot, estimated_size,
};
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::{
    convert,
    proto::{
        BlockId, BlockRange, ChainSpec, GetSubtreeRootsArg, PoolType, ShieldedProtocol, TxFilter,
        compact_tx_streamer_client::CompactTxStreamerClient,
    },
};

/// What can go wrong talking to a lightwalletd server.
#[derive(Debug)]
#[non_exhaustive]
pub enum LwdError {
    /// The connection could not be established.
    Connect(tonic::transport::Error),
    /// A request failed.
    Rpc(tonic::Status),
    /// The network refused the transaction.
    ///
    /// Distinct from a transport failure: retrying will not help, because the
    /// transaction itself is the problem.
    Rejected {
        /// The server's error code.
        code: i32,
        /// The server's explanation.
        message: String,
    },

    /// The server's response could not be interpreted.
    ///
    /// Kept separate from an RPC failure because the remedies differ: a
    /// transport error is worth retrying, and a malformed response is not.
    Malformed(String),
}

impl fmt::Display for LwdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LwdError::Connect(e) => write!(f, "could not connect to the light server: {e}"),
            LwdError::Rpc(s) => write!(f, "the light server returned an error: {s}"),
            LwdError::Rejected { code, message } => {
                write!(f, "the network refused the transaction ({code}): {message}")
            }
            LwdError::Malformed(m) => write!(f, "the light server sent something invalid: {m}"),
        }
    }
}

impl std::error::Error for LwdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LwdError::Connect(e) => Some(e),
            LwdError::Rpc(s) => Some(s),
            LwdError::Rejected { .. } | LwdError::Malformed(_) => None,
        }
    }
}

/// A chain source backed by a lightwalletd server.
#[derive(Clone)]
pub struct LightwalletdSource {
    // A tonic client is a cheap handle over a `Channel`, and a `Channel`
    // multiplexes concurrent requests over one HTTP/2 connection. Cloning it per
    // call is the intended usage, and it is what lets the engine overlap a block
    // stream with anything else.
    //
    // This was a `Mutex` held across the whole of `fetch`, which meant a tip
    // poll — or a second fetch — waited for an entire batch to download. That
    // serialisation was not protecting anything: the only shared mutable state
    // here is the two atomics below.
    client: CompactTxStreamerClient<Channel>,
    /// Whether the server honours a non-empty `poolTypes`, established by
    /// observation at connect time rather than by asking.
    transparent: bool,
    stats: Arc<Stats>,
}

/// The pool types to request, given whether the server serves transparent data.
///
/// All four, never a subset, and this survives transparent discovery moving to
/// the private ledger. The reason was never transparent detection: eligibility
/// for private Ironwood enhancement is decided by a transaction touching no
/// *other* pool, so a stream pruned to Ironwood — or to Ironwood and Orchard —
/// would make a Sapling-touching transaction look Ironwood-only and hand it to
/// a private query it must never receive. See `docs/zakura_pir_enhance.md`.
///
/// Transparent stays in the list for the same kind of reason: an enhanced
/// transaction's transparent bundle attributes outputs the wallet already
/// holds, and `probe_transparent` below is what establishes the server will
/// serve any of it. Neither is a discovery path.
fn pool_types(transparent: bool) -> Vec<i32> {
    let mut pools = vec![
        PoolType::Sapling as i32,
        PoolType::Orchard as i32,
        PoolType::Ironwood as i32,
    ];
    if transparent {
        pools.push(PoolType::Transparent as i32);
    }
    pools
}

/// Determines whether the server serves transparent data in compact blocks.
///
/// The protocol says a client must verify a server can return transparent data
/// before asking for it, and offers `lightwalletProtocolVersion` to do so — but
/// servers that serve it in practice leave that field empty, so the advertised
/// capability cannot be the gate. This establishes it by observation instead.
///
/// One block settles it: every block has a coinbase, and a coinbase always
/// creates at least one transparent output. So a block whose coinbase has no
/// outputs is a server that pruned them, whether it rejected the request,
/// ignored it, or does not implement it. There is no ambiguous answer and no
/// block for which the probe is inconclusive.
async fn probe_transparent(
    client: &mut CompactTxStreamerClient<Channel>,
) -> Result<bool, LwdError> {
    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(LwdError::Rpc)?
        .into_inner()
        .height;

    let request = BlockRange {
        start: Some(BlockId {
            height: tip,
            hash: Vec::new(),
        }),
        end: Some(BlockId {
            height: tip,
            hash: Vec::new(),
        }),
        pool_types: pool_types(true),
    };

    // A server that rejects the field outright is answering the question, not
    // failing: it cannot serve transparent data.
    let mut stream = match client.get_block_range(request).await {
        Ok(response) => response.into_inner(),
        Err(_) => return Ok(false),
    };

    while let Some(block) = stream.message().await.map_err(LwdError::Rpc)? {
        if let Some(coinbase) = block.vtx.iter().find(|tx| tx.index == 0) {
            return Ok(!coinbase.vout.is_empty());
        }
    }

    Ok(false)
}

/// What a lightwalletd server says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// `main` or `test`, as the server names its chain.
    pub chain_name: String,
    /// Where Sapling activated on that chain, which also tells the chains
    /// apart when the name is missing.
    pub sapling_activation_height: u64,
    /// The consensus branch the server is on, in its own encoding.
    pub consensus_branch_id: String,
    /// The latest block the server holds.
    pub block_height: u64,
    /// Who wrote the server software.
    pub vendor: String,
    /// Its version.
    pub version: String,
    /// Whether it offers address lookups, which this wallet never uses.
    pub serves_transparent_addresses: bool,
}

#[derive(Default)]
struct Stats {
    blocks: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
}

impl LightwalletdSource {
    /// Connects to `url`, which must name a scheme, host and port.
    ///
    /// TLS is configured from the platform's root certificates when the URL is
    /// `https`.
    pub async fn connect(url: &str) -> Result<Self, LwdError> {
        let endpoint = Endpoint::from_shared(url.to_owned())
            .map_err(LwdError::Connect)?
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(LwdError::Connect)?;

        let channel = endpoint.connect().await.map_err(LwdError::Connect)?;

        // Compact blocks are small individually but arrive in long runs; the
        // default 4 MiB message limit is ample, but the stream itself must
        // not be capped.
        let mut client =
            CompactTxStreamerClient::new(channel).max_decoding_message_size(16 * 1024 * 1024);

        let transparent = probe_transparent(&mut client).await?;

        Ok(Self {
            client,
            transparent,
            stats: Arc::new(Stats::default()),
        })
    }

    /// Whether this server serves transparent data in compact blocks.
    ///
    /// When false, transparent outputs and spends cannot be detected from the
    /// block stream at all, and a wallet that needs them must say so rather
    /// than reporting a balance that silently omits every transparent coin.
    pub fn serves_transparent(&self) -> bool {
        self.transparent
    }

    /// Asks the server what it is: which chain it serves, how far it has
    /// got, and what software answers.
    ///
    /// The chain name is the one fact a wallet has to check before trusting a
    /// server with anything: a mainnet wallet pointed at a testnet server
    /// scans a chain its keys have never been paid on and reports an honest,
    /// wrong zero.
    pub async fn server_info(&self) -> Result<ServerInfo, LwdError> {
        let mut client = self.client.clone();
        let info = client
            .get_lightd_info(crate::proto::Empty {})
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();
        Ok(ServerInfo {
            chain_name: info.chain_name,
            sapling_activation_height: info.sapling_activation_height,
            consensus_branch_id: info.consensus_branch_id,
            block_height: info.block_height,
            vendor: info.vendor,
            version: info.version,
            serves_transparent_addresses: info.taddr_support,
        })
    }

    /// Fetches a range as raw protocol messages.
    ///
    /// Exposed for the benchmark that compares this wallet against the forked
    /// one: both must scan byte-identical input for the comparison to say
    /// anything, and the fork parses the wire format with its own generated
    /// types.
    pub async fn fetch_raw(
        &self,
        range: Range<BlockHeight>,
    ) -> Result<Vec<crate::proto::CompactBlock>, LwdError> {
        if range.is_empty() {
            return Ok(Vec::new());
        }

        let mut client = self.client.clone();
        let mut stream = client
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: u64::from(u32::from(range.start)),
                    hash: Vec::new(),
                }),
                end: Some(BlockId {
                    height: u64::from(u32::from(range.end) - 1),
                    hash: Vec::new(),
                }),
                pool_types: Vec::new(),
            })
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        let mut blocks = Vec::new();
        while let Some(block) = stream.message().await.map_err(LwdError::Rpc)? {
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Converts a raw protocol block into the wallet's own type.
    pub fn convert_block(block: crate::proto::CompactBlock) -> Result<CompactBlock, LwdError> {
        convert::block(block)
    }

    /// Fetches the tree state at `height` as a raw protocol message.
    pub async fn tree_state_raw(
        &self,
        height: BlockHeight,
    ) -> Result<crate::proto::TreeState, LwdError> {
        let mut client = self.client.clone();
        Ok(client
            .get_tree_state(BlockId {
                height: u64::from(u32::from(height)),
                hash: Vec::new(),
            })
            .await
            .map_err(LwdError::Rpc)?
            .into_inner())
    }

    /// Broadcasts a signed transaction.
    ///
    /// Returns the server's response text on success. A light server relays
    /// rather than validates, so acceptance here means the transaction reached
    /// the network, not that it will be mined: it can still be rejected by
    /// consensus, or simply expire. The wallet learns which by watching for it.
    pub async fn send(&self, tx_bytes: Vec<u8>) -> Result<String, LwdError> {
        let mut client = self.client.clone();
        let response = client
            .send_transaction(crate::proto::RawTransaction {
                data: tx_bytes,
                height: 0,
            })
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        // The response carries its own error code, distinct from the RPC
        // status: a transport that succeeded can still carry a rejection, and
        // reporting that as success would tell a user their payment was sent
        // when it was not.
        if response.error_code == 0 {
            Ok(response.error_message)
        } else {
            Err(LwdError::Rejected {
                code: response.error_code,
                message: response.error_message,
            })
        }
    }

    /// Returns how many blocks and how many bytes have been downloaded.
    ///
    /// Counted here rather than inferred, because bytes downloaded is one of
    /// the two numbers that decide whether this design is worth having.
    pub fn transferred(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.stats.blocks.load(Ordering::Relaxed),
            self.stats.bytes.load(Ordering::Relaxed),
        )
    }
}

impl ChainSource for LightwalletdSource {
    type Error = LwdError;

    async fn tip(&self) -> Result<ChainTip, Self::Error> {
        let mut client = self.client.clone();
        let id = client
            .get_latest_block(ChainSpec {})
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        let height = u32::try_from(id.height)
            .map_err(|_| LwdError::Malformed("the tip height exceeded u32".into()))?;
        let hash = zakura_wallet_core::BlockHash::from_slice(&id.hash)
            .ok_or_else(|| LwdError::Malformed("the tip hash was not 32 bytes".into()))?;

        Ok(ChainTip {
            height: BlockHeight::from_u32(height),
            hash,
        })
    }

    async fn anchor(&self, height: BlockHeight) -> Result<BlockAnchor, Self::Error> {
        let mut client = self.client.clone();
        let state = client
            .get_tree_state(BlockId {
                height: u64::from(u32::from(height)),
                hash: Vec::new(),
            })
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        let hash = hex::decode(&state.hash)
            .ok()
            .map(|mut b| {
                // Tree-state hashes are hex in display order, which is the
                // reverse of protocol order.
                b.reverse();
                b
            })
            .and_then(|b| zakura_wallet_core::BlockHash::from_slice(&b))
            .ok_or_else(|| LwdError::Malformed("the tree state hash was invalid".into()))?;

        Ok(BlockAnchor {
            height,
            hash,
            tree_sizes: convert::tree_sizes(&state)?,
        })
    }

    async fn fetch(
        &self,
        range: Range<BlockHeight>,
        budget: ByteBudget,
        direction: Direction,
    ) -> Result<Vec<CompactBlock>, Self::Error> {
        use std::sync::atomic::Ordering;

        if range.is_empty() {
            return Ok(Vec::new());
        }

        // `GetBlockRange` is inclusive of its end, and streams downwards when
        // the start is above the end — which is what makes descending recovery
        // a server feature rather than something the wallet has to simulate by
        // guessing how many blocks will fit.
        let low = u64::from(u32::from(range.start));
        let high = u64::from(u32::from(range.end) - 1);
        let (first, last) = match direction {
            Direction::Ascending => (low, high),
            Direction::Descending => (high, low),
        };

        let mut client = self.client.clone();
        let mut stream = client
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: first,
                    hash: Vec::new(),
                }),
                end: Some(BlockId {
                    height: last,
                    hash: Vec::new(),
                }),
                // Every pool, always — never a subset.
                //
                // An empty list is not "everything": the protocol reads it as
                // the legacy default, which prunes transparent data and drops
                // transactions that carry nothing shielded. Asking for all four
                // is what makes `vin`/`vout` arrive at all.
                //
                // Sapling is requested even though this wallet cannot spend it,
                // because eligibility for private enhancement is decided by a
                // transaction touching *no* other pool, and a stream that
                // pruned Sapling would make a Sapling-touching transaction look
                // Ironwood-only. See `docs/zakura_pir_enhance.md`.
                pool_types: pool_types(self.transparent),
            })
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        let mut blocks = Vec::new();
        let mut spent = 0usize;

        while let Some(wire) = stream.message().await.map_err(LwdError::Rpc)? {
            let block = convert::block(wire)?;
            let size = estimated_size(&block);

            self.stats.blocks.fetch_add(1, Ordering::Relaxed);
            self.stats.bytes.fetch_add(size as u64, Ordering::Relaxed);

            // Stop before the budget is exceeded, not after. Deciding once the
            // block is already in hand would overshoot by its whole size, which
            // is what the engine's own bound forbids — and since a batch is
            // usually many blocks, that made the overshoot the normal case
            // rather than the exception.
            //
            // The block being dropped here is not lost. Only the range the
            // returned blocks actually cover is marked scanned, so this one is
            // still queued and arrives at the front of the next batch, where an
            // empty accumulator lets it through however large it is.
            if !budget.admits(spent, size, blocks.len()) {
                break;
            }

            spent += size;
            blocks.push(block);

            // One block larger than the entire budget is still returned, or a
            // wallet would stall permanently on a single busy block. This is
            // the whole reason flow control lives in the source: the engine
            // cannot stop a server stream, and this can.
            if spent >= budget.bytes() {
                break;
            }
        }

        if direction == Direction::Descending {
            // Contiguous and ascending whichever end they came from, because
            // everything above expects blocks in chain order.
            blocks.reverse();
        }

        Ok(blocks)
    }

    async fn transaction(&self, txid: TxId) -> Result<Option<FetchedTransaction>, Self::Error> {
        let mut client = self.client.clone();
        let response = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                // The wallet always asks by identifier. Asking by block and
                // index would tell the server which block it is interested in
                // even when it already has the transaction's identity.
                hash: txid.as_ref().to_vec(),
            })
            .await;

        let raw = match response {
            Ok(response) => response.into_inner(),
            // A definite negative, and only a definite negative. Every other
            // failure is a transport problem and must surface as one: reporting
            // it as "the server does not have this" would start the expiry
            // clock on a transaction that is merely unreachable.
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(status) if is_unknown_transaction(&status) => return Ok(None),
            Err(status) => return Err(LwdError::Rpc(status)),
        };

        Ok(Some(FetchedTransaction {
            status: crate::convert::transaction_status(raw.height),
            raw: raw.data,
        }))
    }

    async fn subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        start_index: u64,
        limit: u32,
    ) -> Result<Vec<SyncSubtreeRoot>, Self::Error> {
        let mut client = self.client.clone();
        let mut stream = client
            .get_subtree_roots(GetSubtreeRootsArg {
                start_index: u32::try_from(start_index)
                    .map_err(|_| LwdError::Malformed("a shard index exceeded u32".into()))?,
                shielded_protocol: match pool {
                    zakura_wallet_core::pool::PoolId::Orchard => ShieldedProtocol::Orchard as i32,
                    zakura_wallet_core::pool::PoolId::Ironwood => ShieldedProtocol::Ironwood as i32,
                },
                max_entries: limit,
            })
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        let mut roots = Vec::new();
        let mut index = start_index;
        while let Some(root) = stream.message().await.map_err(LwdError::Rpc)? {
            let hash = <[u8; 32]>::try_from(&root.root_hash[..])
                .ok()
                .and_then(|b| Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&b)))
                .ok_or_else(|| {
                    LwdError::Malformed(format!("subtree root {index} was not a valid hash"))
                })?;

            roots.push(SyncSubtreeRoot {
                index,
                end_height: BlockHeight::from_u32(
                    u32::try_from(root.completing_block_height).map_err(|_| {
                        LwdError::Malformed("a subtree end height exceeded u32".into())
                    })?,
                ),
                root: hash,
            });
            index += 1;
        }

        Ok(roots)
    }
}

/// Whether a gRPC failure is `zcashd` saying it has never heard of a
/// transaction.
///
/// Servers ought to answer this with `NOT_FOUND`, and some do. Others pass the
/// node's own error text through with a generic code, and the difference
/// matters: read as a transport failure it is retried forever, and the
/// transaction never expires.
fn is_unknown_transaction(status: &tonic::Status) -> bool {
    let message = status.message().to_ascii_lowercase();
    message.contains("no information available about transaction")
        || message.contains("transaction not found")
}
