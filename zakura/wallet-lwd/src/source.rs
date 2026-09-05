//! The gRPC chain source.

use std::{fmt, ops::Range, sync::Arc};

use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zakura_wallet_core::{BlockAnchor, CompactBlock};
use zakura_wallet_sync::{
    ByteBudget, ChainSource, ChainTip, Direction, SubtreeRoot as SyncSubtreeRoot, estimated_size,
};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    convert,
    proto::{
        BlockId, BlockRange, ChainSpec, GetSubtreeRootsArg, ShieldedProtocol,
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
    // gRPC clients need `&mut self` per call, and the engine holds the source
    // by shared reference. One mutex around the client is the honest way to say
    // that requests are serialised on this connection; concurrency comes from
    // opening more than one.
    client: Arc<Mutex<CompactTxStreamerClient<Channel>>>,
    stats: Arc<Stats>,
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

        Ok(Self {
            client: Arc::new(Mutex::new(
                // Compact blocks are small individually but arrive in long
                // runs; the default 4 MiB message limit is ample, but the
                // stream itself must not be capped.
                CompactTxStreamerClient::new(channel).max_decoding_message_size(16 * 1024 * 1024),
            )),
            stats: Arc::new(Stats::default()),
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

        let mut client = self.client.lock().await;
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
    pub fn convert_block(
        block: crate::proto::CompactBlock,
    ) -> Result<CompactBlock, LwdError> {
        convert::block(block)
    }

    /// Fetches the tree state at `height` as a raw protocol message.
    pub async fn tree_state_raw(
        &self,
        height: BlockHeight,
    ) -> Result<crate::proto::TreeState, LwdError> {
        let mut client = self.client.lock().await;
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
        let mut client = self.client.lock().await;
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
        let mut client = self.client.lock().await;
        let id = client
            .get_latest_block(ChainSpec {})
            .await
            .map_err(LwdError::Rpc)?
            .into_inner();

        let height = u32::try_from(id.height)
            .map_err(|_| LwdError::Malformed("the tip height exceeded u32".into()))?;
        let hash = zakura_wallet_core::BlockHash::from_slice(&id.hash).ok_or_else(|| {
            LwdError::Malformed("the tip hash was not 32 bytes".into())
        })?;

        Ok(ChainTip {
            height: BlockHeight::from_u32(height),
            hash,
        })
    }

    async fn anchor(&self, height: BlockHeight) -> Result<BlockAnchor, Self::Error> {
        let mut client = self.client.lock().await;
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

        let mut client = self.client.lock().await;
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
                // Every shielded pool, always. A stream filtered to one pool
                // cannot establish that a transaction touches no other, which
                // is a prerequisite for the private-enhancement routing
                // decision. See `docs/zakura_pir_enhance.md`.
                pool_types: Vec::new(),
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

            spent += size;
            blocks.push(block);

            // Stop pulling once the caller's budget is spent. This is the
            // whole reason flow control lives in the source: the engine cannot
            // stop a server stream, and this can. One block larger than the
            // entire budget is still returned, or a wallet would stall
            // permanently on a single busy block.
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

    async fn subtree_roots(
        &self,
        pool: zakura_wallet_core::pool::PoolId,
        start_index: u64,
        limit: u32,
    ) -> Result<Vec<SyncSubtreeRoot>, Self::Error> {
        let mut client = self.client.lock().await;
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
                .and_then(|b| {
                    Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&b))
                })
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
