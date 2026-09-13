//! A light server that serves fixed blocks from memory.
//!
//! For rehearsals against a synthetic chain: the wallet's real client, the
//! real facade and the real bridge connect to it over plaintext gRPC on the
//! loopback interface and scan what it serves. It answers what a scanning
//! wallet asks — the server's identity, the tip, block ranges in either
//! direction, tree state and subtree roots — and refuses everything else.
//! Its tree states are empty: a fixture chain carries no shielded notes.
//!
//! Not part of the wallet, and never built into it: the feature that
//! compiles this also generates the server side of the protocol.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::proto;
use crate::proto::compact_tx_streamer_server::{CompactTxStreamer, CompactTxStreamerServer};

/// The chain a fixture light server serves.
#[derive(Debug, Clone)]
pub struct FixtureChain {
    /// `main` or `test`.
    pub chain_name: String,
    /// Every block, by height. Heights are contiguous.
    pub blocks: BTreeMap<u64, proto::CompactBlock>,
}

impl FixtureChain {
    fn tip(&self) -> Result<&proto::CompactBlock, Status> {
        self.blocks
            .values()
            .next_back()
            .ok_or_else(|| Status::unavailable("the fixture holds no blocks"))
    }

    fn tree_state(&self, block: &proto::CompactBlock) -> proto::TreeState {
        let mut display = block.hash.clone();
        display.reverse();
        proto::TreeState {
            network: self.chain_name.clone(),
            height: block.height,
            hash: hex::encode(display),
            time: block.time,
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        }
    }
}

type Streamed<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

fn empty<T: Send + 'static>() -> Streamed<T> {
    Box::pin(tokio_stream::empty())
}

fn refused<T>(what: &str) -> Result<Response<T>, Status> {
    Err(Status::unimplemented(format!(
        "the fixture light server does not serve {what}"
    )))
}

/// The server, over a shared chain.
#[derive(Debug, Clone)]
pub struct FixtureLightServer {
    chain: Arc<FixtureChain>,
}

impl FixtureLightServer {
    /// A server over `chain`.
    pub fn new(chain: FixtureChain) -> Self {
        Self {
            chain: Arc::new(chain),
        }
    }

    /// Binds an ephemeral loopback port and serves until the task is dropped.
    /// Returns the address and the task.
    pub async fn spawn(self) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), std::io::Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let task = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(CompactTxStreamerServer::new(self))
                .serve_with_incoming(incoming)
                .await;
        });
        Ok((addr, task))
    }
}

#[tonic::async_trait]
impl CompactTxStreamer for FixtureLightServer {
    async fn get_latest_block(
        &self,
        _: Request<proto::ChainSpec>,
    ) -> Result<Response<proto::BlockId>, Status> {
        let tip = self.chain.tip()?;
        Ok(Response::new(proto::BlockId {
            height: tip.height,
            hash: tip.hash.clone(),
        }))
    }

    async fn get_block(
        &self,
        request: Request<proto::BlockId>,
    ) -> Result<Response<proto::CompactBlock>, Status> {
        let id = request.into_inner();
        self.chain
            .blocks
            .get(&id.height)
            .cloned()
            .map(Response::new)
            .ok_or_else(|| Status::not_found(format!("no block at {}", id.height)))
    }

    async fn get_block_nullifiers(
        &self,
        request: Request<proto::BlockId>,
    ) -> Result<Response<proto::CompactBlock>, Status> {
        self.get_block(request).await
    }

    type GetBlockRangeStream = Streamed<proto::CompactBlock>;

    async fn get_block_range(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let range = request.into_inner();
        let (start, end) = match (range.start, range.end) {
            (Some(s), Some(e)) => (s.height, e.height),
            _ => return Err(Status::invalid_argument("a block range needs both ends")),
        };
        let (low, high) = (start.min(end), start.max(end));
        let mut blocks: Vec<Result<proto::CompactBlock, Status>> = self
            .chain
            .blocks
            .range(low..=high)
            .map(|(_, b)| Ok(b.clone()))
            .collect();
        if start > end {
            blocks.reverse();
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(blocks))))
    }

    type GetBlockRangeNullifiersStream = Streamed<proto::CompactBlock>;

    async fn get_block_range_nullifiers(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        self.get_block_range(request).await
    }

    async fn get_transaction(
        &self,
        _: Request<proto::TxFilter>,
    ) -> Result<Response<proto::RawTransaction>, Status> {
        Err(Status::not_found(
            "the fixture light server holds no raw transactions",
        ))
    }

    async fn send_transaction(
        &self,
        _: Request<proto::RawTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        refused("sending")
    }

    type GetTaddressTxidsStream = Streamed<proto::RawTransaction>;

    async fn get_taddress_txids(
        &self,
        _: Request<proto::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        refused("address lookups")
    }

    type GetTaddressTransactionsStream = Streamed<proto::RawTransaction>;

    async fn get_taddress_transactions(
        &self,
        _: Request<proto::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        refused("address lookups")
    }

    async fn get_taddress_balance(
        &self,
        _: Request<proto::AddressList>,
    ) -> Result<Response<proto::Balance>, Status> {
        refused("address lookups")
    }

    async fn get_taddress_balance_stream(
        &self,
        _: Request<tonic::Streaming<proto::Address>>,
    ) -> Result<Response<proto::Balance>, Status> {
        refused("address lookups")
    }

    type GetMempoolTxStream = Streamed<proto::CompactTx>;

    async fn get_mempool_tx(
        &self,
        _: Request<proto::GetMempoolTxRequest>,
    ) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        Ok(Response::new(empty()))
    }

    type GetMempoolStreamStream = Streamed<proto::RawTransaction>;

    async fn get_mempool_stream(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        Ok(Response::new(empty()))
    }

    async fn get_tree_state(
        &self,
        request: Request<proto::BlockId>,
    ) -> Result<Response<proto::TreeState>, Status> {
        let id = request.into_inner();
        let block = self
            .chain
            .blocks
            .get(&id.height)
            .ok_or_else(|| Status::not_found(format!("no block at {}", id.height)))?;
        Ok(Response::new(self.chain.tree_state(block)))
    }

    async fn get_latest_tree_state(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::TreeState>, Status> {
        let tip = self.chain.tip()?;
        Ok(Response::new(self.chain.tree_state(tip)))
    }

    type GetSubtreeRootsStream = Streamed<proto::SubtreeRoot>;

    async fn get_subtree_roots(
        &self,
        _: Request<proto::GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        Ok(Response::new(empty()))
    }

    async fn get_address_utxos(
        &self,
        _: Request<proto::GetAddressUtxosArg>,
    ) -> Result<Response<proto::GetAddressUtxosReplyList>, Status> {
        refused("address lookups")
    }

    type GetAddressUtxosStreamStream = Streamed<proto::GetAddressUtxosReply>;

    async fn get_address_utxos_stream(
        &self,
        _: Request<proto::GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        refused("address lookups")
    }

    async fn get_lightd_info(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::LightdInfo>, Status> {
        let tip = self.chain.tip()?;
        Ok(Response::new(proto::LightdInfo {
            version: "fixture".into(),
            vendor: "zakura fixture light server".into(),
            taddr_support: true,
            chain_name: self.chain.chain_name.clone(),
            sapling_activation_height: 419_200,
            consensus_branch_id: String::new(),
            block_height: tip.height,
            git_commit: String::new(),
            branch: String::new(),
            build_date: String::new(),
            build_user: String::new(),
            estimated_height: tip.height,
            ..proto::LightdInfo::default()
        }))
    }

    async fn ping(
        &self,
        request: Request<proto::Duration>,
    ) -> Result<Response<proto::PingResponse>, Status> {
        let d = request.into_inner();
        Ok(Response::new(proto::PingResponse {
            entry: d.interval_us,
            exit: d.interval_us,
        }))
    }
}
