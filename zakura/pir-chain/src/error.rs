//! Errors of node reads and of decoding and interpreting their answers. Decoding
//! needs no transport, so this type exists without the `rpc` feature.
use crate::FeeError;

/// A failed node request or a node answer this crate refuses.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// A transport failure; only the `rpc` client produces it.
    #[cfg(feature = "rpc")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("cookie error: {0}")]
    Cookie(#[from] std::io::Error),
    #[error("invalid RPC cookie")]
    InvalidCookie,
    #[error("RPC returned {0}: {1}")]
    Rpc(i64, String),
    #[error("RPC response is missing a result")]
    MissingResult,
    #[error("invalid block hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid canonical block: {0}")]
    Block(String),
    #[error("Ironwood tree size is unavailable at height {0}")]
    MissingTreeSize(u64),
    #[error("Ironwood tree root is unavailable at height {0}")]
    MissingTreeRoot(u64),
    #[error("response is larger than {0} bytes")]
    Oversized(usize),
    #[error("invalid RPC response: {0}")]
    Decode(serde_json::Error),
    #[error("node is on another network")]
    OtherNetwork,
    #[error("invalid JSON-RPC batch response: {0}")]
    Batch(String),
    #[error("node has no transaction {0}")]
    MissingTransaction(String),
    #[error("invalid transaction {0}: {1}")]
    Transaction(String, String),
    #[error("spent output {outpoint} is outside its transaction's {outputs} outputs")]
    PrevoutIndex { outpoint: String, outputs: usize },
    #[error("fee of transaction {0} is unavailable: {1}")]
    Fee(String, FeeError),
}
