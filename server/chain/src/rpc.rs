//! A JSON-RPC client for a Zakura node.
//!
//! Two configurations keep the services' existing behaviour: [`NodeClient::new`]
//! (the receiver indexer's) rereads a cookie file on every request, since the node
//! rotates it when it restarts, and bounds every response; and
//! [`NodeClient::from_cookie_file`] (Enhance's and Status's) reads the cookie once
//! and reports a refused credential as [`NodeError::InvalidCookie`].
use reqwest::StatusCode;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::path::{Path, PathBuf};

use crate::FeeError;

/// A failed node request or a node answer this crate refuses.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
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

/// Bound on every response of a [`NodeClient::new`] client. The largest the receiver
/// indexer reads is a verbose (verbosity 1) `getblock`, which lists one quoted
/// transaction ID per transaction, allowed 128 bytes with separators and whitespace,
/// for as many of the smallest transactions as fit in a maximum-size block (about
/// 4.7 MB), plus 64 KiB for the envelope and the block's other fields. That exceeds a
/// maximum-size raw block's hex (4 MB), as the assertion below keeps.
pub const RPC_RESPONSE_BYTES: usize = (zakura_chain::block::MAX_BLOCK_BYTES
    / zakura_chain::transaction::MIN_TRANSPARENT_TX_SIZE)
    as usize
    * 128
    + 64 * 1024;
const _: () =
    assert!(RPC_RESPONSE_BYTES > 2 * zakura_chain::block::MAX_BLOCK_BYTES as usize + 64 * 1024);

/// How a client authenticates.
#[derive(Clone)]
enum Credentials {
    /// A node whose RPC disables authentication.
    None,
    /// A cookie file reread on every request.
    CookieFile(PathBuf),
    /// Credentials read once, at construction.
    Fixed { username: String, password: String },
}

/// One node's JSON-RPC endpoint and how to authenticate to it.
#[derive(Clone)]
pub struct NodeClient {
    http: reqwest::Client,
    url: String,
    credentials: Credentials,
    /// The response bound, when one applies.
    limit: Option<usize>,
    /// The JSON-RPC request ID, which names the caller in node logs.
    id: &'static str,
}

/// The `user` and `password` of a cookie file.
fn read_cookie(path: &Path) -> Result<(String, String), NodeError> {
    let cookie = std::fs::read_to_string(path)?;
    match cookie.trim().split_once(':') {
        Some((username, password)) if !username.is_empty() && !password.is_empty() => {
            Ok((username.to_owned(), password.to_owned()))
        }
        _ => Err(NodeError::InvalidCookie),
    }
}

#[derive(Deserialize)]
pub(crate) struct RpcResponse<T> {
    pub(crate) result: Option<T>,
    pub(crate) error: Option<RpcError>,
}

#[derive(Deserialize)]
pub(crate) struct RpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
}

/// `response`'s body, refused as soon as it declares or reaches more than `limit`
/// bytes, so an oversized body is never buffered past the limit.
async fn read_limited(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, NodeError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(NodeError::Oversized(limit));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            return Err(NodeError::Oversized(limit));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl NodeClient {
    /// A client for the node at `url` that authenticates with the cookie file at
    /// `cookie`, read on every request since the node rotates it when it restarts, or
    /// sends no credentials for `None`, for a node whose RPC disables authentication.
    /// Every response is read up to [`RPC_RESPONSE_BYTES`].
    pub fn new(url: String, cookie: Option<&Path>) -> Result<Self, NodeError> {
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(120))
                .build()?,
            url,
            credentials: cookie.map_or(Credentials::None, |path| {
                Credentials::CookieFile(path.to_owned())
            }),
            limit: Some(RPC_RESPONSE_BYTES),
            id: "receiver-indexer",
        })
    }

    /// A client for the node at `rpc_url` with the credentials the cookie file at
    /// `cookie_path` holds now. A refused credential is [`NodeError::InvalidCookie`].
    pub fn from_cookie_file(
        rpc_url: impl Into<String>,
        cookie_path: impl AsRef<Path>,
    ) -> Result<Self, NodeError> {
        let (username, password) = read_cookie(cookie_path.as_ref())?;
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()?,
            url: rpc_url.into(),
            credentials: Credentials::Fixed { username, password },
            limit: None,
            id: "enhance-pir",
        })
    }

    /// This client, naming itself `id` in its JSON-RPC requests, as the node logs.
    pub fn with_request_id(mut self, id: &'static str) -> Self {
        self.id = id;
        self
    }

    /// The endpoint this client calls.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The `nodes` whose genesis block is `genesis` (see [`Self::check_network`]), each
    /// with its tip, highest first and in `nodes` order among equal tips. A caller runs
    /// a whole pass on the first, so every read in it comes from one node, and the next
    /// pass ranks again, rereading each genesis, since an endpoint can be repointed.
    /// Fails, with the last node's error, only when no node qualifies. Every read is
    /// concurrent, so a stalled node delays ranking by one timeout, not one per node.
    pub async fn ranked(
        nodes: &[NodeClient],
        genesis: [u8; 32],
    ) -> Result<Vec<(u64, NodeClient)>, NodeError> {
        let tips: Vec<_> = nodes
            .iter()
            .map(|node| {
                let node = node.clone();
                tokio::spawn(async move {
                    let (_, tip) =
                        tokio::try_join!(node.check_network(genesis), node.tip_height())?;
                    Ok::<_, NodeError>(tip)
                })
            })
            .collect();
        let (mut ranked, mut last) = (Vec::new(), None);
        for (node, tip) in nodes.iter().zip(tips) {
            match tip.await.expect("tip read task") {
                Ok(tip) => ranked.push((tip, node.clone())),
                Err(error) => last = Some(error),
            }
        }
        if ranked.is_empty() {
            return Err(last.unwrap_or_else(|| NodeError::Block("no node RPC endpoint".into())));
        }
        // A stable sort keeps the configured order among equal tips.
        ranked.sort_by_key(|(tip, _)| std::cmp::Reverse(*tip));
        Ok(ranked)
    }

    /// Fails with [`NodeError::OtherNetwork`] unless the node's genesis block is
    /// `genesis` (protocol byte order), so a node on another network is never taken as
    /// evidence about this one's chain.
    pub async fn check_network(&self, genesis: [u8; 32]) -> Result<(), NodeError> {
        match self.block_hash(0).await? == genesis {
            true => Ok(()),
            false => Err(NodeError::OtherNetwork),
        }
    }

    /// The node's chain tip height.
    pub async fn tip_height(&self) -> Result<u64, NodeError> {
        self.call("getblockcount", json!([])).await
    }

    /// The hash, in protocol byte order, of the node's block at `height`.
    pub async fn block_hash(&self, height: u64) -> Result<[u8; 32], NodeError> {
        crate::hash::parse_display(&self.block_hash_display(height).await?)
    }

    /// The hash of the node's block at `height`, in RPC display order.
    pub async fn block_hash_display(&self, height: u64) -> Result<String, NodeError> {
        self.call("getblockhash", json!([height])).await
    }

    /// The node's raw `getblock` bytes for `block`, a height or a display-order hash.
    pub(crate) async fn raw_block(&self, block: String) -> Result<Vec<u8>, NodeError> {
        let raw: String = self.call("getblock", json!([block, 0])).await?;
        Ok(hex::decode(raw)?)
    }

    /// The request builder for one POST to the node, with its credentials.
    fn post(&self) -> Result<reqwest::RequestBuilder, NodeError> {
        let request = self.http.post(&self.url);
        Ok(match &self.credentials {
            Credentials::None => request,
            Credentials::CookieFile(path) => {
                let (username, password) = read_cookie(path)?;
                request.basic_auth(username, Some(password))
            }
            Credentials::Fixed { username, password } => {
                request.basic_auth(username, Some(password))
            }
        })
    }

    /// Sends `request` and reads its body within this client's bound, refusing a
    /// non-success status.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>, NodeError> {
        let response = request.send().await?;
        if matches!(self.credentials, Credentials::Fixed { .. })
            && response.status() == StatusCode::UNAUTHORIZED
        {
            return Err(NodeError::InvalidCookie);
        }
        let response = response.error_for_status()?;
        match self.limit {
            Some(limit) => read_limited(response, limit).await,
            None => Ok(response.bytes().await?.to_vec()),
        }
    }

    /// One JSON-RPC 1.0 call to the node.
    pub(crate) async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, NodeError> {
        let body = json!({"jsonrpc": "1.0", "id": self.id, "method": method, "params": params});
        let body = self.send(self.post()?.json(&body)).await?;
        let response: RpcResponse<T> = serde_json::from_slice(&body).map_err(NodeError::Decode)?;
        if let Some(error) = response.error {
            return Err(NodeError::Rpc(error.code, error.message));
        }
        response.result.ok_or(NodeError::MissingResult)
    }

    /// One JSON-RPC 2.0 batch, results placed by their echoed id.
    ///
    /// The node rejects 1.0 batches, so batches use 2.0 while single calls
    /// stay on 1.0. Per-entry RPC errors are returned to the caller; a
    /// malformed batch response is an error for the whole batch.
    pub(crate) async fn batch<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<Vec<Result<T, (i64, String)>>, NodeError> {
        self.batch_mixed(
            params
                .into_iter()
                .map(|params| json!({"method": method, "params": params}))
                .collect(),
        )
        .await
    }

    /// [`Self::batch`] for calls of any methods, each given as
    /// `{"method": ..., "params": ...}`.
    pub(crate) async fn batch_mixed<T: DeserializeOwned>(
        &self,
        calls: Vec<serde_json::Value>,
    ) -> Result<Vec<Result<T, (i64, String)>>, NodeError> {
        if calls.is_empty() {
            return Ok(Vec::new());
        }
        let requests: Vec<_> = calls
            .into_iter()
            .enumerate()
            .map(|(id, call)| {
                json!({"jsonrpc": "2.0", "id": id, "method": call["method"], "params": call["params"]})
            })
            .collect();
        let body = self.send(self.post()?.json(&requests)).await?;
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(NodeError::Decode)?;
        let entries = match value {
            serde_json::Value::Array(entries) => entries,
            other => {
                // A node refusing the whole batch answers with one error object.
                return Err(
                    match other.pointer("/error/code").and_then(|c| c.as_i64()) {
                        Some(code) => NodeError::Rpc(
                            code,
                            other
                                .pointer("/error/message")
                                .and_then(|m| m.as_str())
                                .unwrap_or_default()
                                .to_string(),
                        ),
                        None => NodeError::Batch("batch response is not an array".into()),
                    },
                );
            }
        };
        if entries.len() != requests.len() {
            return Err(NodeError::Batch(format!(
                "asked for {} results, got {}",
                requests.len(),
                entries.len()
            )));
        }
        let mut placed: Vec<Option<Result<T, (i64, String)>>> =
            (0..requests.len()).map(|_| None).collect();
        for entry in entries {
            let id = entry
                .get("id")
                .and_then(|id| id.as_u64())
                .and_then(|id| usize::try_from(id).ok())
                .filter(|id| *id < placed.len())
                .ok_or_else(|| {
                    NodeError::Batch("batch entry id is missing or out of range".into())
                })?;
            if placed[id].is_some() {
                return Err(NodeError::Batch(format!("batch id {id} appeared twice")));
            }
            let response: RpcResponse<T> = serde_json::from_value(entry)
                .map_err(|error| NodeError::Batch(format!("batch entry {id}: {error}")))?;
            placed[id] = Some(match (response.error, response.result) {
                (Some(error), _) => Err((error.code, error.message)),
                (None, Some(result)) => Ok(result),
                (None, None) => {
                    return Err(NodeError::Batch(format!("batch entry {id} has no result")));
                }
            });
        }
        Ok(placed
            .into_iter()
            .map(|entry| entry.expect("every id placed"))
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    };

    /// Serves `app` on a local port. Returns its URL.
    pub(crate) async fn serve(app: Router) -> String {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        url
    }

    /// A node at tip `tip` whose genesis block is `[genesis; 32]`, read on each
    /// request. Returns its URL.
    async fn node(tip: u64, genesis: Arc<AtomicU8>) -> String {
        serve(Router::new().route(
            "/",
            post(move |Json(request): Json<serde_json::Value>| {
                let genesis = genesis.load(Ordering::SeqCst);
                async move {
                    let result = match request["method"].as_str() {
                        Some("getblockhash") => json!(crate::hash::display(&[genesis; 32])),
                        _ => json!(tip),
                    };
                    Json(json!({"result": result, "error": null}))
                }
            }),
        ))
        .await
    }

    /// A node at tip 7 that accepts only the cookie `accepted` holds. Returns its URL.
    async fn cookie_node(accepted: Arc<Mutex<String>>) -> String {
        async fn handler(
            State(accepted): State<Arc<Mutex<String>>>,
            headers: axum::http::HeaderMap,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            let cookie = accepted.lock().unwrap().clone();
            let (username, password) = cookie.split_once(':').unwrap();
            // The header reqwest sends for these credentials.
            let expected = reqwest::Client::new()
                .post("http://node")
                .basic_auth(username, Some(password))
                .build()
                .unwrap()
                .headers()[axum::http::header::AUTHORIZATION]
                .clone();
            if headers.get(axum::http::header::AUTHORIZATION) != Some(&expected) {
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }
            Json(json!({"result": 7, "error": null})).into_response()
        }
        serve(Router::new().route("/", post(handler)).with_state(accepted)).await
    }

    /// Each request reads the cookie file, so a client follows a rotated cookie and
    /// recovers once a missing one is replaced.
    #[tokio::test]
    async fn a_rotated_cookie_is_reread() {
        let dir = std::env::temp_dir().join(format!("cookie-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".cookie");
        let accepted = Arc::new(Mutex::new(String::new()));
        let rpc = NodeClient::new(cookie_node(accepted.clone()).await, Some(&path)).unwrap();
        let rotate = |cookie: &str| {
            *accepted.lock().unwrap() = cookie.to_owned();
            std::fs::write(&path, cookie).unwrap();
        };
        rotate("user:a");
        assert_eq!(rpc.tip_height().await.unwrap(), 7);
        rotate("user:b");
        assert_eq!(rpc.tip_height().await.unwrap(), 7);
        // A node restarting removes its cookie before writing the next one.
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(rpc.tip_height().await, Err(NodeError::Cookie(_))));
        rotate("user:c");
        assert_eq!(rpc.tip_height().await.unwrap(), 7);
        // A client that read its cookie once reports the node's refusal as a bad
        // cookie once the node rotates it.
        let fixed = NodeClient::from_cookie_file(rpc.url(), &path).unwrap();
        assert_eq!(fixed.tip_height().await.unwrap(), 7);
        rotate("user:d");
        assert!(matches!(
            fixed.tip_height().await,
            Err(NodeError::InvalidCookie)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Nodes rank by tip, highest first and in configured order among equal tips,
    /// leaving out a node that does not answer or, checked again on every ranking, is
    /// on another network, however high its tip; with none left ranking fails.
    #[tokio::test]
    async fn nodes_rank_by_tip() {
        let ours = [1; 32];
        let client = |url: String| NodeClient::new(url, None).unwrap();
        let on = |genesis: u8| Arc::new(AtomicU8::new(genesis));
        let down = client("http://127.0.0.1:1".into());
        let other = client(node(200, on(2)).await);
        let repointed = on(1);
        let nodes = [
            down.clone(),
            other.clone(),
            client(node(100, on(1)).await),
            client(node(105, on(1)).await),
            client(node(105, on(1)).await),
            client(node(150, repointed.clone()).await),
        ];
        let order = |ranked: Vec<(u64, NodeClient)>| -> Vec<_> {
            ranked
                .into_iter()
                .map(|(tip, node)| (tip, node.url))
                .collect()
        };
        let urls: Vec<_> = nodes.iter().map(|node| node.url.clone()).collect();
        let ranked = NodeClient::ranked(&nodes, ours).await.unwrap();
        let mut expected = vec![
            (150, urls[5].clone()),
            (105, urls[3].clone()),
            (105, urls[4].clone()),
            (100, urls[2].clone()),
        ];
        assert_eq!(order(ranked), expected);
        repointed.store(2, Ordering::SeqCst);
        expected.remove(0);
        let ranked = NodeClient::ranked(&nodes, ours).await.unwrap();
        assert_eq!(order(ranked), expected);
        assert!(NodeClient::ranked(&[down, other], ours).await.is_err());
    }

    /// A bounded client refuses a body over its bound, declared or not.
    #[tokio::test]
    async fn bounded_clients_refuse_oversized_answers() {
        let huge = "0".repeat(RPC_RESPONSE_BYTES);
        let url = serve(Router::new().route(
            "/",
            post(move || {
                let huge = huge.clone();
                async move { Json(json!({"result": huge, "error": null})) }
            }),
        ))
        .await;
        let rpc = NodeClient::new(url, None).unwrap();
        assert!(matches!(
            rpc.block_hash_display(1).await,
            Err(NodeError::Oversized(RPC_RESPONSE_BYTES))
        ));
    }
}
