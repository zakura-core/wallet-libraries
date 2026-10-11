//! The loopback side of the in-process transparent shard service: a server per
//! publication whose requests one recorder captures as the service received
//! them, and the exchange a wallet reaches it over. The publisher is the
//! `testing` feature's [`zakura_pir_transparent::testing::service`].

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use tokio::{net::TcpListener, runtime::Runtime, task::JoinHandle};
use transparent_shard_server::service::{ServiceConfig, ServiceState, router};
use transparent_shard_server::shardset::{DEFAULT_RETAIN_REVISIONS, ShardSet};
use zakura_pir_transparent::{HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest};

pub use zakura_pir_transparent::testing::service::{
    GEOMETRY, SEAL, ShardSpec, WIDE, publish, superseded, synthetic,
};

/// One request as the service received it.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Every header, by name and raw value.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// A loopback shard service, restarted for each publication, that records
/// every request it receives before handling it.
pub struct Server {
    runtime: Runtime,
    requests: Arc<Mutex<Vec<Recorded>>>,
    serving: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        Self {
            runtime,
            requests: Arc::default(),
            serving: None,
        }
    }

    /// Stops serving the previous publication and serves the one in `dir`,
    /// returning its base URL.
    pub fn serve(&mut self, dir: &Path) -> String {
        if let Some(previous) = self.serving.take() {
            previous.abort();
        }
        let requests = self.requests.clone();
        let set = ShardSet::open(dir, DEFAULT_RETAIN_REVISIONS).expect("a verified shard set");
        let (url, serving) = self.runtime.block_on(async move {
            let state = ServiceState::build(set, ServiceConfig::default()).expect("a service");
            let app = router(state).layer(axum::middleware::from_fn(
                move |request: Request, next: Next| record(requests.clone(), request, next),
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let serving = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (url, serving)
        });
        self.serving = Some(serving);
        url
    }

    /// Every request any publication's server received, in arrival order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Records `request`, headers and body included, then hands it on unchanged.
async fn record(requests: Arc<Mutex<Vec<Recorded>>>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("a readable request body");
    requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Recorded {
            method: parts.method.to_string(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            body: body.to_vec(),
        });
    next.run(Request::from_parts(parts, Body::from(body))).await
}

/// A wallet's [`HttpExchange`] over loopback HTTP to one served publication: one
/// blocking request at a time, never retried, with a 60 s deadline.
pub struct Loopback {
    client: reqwest::blocking::Client,
    url: String,
}

impl Loopback {
    /// The exchange bound to the publication served at `url`.
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("an HTTP client"),
            url: url.to_owned(),
        }
    }
}

impl HttpExchange for Loopback {
    fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
        let url = format!("{}{}", self.url, request.path);
        let sending = match request.method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post => self
                .client
                .post(url)
                .header("content-type", "application/octet-stream")
                .body(request.body.clone()),
        };
        let failure = |error: reqwest::Error| {
            if error.is_timeout() {
                HttpFailure::Timeout
            } else {
                HttpFailure::Unreachable
            }
        };
        let response = sending.send().map_err(failure)?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (retry_after, map_sha256) = (header("retry-after"), header("x-txid-map-sha256"));
        let mut body = response.bytes().map_err(failure)?.to_vec();
        if (200..300).contains(&status) {
            if body.len() > request.limit {
                return Err(HttpFailure::TooLarge);
            }
        } else {
            body.truncate(request.error_limit);
        }
        Ok(HttpReply {
            status,
            retry_after,
            map_sha256,
            body,
        })
    }
}
