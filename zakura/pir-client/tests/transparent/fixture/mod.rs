//! The loopback side of the in-process transparent shard service: a server per
//! publication whose requests one recorder captures as the service received
//! them, and the exchange a wallet reaches it over. The publisher is the
//! `testing` feature's [`zakura_pir_client::transparent::testing::service`].

use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use http::{Request, Response};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, runtime::Runtime, task::JoinHandle};
use zakura_pir_client::transparent::testing::service::InProcess;
use zakura_pir_client::transparent::{
    HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest,
};

pub use zakura_pir_client::transparent::testing::service::{
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
        let service = InProcess::serve(dir);
        let (url, serving) = self.runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let serving = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let service = service.clone();
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let answering = service_fn(move |request| {
                            forward(service.clone(), requests.clone(), request)
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), answering)
                            .await;
                    });
                }
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

/// Records the complete request, then evaluates real PIR off the async runtime.
async fn forward(
    service: InProcess,
    requests: Arc<Mutex<Vec<Recorded>>>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .expect("a readable request body")
        .to_bytes();
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
    let request = Request::from_parts(parts, body.to_vec());
    let reply = tokio::task::spawn_blocking(move || service.answer(request))
        .await
        .expect("the service answered");
    Ok(reply.map(|body| Full::new(Bytes::from(body))))
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
