//! Application-routed HTTP with bounded collection and manifest-bound batches.
use crate::client::record_in_row;
use crate::{
    ClientError, EnhanceRecord, GenerationAcceptance, Manifest, QuerySession, RECORDS_PER_ROW,
    ShardSession,
};
use futures_util::{Stream, stream};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Default maximum number of input items, including duplicates, in one batch.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 4096;

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// A setup response can be larger than a manifest but is capped before parsing.
pub const MAX_SESSION_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Method {
    Get,
    Post,
}

pub struct Request {
    pub method: Method,
    pub url: String,
    pub body: Vec<u8>,
    response_limit: usize,
}

impl Request {
    /// Creates the only supported response collector, with the limit chosen by
    /// the protocol client. Stream network chunks into it before returning.
    pub fn response_body(&self) -> BoundedBody {
        BoundedBody::new(self.response_limit)
    }
}

/// Implementations must report unsuccessful HTTP status codes as
/// `ClientError::HttpStatus(status.as_u16())` and abort on
/// application cancellation. Return `request.response_body().finish()` after
/// extending the collector with each network chunk; do not buffer the complete
/// HTTP body first. Dropping the future must stop further dispatch.
///
/// The opaque result enforces checked collection. Transport-internal buffers
/// and individual network chunks remain the transport implementation's responsibility.
#[allow(async_fn_in_trait)]
pub trait Transport {
    fn execute(&self, request: Request) -> impl Future<Output = Result<ResponseBody, ClientError>>;
}

/// A response constructed exclusively through a request's checked collector.
/// There is no unchecked constructor or conversion from an allocated `Vec`.
///
/// ```compile_fail
/// use zakura_pir_enhance::transport::{Request, ResponseBody, Transport};
/// use zakura_pir_enhance::ClientError;
/// struct Unbounded;
/// impl Transport for Unbounded {
///     async fn execute(&self, _: Request) -> Result<ResponseBody, ClientError> {
///         Ok(vec![0; 1024]) // An unchecked buffer is not a transport response.
///     }
/// }
/// ```
#[derive(Debug)]
pub struct ResponseBody(Vec<u8>);
impl AsRef<[u8]> for ResponseBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Incremental collector; checks before allocation, including integer overflow.
pub struct BoundedBody {
    bytes: Vec<u8>,
    limit: usize,
}
impl BoundedBody {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    pub fn extend(&mut self, chunk: &[u8]) -> Result<(), ClientError> {
        if self
            .bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(ClientError::Response("HTTP body exceeds limit".into()));
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
    pub fn finish(self) -> ResponseBody {
        ResponseBody(self.bytes)
    }
}

/// Unallocated initialization. Wallet acceptance is required before setup.
pub struct PendingClient {
    base_url: String,
    manifest: Manifest,
}
impl PendingClient {
    pub async fn fetch(transport: &impl Transport, base_url: &str) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let url = endpoint(&base_url, "/v1/enhance/init")?;
        let bytes = transport
            .execute(Request {
                method: Method::Get,
                url,
                body: vec![],
                response_limit: MAX_MANIFEST_BYTES,
            })
            .await?;
        if bytes.as_ref().len() > MAX_MANIFEST_BYTES {
            return Err(ClientError::Response("HTTP body exceeds limit".into()));
        }
        let manifest: Manifest = serde_json::from_slice(bytes.as_ref())?;
        manifest.validate().map_err(ClientError::Generation)?;
        Ok(Self { base_url, manifest })
    }
    pub fn generation(&self) -> &Manifest {
        &self.manifest
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn accept(self, acceptance: &GenerationAcceptance) -> Result<Client, ClientError> {
        acceptance.validate(&self.manifest)?;
        Ok(Client {
            base_url: self.base_url,
            manifest: self.manifest,
            acceptance: acceptance.clone(),
            cache: Mutex::new(SessionCache::default()),
            expired: AtomicBool::new(false),
        })
    }
}

#[derive(Default)]
struct SessionCache {
    sessions: BTreeMap<u64, Arc<QuerySession>>,
    order: VecDeque<u64>,
}

/// One wallet-accepted manifest. Refresh by fetching and accepting a new
/// `PendingClient`; a batch never silently changes generation or coverage.
pub struct Client {
    pub(crate) base_url: String,
    manifest: Manifest,
    acceptance: GenerationAcceptance,
    cache: Mutex<SessionCache>,
    expired: AtomicBool,
}
#[derive(Debug)]
pub struct PositionResult {
    pub position: u64,
    pub record: Result<EnhanceRecord, ClientError>,
}
impl Client {
    pub fn generation(&self) -> &Manifest {
        &self.manifest
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn check_live(&self) -> Result<(), ClientError> {
        if self.expired.load(Ordering::Acquire) {
            Err(ClientError::HttpStatus(410))
        } else {
            Ok(())
        }
    }

    fn note_status(&self, error: &ClientError) {
        if matches!(error, ClientError::HttpStatus(410)) {
            self.expired.store(true, Ordering::Release);
            let mut cache = self.cache.lock().unwrap();
            cache.sessions.clear();
            cache.order.clear();
        }
    }

    async fn session(
        &self,
        transport: &impl Transport,
        shard_id: u64,
    ) -> Result<Arc<QuerySession>, ClientError> {
        self.check_live()?;
        if !self
            .manifest
            .sessions
            .iter()
            .any(|reference| reference.shard_id == shard_id)
        {
            return Err(ClientError::Generation("unknown shard".into()));
        }
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(session) = cache.sessions.get(&shard_id).cloned() {
                cache.order.retain(|id| *id != shard_id);
                cache.order.push_back(shard_id);
                return Ok(session);
            }
        }
        let response = transport
            .execute(Request {
                method: Method::Get,
                url: endpoint(
                    &self.base_url,
                    &format!(
                        "/v1/enhance/sessions/{}/{}",
                        self.manifest.generation, shard_id
                    ),
                )?,
                body: vec![],
                response_limit: MAX_SESSION_BYTES,
            })
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.note_status(&error);
                return Err(error);
            }
        };
        // A custom transport may use its own collector. Retain the protocol cap.
        if response.as_ref().len() > MAX_SESSION_BYTES {
            return Err(ClientError::Response("HTTP body exceeds limit".into()));
        }
        self.check_live()?;
        let session: ShardSession = serde_json::from_slice(response.as_ref())?;
        let session = Arc::new(QuerySession::from_session(
            &self.manifest,
            session,
            &self.acceptance,
        )?);
        self.check_live()?;
        let mut cache = self.cache.lock().unwrap();
        if let Some(existing) = cache.sessions.get(&shard_id).cloned() {
            return Ok(existing);
        }
        let limit = self.acceptance.limits.max_cached_shards;
        if limit == 0 {
            return Err(ClientError::Generation("zero shard cache limit".into()));
        }
        while cache.sessions.len() >= limit {
            if let Some(evicted) = cache.order.pop_front() {
                cache.sessions.remove(&evicted);
            } else {
                return Err(ClientError::Generation("invalid shard cache state".into()));
            }
        }
        cache.order.push_back(shard_id);
        cache.sessions.insert(shard_id, session.clone());
        Ok(session)
    }
    pub async fn query_dummy(
        &self,
        transport: &impl Transport,
        shard_id: u64,
    ) -> Result<(), ClientError> {
        let session = self.session(transport, shard_id).await?;
        let query = session.prepare_dummy()?;
        self.check_live()?;
        let response = transport
            .execute(Request {
                method: Method::Post,
                url: endpoint(&self.base_url, "/v1/enhance/query")?,
                body: query.body().to_vec(),
                response_limit: MAX_RESPONSE_BYTES,
            })
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.note_status(&error);
                return Err(error);
            }
        };
        self.check_live()?;
        session.decode(query, response.as_ref()).map(|_| ())
    }

    /// Rejects more than `DEFAULT_MAX_BATCH_SIZE` input items before returning.
    /// Use `query_batch_with_limit` to select a local limit.
    /// Deduplicates positions and sends one query per shard-local row, sequentially.
    /// Results are in ascending position order for covered positions, followed
    /// by ascending uncovered positions; duplicate inputs yield one result. A row
    /// failure is associated with every position in that row; earlier records
    /// have already been yielded and can be committed independently. Covered rows
    /// are processed before explicit `OutsideCoverage` results. HTTP 410 expires
    /// this client and stops dispatch; HTTP 429/503 also stop dispatch so the
    /// application can reschedule with a bounded backoff. Earlier row results
    /// remain available for independent durable commits. After cancellation,
    /// remaining covered positions yield cancellation lazily without dispatch.
    ///
    /// Privacy: request count reveals the number of distinct covered rows.
    /// For a known fixed-size batch this leaks row-sharing relationships; no
    /// padding hides duplicates, uncovered positions, or early termination.
    /// This traffic-analysis leakage is accepted for the current integration.
    pub fn query_batch<'a>(
        &'a self,
        transport: &'a impl Transport,
        positions: impl IntoIterator<Item = u64>,
    ) -> Result<impl Stream<Item = PositionResult> + 'a, ClientError> {
        self.query_batch_with_limit(transport, positions, DEFAULT_MAX_BATCH_SIZE)
    }

    /// Ingests at most `max_items + 1` input items before returning a stream or
    /// `BatchTooLarge`. Counts duplicates and uncovered positions. No network I/O
    /// occurs on rejection. The caller must ensure each iterator step terminates.
    /// Choose a local limit suitable for the device; zero accepts only empty input.
    pub fn query_batch_with_limit<'a>(
        &'a self,
        transport: &'a impl Transport,
        positions: impl IntoIterator<Item = u64>,
        max_items: usize,
    ) -> Result<impl Stream<Item = PositionResult> + 'a, ClientError> {
        let mut rows = BTreeMap::<u64, (u64, usize, Vec<u64>)>::new();
        let ready = VecDeque::new();
        let mut uncovered = VecDeque::new();
        let mut unique = BTreeSet::new();
        for (index, position) in positions.into_iter().enumerate() {
            if index == max_items {
                return Err(ClientError::BatchTooLarge { max_items });
            }
            unique.insert(position);
        }
        for position in unique {
            if let Some((shard, row, _slot)) = self.manifest.coverage.locate(position) {
                let global_row = position / RECORDS_PER_ROW as u64;
                rows.entry(global_row)
                    .or_insert_with(|| (shard.id, row, Vec::new()))
                    .2
                    .push(position);
            } else {
                uncovered.push_back(position);
            }
        }
        Ok(stream::unfold(
            (rows.into_values(), ready, uncovered, None::<u16>, false),
            move |(mut rows, mut ready, mut uncovered, mut stopped, mut cancelled)| async move {
                if let Some(result) = ready.pop_front() {
                    return Some((result, (rows, ready, uncovered, stopped, cancelled)));
                }
                let Some((shard_id, row, positions)) = rows.next() else {
                    let position = uncovered.pop_front()?;
                    return Some((
                        PositionResult {
                            position,
                            record: Err(ClientError::OutsideCoverage(position)),
                        },
                        (rows, ready, uncovered, stopped, cancelled),
                    ));
                };
                let row = async {
                    if cancelled {
                        return Err(ClientError::Cancelled);
                    }
                    if let Some(status) = stopped {
                        return Err(ClientError::HttpStatus(status));
                    }
                    let session = self.session(transport, shard_id).await?;
                    let query = session.prepare_row(row)?;
                    self.check_live()?;
                    let response = transport
                        .execute(Request {
                            method: Method::Post,
                            url: endpoint(&self.base_url, "/v1/enhance/query")?,
                            body: query.body().to_vec(),
                            response_limit: MAX_RESPONSE_BYTES,
                        })
                        .await;
                    let response = match response {
                        Ok(response) => response,
                        Err(error) => {
                            self.note_status(&error);
                            return Err(error);
                        }
                    };
                    self.check_live()?;
                    if response.as_ref().len() > MAX_RESPONSE_BYTES {
                        return Err(ClientError::Response("HTTP body exceeds limit".into()));
                    }
                    session.decode(query, response.as_ref())
                }
                .await;
                match row {
                    Ok(row) => {
                        for position in positions {
                            ready.push_back(PositionResult {
                                position,
                                record: record_in_row(
                                    &row,
                                    (position % RECORDS_PER_ROW as u64) as usize,
                                ),
                            });
                        }
                    }
                    Err(error) => {
                        // Stop dispatch when retry scheduling or wallet acceptance is needed.
                        cancelled = matches!(error, ClientError::Cancelled);
                        if let ClientError::HttpStatus(code @ (410 | 429 | 503)) = &error {
                            stopped = Some(*code);
                        }
                        let error = std::sync::Arc::new(error);
                        for position in positions {
                            ready.push_back(PositionResult {
                                position,
                                record: Err(if cancelled {
                                    ClientError::Cancelled
                                } else if let Some(status) = stopped {
                                    ClientError::HttpStatus(status)
                                } else {
                                    ClientError::Row(error.clone())
                                }),
                            });
                        }
                    }
                }
                ready
                    .pop_front()
                    .map(|result| (result, (rows, ready, uncovered, stopped, cancelled)))
            },
        ))
    }
}

fn endpoint(base: &str, path: &str) -> Result<String, ClientError> {
    let mut url = url::Url::parse(base).map_err(|e| ClientError::Transport(e.to_string()))?;
    let local_http = url.scheme() == "http"
        && match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            None => false,
        };
    if !(url.scheme() == "https" || local_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::Transport(
            "PIR endpoint must be HTTPS (or loopback HTTP) without credentials, query or fragment"
                .into(),
        ));
    }
    url.set_path(&format!("{}{path}", url.path().trim_end_matches('/')));
    Ok(url.into())
}

#[cfg(feature = "https-client")]
/// HTTPS transport with redirects disabled and a deadline covering the response body.
/// Construct with `new`; arbitrary Reqwest clients cannot bypass these policies.
#[derive(Clone)]
pub struct ReqwestTransport(reqwest::Client);

#[cfg(feature = "https-client")]
impl ReqwestTransport {
    /// Builds a transport with a 120-second request deadline. Returns an HTTP
    /// client construction error if TLS or resolver initialization fails.
    pub fn new() -> Result<Self, ClientError> {
        Ok(Self(
            Self::builder(std::time::Duration::from_secs(120)).build()?,
        ))
    }

    fn builder(timeout: std::time::Duration) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
    }
}

#[cfg(feature = "https-client")]
impl Transport for ReqwestTransport {
    async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
        let mut body = request.response_body();
        let mut response = self
            .0
            .request(
                match request.method {
                    Method::Get => reqwest::Method::GET,
                    Method::Post => reqwest::Method::POST,
                },
                request.url,
            )
            .header("content-type", "application/octet-stream")
            .body(request.body)
            .send()
            .await?;
        validate_http_status(response.status())?;
        while let Some(chunk) = response.chunk().await? {
            body.extend(&chunk)?;
        }
        Ok(body.finish())
    }
}

#[cfg(feature = "https-client")]
fn validate_http_status(status: reqwest::StatusCode) -> Result<(), ClientError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(ClientError::HttpStatus(status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "https-client")]
    fn serve_once(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let mut received = Vec::new();
            while !received.ends_with(b"\r\n\r\n") {
                let read = stream.read(&mut request).unwrap();
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&request[..read]);
            }
            stream.write_all(response).unwrap();
        });
        (format!("http://{address}/"), server)
    }

    #[test]
    fn bounds_before_extending() {
        let mut body = BoundedBody::new(3);
        body.extend(&[1, 2]).unwrap();
        assert!(body.extend(&[3, 4]).is_err());
        body.extend(&[3]).unwrap();
        assert_eq!(body.finish().as_ref(), [1, 2, 3]);
    }
    #[cfg(feature = "https-client")]
    #[test]
    fn accepts_only_successful_http_statuses() {
        for code in [100, 200, 204, 299, 300, 302, 400, 404, 500, 503] {
            let result = validate_http_status(reqwest::StatusCode::from_u16(code).unwrap());
            assert_eq!(result.is_ok(), (200..300).contains(&code));
            if let Err(error) = result {
                assert!(matches!(error, ClientError::HttpStatus(actual) if actual == code));
            }
        }
    }

    #[cfg(feature = "https-client")]
    #[test]
    fn reqwest_rejects_redirects_and_bounds_chunked_responses() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // Local HTTP fixture; keep the production redirect policy and a short deadline.
        let client = ReqwestTransport(
            ReqwestTransport::builder(std::time::Duration::from_millis(200))
                .https_only(false)
                .build()
                .unwrap(),
        );

        let (url, server) = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let redirect = runtime.block_on(Transport::execute(
            &client,
            Request {
                method: Method::Get,
                url,
                body: vec![],
                response_limit: 3,
            },
        ));
        server.join().unwrap();
        assert!(matches!(redirect, Err(ClientError::HttpStatus(302))));

        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n",
        );
        let oversized = runtime.block_on(Transport::execute(
            &client,
            Request {
                method: Method::Get,
                url,
                body: vec![],
                response_limit: 3,
            },
        ));
        server.join().unwrap();
        assert!(matches!(
            oversized,
            Err(ClientError::Response(message)) if message == "HTTP body exceeds limit"
        ));
    }

    #[cfg(feature = "https-client")]
    #[test]
    fn reqwest_rejects_http_and_times_out_an_unfinished_body() {
        use std::io::{Read, Write};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let safe = ReqwestTransport::new().unwrap();
        let denied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        denied.set_nonblocking(true).unwrap();
        let result = runtime.block_on(safe.execute(Request {
            method: Method::Get,
            url: format!("http://{}/", denied.local_addr().unwrap()),
            body: vec![],
            response_limit: 3,
        }));
        assert!(result.is_err());
        assert!(matches!(denied.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (release, hold) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0; 1024];
            socket.read(&mut buf).unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na")
                .unwrap();
            let _ = hold.recv_timeout(std::time::Duration::from_secs(2));
        });
        let client = ReqwestTransport(
            ReqwestTransport::builder(std::time::Duration::from_millis(200))
                .https_only(false)
                .build()
                .unwrap(),
        );
        let result = runtime.block_on(client.execute(Request {
            method: Method::Get,
            url,
            body: vec![],
            response_limit: 3,
        }));
        let _ = release.send(());
        server.join().unwrap();
        assert!(matches!(result, Err(ClientError::Http(e)) if e.is_timeout()));
    }

    #[test]
    fn validates_endpoint() {
        for url in [
            "http://example.org",
            "https://user@example.org",
            "https://example.org?a=1",
            "https://example.org/#x",
        ] {
            assert!(endpoint(url, "/v1/enhance/init").is_err());
        }
        assert_eq!(
            endpoint("  HTTPS://EXAMPLE.ORG:443/a/../base/  ", "/v1/enhance/init").unwrap(),
            "https://example.org/base/v1/enhance/init"
        );
        assert_eq!(
            endpoint("https://example.org/a%2Fb", "/v1/enhance/init").unwrap(),
            "https://example.org/a%2Fb/v1/enhance/init"
        );
        assert_eq!(
            endpoint("https://example.org/base/", "/v1/enhance/init").unwrap(),
            "https://example.org/base/v1/enhance/init"
        );
        assert_eq!(
            endpoint("http://127.0.0.1:8080", "/v1/enhance/init").unwrap(),
            "http://127.0.0.1:8080/v1/enhance/init"
        );
    }
}

#[cfg(test)]
mod initialization_tests {
    use super::*;
    struct Fake(Vec<u8>);
    impl Transport for Fake {
        async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
            assert!(matches!(request.method, Method::Get));
            assert_eq!(request.response_limit, MAX_MANIFEST_BYTES);
            let mut body = request.response_body();
            body.extend(&self.0)?;
            Ok(body.finish())
        }
    }
    #[test]
    fn custom_transport_stops_collection_at_the_request_limit() {
        struct Endless(std::cell::Cell<usize>);
        impl Transport for Endless {
            async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
                let mut body = request.response_body();
                // Reuse one small chunk: the attacker never supplies a pre-collected Vec.
                let chunk = [0u8; 4096];
                loop {
                    self.0.set(self.0.get() + 1);
                    body.extend(&chunk)?;
                }
            }
        }
        let transport = Endless(std::cell::Cell::new(0));
        assert!(matches!(
            futures::executor::block_on(PendingClient::fetch(&transport, "https://example.test")),
            Err(ClientError::Response(_))
        ));
        assert_eq!(transport.0.get(), MAX_MANIFEST_BYTES / 4096 + 1);
    }

    #[test]
    fn rejects_oversized_and_malformed_initialization_without_setup() {
        assert!(matches!(
            futures::executor::block_on(PendingClient::fetch(
                &Fake(vec![0; MAX_MANIFEST_BYTES + 1]),
                "https://example.test"
            )),
            Err(ClientError::Response(_))
        ));
        assert!(matches!(
            futures::executor::block_on(PendingClient::fetch(
                &Fake(b"{}".to_vec()),
                "https://example.test"
            )),
            Err(ClientError::Json(_))
        ));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::{AcceptedAnchor, ClientResourceLimits};
    use futures::StreamExt;
    use std::cell::Cell;

    struct FixtureTransport {
        manifest: Vec<u8>,
        session: Vec<u8>,
        session_status: Option<u16>,
        query_status: Option<u16>,
        init_requests: Cell<usize>,
        session_requests: Cell<usize>,
        query_requests: Cell<usize>,
    }

    impl FixtureTransport {
        fn new(session_status: Option<u16>, query_status: Option<u16>) -> Self {
            let fixture: serde_json::Value =
                serde_json::from_str(include_str!("../tests/fixtures/upstream-session.json"))
                    .unwrap();
            Self {
                manifest: serde_json::to_vec(&fixture["manifest"]).unwrap(),
                session: serde_json::to_vec(&fixture["session"]).unwrap(),
                session_status,
                query_status,
                init_requests: Cell::new(0),
                session_requests: Cell::new(0),
                query_requests: Cell::new(0),
            }
        }

        fn acceptance(&self, hash: u8, max_cached_shards: usize) -> GenerationAcceptance {
            GenerationAcceptance::new(
                "main",
                3_428_143,
                AcceptedAnchor::new(3_428_143, [hash; 32], 67),
                ClientResourceLimits::with_cache(4_096, max_cached_shards),
            )
        }
    }

    impl Transport for FixtureTransport {
        async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
            let bytes = if request.url.ends_with("/v1/enhance/init") {
                assert!(matches!(request.method, Method::Get));
                self.init_requests.set(self.init_requests.get() + 1);
                &self.manifest
            } else if request.url.ends_with("/v1/enhance/sessions/7/0") {
                assert!(matches!(request.method, Method::Get));
                self.session_requests.set(self.session_requests.get() + 1);
                if let Some(status) = self.session_status {
                    return Err(ClientError::HttpStatus(status));
                }
                &self.session
            } else if request.url.ends_with("/v1/enhance/query") {
                assert!(matches!(request.method, Method::Post));
                self.query_requests.set(self.query_requests.get() + 1);
                if let Some(status) = self.query_status {
                    return Err(ClientError::HttpStatus(status));
                }
                panic!("fixture transport does not synthesize PIR answers");
            } else {
                panic!("unexpected endpoint: {}", request.url);
            };
            let mut body = request.response_body();
            body.extend(bytes)?;
            Ok(body.finish())
        }
    }

    #[test]
    fn expired_shard_session_requires_new_wallet_acceptance() {
        let transport = FixtureTransport::new(Some(410), None);
        futures::executor::block_on(async {
            let pending = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            let client = pending.accept(&transport.acceptance(0x42, 1)).unwrap();
            let results = client
                .query_batch(&transport, [33, 0, 0, 1])
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert_eq!(
                results.iter().map(|r| r.position).collect::<Vec<_>>(),
                [0, 1, 33]
            );
            assert!(
                results
                    .iter()
                    .all(|r| matches!(&r.record, Err(ClientError::HttpStatus(410))))
            );
            assert_eq!(transport.session_requests.get(), 1);
            assert_eq!(transport.query_requests.get(), 0);

            let stale = client
                .query_batch(&transport, [0])
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert!(matches!(
                &stale[0].record,
                Err(ClientError::HttpStatus(410))
            ));
            assert_eq!(transport.session_requests.get(), 1);

            let fresh = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            assert!(matches!(
                fresh.accept(&transport.acceptance(0x43, 1)),
                Err(ClientError::Generation(_))
            ));
            assert_eq!(transport.init_requests.get(), 2);
        });
    }

    #[test]
    fn retryable_session_status_stops_batch_without_more_dispatch() {
        for status in [429, 503] {
            let transport = FixtureTransport::new(Some(status), None);
            futures::executor::block_on(async {
                let client = PendingClient::fetch(&transport, "https://example.test")
                    .await
                    .unwrap()
                    .accept(&transport.acceptance(0x42, 1))
                    .unwrap();
                let results = client
                    .query_batch(&transport, [34, 0, 0, 1, 33, 67])
                    .unwrap()
                    .collect::<Vec<_>>()
                    .await;
                assert_eq!(
                    results.iter().map(|r| r.position).collect::<Vec<_>>(),
                    [0, 1, 33, 34, 67]
                );
                assert!(
                    results[..4]
                        .iter()
                        .all(|r| r.record.as_ref().unwrap_err().http_status() == Some(status))
                );
                assert!(matches!(
                    &results[4].record,
                    Err(ClientError::OutsideCoverage(67))
                ));
                assert_eq!(transport.session_requests.get(), 1);
                assert_eq!(transport.query_requests.get(), 0);
            });
        }
    }

    #[test]
    fn query_status_reuses_one_cached_shard_session() {
        let transport = FixtureTransport::new(None, Some(503));
        futures::executor::block_on(async {
            let client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&transport.acceptance(0x42, 1))
                .unwrap();
            let results = client
                .query_batch(&transport, [33, 0, 1, 0, 33])
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert_eq!(
                results.iter().map(|r| r.position).collect::<Vec<_>>(),
                [0, 1, 33]
            );
            assert!(
                results
                    .iter()
                    .all(|r| r.record.as_ref().unwrap_err().http_status() == Some(503))
            );
            assert_eq!(transport.session_requests.get(), 1);
            assert_eq!(transport.query_requests.get(), 1);

            let again = client
                .query_batch(&transport, [33])
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert_eq!(again.len(), 1);
            assert_eq!(transport.session_requests.get(), 1);
            assert_eq!(transport.query_requests.get(), 2);
        });
    }

    #[test]
    fn zero_cache_limit_is_rejected_before_setup() {
        let transport = FixtureTransport::new(None, None);
        futures::executor::block_on(async {
            let pending = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            assert!(matches!(
                pending.accept(&transport.acceptance(0x42, 0)),
                Err(ClientError::Generation(_))
            ));
            assert_eq!(transport.session_requests.get(), 0);
        });
    }
}
