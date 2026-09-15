//! Application-routed HTTP with bounded collection and generation-bound batches.
use crate::client::record_in_row;
use crate::{
    ClientError, EnhanceGeneration, EnhanceRecord, EnhanceSession, GenerationAcceptance,
    QuerySession, RECORDS_PER_ROW,
};
use futures_util::{Stream, stream};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
};

/// Default maximum number of input items, including duplicates, in one batch.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 4096;

pub const MAX_SESSION_BYTES: usize = 1024 * 1024;
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

/// Implementations must reject unsuccessful HTTP status codes and abort on
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
    session: EnhanceSession,
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
                response_limit: MAX_SESSION_BYTES,
            })
            .await?;
        if bytes.as_ref().len() > MAX_SESSION_BYTES {
            return Err(ClientError::Response("HTTP body exceeds limit".into()));
        }
        Ok(Self {
            base_url,
            session: serde_json::from_slice(bytes.as_ref())?,
        })
    }
    pub fn generation(&self) -> &EnhanceGeneration {
        &self.session.generation
    }
    pub fn accept(self, acceptance: &GenerationAcceptance) -> Result<Client, ClientError> {
        Ok(Client {
            base_url: self.base_url,
            session: QuerySession::from_session(self.session, acceptance)?,
        })
    }
}

/// Immutable generation. A refresh creates a separate client, so existing
/// streams cannot switch generation midway through a batch.
pub struct Client {
    pub(crate) base_url: String,
    pub(crate) session: QuerySession,
}
#[derive(Debug)]
pub struct PositionResult {
    pub position: u64,
    pub record: Result<EnhanceRecord, ClientError>,
}
impl Client {
    pub fn generation(&self) -> &EnhanceGeneration {
        self.session.generation()
    }
    pub async fn query_dummy(&self, transport: &impl Transport) -> Result<(), ClientError> {
        let query = self.session.prepare_dummy()?;
        let response = transport
            .execute(Request {
                method: Method::Post,
                url: endpoint(&self.base_url, "/v1/enhance/query")?,
                body: query.body().to_vec(),
                response_limit: MAX_RESPONSE_BYTES,
            })
            .await?;
        self.session.decode(query, response.as_ref()).map(|_| ())
    }

    /// Rejects more than `DEFAULT_MAX_BATCH_SIZE` input items before returning.
    /// Use `query_batch_with_limit` to select a local limit.
    /// Deduplicates positions and sends one query per row, sequentially. A row
    /// failure is associated with every position in that row; earlier records
    /// have already been yielded and can be committed independently. Covered rows
    /// are processed before explicit `OutsideCoverage` results. After cancellation,
    /// remaining covered positions yield cancellation lazily without more dispatch.
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
        let mut rows = BTreeMap::<u64, Vec<u64>>::new();
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
            if position >= self.generation().ironwood_tree_size {
                uncovered.push_back(position);
            } else {
                rows.entry(position / RECORDS_PER_ROW as u64)
                    .or_default()
                    .push(position);
            }
        }
        Ok(stream::unfold(
            (rows.into_values(), ready, uncovered, false),
            move |(mut rows, mut ready, mut uncovered, mut cancelled)| async move {
                if let Some(result) = ready.pop_front() {
                    return Some((result, (rows, ready, uncovered, cancelled)));
                }
                let Some(positions) = rows.next() else {
                    let position = uncovered.pop_front()?;
                    return Some((
                        PositionResult {
                            position,
                            record: Err(ClientError::OutsideCoverage(position)),
                        },
                        (rows, ready, uncovered, cancelled),
                    ));
                };
                let row = async {
                    if cancelled {
                        return Err(ClientError::Cancelled);
                    }
                    let (query, _) = self.session.prepare_position(positions[0])?;
                    let response = transport
                        .execute(Request {
                            method: Method::Post,
                            url: endpoint(&self.base_url, "/v1/enhance/query")?,
                            body: query.body().to_vec(),
                            response_limit: MAX_RESPONSE_BYTES,
                        })
                        .await?;
                    if response.as_ref().len() > MAX_RESPONSE_BYTES {
                        return Err(ClientError::Response("HTTP body exceeds limit".into()));
                    }
                    self.session.decode(query, response.as_ref())
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
                        // Stop dispatch on cancellation. Other row failures remain retryable.
                        cancelled = matches!(error, ClientError::Cancelled);
                        let error = std::sync::Arc::new(error);
                        for position in positions {
                            ready.push_back(PositionResult {
                                position,
                                record: Err(if cancelled {
                                    ClientError::Cancelled
                                } else {
                                    ClientError::Row(error.clone())
                                }),
                            });
                        }
                    }
                }
                ready
                    .pop_front()
                    .map(|result| (result, (rows, ready, uncovered, cancelled)))
            },
        ))
    }
}

fn endpoint(base: &str, path: &str) -> Result<String, ClientError> {
    let mut url = url::Url::parse(base).map_err(|e| ClientError::Transport(e.to_string()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::Transport(
            "PIR endpoint must be an HTTPS URL without credentials, query or fragment".into(),
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
        Err(ClientError::Response(format!("server returned {status}")))
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
                assert!(matches!(error, ClientError::Response(_)));
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
        assert!(matches!(
            redirect,
            Err(ClientError::Response(message)) if message.contains("302")
        ));

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
    }
}

#[cfg(test)]
mod initialization_tests {
    use super::*;
    struct Fake(Vec<u8>);
    impl Transport for Fake {
        async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
            assert!(matches!(request.method, Method::Get));
            assert_eq!(request.response_limit, MAX_SESSION_BYTES);
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
        assert_eq!(transport.0.get(), MAX_SESSION_BYTES / 4096 + 1);
    }

    #[test]
    fn rejects_oversized_and_malformed_initialization_without_setup() {
        assert!(matches!(
            futures::executor::block_on(PendingClient::fetch(
                &Fake(vec![0; MAX_SESSION_BYTES + 1]),
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
