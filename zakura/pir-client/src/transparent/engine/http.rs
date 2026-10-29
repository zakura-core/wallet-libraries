//! Reference HTTP adapters, behind the `reqwest` feature.
//!
//! One blocking client each for the private shard service and the public
//! filter origin, reading the reply's status, `retry-after` and body before
//! anything is discarded, so the two refusals a wallet can act on reach it as
//! typed errors. A wallet with its own HTTP stack implements the transport
//! traits itself; this is what the tests, the measurement tools and a first
//! integration use.

use crate::transparent::engine::client::Table;
pub use crate::transparent::engine::init::parse_init;
use crate::transparent::engine::sync::ServiceGeometry;
use crate::transparent::engine::transport::{
    BoxError, FilterSource, ShardReply, ShardRequest, ShardTransport, TransferFailure, refusal,
};
use crate::transparent::http_client::{Client as BlockingClient, Request as BufferedRequest};
use crate::transparent::routes;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zakura_pir_protocol::endpoint::Endpoint;

// Callers may explicitly choose a different finite success-body limit for a
// larger publication. Error bodies never need the binary-response allowance.
const DEFAULT_RESPONSE_LIMIT: usize = 64 * 1024 * 1024;
const ERROR_RESPONSE_LIMIT: usize = 64 * 1024;

/// How the reference clients are built.
#[derive(Clone, Debug)]
pub struct HttpOptions {
    /// Total budget for one HTTP call, including every attempt and backoff.
    pub timeout: Duration,
    pub user_agent: String,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            user_agent: "transparent-wallet".into(),
        }
    }
}

fn build(options: &HttpOptions) -> Result<BlockingClient, BoxError> {
    Ok(BlockingClient::new(
        options.timeout,
        Some(&options.user_agent),
    )?)
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct HttpStatusError {
    status: u16,
    message: String,
    #[source]
    cause: Option<BoxError>,
}

fn status_error(
    status: ureq::http::StatusCode,
    shard: u64,
    revision: &str,
    body: &[u8],
) -> BoxError {
    Box::new(HttpStatusError {
        status: status.as_u16(),
        cause: None,
        message: format!(
            "shard {shard} revision {revision}: HTTP {status}: {}",
            String::from_utf8_lossy(body)
        ),
    })
}

/// Reads a reply, turning a refusal the wallet can act on into one.
///
/// The body and the `retry-after` header are read before the status is thrown
/// away: `error_for_status` keeps only the code, and the map digest a stale
/// refusal carries lives in the body.
pub fn checked(
    response: ureq::http::Response<ureq::Body>,
    shard_id: u64,
    revision: &str,
) -> Result<Vec<u8>, BoxError> {
    let status = response.status();
    if status.is_success() {
        return response_body(response, "checked", DEFAULT_RESPONSE_LIMIT);
    }
    let retry_after = response
        .headers()
        .get(ureq::http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response_body(response, "checked", DEFAULT_RESPONSE_LIMIT)?;
    if let Some(refused) = refusal(
        status.as_u16(),
        retry_after.as_deref(),
        &body,
        shard_id,
        revision,
    ) {
        return Err(Box::new(HttpStatusError {
            status: status.as_u16(),
            message: refused.to_string(),
            cause: Some(refused),
        }));
    }
    Err(status_error(status, shard_id, revision, &body))
}

/// One completed HTTP attempt. Contains no URL, query body, script or key.
#[derive(Clone, Debug)]
pub struct HttpObservation {
    pub stage: &'static str,
    /// Process-local identifier shared by all attempts of one HTTP call.
    pub request_id: u64,
    pub attempt: usize,
    pub status: Option<u16>,
    pub elapsed: Duration,
    /// Submitted request payload size; not a measurement of socket delivery.
    pub bytes_up: u64,
    /// Response payload bytes read, including error responses.
    pub bytes_down: u64,
    pub failed: bool,
    /// Underlying transport causes, without the top-level request URL.
    pub transport_error: Option<String>,
}

/// Optional local observer. Called once per attempt, including transport errors.
pub type HttpObserver = Arc<dyn Fn(HttpObservation) + Send + Sync>;

#[derive(Clone, Copy)]
struct RetryPolicy {
    attempts: usize,
    overload: bool,
    response_limit: usize,
    timeout: Duration,
}

/// Find a typed transport cause without losing it through receipt or IO
/// wrappers. IO's source chain can skip the contained error itself, so inspect
/// get_ref before continuing through its ordinary sources.
fn transport_cause<'a, E: std::error::Error + 'static>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a E> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(cause) = error.downcast_ref::<E>() {
            return Some(cause);
        }
        current = error
            .downcast_ref::<std::io::Error>()
            .and_then(|error| {
                error
                    .get_ref()
                    .map(|cause| cause as &(dyn std::error::Error + 'static))
            })
            .or_else(|| error.source());
    }
    None
}

/// Opt-in retries replay the same buffered request within one shared deadline.
/// Application decoding and revision validation occur after this function and
/// are never retried here. The observer records every attempt; callers must
/// still impose an overall recovery deadline.
fn execute(
    request: BufferedRequest,
    stage: &'static str,
    bytes_up: u64,
    binding: Option<(u64, &str)>,
    observer: &Option<HttpObserver>,
    policy: RetryPolicy,
) -> Result<Vec<u8>, BoxError> {
    execute_measured(request, stage, bytes_up, binding, observer, policy).map(|(bytes, _)| bytes)
}

fn execute_measured(
    request: BufferedRequest,
    stage: &'static str,
    bytes_up: u64,
    binding: Option<(u64, &str)>,
    observer: &Option<HttpObserver>,
    policy: RetryPolicy,
) -> Result<(Vec<u8>, u64), BoxError> {
    static REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let request_id = REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let attempts = policy.attempts.max(1);
    let retry_overload = policy.overload;
    let started = Instant::now();
    let mut downloaded = 0u64;
    for attempt in 0..attempts {
        let remaining = policy.timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(TransferFailure::boxed(
                downloaded,
                "HTTP call deadline exhausted".into(),
            ));
        }
        let observed = observer.as_ref().map(|observer| {
            let observer = observer.clone();
            Arc::new(move |mut event: HttpObservation| {
                event.request_id = request_id;
                event.attempt = attempt + 1;
                observer(event);
            }) as HttpObserver
        });
        let copy = request.clone().timeout(remaining);
        let result = execute_once(
            copy,
            stage,
            bytes_up,
            binding,
            &observed,
            policy.response_limit,
        );
        downloaded += match &result {
            Ok(bytes) => bytes.len() as u64,
            Err(error) => TransferFailure::downloaded(error),
        };
        let delay = result.as_ref().err().and_then(|error| {
            if !retry_overload
                && transport_cause::<HttpStatusError>(error.as_ref())
                    .is_some_and(|e| matches!(e.status, 502 | 504))
            {
                return Some(transient_backoff(attempt));
            }
            if let Some(overloaded) =
                crate::transparent::engine::transport::Overloaded::found_in(error)
            {
                return if retry_overload {
                    overloaded
                        .retry_after
                        .map(crate::transparent::engine::backoff::jittered)
                } else {
                    None
                };
            }
            if transport_cause::<HttpStatusError>(error.as_ref()).is_some_and(|error| {
                matches!(error.status, 408 | 502 | 504) || (retry_overload && error.status == 503)
            }) {
                return Some(transient_backoff(attempt));
            }
            if transport_cause::<std::io::Error>(error.as_ref()).is_some() {
                return Some(transient_backoff(attempt));
            }
            transport_cause::<ureq::Error>(error.as_ref()).and_then(|error| {
                // Only transport failures replay buffered requests. Builder,
                // status and application-decoding errors stay separate.
                matches!(
                    error,
                    ureq::Error::Timeout(_)
                        | ureq::Error::HostNotFound
                        | ureq::Error::ConnectionFailed
                        | ureq::Error::Io(_)
                        | ureq::Error::Protocol(_)
                        | ureq::Error::Tls(_)
                        | ureq::Error::Rustls(_)
                )
                .then(|| transient_backoff(attempt))
            })
        });
        if attempt + 1 == attempts || delay.is_none() {
            return result
                .map(|bytes| (bytes, downloaded))
                .map_err(|error| TransferFailure::boxed(downloaded, error));
        }
        let delay = delay.unwrap();
        if delay >= policy.timeout.saturating_sub(started.elapsed()) {
            // Return the last refusal/error without oversleeping its budget.
            return result
                .map(|bytes| (bytes, downloaded))
                .map_err(|error| TransferFailure::boxed(downloaded, error));
        }
        std::thread::sleep(delay);
    }
    unreachable!("attempts is positive")
}

/// The wait before retrying a transient failure: one second, doubled per
/// attempt, jittered so that clients failed together do not retry together.
fn transient_backoff(attempt: usize) -> Duration {
    crate::transparent::engine::backoff::exponential(
        Duration::from_secs(1),
        u32::try_from(attempt + 1).unwrap_or(u32::MAX),
        Duration::from_secs(8),
    )
}

fn response_body(
    response: ureq::http::Response<ureq::Body>,
    stage: &str,
    response_limit: usize,
) -> Result<Vec<u8>, BoxError> {
    let limit = if response.status().is_success() {
        match stage {
            "parent_manifest" => 2 * 1024 * 1024,
            "parent_filters" => {
                zakura_pir_protocol::transparent::filter::experimental_parent::LIMITS.max_bytes
            }
            _ => response_limit,
        }
    } else {
        ERROR_RESPONSE_LIMIT
    }
    .min(response_limit)
    .min(usize::MAX - 1);
    if response
        .body()
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err("HTTP response exceeds size limit".into());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    if let Err(error) = response
        .into_body()
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
    {
        return Err(TransferFailure::boxed(bytes.len() as u64, error.into()));
    }
    if bytes.len() > limit {
        return Err(TransferFailure::boxed(
            bytes.len() as u64,
            "HTTP response exceeds size limit".into(),
        ));
    }
    Ok(bytes)
}

fn execute_once(
    request: BufferedRequest,
    stage: &'static str,
    bytes_up: u64,
    binding: Option<(u64, &str)>,
    observer: &Option<HttpObserver>,
    response_limit: usize,
) -> Result<Vec<u8>, BoxError> {
    let started = Instant::now();
    let mut status = None;
    let mut bytes_down = 0;
    let result = (|| -> Result<Vec<u8>, BoxError> {
        let response = request.send()?;
        let code = response.status();
        status = Some(code.as_u16());
        let public_error = code.is_client_error() || code.is_server_error();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let body = match response_body(response, stage, response_limit) {
            Ok(body) => body,
            Err(error) => {
                bytes_down = TransferFailure::downloaded(&error);
                return Err(error);
            }
        };
        bytes_down = body.len() as u64;
        if let Some((shard, revision)) = binding {
            if !code.is_success() {
                if let Some(error) = refusal(
                    code.as_u16(),
                    retry_after.as_deref(),
                    &body,
                    shard,
                    revision,
                ) {
                    return Err(Box::new(HttpStatusError {
                        status: code.as_u16(),
                        message: error.to_string(),
                        cause: Some(error),
                    }));
                }
                return Err(status_error(code, shard, revision, &body));
            }
        } else if public_error {
            if let Some(overloaded) = crate::transparent::engine::transport::Overloaded::from_http(
                code.as_u16(),
                retry_after.as_deref(),
            ) {
                return Err(Box::new(HttpStatusError {
                    status: code.as_u16(),
                    message: overloaded.to_string(),
                    cause: Some(Box::new(overloaded)),
                }));
            }
            return Err(Box::new(HttpStatusError {
                status: code.as_u16(),
                message: format!("HTTP {code}"),
                cause: None,
            }) as BoxError);
        }
        Ok(body)
    })();
    if let Some(observer) = observer {
        observer(HttpObservation {
            request_id: 0,
            attempt: 1,
            stage,
            status,
            elapsed: started.elapsed(),
            bytes_up,
            bytes_down,
            failed: result.is_err(),
            transport_error: result.as_ref().err().and_then(|error| {
                let Some(error) = transport_cause::<ureq::Error>(error.as_ref()) else {
                    return transport_cause::<std::io::Error>(error.as_ref())
                        .map(|_| "HTTP I/O failure".into());
                };
                let description = match error {
                    ureq::Error::Http(_) | ureq::Error::BadUri(_) | ureq::Error::StatusCode(_) => {
                        return None;
                    }
                    ureq::Error::Timeout(_) => "HTTP timeout",
                    ureq::Error::HostNotFound => "name resolution failed",
                    ureq::Error::ConnectionFailed => "connection failed",
                    ureq::Error::Io(_) => "HTTP I/O failure",
                    ureq::Error::Protocol(_) => "invalid HTTP response",
                    ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS failure",
                    _ => "HTTP transport failure",
                };
                Some(description.into())
            }),
        });
    }
    result.map_err(|error| {
        if bytes_down == 0 || TransferFailure::downloaded(&error) != 0 {
            error
        } else {
            TransferFailure::boxed(bytes_down, error)
        }
    })
}

/// A public immutable resource downloaded with the same measured retry policy.
/// Response bytes are returned before any application decoding occurs.
pub struct HttpResourceClient {
    client: BlockingClient,
    observer: Option<HttpObserver>,
    retry: RetryPolicy,
}
impl HttpResourceClient {
    /// Bound every response before allocating its complete body. Oversized
    /// replies fail without retry; parent experiment limits remain stricter.
    pub fn with_response_limit(mut self, bytes: usize) -> Self {
        self.retry.response_limit = bytes.min(usize::MAX - 1);
        self
    }

    pub fn new(
        options: &HttpOptions,
        observer: Option<HttpObserver>,
        attempts: usize,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            client: build(options)?,
            observer,
            retry: RetryPolicy {
                response_limit: DEFAULT_RESPONSE_LIMIT,
                attempts: attempts.clamp(1, 3),
                overload: false,

                timeout: options.timeout,
            },
        })
    }
    pub fn get(&self, url: &str, stage: &'static str) -> Result<Vec<u8>, BoxError> {
        execute(
            // Explicit negotiation also prevents intermediary HTTP clients from
            // transparently decompressing a response before forwarding it.
            self.client
                .get(url)
                .header("accept-encoding", "gzip, identity"),
            stage,
            0,
            None,
            &self.observer,
            self.retry,
        )
    }
}

/// The private shard service over HTTP.
pub struct HttpShardTransport {
    /// The server base; every request addresses a Transparent route below it.
    base: Endpoint,
    client: BlockingClient,
    observer: Option<HttpObserver>,
    retry: RetryPolicy,
    /// Requests a batch keeps in flight.
    concurrency: usize,
}

/// Shard service requests a batch keeps in flight by default.
///
/// Lower than the filter prefetch's, because each of these requests costs the
/// service a runtime rather than a file read.
pub const SHARD_REQUEST_CONCURRENCY: usize = 4;

impl HttpShardTransport {
    /// Bound every response before allocating its complete body. Oversized
    /// replies fail without retry; parent experiment limits remain stricter.
    pub fn with_response_limit(mut self, bytes: usize) -> Self {
        self.retry.response_limit = bytes.min(usize::MAX - 1);
        self
    }

    /// The shard service below the server base `base_url`, whose path prefix
    /// every request keeps. Refuses a base [`Endpoint::parse`] refuses.
    pub fn new(base_url: impl Into<String>, options: &HttpOptions) -> Result<Self, BoxError> {
        Ok(Self {
            base: Endpoint::parse(&base_url.into())?,
            client: build(options)?,
            observer: None,
            retry: RetryPolicy {
                response_limit: DEFAULT_RESPONSE_LIMIT,
                attempts: 1,
                overload: true,

                timeout: options.timeout,
            },
            concurrency: SHARD_REQUEST_CONCURRENCY,
        })
    }

    /// Requests a batch keeps in flight; 1 makes the sync walk every request
    /// in sequence, which is the reference behaviour.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Opt into a bounded number of attempts per HTTP call (1–3). This is
    /// for init and manifests. Setup and private queries always make one
    /// physical attempt; wallet-level refusal handling owns their retries.
    pub fn with_retry_attempts(mut self, attempts: usize) -> Self {
        self.retry.attempts = attempts.clamp(1, 3);
        self
    }

    /// Retry transient gateway/upload/connection failures without layering
    /// additional overload retries on the wallet's refusal policy. This applies
    /// to init and manifests; setup and private queries always attempt once.
    pub fn with_transient_retry_attempts(mut self, attempts: usize) -> Self {
        self.retry.attempts = attempts.clamp(1, 3);
        self.retry.overload = false;
        self
    }

    /// Attach an observer without changing request or retry behavior.
    pub fn with_observer(mut self, observer: HttpObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Fetches and parses the init document.
    pub fn geometry(&mut self) -> Result<ServiceGeometry, BoxError> {
        let (raw, _) = self.init()?;
        parse_init(&raw)
    }

    /// Sends one request. Shared by the single-request methods and a batch,
    /// so both take exactly the same path, retries and observation included.
    fn send(&self, request: &ShardRequest<'_>) -> Result<(Vec<u8>, u64), BoxError> {
        let revision = match request {
            ShardRequest::Manifest { revision, .. }
            | ShardRequest::Setup { revision, .. }
            | ShardRequest::Query { revision, .. } => revision,
        };
        if revision.len() != 64
            || !revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("revision digest must contain exactly 64 hexadecimal characters".into());
        }
        let url = routes::url(&self.base, &request.operation())?;
        let (builder, binding) = match *request {
            ShardRequest::Manifest { shard_id, revision }
            | ShardRequest::Setup {
                shard_id, revision, ..
            } => (self.client.get(url), (shard_id, revision)),
            ShardRequest::Query {
                shard_id,
                revision,
                body,
                ..
            } => (
                self.client.post(url).body(body.to_vec()),
                (shard_id, revision),
            ),
        };
        // Wallet work limits and refusal handling own private retries. One
        // trait call must represent one physical setup or query attempt.
        let policy = if matches!(
            request,
            ShardRequest::Setup { .. } | ShardRequest::Query { .. }
        ) {
            RetryPolicy {
                attempts: 1,
                ..self.retry
            }
        } else {
            self.retry
        };
        let (bytes, len) = execute_measured(
            builder,
            request.stage(),
            request.upload(),
            Some(binding),
            &self.observer,
            policy,
        )?;
        Ok((bytes, len))
    }
}

impl ShardTransport for HttpShardTransport {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let (bytes, len) = execute_measured(
            self.client.get(routes::url(&self.base, "/shards/init")?),
            "init",
            0,
            None,
            &self.observer,
            self.retry,
        )?;
        Ok((bytes, len))
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.send(&ShardRequest::Manifest { shard_id, revision })
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.send(&ShardRequest::Setup {
            shard_id,
            revision,
            table,
            segment,
        })
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.send(&ShardRequest::Query {
            shard_id,
            revision,
            table,
            body,
        })
        .map(|(bytes, _)| bytes)
    }

    fn concurrency(&self) -> usize {
        self.concurrency
    }

    fn batch(&mut self, requests: &[ShardRequest<'_>]) -> Vec<Option<ShardReply>> {
        let workers = self.concurrency.min(requests.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failed = std::sync::atomic::AtomicBool::new(false);
        let replies = std::sync::Mutex::new(
            (0..requests.len())
                .map(|_| None)
                .collect::<Vec<Option<ShardReply>>>(),
        );
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        // Requests are taken in order, so what was sent is always
                        // a prefix. One failure ends the batch: a refusing or
                        // unreachable service should not receive a burst, and the
                        // walk's own requests carry the ordinary handling.
                        if failed.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(request) = requests.get(at) else {
                            break;
                        };
                        let reply = self.send(request);
                        if reply.is_err() {
                            failed.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        replies.lock().expect("unpoisoned")[at] = Some(reply);
                    }
                });
            }
        });
        replies.into_inner().expect("unpoisoned")
    }
}

/// The public filter origin over HTTP: the map and each shard's filter.
#[path = "experimental_parent_http.rs"]
mod experimental_parent_http;
use experimental_parent_http::ParentExperiment;

pub struct HttpFilterSource {
    parent_experiments: Vec<ParentExperiment>,
    /// The server base; every request addresses a Transparent route below it.
    base: Endpoint,
    client: BlockingClient,
    observer: Option<HttpObserver>,
    retry: RetryPolicy,
    /// Filters fetched ahead of the walk, each handed out at most once.
    ///
    /// Kept only for the walk that asked for them. A filter is addressed by
    /// shard id, and a map fetched since may give that id to another shard (a
    /// re-cut renumbers every shard above it), so the next prefetch or map
    /// fetch drops whatever the last walk left unused rather than hand it out
    /// under a map it was not fetched for.
    prefetched: std::collections::HashMap<u64, (Vec<u8>, u64)>,
    prefetched_paid: bool,
    prefetch_failed_bytes: u64,
    /// Requests a prefetch keeps in flight.
    concurrency: usize,
}

/// Filter requests a prefetch keeps in flight by default.
pub const FILTER_PREFETCH_CONCURRENCY: usize = 8;

impl HttpFilterSource {
    /// Bound every response before allocating its complete body. Oversized
    /// replies fail without retry; parent experiment limits remain stricter.
    pub fn with_response_limit(mut self, bytes: usize) -> Self {
        self.retry.response_limit = bytes.min(usize::MAX - 1);
        self
    }

    /// Explicit research opt-in. The geometry prevents archive discovery from
    /// adding any requests to wallets that only need recent history.
    pub fn with_parent_experiment(mut self, manifest_url: String, geometry: String) -> Self {
        self.parent_experiments
            .push(ParentExperiment::new(manifest_url, geometry));
        self
    }

    /// The URL of shard `shard_id`'s filter.
    fn filter_url(&self, shard_id: u64) -> Result<String, BoxError> {
        Ok(routes::url(
            &self.base,
            &format!("/filters/shards/{shard_id}/filter"),
        )?)
    }

    /// The filter origin below the server base `base_url`, whose path prefix
    /// every request keeps. Refuses a base [`Endpoint::parse`] refuses.
    pub fn new(base_url: impl Into<String>, options: &HttpOptions) -> Result<Self, BoxError> {
        Ok(Self {
            parent_experiments: Vec::new(),
            base: Endpoint::parse(&base_url.into())?,
            client: build(options)?,
            observer: None,
            retry: RetryPolicy {
                response_limit: DEFAULT_RESPONSE_LIMIT,
                attempts: 1,
                overload: true,

                timeout: options.timeout,
            },
            prefetched: std::collections::HashMap::new(),
            prefetched_paid: false,
            prefetch_failed_bytes: 0,
            concurrency: FILTER_PREFETCH_CONCURRENCY,
        })
    }

    /// Filter requests a prefetch keeps in flight; 1 disables overlap.
    pub fn with_prefetch_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Opt into a bounded number of attempts per HTTP call (1–3). This is
    /// separate from wallet-level overload retries and defaults to one attempt.
    pub fn with_retry_attempts(mut self, attempts: usize) -> Self {
        self.retry.attempts = attempts.clamp(1, 3);
        self
    }

    /// Retry transient gateway/upload/connection failures without layering
    /// additional overload retries on the wallet's refusal policy.
    pub fn with_transient_retry_attempts(mut self, attempts: usize) -> Self {
        self.retry.attempts = attempts.clamp(1, 3);
        self.retry.overload = false;
        self
    }

    /// Attach an observer without changing request or retry behavior.
    pub fn with_observer(mut self, observer: HttpObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Fetches and validates the map, returning its payload length.
    pub fn map(
        &mut self,
    ) -> Result<(zakura_pir_protocol::transparent::filter::ShardMap, u64), BoxError> {
        let (raw, len) = self.shard_map()?;
        let map: zakura_pir_protocol::transparent::filter::ShardMap = serde_json::from_slice(&raw)?;
        map.validate_supported()?;
        Ok((map, len))
    }
}

impl FilterSource for HttpFilterSource {
    fn uses_parents(&self) -> bool {
        !self.parent_experiments.is_empty()
    }
    fn prepare_parents(
        &mut self,
        map: &zakura_pir_protocol::transparent::filter::ShardMap,
        uncached: &[u64],
        store: &mut dyn crate::transparent::engine::WalletStore,
    ) -> Result<u64, BoxError> {
        let mut states = std::mem::take(&mut self.parent_experiments);
        let result = states.iter_mut().try_fold(0, |cost, state| {
            Ok(cost + state.prepare(self, map, uncached, store)?)
        });
        self.parent_experiments = states;
        result
    }
    fn parent_negative(
        &mut self,
        map: &zakura_pir_protocol::transparent::filter::ShardMap,
        id: u64,
        scripts: &[Vec<u8>],
        store: &mut dyn crate::transparent::engine::WalletStore,
    ) -> Result<(bool, u64), BoxError> {
        let mut states = std::mem::take(&mut self.parent_experiments);
        let result = states
            .iter_mut()
            .try_fold((false, 0), |(negative, cost), state| {
                let (next, bytes) = state.negative(self, map, id, scripts, store)?;
                Ok((negative || next, cost + bytes))
            });
        self.parent_experiments = states;
        result
    }

    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        // The map about to be read may number its shards differently.
        self.prefetched.clear();
        let (bytes, len) = execute_measured(
            self.client.get(routes::url(&self.base, "/filters/shards")?),
            "map",
            0,
            None,
            &self.observer,
            self.retry,
        )?;
        Ok((bytes, len))
    }

    fn prefetch(&mut self, shard_ids: &[u64]) {
        // A new walk: what an earlier one left was fetched for its map.
        self.prefetched.clear();
        self.prefetched_paid = false;
        self.prefetch_failed_bytes = 0;
        if self.concurrency <= 1 || shard_ids.len() <= 1 {
            return;
        }
        let mut wanted: Vec<u64> = shard_ids.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failed = std::sync::atomic::AtomicBool::new(false);
        let failed_bytes = std::sync::atomic::AtomicU64::new(0);
        let fetched = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..self.concurrency.min(wanted.len()) {
                scope.spawn(|| {
                    loop {
                        // One failure ends the prefetch: a refusing or unreachable
                        // service should not receive a burst, and the walk's own
                        // sequential requests carry the ordinary error handling.
                        if failed.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&id) = wanted.get(at) else { break };
                        match self.filter_url(id).and_then(|url| {
                            execute_measured(
                                self.client.get(url),
                                "filters",
                                0,
                                None,
                                &self.observer,
                                self.retry,
                            )
                        }) {
                            Ok(bytes) => fetched.lock().expect("unpoisoned").push((id, bytes)),
                            Err(error) => {
                                failed_bytes.fetch_add(
                                    TransferFailure::downloaded(&error),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                failed.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });
        self.prefetch_failed_bytes = failed_bytes.into_inner();
        self.prefetched
            .extend(fetched.into_inner().expect("unpoisoned"));
    }

    fn prefetch_charged(&mut self, shard_ids: &[u64]) -> u64 {
        self.prefetch(shard_ids);
        self.prefetched_paid = true;
        self.prefetch_failed_bytes + self.prefetched.values().map(|(_, cost)| *cost).sum::<u64>()
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        if let Some((bytes, cost)) = self.prefetched.remove(&shard_id) {
            let cost = if self.prefetched_paid { 0 } else { cost };
            return Ok((bytes, cost));
        }
        let (bytes, len) = execute_measured(
            self.client.get(self.filter_url(shard_id)?),
            "filters",
            0,
            None,
            &self.observer,
            self.retry,
        )?;
        Ok((bytes, len))
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Mutex;

    fn read_headers(stream: &mut std::net::TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
            assert!(headers.len() < 8192);
        }
    }

    #[test]
    fn default_clients_and_checked_reject_oversized_headers_before_reading_body() {
        for client_kind in ["resource", "filter", "shard", "checked"] {
            for status in [200, 503] {
                let limit = if status == 200 {
                    DEFAULT_RESPONSE_LIMIT
                } else {
                    ERROR_RESPONSE_LIMIT
                };
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let server = std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    read_headers(&mut stream);
                    // No large allocation or payload is needed to prove that
                    // the advertised length is refused before a full read.
                    write!(
                        stream,
                        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        limit + 1
                    )
                    .unwrap();
                });
                let base = format!("http://{address}");
                let options = HttpOptions::default();
                let result = match client_kind {
                    "resource" => HttpResourceClient::new(&options, None, 1)
                        .unwrap()
                        .get(&base, "test"),
                    "filter" => HttpFilterSource::new(base, &options)
                        .unwrap()
                        .shard_map()
                        .map(|(bytes, _)| bytes),
                    "shard" => HttpShardTransport::new(base, &options)
                        .unwrap()
                        .init()
                        .map(|(bytes, _)| bytes),
                    "checked" => checked(
                        build(&options).unwrap().get(base).send().unwrap(),
                        1,
                        "revision",
                    ),
                    _ => unreachable!(),
                };
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("response exceeds size limit"),
                    "{client_kind} {status}"
                );
                server.join().unwrap();
            }
        }
    }

    #[test]
    fn private_http_refusals_are_single_attempt_and_charge_their_bodies() {
        use crate::transparent::engine::client::TableClient;
        use crate::transparent::engine::transport::ByteCharges;
        use crate::transparent::native::TableProfile;
        for status in [503, 410] {
            for setup in [false, true] {
                // Derive native parameters before starting the server deadline.
                let profile = TableProfile::new(
                    zakura_pir_protocol::transparent::shard::SCHEMA,
                    "recent-4k",
                    "directory",
                    4096,
                    4096,
                )
                .unwrap();
                let mut client = TableClient::new(
                    Table::Directory,
                    "recent-4k",
                    4096,
                    4096,
                    &profile.scheme,
                    None,
                )
                .unwrap();
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                listener.set_nonblocking(true).unwrap();
                let server = std::thread::spawn(move || {
                    let mut sent = 0;
                    let mut deadline = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < deadline {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                let mut headers = Vec::new();
                                stream
                                    .set_read_timeout(Some(Duration::from_secs(2)))
                                    .unwrap();
                                while !headers.ends_with(b"\r\n\r\n") {
                                    let mut byte = [0];
                                    stream.read_exact(&mut byte).unwrap();
                                    headers.push(byte[0]);
                                }
                                let length = String::from_utf8(headers)
                                    .unwrap()
                                    .lines()
                                    .find_map(|line| {
                                        let (name, value) = line.split_once(':')?;
                                        name.eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().parse::<usize>().unwrap())
                                    })
                                    .unwrap_or(0);
                                stream.read_exact(&mut vec![0; length]).unwrap();
                                write!(stream, "HTTP/1.1 {status} Test\r\nRetry-After: 0\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy").unwrap();
                                sent += 1;
                                deadline = Instant::now() + Duration::from_millis(200);
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(2))
                            }
                            Err(error) => panic!("{error}"),
                        }
                    }
                    sent
                });
                let mut transport =
                    HttpShardTransport::new(format!("http://{address}"), &HttpOptions::default())
                        .unwrap()
                        .with_retry_attempts(3);
                let revision = "ab".repeat(32);
                let mut charges = ByteCharges::default();
                if setup {
                    let error = transport
                        .setup(7, &revision, Table::Directory, 0)
                        .unwrap_err();
                    charges.add_failed_setup(Table::Directory, &error);
                    assert_eq!(charges.setup_bytes(), 4);
                    assert_eq!(charges.shards_opened(), 0);
                } else {
                    let upload = client
                        .prepare(&revision, Table::Directory, 17)
                        .unwrap()
                        .body
                        .len() as u64;
                    assert!(
                        client
                            .fetch_row(
                                &mut transport,
                                7,
                                &revision,
                                Table::Directory,
                                1,
                                4096,
                                17,
                                &mut charges
                            )
                            .is_err()
                    );
                    assert_eq!(
                        charges.queries(),
                        1,
                        "one query exhausts a one-query work allowance"
                    );
                    assert_eq!(charges.query_upload(), upload);
                    assert_eq!(charges.query_download(), 4);
                }
                assert_eq!(
                    server.join().unwrap(),
                    1,
                    "retry options must not hide private attempts from wallet limits"
                );
            }
        }
    }

    #[test]
    fn invalid_revision_digests_never_reach_the_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut client = HttpShardTransport::new(base, &HttpOptions::default()).unwrap();
        for revision in [
            String::new(),
            "../setup".into(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            "A".repeat(64),
            format!("{}?x=1", "a".repeat(64)),
        ] {
            assert!(
                client
                    .manifest(1, &revision)
                    .unwrap_err()
                    .to_string()
                    .contains("revision digest")
            );
            assert!(
                client
                    .setup(1, &revision, Table::Directory, 0)
                    .unwrap_err()
                    .to_string()
                    .contains("revision digest")
            );
            assert!(
                client
                    .query(1, &revision, Table::Directory, &[])
                    .unwrap_err()
                    .to_string()
                    .contains("revision digest")
            );
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn enormous_retry_after_returns_the_refusal_without_panicking_or_waiting() {
        for attempts in [1, 3] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                read_headers(&mut stream);
                write!(stream, "HTTP/1.1 503 Busy\r\nRetry-After: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", u64::MAX).unwrap();
            });
            let mut client =
                HttpShardTransport::new(format!("http://{address}"), &HttpOptions::default())
                    .unwrap()
                    .with_retry_attempts(attempts);
            let started = Instant::now();
            let error = client.init().unwrap_err();
            assert!(crate::transparent::engine::transport::Overloaded::found_in(&error).is_some());
            assert!(started.elapsed() < Duration::from_secs(1));
            server.join().unwrap();
        }
    }

    #[test]
    fn oversized_success_and_error_bodies_stop_without_retry_or_fallback() {
        for status in [200, 503] {
            for chunked in [false, true] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let server = std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    read_headers(&mut stream);
                    let framing = if chunked {
                        "Transfer-Encoding: chunked"
                    } else {
                        "Content-Length: 9"
                    };
                    write!(
                        stream,
                        "HTTP/1.1 {status} Test\r\n{framing}\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                    let body: &[u8] = if chunked {
                        b"9\r\n123456789\r\n0\r\n\r\n"
                    } else {
                        b"123456789"
                    };
                    stream.write_all(body).unwrap();
                });
                let observed = Arc::new(Mutex::new(Vec::new()));
                let saved = observed.clone();
                let mut client =
                    HttpFilterSource::new(format!("http://{address}"), &HttpOptions::default())
                        .unwrap()
                        .with_response_limit(8)
                        .with_retry_attempts(3)
                        .with_observer(Arc::new(move |event| saved.lock().unwrap().push(event)));
                let error = client.shard_map().unwrap_err();
                assert!(error.to_string().contains("response exceeds size limit"));
                server.join().unwrap();
                let observations = observed.lock().unwrap();
                assert_eq!(observations.len(), 1);
                assert!(observations[0].failed);
                assert_eq!(observations[0].status, Some(status));
            }
        }
    }

    /// Prefetched filters are fetched together and each is handed out once;
    /// asking for the same shard again goes back to the network.
    #[test]
    fn prefetched_filters_are_served_once_then_fetched_afresh() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let paths = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = paths.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let seen = seen.clone();
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        if stream.read_exact(&mut byte).is_err() {
                            return;
                        }
                        headers.push(byte[0]);
                    }
                    let line = String::from_utf8_lossy(&headers)
                        .lines()
                        .next()
                        .unwrap()
                        .to_string();
                    let path = line.split(' ').nth(1).unwrap().to_string();
                    seen.lock().unwrap().push(path.clone());
                    let status = if path.contains("/99/") {
                        "500 Internal Server Error"
                    } else {
                        "200 OK"
                    };
                    let body = path.into_bytes();
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    let _ = stream.write_all(&body);
                });
            }
        });
        let mut source = HttpFilterSource::new(
            format!("http://{address}"),
            &HttpOptions {
                timeout: Duration::from_secs(5),
                user_agent: "prefetch-test".into(),
            },
        )
        .unwrap();
        source.prefetch(&[1, 2, 3]);
        assert_eq!(paths.lock().unwrap().len(), 3);
        for id in [1u64, 2, 3] {
            let (bytes, cost) = source.filter(id).unwrap();
            assert_eq!(
                bytes,
                format!("/transparent/v1/filters/shards/{id}/filter").into_bytes()
            );
            assert_eq!(cost, bytes.len() as u64);
        }
        assert_eq!(
            paths.lock().unwrap().len(),
            3,
            "prefetched filters cost no request"
        );
        source.filter(2).unwrap();
        assert_eq!(
            paths.lock().unwrap().len(),
            4,
            "a second request is fetched afresh"
        );

        // What one walk left unused is never handed to the next walk, or
        // under a map fetched since: either may number its shards differently.
        source.prefetch(&[1, 2, 3]);
        source.filter(1).unwrap();
        assert_eq!(paths.lock().unwrap().len(), 7);
        source.prefetch(&[2]);
        source.filter(2).unwrap();
        assert_eq!(
            paths.lock().unwrap().len(),
            8,
            "a later prefetch drops what the last walk left"
        );
        source.prefetch(&[1, 2, 3]);
        source.shard_map().unwrap();
        source.filter(3).unwrap();
        assert_eq!(
            paths.lock().unwrap().len(),
            13,
            "a map fetch drops every prefetched filter"
        );

        let mut serial = HttpFilterSource::new(
            format!("http://{address}"),
            &HttpOptions {
                timeout: Duration::from_secs(5),
                user_agent: "prefetch-test".into(),
            },
        )
        .unwrap()
        .with_prefetch_concurrency(1);
        serial.prefetch(&[1, 2, 3]);
        assert_eq!(
            paths.lock().unwrap().len(),
            13,
            "concurrency 1 disables prefetch"
        );

        let paid = source.prefetch_charged(&[1, 2, 3]);
        let expected: u64 = [1, 2, 3]
            .iter()
            .map(|id| format!("/transparent/v1/filters/shards/{id}/filter").len() as u64)
            .sum();
        assert_eq!(
            paid, expected,
            "all dispatched filters are charged immediately"
        );
        assert_eq!(
            source.filter(1).unwrap().1,
            0,
            "consuming a prepaid filter is free"
        );
        // Abandon 2 and 3, as an early exit or a map refresh would.
        source.prefetch_charged(&[]);
        assert_eq!(
            paid, expected,
            "discarding unused replies cannot erase their charge"
        );
        assert!(
            source.filter(2).unwrap().1 > 0,
            "a fresh network request is charged"
        );

        let first = paths.lock().unwrap().len();
        let paid = source.prefetch_charged(&[99, 100]);
        let paths = paths.lock().unwrap();
        assert!(paths[first..].iter().any(|path| path.contains("/99/")));
        let delivered: u64 = paths[first..].iter().map(|path| path.len() as u64).sum();
        assert_eq!(
            paid, delivered,
            "failed prefetch bodies are paid even when abandoned"
        );
    }

    /// A batch keeps at most its concurrency in flight, returns replies in
    /// request order, recognises refusals as the single methods do, and stops
    /// at the first failure, so what was sent is a prefix.
    #[test]
    fn a_batch_overlaps_requests_in_order_and_stops_at_the_first_failure() {
        use crate::transparent::engine::transport::{ShardRequest, StaleRevision};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let most = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let (seen, in_flight, most) = (seen.clone(), in_flight.clone(), most.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let mut stream = stream.unwrap();
                    let (seen, in_flight, most) = (seen.clone(), in_flight.clone(), most.clone());
                    std::thread::spawn(move || {
                        use std::sync::atomic::Ordering::SeqCst;
                        let mut headers = Vec::new();
                        while !headers.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            if stream.read_exact(&mut byte).is_err() {
                                return;
                            }
                            headers.push(byte[0]);
                        }
                        let now = in_flight.fetch_add(1, SeqCst) + 1;
                        most.fetch_max(now, SeqCst);
                        let path = String::from_utf8_lossy(&headers)
                            .lines()
                            .next()
                            .unwrap()
                            .split(' ')
                            .nth(1)
                            .unwrap()
                            .to_string();
                        seen.lock().unwrap().push(path.clone());
                        std::thread::sleep(Duration::from_millis(150));
                        let (status, body) = if path.contains("/shards/99/") {
                            ("409 Conflict", br#"{"map_sha256":"beef"}"#.to_vec())
                        } else {
                            ("200 OK", path.into_bytes())
                        };
                        in_flight.fetch_sub(1, SeqCst);
                        let _ = stream.write_all(
                            format!(
                                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: \
                                 close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        );
                        let _ = stream.write_all(&body);
                    });
                }
            });
        }
        let options = HttpOptions {
            timeout: Duration::from_secs(5),
            user_agent: "batch-test".into(),
        };
        let mut transport = HttpShardTransport::new(format!("http://{address}"), &options)
            .unwrap()
            .with_concurrency(3);
        assert_eq!(transport.concurrency(), 3);

        let ids = [0u64, 1, 2, 3, 4, 5];
        let requests: Vec<ShardRequest<'_>> = ids
            .iter()
            .map(|&shard_id| ShardRequest::Manifest {
                shard_id,
                revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            })
            .collect();
        let started = Instant::now();
        let replies = transport.batch(&requests);
        assert!(
            started.elapsed() < Duration::from_millis(6 * 150),
            "requests overlap"
        );
        assert!(most.load(std::sync::atomic::Ordering::SeqCst) <= 3);
        assert!(most.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        for (request, reply) in requests.iter().zip(&replies) {
            let (bytes, cost) = reply.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(bytes, request.route().as_bytes(), "replies are in order");
            assert_eq!(*cost, bytes.len() as u64);
        }

        seen.lock().unwrap().clear();
        let ids = [0u64, 99, 1, 2, 3, 4, 5, 6, 7];
        let requests: Vec<ShardRequest<'_>> = ids
            .iter()
            .map(|&shard_id| ShardRequest::Setup {
                shard_id,
                revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                table: Table::Directory,
                segment: 0,
            })
            .collect();
        let replies = transport.batch(&requests);
        assert_eq!(replies.len(), requests.len());
        let refused = replies[1].as_ref().unwrap().as_ref().unwrap_err();
        assert!(
            StaleRevision::found_in(refused).is_some(),
            "a refusal is recognised in a batch"
        );
        let sent = replies.iter().take_while(|reply| reply.is_some()).count();
        assert!(
            replies[sent..].iter().all(Option::is_none),
            "what was sent is a prefix"
        );
        assert!(sent < requests.len(), "the batch stopped");
        assert!(
            sent <= 2 + 3,
            "at most the in-flight width after the failure"
        );
        assert_eq!(seen.lock().unwrap().len(), sent);
    }

    #[test]
    fn retry_after_cannot_extend_the_deadline_on_public_or_bound_requests() {
        for bound in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                read_headers(&mut stream);
                stream.write_all(b"HTTP/1.1 503 Busy\r\nRetry-After: 10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            });
            let events = Arc::new(Mutex::new(Vec::new()));
            let saved = events.clone();
            let mut client = HttpShardTransport::new(
                format!("http://{address}"),
                &HttpOptions {
                    timeout: Duration::from_millis(500),
                    user_agent: "deadline-test".into(),
                },
            )
            .unwrap()
            .with_retry_attempts(3)
            .with_observer(Arc::new(move |e| saved.lock().unwrap().push(e)));
            let started = Instant::now();
            let result = if bound {
                client.manifest(1, &"a".repeat(64))
            } else {
                client.init()
            };
            let error = result.unwrap_err();
            assert!(crate::transparent::engine::transport::Overloaded::found_in(&error).is_some());
            assert!(started.elapsed() < Duration::from_secs(1));
            server.join().unwrap();
            assert_eq!(events.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn retries_share_one_deadline_including_backoff_and_response_reads() {
        // The first retry waits one second jittered by up to half. A budget
        // of three seconds always leaves room for it, and leaves the second
        // attempt between one and a half and two seconds. The server answers
        // that attempt after two and a half: past what is left, short of a
        // fresh budget. So the second attempt fails only if it shares the
        // first one's deadline, whatever the jitter drew.
        const BUDGET: Duration = Duration::from_millis(3_000);
        const ANSWER_AFTER: Duration = Duration::from_millis(2_500);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        // Never blocks without bound and never panics on a client that gave
        // up, so a failure is an assertion below rather than a hung or
        // panicking server thread.
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut served = 0usize;
            while served < 2 && Instant::now() < deadline {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let mut headers = Vec::new();
                let mut byte = [0];
                while !headers.ends_with(b"\r\n\r\n") && headers.len() < 8192 {
                    match stream.read(&mut byte) {
                        Ok(1) => headers.push(byte[0]),
                        _ => break,
                    }
                }
                served += 1;
                if served == 1 {
                    let _ = stream.write_all(
                        b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                } else {
                    std::thread::sleep(ANSWER_AFTER);
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            }
            served
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let saved = events.clone();
        let mut client = HttpShardTransport::new(
            format!("http://{address}"),
            &HttpOptions {
                timeout: BUDGET,
                user_agent: "deadline-test".into(),
            },
        )
        .unwrap()
        .with_retry_attempts(3)
        .with_observer(Arc::new(move |e| saved.lock().unwrap().push(e)));
        let started = Instant::now();
        assert!(
            client.init().is_err(),
            "second attempt must not receive a fresh timeout"
        );
        let elapsed = started.elapsed();
        assert_eq!(server.join().unwrap(), 2, "the retry was sent");
        // The budget plus scheduling slack on a loaded machine; a fresh
        // budget for the second attempt would also have failed the
        // assertion above.
        assert!(elapsed < BUDGET + Duration::from_secs(2), "{elapsed:?}");
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, Some(503));
        assert!(events.iter().all(|e| e.failed));
    }

    #[test]
    fn receipt_and_io_wrappers_preserve_the_contained_transport_error() {
        // A builder failure needs no network and supplies the same HTTP client
        // error type the bounded body reader retains inside an IO error.
        let original = BlockingClient::new(Duration::from_secs(30), None)
            .unwrap()
            .get("http://[")
            .send()
            .unwrap_err();
        let error = TransferFailure::boxed(7, std::io::Error::other(original).into());
        assert!(transport_cause::<ureq::Error>(error.as_ref()).is_some());
        assert!(transport_cause::<std::io::Error>(error.as_ref()).is_some());
        assert_eq!(TransferFailure::downloaded(&error), 7);
    }

    #[test]
    fn retries_established_connection_failures_with_bounded_attempts() {
        // Exercise both public GETs and private POSTs, with and without telemetry.
        for partial_body in [false, true] {
            for private in [false, true] {
                for (attempts, failures, observe) in
                    [(1, 1, true), (3, 1, true), (3, 3, true), (3, 1, false)]
                {
                    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = listener.local_addr().unwrap();
                    listener.set_nonblocking(true).unwrap();
                    let expected = attempts.min(failures + 1);
                    let server = std::thread::spawn(move || {
                        let deadline = Instant::now() + Duration::from_secs(60);
                        for index in 0..expected {
                            let mut stream = loop {
                                match listener.accept() {
                                    Ok((stream, _)) => break stream,
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        assert!(Instant::now() < deadline, "missing retry {index}");
                                        std::thread::sleep(Duration::from_millis(10));
                                    }
                                    Err(e) => panic!("{e}"),
                                }
                            };
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(30)))
                                .unwrap();
                            let mut headers = Vec::new();
                            while !headers.ends_with(b"\r\n\r\n") {
                                let mut byte = [0];
                                stream.read_exact(&mut byte).unwrap();
                                headers.push(byte[0]);
                                assert!(headers.len() <= 4096);
                            }
                            if private {
                                let mut body = [0; 7];
                                stream.read_exact(&mut body).unwrap();
                                assert_eq!(&body, b"payload");
                            }
                            if index >= failures {
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                            } else if partial_body {
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial").unwrap();
                            }
                            // Close an established connection before headers or a full body.
                        }
                    });
                    let events = Arc::new(Mutex::new(Vec::new()));
                    let observed = events.clone();
                    let observer: Option<HttpObserver> = observe.then(|| {
                        Arc::new(move |o: HttpObservation| observed.lock().unwrap().push(o))
                            as HttpObserver
                    });
                    let client = BlockingClient::new(Duration::from_secs(30), None).unwrap();
                    let url = format!("http://{address}");
                    let request = if private {
                        client.post(&url).body("payload")
                    } else {
                        client.get(&url)
                    };
                    let result = execute_measured(
                        request,
                        "test",
                        if private { 7 } else { 0 },
                        private.then_some((1, "revision")),
                        &observer,
                        RetryPolicy {
                            response_limit: usize::MAX,
                            attempts,
                            overload: false,

                            timeout: Duration::from_secs(30),
                        },
                    );
                    server.join().unwrap();
                    assert_eq!(
                        result.is_ok(),
                        failures < attempts,
                        "partial={partial_body} private={private}: {result:?}"
                    );
                    let paid = match &result {
                        Ok((body, paid)) => {
                            assert_eq!(body, b"ok");
                            *paid
                        }
                        Err(error) => TransferFailure::downloaded(error),
                    };
                    assert_eq!(
                        paid,
                        if partial_body {
                            failures.min(attempts) as u64 * 7
                        } else {
                            0
                        } + if failures < attempts { 2 } else { 0 }
                    );
                    let events = events.lock().unwrap();
                    assert_eq!(events.len(), if observe { expected } else { 0 });
                    for (index, event) in events.iter().enumerate() {
                        assert_eq!(event.request_id, events[0].request_id);
                        assert_eq!(event.attempt, index + 1);
                        assert_eq!(event.bytes_up, if private { 7 } else { 0 });
                        assert_eq!(event.failed, index < failures);
                        assert_eq!(
                            event.status,
                            (partial_body || index >= failures).then_some(200)
                        );
                        if event.failed {
                            let cause = event.transport_error.as_ref().unwrap();
                            assert!(!cause.is_empty());
                            assert!(!cause.contains(&url));
                        } else {
                            assert!(event.transport_error.is_none());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn opt_in_retries_are_bounded_and_account_for_every_response() {
        for (retry_overload, statuses) in [
            (true, vec![502, 200]),
            (true, vec![502, 502, 502]),
            (false, vec![502, 200]),
            (false, vec![504, 200]),
            (false, vec![408, 200]),
            (false, vec![408, 408, 408]),
            (true, vec![503, 200]),
            (false, vec![503]),
            (false, vec![404]),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = statuses.len();
            let success = statuses.last() == Some(&200);
            let server = std::thread::spawn(move || {
                for status in statuses {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                        assert!(request.len() <= 4096);
                    }
                    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nRetry-After: 0\r\nConnection: close\r\n\r\nok").unwrap();
                }
            });
            let observations = Arc::new(Mutex::new(Vec::new()));
            let observed = observations.clone();
            let observer: HttpObserver = Arc::new(move |o| observed.lock().unwrap().push(o));
            let request = BlockingClient::new(Duration::from_secs(30), None)
                .unwrap()
                .get(format!("http://{address}"));
            let result = execute_measured(
                request,
                "setup_directory",
                0,
                Some((1, "revision")),
                &Some(observer),
                RetryPolicy {
                    response_limit: usize::MAX,
                    attempts: 3,
                    overload: retry_overload,

                    timeout: Duration::from_secs(30),
                },
            );
            assert_eq!(result.is_ok(), success);
            let paid = match &result {
                Ok((body, paid)) => {
                    assert_eq!(body, b"ok");
                    *paid
                }
                Err(error) => TransferFailure::downloaded(error),
            };
            assert_eq!(paid, expected as u64 * 2);
            server.join().unwrap();
            let observations = observations.lock().unwrap();
            assert_eq!(observations.len(), expected);
            assert!(
                observations
                    .iter()
                    .all(|o| o.request_id == observations[0].request_id)
            );
            assert_eq!(
                observations.iter().map(|o| o.attempt).collect::<Vec<_>>(),
                (1..=expected).collect::<Vec<_>>()
            );
            assert_eq!(
                observations.iter().map(|o| o.bytes_down).sum::<u64>(),
                expected as u64 * 2
            );
            assert_eq!(
                observations.iter().filter(|o| o.failed).count(),
                expected - usize::from(success)
            );
        }
    }

    #[test]
    fn observes_success_refusal_payload_and_connection_failure_without_changing_results() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for (status, body) in [(200, "ok"), (503, "busy")] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 1024];
                let _ = stream.read(&mut request).unwrap();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let mut filters =
            HttpFilterSource::new(format!("http://{address}"), &HttpOptions::default())
                .unwrap()
                .with_observer(Arc::new(move |o| observed.lock().unwrap().push(o)));
        assert_eq!(filters.filter(0).unwrap().0, b"ok");
        assert!(filters.filter(0).unwrap_err().to_string().contains("503"));
        server.join().unwrap();
        assert!(filters.filter(0).is_err());
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].status, Some(200));
        assert_eq!(events[0].bytes_down, 2);
        assert!(!events[0].failed);
        assert_eq!(events[1].status, Some(503));
        assert_eq!(events[1].bytes_down, 4);
        assert!(events[1].failed);
        assert_eq!(events[2].status, None);
        assert!(events[2].failed);
    }

    #[test]
    fn history_requests_keep_the_base_path_below_the_transparent_namespace() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    headers.push(byte[0]);
                }
                let line = String::from_utf8_lossy(&headers)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let mut parts = line.split(' ');
                let (method, path) = (parts.next().unwrap_or_default(), parts.next());
                let length: usize = String::from_utf8_lossy(&headers)
                    .lines()
                    .find_map(|header| {
                        header
                            .to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|length| length.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let _ = stream.read_exact(&mut vec![0; length]);
                recorded
                    .lock()
                    .unwrap()
                    .push(format!("{method} {}", path.unwrap_or_default()));
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        let base = format!("http://{address}/edge/");
        let options = HttpOptions::default();
        let mut filters = HttpFilterSource::new(&base, &options)
            .unwrap()
            .with_prefetch_concurrency(1);
        let mut shards = HttpShardTransport::new(&base, &options).unwrap();
        let revision = "ab".repeat(32);
        filters.shard_map().unwrap();
        filters.filter(7).unwrap();
        shards.init().unwrap();
        shards.manifest(7, &revision).unwrap();
        shards.setup(7, &revision, Table::Pages(1), 0).unwrap();
        shards.query(7, &revision, Table::Directory, b"q").unwrap();

        let shard = format!("/edge/transparent/v1/shards/7/revisions/{revision}");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "GET /edge/transparent/v1/filters/shards".to_owned(),
                "GET /edge/transparent/v1/filters/shards/7/filter".to_owned(),
                "GET /edge/transparent/v1/shards/init".to_owned(),
                format!("GET {shard}/manifest"),
                format!("GET {shard}/setup/pages-1/0"),
                format!("POST {shard}/query/directory"),
            ],
            "every request is canonical; none falls back to a legacy route"
        );
        assert!(HttpShardTransport::new("https://pir.example/edge?legacy=1", &options).is_err());
    }
}
