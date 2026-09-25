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
    sync::Arc,
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
        let bytes = fetch(
            transport,
            &base_url,
            Method::Get,
            "/v1/enhance/init",
            vec![],
            MAX_MANIFEST_BYTES,
        )
        .await?;
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
            cache: SessionCache::default(),
            expired: false,
            accepted_at: std::time::Instant::now(),
        })
    }
}

#[derive(Default)]
struct SessionCache {
    sessions: BTreeMap<u64, Arc<QuerySession>>,
    order: VecDeque<u64>,
}

/// Drop an idle expanded setup before allocating its replacement. Query methods
/// borrow the client exclusively, so no other query can retain an evicted setup.
fn make_room<T>(
    sessions: &mut BTreeMap<u64, Arc<T>>,
    order: &mut VecDeque<u64>,
    limit: usize,
) -> Result<(), ClientError> {
    if limit == 0 {
        return Err(ClientError::Generation("zero shard cache limit".into()));
    }
    trim_cache(sessions, order, limit - 1)
}

/// Enforce an accepted cache limit without reserving a slot for a new setup.
fn trim_cache<T>(
    sessions: &mut BTreeMap<u64, Arc<T>>,
    order: &mut VecDeque<u64>,
    limit: usize,
) -> Result<(), ClientError> {
    while sessions.len() > limit {
        let id = order
            .pop_front()
            .ok_or_else(|| ClientError::Generation("invalid shard cache state".into()))?;
        sessions
            .remove(&id)
            .ok_or_else(|| ClientError::Generation("invalid shard cache state".into()))?;
    }
    Ok(())
}

/// One wallet-accepted manifest. Refresh by fetching and accepting a new
/// `PendingClient`; a batch never silently changes generation or coverage.
pub struct Client {
    pub(crate) base_url: String,
    manifest: Manifest,
    acceptance: GenerationAcceptance,
    cache: SessionCache,
    expired: bool,
    accepted_at: std::time::Instant,
}
/// Persist expiration on completion or cancellation without interrupting cover
/// dispatch within a round after a query rejection.
struct CoverRound<'a> {
    client: &'a mut Client,
    expired: bool,
}

impl Drop for CoverRound<'_> {
    fn drop(&mut self) {
        self.client.expired |= self.expired;
    }
}

#[derive(Debug)]
pub struct PositionResult {
    pub position: u64,
    pub record: Result<EnhanceRecord, ClientError>,
}
impl Client {
    /// Fetch at sync start and when refresh_due() is true, validate against the
    /// locally scanned anchor, then reuse unchanged sessions through this method.
    pub fn accept_routing(
        &mut self,
        pending: PendingClient,
        acceptance: &GenerationAcceptance,
    ) -> Result<(), ClientError> {
        acceptance.validate(&pending.manifest)?;
        if pending.base_url != self.base_url
            || pending.manifest.generation < self.manifest.generation
            || pending.manifest.recovery_epoch < self.manifest.recovery_epoch
        {
            return Err(ClientError::Generation(
                "routing origin or revision changed".into(),
            ));
        }
        self.cache.sessions.retain(|_, session| {
            Arc::get_mut(session).is_some_and(|s| s.rebind(&pending.manifest, acceptance).is_ok())
        });
        self.cache
            .order
            .retain(|id| self.cache.sessions.contains_key(id));
        trim_cache(
            &mut self.cache.sessions,
            &mut self.cache.order,
            acceptance.limits.max_cached_shards,
        )?;
        self.manifest = pending.manifest;
        self.acceptance = acceptance.clone();
        self.expired = false;
        self.accepted_at = std::time::Instant::now();
        Ok(())
    }

    /// Refresh before starting new work; an in-flight operation retains its accepted view.
    pub fn refresh_due(&self) -> bool {
        self.expired || self.accepted_at.elapsed() >= std::time::Duration::from_secs(30)
    }

    /// Opt-in birthday cover policy. One interval is one accepted routing view.
    /// Every round visits every domain since the birthday with fresh randomness
    /// and target-independent ordering. A retry repeats the entire round.
    /// Record validation errors are returned only after the scheduled traffic finishes;
    /// they never affect round counts or transport retries.
    /// Dropping the future preserves any expiration already observed in this round.
    /// No records are returned until the complete operation succeeds.
    /// Cross-interval intersection and the public birthday range remain visible.
    pub async fn query_positions_with_cover(
        &mut self,
        transport: &impl Transport,
        positions: &[u64],
        birthday_first_position: u64,
    ) -> Result<Vec<EnhanceRecord>, ClientError> {
        use rand::seq::SliceRandom;
        if positions.len() > DEFAULT_MAX_BATCH_SIZE {
            return Err(ClientError::BatchTooLarge {
                max_items: DEFAULT_MAX_BATCH_SIZE,
            });
        }
        self.check_live()?;
        self.check_fresh()?;
        let birthday_row = birthday_first_position / RECORDS_PER_ROW as u64;
        let domains: BTreeSet<_> = self
            .manifest
            .coverage
            .routes
            .iter()
            .filter(|r| r.global_end > birthday_row)
            .map(|r| r.domain_id)
            .collect();
        let mut rows = BTreeMap::<u64, BTreeMap<usize, Vec<(usize, usize)>>>::new();
        for (index, position) in positions.iter().copied().enumerate() {
            if position < birthday_first_position {
                return Err(ClientError::OutsideCoverage(position));
            }
            let (domain, row, slot) = self
                .manifest
                .coverage
                .locate(position)
                .ok_or(ClientError::OutsideCoverage(position))?;
            if !domains.contains(&domain.id) {
                return Err(ClientError::OutsideCoverage(position));
            }
            rows.entry(domain.id)
                .or_default()
                .entry(row)
                .or_default()
                .push((index, slot));
        }
        let rows: BTreeMap<_, Vec<_>> = rows
            .into_iter()
            .map(|(id, rows)| (id, rows.into_iter().collect()))
            .collect();
        let rounds = rows.values().map(Vec::len).max().unwrap_or(0);
        let mut result: Vec<_> = (0..positions.len()).map(|_| None).collect();
        for round in 0..rounds {
            for attempt in 0..2 {
                let mut order: Vec<_> = domains.iter().copied().collect();
                order.shuffle(&mut rand::rngs::OsRng);
                let mut error = None;
                let mut round_state = CoverRound {
                    client: self,
                    expired: false,
                };
                let mut completed = Vec::new();
                for domain in order {
                    let wanted = rows.get(&domain).and_then(|r| r.get(round));
                    let decoded = async {
                        let session = round_state.client.session(transport, domain).await?;
                        let query = match wanted {
                            Some((row, _)) => session.prepare_row(*row)?,
                            None => session.prepare_dummy()?,
                        };
                        let response = fetch(
                            transport,
                            &round_state.client.base_url,
                            Method::Post,
                            "/v1/enhance/query",
                            query.body().to_vec(),
                            MAX_RESPONSE_BYTES,
                        )
                        .await?;
                        session.decode(query, response.as_ref())
                    }
                    .await;
                    match decoded {
                        Ok(row) => {
                            if let Some((_, slots)) = wanted {
                                for (index, slot) in slots {
                                    completed.push((*index, record_in_row(&row, *slot)));
                                }
                            }
                        }
                        Err(failure) => {
                            round_state.expired |= matches!(failure.http_status(), Some(409 | 410));
                            // Any nonretryable failure dominates a retryable one,
                            // independent of the domain's randomized position.
                            if error.as_ref().is_none_or(|e: &ClientError| {
                                matches!(e.http_status(), Some(429 | 503))
                            }) {
                                error = Some(failure);
                            }
                        }
                    }
                }
                // Apply observed expiration before deciding whether to retry or return.
                drop(round_state);
                if let Some(error) = error {
                    if attempt == 0 && matches!(error.http_status(), Some(429 | 503)) {
                        continue;
                    }
                    self.note_status(&error);
                    return Err(error);
                }
                for (index, record) in completed {
                    result[index] = Some(record);
                }
                break;
            }
        }
        result
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|| Err(ClientError::Response("missing covered record".into())))
            })
            .collect()
    }

    pub fn generation(&self) -> &Manifest {
        &self.manifest
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn check_live(&self) -> Result<(), ClientError> {
        if self.expired {
            Err(ClientError::HttpStatus(410))
        } else {
            Ok(())
        }
    }

    /// A live view that is due for refresh rejects new work with 409. Expiration is
    /// left to `check_live`, so an expired client always reports 410.
    fn check_fresh(&self) -> Result<(), ClientError> {
        if !self.expired && self.refresh_due() {
            Err(ClientError::HttpStatus(409))
        } else {
            Ok(())
        }
    }

    fn note_status(&mut self, error: &ClientError) {
        if matches!(error, ClientError::HttpStatus(409 | 410)) {
            self.expired = true;
        }
    }

    async fn session(
        &mut self,
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
        if let Some(session) = self.cache.sessions.get(&shard_id).cloned() {
            self.cache.order.retain(|id| *id != shard_id);
            self.cache.order.push_back(shard_id);
            return Ok(session);
        }
        let path = format!(
            "/v1/enhance/session/{}",
            hex::encode(
                self.manifest
                    .session_id(shard_id)
                    .map_err(ClientError::Generation)?
            )
        );
        let response = fetch(
            transport,
            &self.base_url,
            Method::Get,
            &path,
            vec![],
            MAX_SESSION_BYTES,
        )
        .await
        .inspect_err(|error| self.note_status(error))?;
        self.check_live()?;
        let session: ShardSession = serde_json::from_slice(response.as_ref())?;
        make_room(
            &mut self.cache.sessions,
            &mut self.cache.order,
            self.acceptance.limits.max_cached_shards,
        )?;
        let session = Arc::new(QuerySession::from_session(
            &self.manifest,
            session,
            &self.acceptance,
        )?);
        self.cache.order.push_back(shard_id);
        self.cache.sessions.insert(shard_id, session.clone());
        Ok(session)
    }
    pub async fn query_dummy(
        &mut self,
        transport: &impl Transport,
        shard_id: u64,
    ) -> Result<(), ClientError> {
        self.check_fresh()?;
        let session = self.session(transport, shard_id).await?;
        let query = session.prepare_dummy()?;
        self.check_live()?;
        let response = fetch(
            transport,
            &self.base_url,
            Method::Post,
            "/v1/enhance/query",
            query.body().to_vec(),
            MAX_RESPONSE_BYTES,
        )
        .await
        .inspect_err(|error| self.note_status(error))?;
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
        &'a mut self,
        transport: &'a impl Transport,
        positions: impl IntoIterator<Item = u64>,
    ) -> Result<impl Stream<Item = PositionResult> + 'a, ClientError> {
        self.query_batch_with_limit(transport, positions, DEFAULT_MAX_BATCH_SIZE)
    }

    /// Queries only one transaction in one row. Shape and coverage failures perform
    /// no network I/O. Session setup may precede the single row query POST.
    #[cfg(feature = "wallet")]
    pub async fn query_row_requests(
        &mut self,
        transport: &impl Transport,
        requests: &[zcash_client_backend::data_api::enhance_pir::EnhancePirRequest],
    ) -> Result<crate::wallet::RowQueryResult, ClientError> {
        use futures_util::StreamExt;
        let first = requests.first().ok_or(ClientError::EmptyBatch)?;
        if requests.len() > DEFAULT_MAX_BATCH_SIZE {
            return Err(ClientError::BatchTooLarge {
                max_items: DEFAULT_MAX_BATCH_SIZE,
            });
        }
        let row = u64::from(first.position()) / RECORDS_PER_ROW as u64;
        for request in requests {
            if request.request_id().txid() != first.request_id().txid() {
                return Err(ClientError::MixedTxid);
            }
            let position = u64::from(request.position());
            if position / RECORDS_PER_ROW as u64 != row {
                return Err(ClientError::CrossRowBatch);
            }
            if self.manifest.coverage.locate(position).is_none() {
                return Err(ClientError::OutsideCoverage(position));
            }
        }
        let stream =
            self.query_batch(transport, requests.iter().map(|r| u64::from(r.position())))?;
        futures_util::pin_mut!(stream);
        let mut records = BTreeMap::new();
        while let Some(result) = stream.next().await {
            records.insert(result.position, result.record?);
        }
        let slots = requests
            .iter()
            .map(|request| {
                records
                    .get(&u64::from(request.position()))
                    .cloned()
                    .map(|record| (*request, record))
                    .ok_or_else(|| ClientError::Response("missing requested row slot".into()))
            })
            .collect::<Result<_, _>>()?;
        Ok(crate::wallet::RowQueryResult { row, slots })
    }

    /// Ingests at most `max_items + 1` input items before returning a stream or
    /// `BatchTooLarge`. Counts duplicates and uncovered positions. No network I/O
    /// occurs on rejection. The caller must ensure each iterator step terminates.
    /// Choose a local limit suitable for the device; zero accepts only empty input.
    pub fn query_batch_with_limit<'a>(
        &'a mut self,
        transport: &'a impl Transport,
        positions: impl IntoIterator<Item = u64>,
        max_items: usize,
    ) -> Result<impl Stream<Item = PositionResult> + 'a, ClientError> {
        self.check_fresh()?;
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
            (
                self,
                rows.into_values(),
                ready,
                uncovered,
                None::<u16>,
                false,
            ),
            move |(client, mut rows, mut ready, mut uncovered, mut stopped, mut cancelled)| async move {
                if let Some(result) = ready.pop_front() {
                    return Some((result, (client, rows, ready, uncovered, stopped, cancelled)));
                }
                let Some((shard_id, row, positions)) = rows.next() else {
                    let position = uncovered.pop_front()?;
                    return Some((
                        PositionResult {
                            position,
                            record: Err(ClientError::OutsideCoverage(position)),
                        },
                        (client, rows, ready, uncovered, stopped, cancelled),
                    ));
                };
                let row = async {
                    if cancelled {
                        return Err(ClientError::Cancelled);
                    }
                    if let Some(status) = stopped {
                        return Err(ClientError::HttpStatus(status));
                    }
                    let session = client.session(transport, shard_id).await?;
                    let query = session.prepare_row(row)?;
                    client.check_live()?;
                    let response = fetch(
                        transport,
                        &client.base_url,
                        Method::Post,
                        "/v1/enhance/query",
                        query.body().to_vec(),
                        MAX_RESPONSE_BYTES,
                    )
                    .await
                    .inspect_err(|error| client.note_status(error))?;
                    client.check_live()?;
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
                        if let ClientError::HttpStatus(code @ (409 | 410 | 429 | 503)) = &error {
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
                    .map(|result| (result, (client, rows, ready, uncovered, stopped, cancelled)))
            },
        ))
    }
}

/// Dispatches one request to `path` under `base`. A custom transport may use its
/// own collector, so the protocol cap is enforced again on the returned body.
async fn fetch(
    transport: &impl Transport,
    base: &str,
    method: Method,
    path: &str,
    body: Vec<u8>,
    response_limit: usize,
) -> Result<ResponseBody, ClientError> {
    let response = transport
        .execute(Request {
            method,
            url: endpoint(base, path)?,
            body,
            response_limit,
        })
        .await?;
    if response.as_ref().len() > response_limit {
        return Err(ClientError::Response("HTTP body exceeds limit".into()));
    }
    Ok(response)
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
            let received = socket.read(&mut buf).unwrap();
            assert!(
                received > 0,
                "client must send a request before the mock responds"
            );
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

    #[test]
    fn cache_releases_old_setup_before_admitting_new_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct SetupProbe(Arc<AtomicUsize>);
        impl Drop for SetupProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let mut sessions = BTreeMap::from([(0, Arc::new(SetupProbe(dropped.clone())))]);
        let mut order = VecDeque::from([0]);
        make_room(&mut sessions, &mut order, 1).unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(sessions.is_empty());
        assert!(order.is_empty());

        sessions.insert(1, Arc::new(SetupProbe(dropped.clone())));
        order.push_back(1);
        make_room(&mut sessions, &mut order, 2).unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.len(), 1);
    }

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
                serde_json::from_str(include_str!("../tests/fixtures/wallet-schema11.json"))
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
            } else if request.url.contains("/v1/enhance/session/") {
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
                // Zero public material and zero packed response model an all-zero
                // database. This exercises client decoding without a server process.
                let (_, params) = ipir_sp::params_for_simplepir_profile(
                    4096,
                    crate::ITEM_SIZE_BITS,
                    ipir_sp::SimplePirProfile::P16Q48,
                )
                .unwrap();
                let binding = crate::types::QueryBinding::decode(&request.body).unwrap();
                let mut response = binding.encode();
                response.resize(
                    crate::HEADER_BYTES
                        + params.db_cols / params.poly_len
                            * ipir_sp::modulus_switch::response_body_len(
                                params.poly_len,
                                params.q_prime_1,
                            ),
                    0,
                );
                let mut body = request.response_body();
                body.extend(&response)?;
                return Ok(body.finish());
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
            let mut client = pending.accept(&transport.acceptance(0x42, 1)).unwrap();
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
                let mut client = PendingClient::fetch(&transport, "https://example.test")
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
            let mut client = PendingClient::fetch(&transport, "https://example.test")
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

    #[cfg(feature = "wallet")]
    #[test]
    fn row_requests_decode_one_row_and_preserve_order_and_duplicate_identities() {
        use zcash_client_backend::data_api::enhance_pir::{
            EnhancePirRequest, IronwoodEnhanceRequestId,
        };
        use zcash_primitives::transaction::TxId;
        let transport = FixtureTransport::new(None, None);
        let request = |position: u64, index| {
            EnhancePirRequest::new(
                position.into(),
                IronwoodEnhanceRequestId::new(TxId::from_bytes([1; 32]), index),
            )
        };
        let requests = [
            request(32, 2),
            request(0, 0),
            request(32, 2),
            request(32, 3),
        ];
        futures::executor::block_on(async {
            let mut client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&transport.acceptance(0x42, 1))
                .unwrap();
            let result = client
                .query_row_requests(&transport, &requests)
                .await
                .unwrap();
            assert_eq!(result.row, 0);
            assert_eq!(
                result.slots.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
                requests
            );
            assert!(
                result
                    .slots
                    .iter()
                    .all(|(_, record)| record.as_bytes() == &[0; crate::RECORD_BYTES])
            );
            assert_eq!(transport.session_requests.get(), 1);
            assert_eq!(transport.query_requests.get(), 1);
        });
    }

    #[cfg(feature = "wallet")]
    #[test]
    fn row_requests_reject_shape_without_io_and_query_only_one_row() {
        use zcash_client_backend::data_api::enhance_pir::{
            EnhancePirRequest, IronwoodEnhanceRequestId,
        };
        use zcash_primitives::transaction::TxId;
        let transport = FixtureTransport::new(None, Some(503));
        let request = |position: u64, txid| {
            EnhancePirRequest::new(
                position.into(),
                IronwoodEnhanceRequestId::new(TxId::from_bytes([txid; 32]), position as u32),
            )
        };
        futures::executor::block_on(async {
            let mut client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&transport.acceptance(0x42, 1))
                .unwrap();
            assert!(matches!(
                client.query_row_requests(&transport, &[]).await,
                Err(ClientError::EmptyBatch)
            ));
            assert!(matches!(
                client
                    .query_row_requests(&transport, &[request(0, 1), request(1, 2)])
                    .await,
                Err(ClientError::MixedTxid)
            ));
            assert!(matches!(
                client
                    .query_row_requests(&transport, &[request(32, 1), request(33, 1)])
                    .await,
                Err(ClientError::CrossRowBatch)
            ));
            assert!(matches!(
                client
                    .query_row_requests(&transport, &[request(67, 1)])
                    .await,
                Err(ClientError::OutsideCoverage(67))
            ));
            assert!(matches!(
                client
                    .query_row_requests(
                        &transport,
                        &vec![request(0, 1); DEFAULT_MAX_BATCH_SIZE + 1]
                    )
                    .await,
                Err(ClientError::BatchTooLarge { .. })
            ));
            assert_eq!(transport.session_requests.get(), 0);
            assert_eq!(transport.query_requests.get(), 0);
            let error = client
                .query_row_requests(&transport, &[request(32, 1), request(0, 1), request(32, 1)])
                .await
                .unwrap_err();
            assert_eq!(error.http_status(), Some(503));
            assert_eq!(transport.session_requests.get(), 1);
            assert_eq!(transport.query_requests.get(), 1);
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

#[cfg(test)]
mod v7_cover_tests {
    use super::*;
    use crate::types::*;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::cell::{Cell, RefCell};

    struct Mock {
        manifest: Manifest,
        posts: RefCell<Vec<u64>>,
        setups: Cell<usize>,
        retry: Cell<bool>,
        retry_domain: u64,
        corrupt: bool,
        delay_once: Cell<bool>,
        post_statuses: RefCell<VecDeque<Option<u16>>>,
        session_statuses: RefCell<VecDeque<Option<u16>>>,
        pending_post: Option<usize>,
        pending_session: Option<usize>,
        oversized_post: bool,
    }
    impl Mock {
        fn new() -> Self {
            let mut manifest = crate::test_support::synthetic_manifest(
                32768 * 33 + 1,
                |shard| {
                    let params = parameters(shard.logical_rows).unwrap();
                    let (rlwe, _) = ipir_sp::params_for_simplepir_profile(
                        shard.logical_rows,
                        ITEM_SIZE_BITS,
                        ipir_sp::SimplePirProfile::P16Q48,
                    )
                    .unwrap();
                    let public =
                        vec![
                            0u8;
                            params.db_cols / rlwe.d
                                * ipir_sp::modulus_switch::published_c1_len(rlwe.d, rlwe.q)
                        ];
                    hex::encode(Sha256::digest(&public))
                },
                &"00".repeat(32),
            );
            manifest.anchor_height = 3428143;
            manifest.anchor_block_hash = "42".repeat(32);
            Self {
                manifest,
                posts: RefCell::new(Vec::new()),
                setups: Cell::new(0),
                retry: Cell::new(false),
                retry_domain: 1,
                corrupt: false,
                delay_once: Cell::new(false),
                post_statuses: RefCell::new(VecDeque::new()),
                session_statuses: RefCell::new(VecDeque::new()),
                pending_post: None,
                pending_session: None,
                oversized_post: false,
            }
        }
        fn acceptance(&self) -> GenerationAcceptance {
            GenerationAcceptance::new(
                "main",
                3428143,
                crate::AcceptedAnchor::new(
                    self.manifest.anchor_height,
                    hex::decode(&self.manifest.anchor_block_hash)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    self.manifest.coverage.records,
                ),
                crate::ClientResourceLimits::with_cache(32768, 2),
            )
        }
    }
    impl Transport for Mock {
        async fn execute(&self, request: Request) -> Result<ResponseBody, ClientError> {
            let bytes = if request.url.ends_with("/init") {
                serde_json::to_vec(&self.manifest).unwrap()
            } else if request.url.contains("/session/") {
                self.setups.set(self.setups.get() + 1);
                if self.pending_session == Some(self.setups.get()) {
                    std::future::pending::<()>().await;
                }
                if let Some(Some(status)) = self.session_statuses.borrow_mut().pop_front() {
                    return Err(ClientError::HttpStatus(status));
                }
                let shard = self
                    .manifest
                    .coverage
                    .shards
                    .iter()
                    .find(|s| {
                        request
                            .url
                            .ends_with(&hex::encode(self.manifest.session_id(s.id).unwrap()))
                    })
                    .unwrap();
                let params = parameters(shard.logical_rows).unwrap();
                let (rlwe, _) = ipir_sp::params_for_simplepir_profile(
                    shard.logical_rows,
                    ITEM_SIZE_BITS,
                    ipir_sp::SimplePirProfile::P16Q48,
                )
                .unwrap();
                let public = vec![
                    0;
                    params.db_cols / rlwe.d
                        * ipir_sp::modulus_switch::published_c1_len(rlwe.d, rlwe.q)
                ];
                serde_json::to_vec(&ShardSession {
                    session_id: hex::encode(self.manifest.session_id(shard.id).unwrap()),
                    generation: self.manifest.generation,
                    shard_id: shard.id,
                    params,
                    public_params_base64: base64::engine::general_purpose::STANDARD.encode(public),
                })
                .unwrap()
            } else {
                let binding = QueryBinding::decode(&request.body).unwrap();
                self.posts.borrow_mut().push(binding.shard_id);
                if self.pending_post == Some(self.posts.borrow().len()) {
                    std::future::pending::<()>().await;
                }
                if let Some(Some(status)) = self.post_statuses.borrow_mut().pop_front() {
                    return Err(ClientError::HttpStatus(status));
                }
                if self.oversized_post {
                    // A custom transport that ignores the request's collector.
                    return Ok(ResponseBody(vec![0; MAX_RESPONSE_BYTES + 1]));
                }
                if self.delay_once.replace(false) {
                    tokio::time::sleep(std::time::Duration::from_secs(31)).await;
                }
                if binding.shard_id == self.retry_domain && self.retry.replace(false) {
                    return Err(ClientError::HttpStatus(429));
                }
                let shard = &self.manifest.coverage.shards[binding.shard_id as usize];
                let params = parameters(shard.logical_rows).unwrap();
                let mut response = binding.encode();
                response.resize(
                    HEADER_BYTES
                        + params.db_cols / params.poly_len
                            * ipir_sp::modulus_switch::response_body_len(
                                params.poly_len,
                                params.q_prime_1,
                            ),
                    0,
                );
                if self.corrupt && binding.shard_id == 1 {
                    response[HEADER_BYTES..].fill(0x55);
                }
                response
            };
            let mut body = request.response_body();
            body.extend(&bytes)?;
            Ok(body.finish())
        }
    }
    #[test]
    fn cover_rounds_hide_target_and_retry_every_domain() {
        futures::executor::block_on(async {
            for position in [0, 32768 * 33] {
                let transport = Mock::new();
                transport.retry.set(true);
                let mut client = PendingClient::fetch(&transport, "https://example.test")
                    .await
                    .unwrap()
                    .accept(&transport.acceptance())
                    .unwrap();
                let records = client
                    .query_positions_with_cover(&transport, &[position, position], 0)
                    .await
                    .unwrap();
                assert_eq!(records.len(), 2);
                let posts = transport.posts.borrow();
                assert_eq!(posts.len(), 4);
                for round in posts.chunks_exact(2) {
                    let mut set = round.to_vec();
                    set.sort();
                    assert_eq!(set, [0, 1]);
                }
            }
        });
    }
    #[test]
    fn routing_refresh_reuses_unchanged_material() {
        futures::executor::block_on(async {
            let mut transport = Mock::new();
            let mut client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&transport.acceptance())
                .unwrap();
            client
                .query_positions_with_cover(&transport, &[0], 0)
                .await
                .unwrap();
            assert_eq!(transport.setups.get(), 2);
            transport.manifest.generation += 1;
            transport.manifest.placement_revision += 1;
            transport.manifest.anchor_height += 1;
            transport.manifest.anchor_block_hash = "43".repeat(32);
            let pending = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            client
                .accept_routing(pending, &transport.acceptance())
                .unwrap();
            client
                .query_positions_with_cover(&transport, &[0], 0)
                .await
                .unwrap();
            assert_eq!(transport.setups.get(), 2);
        });
    }
    #[test]
    fn record_errors_do_not_change_cover_rounds_or_retries() {
        futures::executor::block_on(async {
            for real in [false, true] {
                for retry in [false, true] {
                    let mut transport = Mock::new();
                    transport.corrupt = true;
                    transport.retry_domain = 0;
                    transport.retry.set(retry);
                    let mut client = PendingClient::fetch(&transport, "https://example.test")
                        .await
                        .unwrap()
                        .accept(&transport.acceptance())
                        .unwrap();
                    // Domain 0 sets two rounds in both cases. Domain 1 is real or dummy.
                    let positions = if real {
                        vec![0, 33, 32768 * 33]
                    } else {
                        vec![0, 33]
                    };
                    let result = client
                        .query_positions_with_cover(&transport, &positions, 0)
                        .await;
                    assert_eq!(result.is_err(), real);
                    let posts = transport.posts.borrow();
                    assert_eq!(posts.len(), if retry { 6 } else { 4 });
                    for round in posts.chunks_exact(2) {
                        let mut round = round.to_vec();
                        round.sort();
                        assert_eq!(round, [0, 1]);
                    }
                }
            }
        });
    }

    #[test]
    fn cover_finishes_after_refresh_becomes_due() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let transport = Mock::new();
                transport.delay_once.set(true);
                let mut client = PendingClient::fetch(&transport, "https://example.test")
                    .await
                    .unwrap()
                    .accept(&transport.acceptance())
                    .unwrap();
                assert_eq!(
                    client
                        .query_positions_with_cover(&transport, &[0, 33], 0)
                        .await
                        .unwrap()
                        .len(),
                    2
                );
                assert_eq!(transport.posts.borrow().len(), 4);
                assert!(client.refresh_due());
                assert!(matches!(
                    client.query_positions_with_cover(&transport, &[0], 0).await,
                    Err(ClientError::HttpStatus(409))
                ));
                assert!(client.query_batch(&transport, [0]).is_err());
                assert!(matches!(
                    client.query_dummy(&transport, 0).await,
                    Err(ClientError::HttpStatus(409))
                ));
                assert_eq!(transport.posts.borrow().len(), 4);
            });
    }

    #[test]
    fn expired_client_reports_410_on_every_query_path() {
        futures::executor::block_on(async {
            use futures_util::StreamExt;
            let transport = Mock::new();
            let mut client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&transport.acceptance())
                .unwrap();
            transport.post_statuses.borrow_mut().push_back(Some(410));
            assert!(matches!(
                client.query_dummy(&transport, 0).await,
                Err(ClientError::HttpStatus(410))
            ));
            assert!(client.refresh_due());
            // Expiration wins over the refresh-due 409 on every entry point.
            assert!(matches!(
                client.query_positions_with_cover(&transport, &[0], 0).await,
                Err(ClientError::HttpStatus(410))
            ));
            assert!(matches!(
                client.query_dummy(&transport, 0).await,
                Err(ClientError::HttpStatus(410))
            ));
            let stale: Vec<_> = client.query_batch(&transport, [0]).unwrap().collect().await;
            assert!(matches!(
                &stale[0].record,
                Err(ClientError::HttpStatus(410))
            ));
            assert_eq!(transport.posts.borrow().len(), 1);
        });
    }

    #[test]
    fn every_query_path_caps_custom_transport_responses() {
        futures::executor::block_on(async {
            let mut transport = Mock::new();
            transport.oversized_post = true;
            let mut client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&transport.acceptance())
                .unwrap();
            let dummy = client.query_dummy(&transport, 0).await;
            let cover = client
                .query_positions_with_cover(&transport, &[0], 0)
                .await
                .map(|_| ());
            for result in [dummy, cover] {
                assert!(matches!(
                    result,
                    Err(ClientError::Response(message)) if message == "HTTP body exceeds limit"
                ));
            }
            assert_eq!(transport.posts.borrow().len(), 3);
        });
    }

    #[test]
    fn streaming_batch_finishes_after_refresh_becomes_due() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use futures_util::StreamExt;
                let transport = Mock::new();
                transport.delay_once.set(true);
                let mut client = PendingClient::fetch(&transport, "https://example.test")
                    .await
                    .unwrap()
                    .accept(&transport.acceptance())
                    .unwrap();
                let results: Vec<_> = client
                    .query_batch(&transport, [0, 33])
                    .unwrap()
                    .collect()
                    .await;
                assert_eq!(results.len(), 2);
                assert!(results.iter().all(|r| r.record.is_ok()));
                assert!(client.refresh_due());
                assert_eq!(transport.posts.borrow().len(), 2);
            });
    }
    #[test]
    fn mixed_cover_errors_preserve_expiration_in_either_order() {
        futures::executor::block_on(async {
            for status in [409, 410] {
                for statuses in [[400, status], [status, 400]] {
                    let transport = Mock::new();
                    let mut client = PendingClient::fetch(&transport, "https://example.test")
                        .await
                        .unwrap()
                        .accept(&transport.acceptance())
                        .unwrap();
                    transport
                        .post_statuses
                        .borrow_mut()
                        .extend(statuses.map(Some));
                    let failure = client
                        .query_positions_with_cover(&transport, &[0], 0)
                        .await
                        .unwrap_err();
                    assert_eq!(failure.http_status(), Some(statuses[0]));
                    assert_eq!(transport.posts.borrow().len(), 2);
                    assert!(client.refresh_due(), "expiration hidden by {statuses:?}");
                    assert!(matches!(
                        client.query_dummy(&transport, 0).await,
                        Err(ClientError::HttpStatus(410))
                    ));
                    assert_eq!(transport.posts.borrow().len(), 2);
                    // Fresh acceptance clears expiration and retains valid setups.
                    let pending = PendingClient::fetch(&transport, "https://example.test")
                        .await
                        .unwrap();
                    client
                        .accept_routing(pending, &transport.acceptance())
                        .unwrap();
                    assert!(!client.refresh_due());
                    client.query_dummy(&transport, 0).await.unwrap();
                    assert_eq!(transport.setups.get(), 2);
                }
            }
        });
    }

    #[test]
    fn cover_expiration_survives_a_later_session_failure() {
        futures::executor::block_on(async {
            for status in [409, 410] {
                let transport = Mock::new();
                let mut client = PendingClient::fetch(&transport, "https://example.test")
                    .await
                    .unwrap()
                    .accept(&transport.acceptance())
                    .unwrap();
                transport.post_statuses.borrow_mut().push_back(Some(status));
                transport
                    .session_statuses
                    .borrow_mut()
                    .extend([None, Some(400)]);
                let failure = client
                    .query_positions_with_cover(&transport, &[0], 0)
                    .await
                    .unwrap_err();
                assert_eq!(failure.http_status(), Some(status));
                assert!(client.refresh_due());
                assert_eq!(transport.posts.borrow().len(), 1);
                assert_eq!(transport.setups.get(), 2);
            }
        });
    }

    #[test]
    fn routing_acceptance_enforces_reduced_cache_limit() {
        futures::executor::block_on(async {
            let transport = Mock::new();
            let mut accepted = transport.acceptance();
            let mut client = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap()
                .accept(&accepted)
                .unwrap();
            for id in [0, 1, 0] {
                client.query_dummy(&transport, id).await.unwrap();
            }
            assert_eq!(transport.setups.get(), 2);
            // Invalid limits must leave the existing cache untouched.
            accepted.limits.max_cached_shards = 0;
            let pending = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            assert!(client.accept_routing(pending, &accepted).is_err());
            assert_eq!(client.cache.sessions.len(), 2);
            // The exact limit keeps all material and the existing LRU ordering.
            accepted.limits.max_cached_shards = 2;
            let pending = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            client.accept_routing(pending, &accepted).unwrap();
            assert_eq!(client.cache.sessions.len(), 2);
            accepted.limits.max_cached_shards = 1;
            let pending = PendingClient::fetch(&transport, "https://example.test")
                .await
                .unwrap();
            client.accept_routing(pending, &accepted).unwrap();
            assert_eq!(client.cache.sessions.len(), 1);
            assert_eq!(client.cache.order, VecDeque::from([0]));
            client.query_dummy(&transport, 0).await.unwrap();
            assert_eq!(transport.setups.get(), 2);
            client.query_dummy(&transport, 1).await.unwrap();
            assert_eq!(transport.setups.get(), 3);
            assert_eq!(client.cache.sessions.len(), 1);
            assert_eq!(client.cache.order, VecDeque::from([1]));
        });
    }
    #[test]
    fn cover_session_overload_retries_the_round() {
        futures::executor::block_on(async {
            for status in [429, 503] {
                let transport = Mock::new();
                let mut client = PendingClient::fetch(&transport, "https://example.test")
                    .await
                    .unwrap()
                    .accept(&transport.acceptance())
                    .unwrap();
                transport
                    .session_statuses
                    .borrow_mut()
                    .extend([None, Some(status)]);
                assert_eq!(
                    client
                        .query_positions_with_cover(&transport, &[0], 0)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
                let posts = transport.posts.borrow();
                assert_eq!(posts.len(), 3);
                let mut retry = posts[1..].to_vec();
                retry.sort();
                assert_eq!(retry, [0, 1]);
                assert_eq!(transport.setups.get(), 3);
                assert!(!client.refresh_due());
            }
        });
    }
    #[test]
    fn dropping_cover_preserves_observed_expiration() {
        futures::executor::block_on(async {
            for status in [None, Some(409), Some(410)] {
                for pending_session in [false, true] {
                    let mut transport = Mock::new();
                    if pending_session {
                        transport.pending_session = Some(2);
                    } else {
                        transport.pending_post = Some(2);
                    }
                    let mut client = PendingClient::fetch(&transport, "https://example.test")
                        .await
                        .unwrap()
                        .accept(&transport.acceptance())
                        .unwrap();
                    transport.post_statuses.borrow_mut().push_back(status);
                    let mut query =
                        Box::pin(client.query_positions_with_cover(&transport, &[0], 0));
                    let mut context =
                        std::task::Context::from_waker(futures_util::task::noop_waker_ref());
                    assert!(query.as_mut().poll(&mut context).is_pending());
                    // First query completed, then the next setup/query suspended.
                    assert_eq!(transport.setups.get(), 2);
                    let posts = transport.posts.borrow().len();
                    assert_eq!(posts, if pending_session { 1 } else { 2 });
                    drop(query);
                    assert_eq!(client.refresh_due(), status.is_some());
                    if status.is_some() {
                        assert!(matches!(
                            client.query_dummy(&transport, 0).await,
                            Err(ClientError::HttpStatus(410))
                        ));
                        assert_eq!(transport.setups.get(), 2);
                        assert_eq!(transport.posts.borrow().len(), posts);
                        let pending = PendingClient::fetch(&transport, "https://example.test")
                            .await
                            .unwrap();
                        client
                            .accept_routing(pending, &transport.acceptance())
                            .unwrap();
                        assert!(!client.refresh_due());
                    }
                    client.query_dummy(&transport, 0).await.unwrap();
                    assert_eq!(transport.posts.borrow().len(), posts + 1);
                }
            }
        });
    }
}
