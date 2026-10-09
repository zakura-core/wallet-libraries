//! Both PIR services over one raw HTTP exchange the caller supplies.
//!
//! The caller implements [`HttpExchange`]: it sends one request to the origin
//! it is bound to and returns the reply as it arrived. Everything about
//! reaching the origin is the caller's (HTTPS, routing, timeouts, cancellation
//! and reading at most a request's body limit). Everything about the services
//! is here: their routes and log templates, body limits, which statuses are
//! refusals the reference clients act on, and which failures say the service
//! is down rather than refusing one request.
//!
//! [`TransparentPirHttp`] hands a recovery pass its [`FilterSource`] and
//! [`ShardTransport`] over the exchange. [`TxidHttp`] is the txid display
//! client's [`TxidTransport`] over it. Nothing is retried or memoized: the
//! reference clients decide what a refusal is worth, and a republished tail
//! reuses its shard id with a new filter.

use std::cell::Cell;
use std::fmt;

use transparent_txid_client::{
    Method as TxidMethod, Route as TxidRoute, TransportError, TxidReply, TxidRequest, TxidTransport,
};
use transparent_wallet::client::Table;
use transparent_wallet::transport::{
    BoxError, FilterSource, Overloaded, ShardRequest, ShardTransport, refusal,
};

/// Error-body bytes worth reading from a shard-bound refusal: a stale
/// refusal's body names the service's map digest, a diagnostic. The status is
/// the refusal, so a longer body costs only that digest.
const REFUSAL_BODY_LIMIT: usize = 4096;

/// An HTTP method a service route uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    /// Sends its body as `application/octet-stream`.
    Post,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

/// One request to the origin an exchange is bound to.
///
/// Its `Debug` shows the template and sizes only: the path and body name shard
/// ids, revisions and private query bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    /// Origin-relative, starting with `/v1/`. It names shard ids, revisions,
    /// tables and segments the public maps already name, never a script or a
    /// txid.
    pub path: String,
    /// The path with every identifier elided: all a log line may name.
    pub template: String,
    /// A `POST` body; empty for `GET`.
    pub body: Vec<u8>,
    /// The largest successful body the exchange accepts. A longer one fails
    /// the exchange with [`HttpFailure::TooLarge`].
    pub limit: usize,
    /// Bytes of an error body worth reading; the rest is dropped. Zero reads
    /// none.
    pub error_limit: usize,
}

/// A reply as it arrived. The library, not the exchange, decides what its
/// status means. Its `Debug` shows the status, delay and body size only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    /// The raw `retry-after` header, when present.
    pub retry_after: Option<String>,
    /// The raw `x-txid-map-sha256` header, when present.
    pub map_sha256: Option<String>,
    /// A success's whole body, or at most `error_limit` bytes of an error's.
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("template", &self.template)
            .field("body_len", &self.body.len())
            .field("limit", &self.limit)
            .field("error_limit", &self.error_limit)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for HttpReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpReply")
            .field("status", &self.status)
            .field("retry_after", &self.retry_after)
            .field("map_sha256", &self.map_sha256.is_some())
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Why an exchange delivered no reply. Carries no URL, identifier or body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HttpFailure {
    /// The caller is stopping: nothing was sent, or the reply is dropped.
    #[error("cancelled")]
    Cancelled,
    /// A successful body exceeded the request's limit.
    #[error("too large")]
    TooLarge,
    /// No whole reply within the exchange's deadline.
    #[error("timed out")]
    Timeout,
    /// The route or connection failed.
    #[error("unreachable")]
    Unreachable,
}

/// Sends one request to the caller's origin and returns its reply, whatever
/// its status.
///
/// An implementation never retries, never interprets a status, reads a
/// success's body up to [`HttpRequest::limit`] and an error's up to
/// [`HttpRequest::error_limit`], and logs at most the method and
/// [`HttpRequest::template`].
pub trait HttpExchange {
    fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure>;
}

impl<E: HttpExchange + ?Sized> HttpExchange for &E {
    fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
        (**self).send(request)
    }
}

/// A transparent PIR origin's shard map, filters, init, manifests, setup and
/// queries over one exchange, for one pass.
///
/// [`split`](Self::split) hands a pass its two halves. A successful body over
/// `limit` fails its request. Refusals the sync acts on come back as
/// wallet-pir's typed `StaleRevision` and [`Overloaded`], recognised by
/// wallet-pir's own [`refusal`] and [`Overloaded::from_http`]; any other
/// status fails the request.
pub struct TransparentPirHttp<E> {
    exchange: E,
    limit: usize,
    outage: Cell<bool>,
}

/// The public half: the shard map and filters.
pub struct PirFilters<'t, E> {
    http: &'t TransparentPirHttp<E>,
}

/// The private half: init, manifests, setup and queries.
pub struct PirShards<'t, E> {
    http: &'t TransparentPirHttp<E>,
}

impl<E: HttpExchange> TransparentPirHttp<E> {
    pub fn new(exchange: E, limit: usize) -> Self {
        Self {
            exchange,
            limit,
            outage: Cell::new(false),
        }
    }

    /// The filter source and shard transport a pass hands
    /// `ReferenceRecovery::recover`.
    pub fn split(&mut self) -> (PirFilters<'_, E>, PirShards<'_, E>) {
        let http = &*self;
        (PirFilters { http }, PirShards { http })
    }

    /// Whether a request failed in a way that says the service cannot be
    /// reached or is not serving, rather than refusing that request: an
    /// unreachable origin or a timeout; a 429 or 5xx on the map, a filter or
    /// init, which the sync does not retry; or a 429, or a 5xx that is not a
    /// capacity refusal, on a shard route. A pass that failed with an outage
    /// failed for every account.
    pub fn outage(&self) -> bool {
        self.outage.get()
    }

    pub fn exchange(&self) -> &E {
        &self.exchange
    }

    /// Sends one request and returns its bytes with their cost, the bytes
    /// delivered.
    fn fetch(&self, route: Route<'_>) -> Result<(Vec<u8>, u64), BoxError> {
        let binding = route.binding();
        let request = HttpRequest {
            method: route.method(),
            path: route.path(),
            template: route.template(),
            body: route.body(),
            limit: self.limit,
            error_limit: if binding.is_some() {
                REFUSAL_BODY_LIMIT
            } else {
                0
            },
        };
        let reply = match self.exchange.send(&request) {
            Ok(reply) => reply,
            Err(failure) => {
                if matches!(failure, HttpFailure::Unreachable | HttpFailure::Timeout) {
                    self.outage.set(true);
                }
                return Err(failure.into());
            }
        };
        if (200..300).contains(&reply.status) {
            let cost = reply.body.len() as u64;
            return Ok((reply.body, cost));
        }
        let retry_after = reply.retry_after.as_deref();
        let refused = match binding {
            Some((shard_id, revision)) => {
                refusal(reply.status, retry_after, &reply.body, shard_id, revision)
            }
            // The map, filters and init name no revision, so only capacity
            // applies.
            None => Overloaded::from_http(reply.status, retry_after).map(Overloaded::boxed),
        };
        let failing = reply.status == 429 || (500..600).contains(&reply.status);
        if failing && (binding.is_none() || refused.is_none()) {
            self.outage.set(true);
        }
        Err(refused.unwrap_or_else(|| Box::new(HttpStatus(reply.status))))
    }
}

impl<E: HttpExchange> FilterSource for PirFilters<'_, E> {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.http.fetch(Route::ShardMap)
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.http.fetch(Route::Filter { shard_id })
    }
}

/// Keeps the trait's default concurrency of one, so the sync walks every
/// request in sequence and a batch is never sent.
impl<E: HttpExchange> ShardTransport for PirShards<'_, E> {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.http.fetch(Route::Init)
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.http
            .fetch(Route::Shard(ShardRequest::Manifest { shard_id, revision }))
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.http.fetch(Route::Shard(ShardRequest::Setup {
            shard_id,
            revision,
            table,
            segment,
        }))
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.http
            .fetch(Route::Shard(ShardRequest::Query {
                shard_id,
                revision,
                table,
                body,
            }))
            .map(|(bytes, _)| bytes)
    }
}

/// A status the service did not phrase as a refusal the sync acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("transparent PIR service returned HTTP {0}")]
pub struct HttpStatus(pub u16);

/// One transparent PIR request, as the service routes it.
#[derive(Clone, Copy)]
enum Route<'r> {
    ShardMap,
    Filter { shard_id: u64 },
    Init,
    Shard(ShardRequest<'r>),
}

impl Route<'_> {
    /// Queries post their opaque body; everything else is a read.
    fn method(&self) -> HttpMethod {
        match self {
            Route::Shard(ShardRequest::Query { .. }) => HttpMethod::Post,
            _ => HttpMethod::Get,
        }
    }

    fn path(&self) -> String {
        match *self {
            Route::ShardMap => "/v1/filters/shards".to_owned(),
            Route::Filter { shard_id } => format!("/v1/filters/shards/{shard_id}/filter"),
            Route::Init => "/v1/shards/init".to_owned(),
            Route::Shard(request) => request.route(),
        }
    }

    fn template(&self) -> String {
        match *self {
            Route::ShardMap => "/v1/filters/shards".to_owned(),
            Route::Filter { .. } => "/v1/filters/shards/{id}/filter".to_owned(),
            Route::Init => "/v1/shards/init".to_owned(),
            Route::Shard(ShardRequest::Manifest { .. }) => {
                "/v1/shards/{id}/revisions/{rev}/manifest".to_owned()
            }
            Route::Shard(ShardRequest::Setup { table, .. }) => format!(
                "/v1/shards/{{id}}/revisions/{{rev}}/setup/{}/{{segment}}",
                table.as_str()
            ),
            Route::Shard(ShardRequest::Query { table, .. }) => format!(
                "/v1/shards/{{id}}/revisions/{{rev}}/query/{}",
                table.as_str()
            ),
        }
    }

    fn body(&self) -> Vec<u8> {
        match self {
            Route::Shard(ShardRequest::Query { body, .. }) => body.to_vec(),
            _ => Vec::new(),
        }
    }

    /// The shard revision a shard-bound request names, which a stale refusal
    /// reports back.
    fn binding(&self) -> Option<(u64, &str)> {
        match *self {
            Route::Shard(
                ShardRequest::Manifest { shard_id, revision }
                | ShardRequest::Setup {
                    shard_id, revision, ..
                }
                | ShardRequest::Query {
                    shard_id, revision, ..
                },
            ) => Some((shard_id, revision)),
            _ => None,
        }
    }
}

/// The txid display client's transport over one exchange.
///
/// Every status reaches the client, which interprets it; error bodies are not
/// read. A success over its route's bound fails the request.
pub struct TxidHttp<E> {
    exchange: E,
}

impl<E: HttpExchange> TxidHttp<E> {
    pub fn new(exchange: E) -> Self {
        Self { exchange }
    }
}

/// The largest successful body of a txid display route. Queries are bounded by
/// every segment's answer of the widest supported geometry.
fn txid_limit(route: TxidRoute) -> usize {
    match route {
        TxidRoute::Init => 256 << 10,
        TxidRoute::Map | TxidRoute::MapChunk => 4 << 20,
        TxidRoute::Manifest | TxidRoute::Setup => 1 << 20,
        TxidRoute::Query => 8 << 20,
    }
}

impl<E: HttpExchange> TxidTransport for TxidHttp<E> {
    fn send(&mut self, request: TxidRequest) -> Result<TxidReply, TransportError> {
        let request = HttpRequest {
            method: match request.method {
                TxidMethod::Get => HttpMethod::Get,
                TxidMethod::Post => HttpMethod::Post,
            },
            path: request.path().to_owned(),
            template: request.template().to_owned(),
            limit: txid_limit(request.route),
            body: request.body,
            error_limit: 0,
        };
        let reply = self
            .exchange
            .send(&request)
            .map_err(|failure| TransportError(failure.to_string()))?;
        Ok(TxidReply {
            status: reply.status,
            retry_after: reply.retry_after,
            map_sha256: reply.map_sha256,
            body: reply.body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::time::Duration;
    use transparent_wallet::transport::StaleRevision;

    const SHARD: u64 = 4242;
    const REVISION: &str = "5f0c2b9e7d41a8c36e19f0b2d47a5c8e9b1d3f6a2c4e8b0d7f9a1c3e5b7d9f0a";
    const QUERY: &[u8] = &[0xc3, 0x5a, 0x01, 0xfe];
    const LIMIT: usize = 1024;

    /// Answers every request with `answer`, recording it.
    struct Fake<A> {
        answer: A,
        sent: RefCell<Vec<HttpRequest>>,
    }

    impl<A: Fn(&HttpRequest) -> Result<HttpReply, HttpFailure>> HttpExchange for Fake<A> {
        fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
            self.sent.borrow_mut().push(request.clone());
            (self.answer)(request)
        }
    }

    fn http<A: Fn(&HttpRequest) -> Result<HttpReply, HttpFailure>>(
        answer: A,
    ) -> TransparentPirHttp<Fake<A>> {
        TransparentPirHttp::new(
            Fake {
                answer,
                sent: RefCell::default(),
            },
            LIMIT,
        )
    }

    fn reply(status: u16, retry_after: Option<&str>, body: &[u8]) -> HttpReply {
        HttpReply {
            status,
            retry_after: retry_after.map(str::to_owned),
            map_sha256: None,
            body: body.to_vec(),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Public,
        ShardBound,
    }

    /// Every request a pass makes, once each, with whether it names a shard
    /// revision.
    fn every_route<E: HttpExchange>(
        http: &mut TransparentPirHttp<E>,
    ) -> Vec<(Kind, Result<Vec<u8>, BoxError>)> {
        let (mut filters, mut shards) = http.split();
        let bytes = |result: Result<(Vec<u8>, u64), BoxError>| result.map(|(bytes, _)| bytes);
        vec![
            (Kind::Public, bytes(filters.shard_map())),
            (Kind::Public, bytes(filters.filter(SHARD))),
            (Kind::Public, bytes(shards.init())),
            (Kind::ShardBound, bytes(shards.manifest(SHARD, REVISION))),
            (
                Kind::ShardBound,
                bytes(shards.setup(SHARD, REVISION, Table::Directory, 3)),
            ),
            (
                Kind::ShardBound,
                bytes(shards.setup(SHARD, REVISION, Table::Pages, 0)),
            ),
            (
                Kind::ShardBound,
                shards.query(SHARD, REVISION, Table::Directory, QUERY),
            ),
            (
                Kind::ShardBound,
                shards.query(SHARD, REVISION, Table::Pages, QUERY),
            ),
        ]
    }

    fn status(error: &BoxError) -> u16 {
        error
            .downcast_ref::<HttpStatus>()
            .unwrap_or_else(|| panic!("not a status failure: {error}"))
            .0
    }

    #[test]
    fn routes_templates_and_limits_match_the_service() {
        let mut http = http(|request| Ok(reply(200, None, request.path.as_bytes())));
        {
            let (mut filters, shards) = http.split();
            assert!(!filters.uses_parents());
            assert_eq!(shards.concurrency(), 1);
            let (map, cost) = filters.shard_map().unwrap();
            assert_eq!(map, b"/v1/filters/shards");
            assert_eq!(cost, map.len() as u64);
        }
        http.exchange().sent.borrow_mut().clear();
        let results = every_route(&mut http);

        let shard = format!("/v1/shards/{SHARD}/revisions/{REVISION}");
        let template = "/v1/shards/{id}/revisions/{rev}";
        let none: &[u8] = &[];
        let expected = [
            (
                HttpMethod::Get,
                "/v1/filters/shards".to_owned(),
                "/v1/filters/shards".to_owned(),
                none,
            ),
            (
                HttpMethod::Get,
                format!("/v1/filters/shards/{SHARD}/filter"),
                "/v1/filters/shards/{id}/filter".to_owned(),
                none,
            ),
            (
                HttpMethod::Get,
                "/v1/shards/init".to_owned(),
                "/v1/shards/init".to_owned(),
                none,
            ),
            (
                HttpMethod::Get,
                format!("{shard}/manifest"),
                format!("{template}/manifest"),
                none,
            ),
            (
                HttpMethod::Get,
                format!("{shard}/setup/directory/3"),
                format!("{template}/setup/directory/{{segment}}"),
                none,
            ),
            (
                HttpMethod::Get,
                format!("{shard}/setup/pages/0"),
                format!("{template}/setup/pages/{{segment}}"),
                none,
            ),
            (
                HttpMethod::Post,
                format!("{shard}/query/directory"),
                format!("{template}/query/directory"),
                QUERY,
            ),
            (
                HttpMethod::Post,
                format!("{shard}/query/pages"),
                format!("{template}/query/pages"),
                QUERY,
            ),
        ];
        let sent = http.exchange().sent.borrow().clone();
        assert_eq!(sent.len(), expected.len());
        for (((method, path, template, body), request), (kind, result)) in
            expected.iter().zip(&sent).zip(results)
        {
            assert_eq!(request.method, *method);
            assert_eq!(&request.path, path);
            assert_eq!(&request.template, template);
            assert_eq!(request.body, body.to_vec());
            assert_eq!(request.limit, LIMIT);
            // Only a shard-bound refusal's body is worth reading.
            let error_limit = if kind == Kind::ShardBound {
                REFUSAL_BODY_LIMIT
            } else {
                0
            };
            assert_eq!(request.error_limit, error_limit);
            assert_eq!(result.unwrap(), path.as_bytes());
            // A template names no identifier.
            assert!(!template.contains(&SHARD.to_string()) && !template.contains(REVISION));
        }
    }

    #[test]
    fn a_409_is_a_stale_revision_only_where_one_is_named() {
        let mut http = http(|_| Ok(reply(409, None, br#"{"error":"gone","map_sha256":"beef"}"#)));
        for (kind, result) in every_route(&mut http) {
            let error = result.unwrap_err();
            match kind {
                Kind::ShardBound => {
                    let stale = StaleRevision::found_in(&error).expect("stale");
                    assert_eq!(stale.shard_id, SHARD);
                    assert_eq!(stale.revision, REVISION);
                    assert_eq!(stale.map_sha256.as_deref(), Some("beef"));
                }
                Kind::Public => assert_eq!(status(&error), 409),
            }
        }
        assert!(!http.outage());
    }

    /// Capacity is wallet-pir's: a 503 naming a delay, or the edge's 502 or 504.
    /// A 429, or a 503 without a delay (not ready, or no shards), is not
    /// capacity; it is an outage of the whole service.
    #[test]
    fn capacity_follows_wallet_pir() {
        for (code, retry_after, delay) in [
            (503, Some("7"), Some(Duration::from_secs(7))),
            (502, None, Some(Overloaded::EDGE_RETRY_AFTER)),
            (504, Some("2"), Some(Duration::from_secs(2))),
        ] {
            let mut http = http(move |_| Ok(reply(code, retry_after, b"")));
            for (_, result) in every_route(&mut http) {
                let error = result.unwrap_err();
                let overloaded = Overloaded::found_in(&error)
                    .unwrap_or_else(|| panic!("HTTP {code} is not capacity: {error}"));
                assert_eq!(overloaded.retry_after, delay);
            }
            // The sync does not retry the map, filters or init.
            assert!(http.outage(), "HTTP {code} on a public route");
        }
        for code in [429, 503] {
            let mut http = http(move |_| Ok(reply(code, None, b"")));
            for (_, result) in every_route(&mut http) {
                let error = result.unwrap_err();
                assert!(Overloaded::found_in(&error).is_none());
                assert_eq!(status(&error), code);
            }
            assert!(http.outage(), "HTTP {code}");
        }
    }

    #[test]
    fn only_unreachable_or_failing_services_are_outages() {
        // Shard-route capacity refusals and ordinary refusals are not.
        for (code, retry_after) in [
            (503, Some("7")),
            (502, None),
            (504, None),
            (404, None),
            (409, None),
        ] {
            let mut http = http(move |request: &HttpRequest| {
                Ok(if request.path.contains("/revisions/") {
                    reply(code, retry_after, b"")
                } else {
                    reply(200, None, b"ok")
                })
            });
            let _ = every_route(&mut http);
            assert!(!http.outage(), "HTTP {code} on a shard route");
        }
        // A public 404 is a refusal, not an outage.
        let mut missing = http(|_| Ok(reply(404, None, b"")));
        assert!(missing.split().0.shard_map().is_err());
        assert!(!missing.outage());
        // A failing or rate-limiting shard route is.
        for code in [500, 429] {
            let mut failing = http(move |request: &HttpRequest| {
                Ok(if request.path.contains("/revisions/") {
                    reply(code, None, b"")
                } else {
                    reply(200, None, b"ok")
                })
            });
            let _ = every_route(&mut failing);
            assert!(failing.outage(), "HTTP {code} on a shard route");
        }
        // As are an unreachable origin and a timeout, but not cancellation or
        // an oversized body.
        for (failure, outage) in [
            (HttpFailure::Unreachable, true),
            (HttpFailure::Timeout, true),
            (HttpFailure::Cancelled, false),
            (HttpFailure::TooLarge, false),
        ] {
            let mut http = http(move |_| Err(failure));
            for (_, result) in every_route(&mut http) {
                let error = result.unwrap_err();
                assert_eq!(error.downcast_ref::<HttpFailure>(), Some(&failure));
            }
            assert_eq!(http.outage(), outage, "{failure:?}");
        }
    }

    #[test]
    fn debug_output_names_no_identifier() {
        let request = HttpRequest {
            method: HttpMethod::Post,
            path: format!("/v1/shards/{SHARD}/revisions/{REVISION}/query/pages"),
            template: "/v1/shards/{id}/revisions/{rev}/query/pages".to_owned(),
            body: QUERY.to_vec(),
            limit: LIMIT,
            error_limit: 0,
        };
        let reply = HttpReply {
            status: 200,
            retry_after: None,
            map_sha256: Some("beef".to_owned()),
            body: format!("{SHARD}{REVISION}").into_bytes(),
        };
        for shown in [format!("{request:?}"), format!("{reply:?}")] {
            for secret in [
                SHARD.to_string(),
                REVISION.to_owned(),
                "beef".to_owned(),
                "c35a".to_owned(),
            ] {
                assert!(!shown.contains(&secret), "{shown} shows {secret}");
            }
        }
    }

    #[test]
    fn nothing_is_retried() {
        let mut http = http(|_| Ok(reply(500, None, b"")));
        let results = every_route(&mut http);
        assert_eq!(http.exchange().sent.borrow().len(), results.len());
    }

    #[test]
    fn txid_requests_carry_their_route_limits_and_replies_reach_the_client() {
        use transparent_txid_client::{TxidDisplayClient, TxidError};
        let sent = RefCell::new(Vec::new());
        let exchange = Fake {
            answer: |_: &HttpRequest| Ok(reply(503, Some("7"), b"")),
            sent,
        };
        let mut http = TxidHttp::new(&exchange);
        let found = TxidDisplayClient::new().lookup(&mut http, [7; 32], 3_460_000, &|| false);
        assert_eq!(
            found.unwrap_err(),
            TxidError::Unavailable {
                retry_after: Some(Duration::from_secs(7))
            }
        );
        let sent = exchange.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            (
                sent[0].method,
                sent[0].path.as_str(),
                sent[0].template.as_str()
            ),
            (HttpMethod::Get, "/v1/txid/init", "/v1/txid/init")
        );
        assert_eq!((sent[0].limit, sent[0].error_limit), (256 << 10, 0));
        for (route, limit) in [
            (TxidRoute::Map, 4 << 20),
            (TxidRoute::MapChunk, 4 << 20),
            (TxidRoute::Manifest, 1 << 20),
            (TxidRoute::Setup, 1 << 20),
            (TxidRoute::Query, 8 << 20),
        ] {
            assert_eq!(txid_limit(route), limit, "{route:?}");
        }
    }

    #[test]
    fn txid_exchange_failures_are_transport_errors() {
        use transparent_txid_client::{TxidDisplayClient, TxidError};
        let exchange = Fake {
            answer: |_: &HttpRequest| Err(HttpFailure::TooLarge),
            sent: RefCell::default(),
        };
        let found = TxidDisplayClient::new().lookup(
            &mut TxidHttp::new(&exchange),
            [7; 32],
            3_460_000,
            &|| false,
        );
        assert_eq!(
            found.unwrap_err(),
            TxidError::Transport(TransportError("too large".to_owned()))
        );
    }
}
