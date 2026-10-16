//! What a wallet fetches, and what it is charged for.
//!
//! Filters and private queries come from *different* sources by construction.
//! A wallet must not learn to fetch public bytes from the same place it makes
//! private requests, or the two become correlated whatever the protocol says,
//! so the two are separate traits and a caller has to supply both.
//!
//! # Accounting
//!
//! Bytes are counted as delivered — envelope and framing included, and
//! including bytes paid for on an attempt that later failed. A measurement that
//! counted only payloads would understate what a wallet actually pays, which is
//! the number the whole design has to beat.
//!
//! Stages are kept apart because they answer different questions. Filter bytes
//! are paid by *every* wallet unconditionally and are the floor. Setup is paid
//! once per shard a wallet opens. Query bytes scale with matches. Collapsing
//! them into one total would hide which part is actually expensive.
//!
//! Private bytes are split by *table* for the same reason. The directory is
//! what a script costs to find and the pages are what its history costs to
//! read, and geometry moves cost between them rather than removing it: wider
//! shards mean fewer directory lookups, but a script's two inline events are
//! granted per shard, so the same history spread over fewer shards keeps fewer
//! of them inline and pays a page query instead. A single private total cannot
//! show that transfer, and a geometry cannot be chosen without seeing it.

use crate::engine::client::Table;
use std::time::Duration;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Retain transport causes when crossing the wallet's string-valued error boundary.
pub(crate) fn describe_error(error: &(dyn std::error::Error + 'static)) -> String {
    let mut description = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        description.push_str(": ");
        description.push_str(&cause.to_string());
        source = cause.source();
    }
    description
}

/// A request named a shard revision the service no longer serves.
///
/// Concrete, and boxed into [`BoxError`], rather than a variant of the
/// transport traits' error type. Those traits have implementors that cannot
/// observe an HTTP status at all — one reading a published set straight off
/// disk, for instance — and a typed error enum would make every one of them
/// enumerate a condition it can never reach.
///
/// The cost of that choice is that recognition is the implementor's job, so
/// [`StaleRevision::from_http`] exists to make it one line rather than a JSON
/// parse each one could get subtly wrong. See [`ShardTransport`] for what an
/// implementor that skips it gives up.
#[derive(Clone, Debug, thiserror::Error)]
#[error("shard {shard_id} revision {revision} is no longer served")]
pub struct StaleRevision {
    pub shard_id: u64,
    /// The manifest digest the refused request named.
    pub revision: String,
    /// The map digest the *service* says is current, when its body carried one.
    ///
    /// Diagnostic, and a short-circuit against a map this sync itself fetched —
    /// never a trust input. It arrives from the private query origin, and
    /// letting it decide which map bytes a wallet accepts would give that
    /// origin a say in the wallet's view of the set, which is the reason public
    /// filters and private queries are separate traits to begin with.
    pub map_sha256: Option<String>,
}

/// The service could not free the cache capacity a request needed.
///
/// Retryable as it stands: unlike [`StaleRevision`] the map is not stale, and
/// refetching it would be pure cost.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the service has no free cache capacity")]
pub struct Overloaded {
    /// How long the service asked the caller to wait, when it said.
    pub retry_after: Option<Duration>,
}

impl StaleRevision {
    /// Recognises the refusal in an HTTP reply, or `None` if it is not one.
    ///
    /// `body` is the response body, which is why an implementor has to read it
    /// *before* discarding the reply: the map digest lives there, and helpers
    /// like `reqwest`'s `error_for_status` keep only the status code.
    pub fn from_http(status: u16, body: &[u8], shard_id: u64, revision: &str) -> Option<Self> {
        if status != 409 {
            return None;
        }
        // A refusal whose body will not parse is still a refusal. The digest is
        // an optimisation; the status is the fact.
        let map_sha256 = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|body| {
                body.get("map_sha256")
                    .and_then(|digest| digest.as_str())
                    .map(str::to_owned)
            });
        Some(Self {
            shard_id,
            revision: revision.to_string(),
            map_sha256,
        })
    }

    /// Finds this refusal inside a boxed transport error.
    ///
    /// Walks the `source` chain rather than inspecting the outermost box alone,
    /// so an implementor that wrapped the refusal in an error of its own is not
    /// silently missed — which would look exactly like a service that never
    /// refused anything.
    pub fn found_in(error: &BoxError) -> Option<&Self> {
        found_in(error)
    }

    pub fn boxed(self) -> BoxError {
        Box::new(self)
    }
}

impl Overloaded {
    /// Recognises an overload refusal, or `None` if it is not one.
    ///
    /// Keyed on `retry-after` and not on the status alone, because 503 is also
    /// how the service reports that it is not ready and that it holds no
    /// shards. Those are not retryable in the same breath — a wallet that
    /// backed off and re-asked would be waiting for a condition no wait fixes —
    /// and only the capacity refusal names a delay.
    ///
    /// Only delta-seconds are read. The HTTP-date form is legal and this
    /// service never sends it; a value that will not parse is treated as no
    /// delay rather than as no refusal.
    ///
    /// A 502 or 504 is the edge failing to reach a worker: the service is
    /// restarting, warming, or gone for the moment. That is the same thing to
    /// a wallet as capacity refused — stop, keep the pending work, try later
    /// — and the edge names no delay, so a short default stands in. A cold
    /// pilot's service was killed and restarted under load on 2026-09-08 and
    /// two syncs failed outright on the 502 rather than stopping short.
    pub fn from_http(status: u16, retry_after: Option<&str>) -> Option<Self> {
        match status {
            503 => {
                let retry_after = retry_after?;
                Some(Self {
                    retry_after: retry_after.trim().parse().ok().map(Duration::from_secs),
                })
            }
            502 | 504 => Some(Self {
                retry_after: Some(
                    retry_after
                        .and_then(|value| value.trim().parse().ok())
                        .map(Duration::from_secs)
                        .unwrap_or(Self::EDGE_RETRY_AFTER),
                ),
            }),
            _ => None,
        }
    }

    /// The delay assumed when the edge, not the service, refused.
    pub const EDGE_RETRY_AFTER: Duration = Duration::from_secs(5);

    pub fn found_in(error: &BoxError) -> Option<&Self> {
        found_in(error)
    }

    pub fn boxed(self) -> BoxError {
        Box::new(self)
    }
}

/// Classifies a non-success reply into a refusal a wallet can act on.
///
/// Takes the parts rather than a response type, so the wallet crate stays free
/// of any particular HTTP client — and so the argument list itself says what an
/// implementor has to read *before* discarding the reply. The body carries the
/// map digest and the header carries the delay; a helper like `reqwest`'s
/// `error_for_status` keeps neither.
///
/// `None` means this reply is not a refusal either kind of retry can help with,
/// and the caller should report it as it would any other failure.
pub fn refusal(
    status: u16,
    retry_after: Option<&str>,
    body: &[u8],
    shard_id: u64,
    revision: &str,
) -> Option<BoxError> {
    if let Some(stale) = StaleRevision::from_http(status, body, shard_id, revision) {
        return Some(stale.boxed());
    }
    Overloaded::from_http(status, retry_after).map(Overloaded::boxed)
}

/// The shared `source`-chain walk behind both `found_in` methods.
fn found_in<E: std::error::Error + 'static>(error: &BoxError) -> Option<&E> {
    if let Some(found) = error.downcast_ref::<E>() {
        return Some(found);
    }
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(found) = current.downcast_ref::<E>() {
            return Some(found);
        }
        source = current.source();
    }
    None
}

/// A failed transport attempt with response bytes the transport observed.
///
/// Wrap a refusal or another error after reading its response. The source is
/// retained so revision recovery and overload handling still recognize it.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct TransferFailure {
    /// Response bytes already read before the attempt failed.
    pub downloaded: u64,
    /// The original transport failure or typed refusal.
    #[source]
    pub source: BoxError,
}

impl TransferFailure {
    /// Retains observed response bytes and the original cause in a trait error.
    pub fn boxed(downloaded: u64, source: BoxError) -> BoxError {
        Box::new(Self { downloaded, source })
    }

    pub(crate) fn downloaded(error: &BoxError) -> u64 {
        found_in::<Self>(error).map_or(0, |failure| failure.downloaded)
    }
}

/// Bytes charged for one private table.
///
/// Every field here is per table because the tables have different geometry —
/// the directory is 2,048 rows and the pages 8,192 — so their queries do not
/// even cost the same number of bytes. Summing them first and dividing later
/// would attribute an average to both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableCharges {
    /// Published PIR setup, once per segment opened. A shard normally has one
    /// segment per table; one that did not fit the pinned geometry has more,
    /// and each publishes its own masks.
    pub setup_bytes: u64,
    /// Private query uploads.
    pub query_upload: u64,
    /// Private query responses.
    pub query_download: u64,
    pub queries: u64,
    /// Segments opened, which is also the number of setups fetched.
    pub segments_opened: u64,
}

impl TableCharges {
    pub fn total(&self) -> u64 {
        self.setup_bytes + self.query_upload + self.query_download
    }
}

/// Bytes charged, split by stage and, for the private stages, by table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ByteCharges {
    /// The shard map. Small, but a wallet cannot start without it.
    ///
    /// Counted once per fetch, so a sync that refreshed the map to recover a
    /// superseded revision shows more than one map here.
    pub map_bytes: u64,
    /// Public activity filters. Paid by every wallet whether or not it matches.
    pub filter_bytes: u64,
    /// Finding a script.
    pub directory: TableCharges,
    /// Reading the history the directory located.
    pub pages: TableCharges,
    /// Filters downloaded and matched.
    ///
    /// A shard re-derived under a later revision is counted again: its filter
    /// is republished with its content, so re-reading the shard means
    /// re-matching it, not just re-querying it.
    pub filters_checked: u64,
    /// Manifests fetched and verified, one per matched shard revision.
    pub manifest_bytes: u64,
    pub manifests_checked: u64,
}

impl ByteCharges {
    fn table_mut(&mut self, table: Table) -> &mut TableCharges {
        match table {
            Table::Directory => &mut self.directory,
            Table::Pages(_) => &mut self.pages,
        }
    }

    pub fn add_query(&mut self, table: Table, upload: u64, download: u64) {
        let charges = self.table_mut(table);
        charges.query_upload += upload;
        charges.query_download += download;
        charges.queries += 1;
    }

    /// Charges one dispatched query, even if its reply failed. Upload size is
    /// known locally; failed response bytes are counted when the transport
    /// retained them in [`TransferFailure`].
    pub(crate) fn add_query_reply(&mut self, table: Table, upload: u64, reply: &ShardReply) {
        let download = match reply {
            Ok((_, cost)) => *cost,
            Err(error) => TransferFailure::downloaded(error),
        };
        self.add_query(table, upload, download);
    }

    pub fn add_manifest(&mut self, cost: u64) {
        self.manifest_bytes += cost;
        self.manifests_checked += 1;
    }

    pub fn add_setup(&mut self, table: Table, cost: u64) {
        let charges = self.table_mut(table);
        charges.setup_bytes += cost;
        charges.segments_opened += 1;
    }

    pub fn setup_bytes(&self) -> u64 {
        self.directory.setup_bytes + self.pages.setup_bytes
    }

    pub fn query_upload(&self) -> u64 {
        self.directory.query_upload + self.pages.query_upload
    }

    pub fn query_download(&self) -> u64 {
        self.directory.query_download + self.pages.query_download
    }

    pub fn queries(&self) -> u64 {
        self.directory.queries + self.pages.queries
    }

    /// Setups fetched: one per segment of each table a sync opened.
    ///
    /// Named for the field the archived measurements report, so a new run stays
    /// comparable with them.
    pub fn shards_opened(&self) -> u64 {
        self.directory.segments_opened + self.pages.segments_opened
    }

    pub fn total(&self) -> u64 {
        self.map_bytes
            + self.filter_bytes
            + self.manifest_bytes
            + self.directory.total()
            + self.pages.total()
    }

    /// What a wallet pays before issuing a single private query.
    ///
    /// This is the floor the design has to beat on its own, before any of the
    /// retrieval it gates is counted.
    pub fn public_floor(&self) -> u64 {
        self.map_bytes + self.filter_bytes
    }
}

/// Source of public shard filters.
///
/// Separate from [`ShardTransport`] on purpose. Default filter requests depend
/// only on public intervals. The explicit parent experiment additionally leaks
/// coarse activity through selective child requests; it never sends scripts.
pub trait FilterSource {
    /// Avoid additional cache reads in the default traversal.
    fn uses_parents(&self) -> bool {
        false
    }
    /// The published shard map, as JSON, with the bytes it cost.
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError>;

    /// One shard's filter bytes, with what they cost.
    ///
    /// Keyed by shard id, but **not** stable under it: a growing tail is
    /// republished as a new revision over a longer range, with a new filter, at
    /// the same id. An implementation that memoises by id alone will hand back
    /// the superseded filter after a republication, which the sync catches as a
    /// digest mismatch against the map rather than acting on.
    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError>;

    /// Starts fetching the filters of `shard_ids` ahead of the walk that asks
    /// for them one at a time, where the source can overlap requests.
    ///
    /// Filters are public, and the wallet downloads every filter in its range
    /// anyway, so fetching them together discloses nothing further. The
    /// default does nothing. An implementation must hand each prefetched
    /// filter out at most once through [`filter`](Self::filter) and fetch
    /// afresh after that, so a republished tail's superseded filter cannot be
    /// served twice. It must also drop what an earlier prefetch left unused
    /// when the next one starts or the map is fetched: those filters were
    /// fetched for the map in hand then, and a re-cut gives their ids to other
    /// shards. The sync still checks every filter against the map.
    fn prefetch(&mut self, _shard_ids: &[u64]) {}

    /// Research-only parent discovery for uncached work. Default sources never
    /// skip child filters. Costs include manifest discovery even on fallback.
    fn prepare_parents(
        &mut self,
        _map: &transparent_filter::ShardMap,
        _uncached: &[u64],
        _store: &mut dyn crate::engine::WalletStore,
    ) -> Result<u64, BoxError> {
        Ok(0)
    }

    /// An explicitly enabled source may establish a negative from a validated
    /// parent covering this exact child revision. Implementations must check
    /// the current scripts on every call, including newly imported scripts.
    fn parent_negative(
        &mut self,
        _map: &transparent_filter::ShardMap,
        _shard_id: u64,
        _scripts: &[Vec<u8>],
        _store: &mut dyn crate::engine::WalletStore,
    ) -> Result<(bool, u64), BoxError> {
        Ok((false, 0))
    }
}

/// Source of private shard retrieval.
///
/// # Refusals an implementor should recognise
///
/// The service distinguishes two refusals a wallet can act on from failures it
/// can only report, and an implementor that can see a status code is expected
/// to surface them: [`StaleRevision`] for `409` and [`Overloaded`] for a `503`
/// carrying `retry-after`. Both have a `from_http` that does the recognition,
/// so this is one `if let` per method.
///
/// Skipping it is not a correctness hole — the refusal degrades into an
/// ordinary transport error and the sync fails where it would otherwise have
/// recovered. But it *is* a silent loss of revision recovery, so an implementor
/// that reads statuses and declines to map them should say why.
pub trait ShardTransport {
    /// The service's init document, as JSON, with the bytes it cost.
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError>;

    /// One shard revision's manifest, in canonical bytes, with its cost.
    ///
    /// The wallet recomputes the digest of what comes back and compares it
    /// with the map before using anything the manifest says, so a transport
    /// need not verify anything itself. Refusals are recognised as for setup.
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError>;

    /// One segment's published setup for one table, as JSON, with its cost.
    ///
    /// `revision` is the manifest digest the map named. Setup is derived from
    /// a segment's own bytes, so a republished tail has different setup under a
    /// different digest; addressing it by revision is what stops a wallet
    /// decoding new bytes against the parameters of the revision it cached.
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError>;

    /// Answers one private query, against every segment of the shard revision.
    ///
    /// The body is opaque and fixed length, and names a row within a segment
    /// rather than a segment: the answer carries one body per segment, in
    /// segment order. Every call counts as one query attempt and charges its
    /// upload before handling a failure. When an error follows response bytes,
    /// wrap it in [`TransferFailure`] so those bytes are charged too; keep any
    /// typed refusal as its source so retries still recognize it.
    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError>;

    /// Requests this transport keeps in flight when handed a [`batch`].
    ///
    /// One, the default, means the sync issues every request itself, one at a
    /// time, in the order of the sequential walk. That walk is the reference:
    /// a larger value changes when requests are sent, never which.
    ///
    /// [`batch`]: Self::batch
    fn concurrency(&self) -> usize {
        1
    }

    /// Issues independent requests, overlapping them where the transport can.
    ///
    /// Returns one entry per request, in request order: `Some` with the reply
    /// of a request that was sent, `None` for one that was not. An
    /// implementation should stop sending after the first failure, so a
    /// refusing or unreachable service does not receive a burst. The sync
    /// uses each reply exactly where the sequential walk would have made that
    /// request, refusals and failures included, so refusals must be
    /// recognised as for the single methods; it makes any unsent request
    /// itself, in its ordinary place. A query's cost is its response length.
    ///
    /// The default sends them one at a time through the methods above.
    fn batch(&mut self, requests: &[ShardRequest<'_>]) -> Vec<Option<ShardReply>> {
        let mut replies = Vec::with_capacity(requests.len());
        let mut failed = false;
        for request in requests {
            if failed {
                replies.push(None);
                continue;
            }
            let reply = match *request {
                ShardRequest::Manifest { shard_id, revision } => self.manifest(shard_id, revision),
                ShardRequest::Setup {
                    shard_id,
                    revision,
                    table,
                    segment,
                } => self.setup(shard_id, revision, table, segment),
                ShardRequest::Query {
                    shard_id,
                    revision,
                    table,
                    body,
                } => self.query(shard_id, revision, table, body).map(|bytes| {
                    let len = bytes.len() as u64;
                    (bytes, len)
                }),
            };
            failed = reply.is_err();
            replies.push(Some(reply));
        }
        replies
    }
}

/// One request a sync may hand a transport to overlap with others.
///
/// The same requests the sequential walk makes through [`ShardTransport`]'s
/// methods, with the same arguments; a batch changes when they are sent.
#[derive(Clone, Copy, Debug)]
pub enum ShardRequest<'a> {
    Manifest {
        shard_id: u64,
        revision: &'a str,
    },
    Setup {
        shard_id: u64,
        revision: &'a str,
        table: Table,
        segment: u32,
    },
    Query {
        shard_id: u64,
        revision: &'a str,
        table: Table,
        body: &'a [u8],
    },
}

impl ShardRequest<'_> {
    /// The stage name the measurement tools report this request under.
    pub fn stage(&self) -> &'static str {
        match self {
            ShardRequest::Manifest { .. } => "manifest",
            ShardRequest::Setup {
                table: Table::Directory,
                ..
            } => "setup_directory",
            ShardRequest::Setup {
                table: Table::Pages(_),
                ..
            } => "setup_pages",
            ShardRequest::Query {
                table: Table::Directory,
                ..
            } => "query_directory",
            ShardRequest::Query {
                table: Table::Pages(_),
                ..
            } => "query_pages",
        }
    }

    /// The service route this request addresses.
    pub fn route(&self) -> String {
        match *self {
            ShardRequest::Manifest { shard_id, revision } => {
                format!("/v2/shards/{shard_id}/revisions/{revision}/manifest")
            }
            ShardRequest::Setup {
                shard_id,
                revision,
                table,
                segment,
            } => format!(
                "/v2/shards/{shard_id}/revisions/{revision}/setup/{}/{segment}",
                table.name()
            ),
            ShardRequest::Query {
                shard_id,
                revision,
                table,
                ..
            } => format!(
                "/v2/shards/{shard_id}/revisions/{revision}/query/{}",
                table.name()
            ),
        }
    }

    /// Bytes this request uploads.
    pub fn upload(&self) -> u64 {
        match self {
            ShardRequest::Query { body, .. } => body.len() as u64,
            _ => 0,
        }
    }
}

/// A reply to one [`ShardRequest`]: the bytes and what they cost.
pub type ShardReply = Result<(Vec<u8>, u64), BoxError>;

impl<T: FilterSource + ?Sized> FilterSource for Box<T> {
    fn uses_parents(&self) -> bool {
        (**self).uses_parents()
    }
    fn prepare_parents(
        &mut self,
        map: &transparent_filter::ShardMap,
        uncached: &[u64],
        store: &mut dyn crate::engine::WalletStore,
    ) -> Result<u64, BoxError> {
        (**self).prepare_parents(map, uncached, store)
    }
    fn parent_negative(
        &mut self,
        map: &transparent_filter::ShardMap,
        id: u64,
        scripts: &[Vec<u8>],
        store: &mut dyn crate::engine::WalletStore,
    ) -> Result<(bool, u64), BoxError> {
        (**self).parent_negative(map, id, scripts, store)
    }

    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        (**self).shard_map()
    }
    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        (**self).filter(shard_id)
    }
    fn prefetch(&mut self, shard_ids: &[u64]) {
        (**self).prefetch(shard_ids)
    }
}

impl<T: ShardTransport + ?Sized> ShardTransport for Box<T> {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        (**self).init()
    }
    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        (**self).manifest(shard_id, revision)
    }
    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        (**self).setup(shard_id, revision, table, segment)
    }
    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        (**self).query(shard_id, revision, table, body)
    }
    fn concurrency(&self) -> usize {
        (**self).concurrency()
    }
    fn batch(&mut self, requests: &[ShardRequest<'_>]) -> Vec<Option<ShardReply>> {
        (**self).batch(requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "aa";

    #[test]
    fn a_stale_refusal_carries_the_map_digest_the_service_reported() {
        let body = br#"{"error":"gone","retry":"refresh","map_sha256":"beef"}"#;
        let stale = StaleRevision::from_http(409, body, 7, DIGEST).expect("a 409 is a refusal");
        assert_eq!(stale.shard_id, 7);
        assert_eq!(stale.revision, DIGEST);
        assert_eq!(stale.map_sha256.as_deref(), Some("beef"));
    }

    /// The status is the fact and the digest is an optimisation, so a body that
    /// will not parse must not turn a refusal into an unrecognised failure.
    #[test]
    fn a_stale_refusal_survives_a_body_it_cannot_parse() {
        let stale = StaleRevision::from_http(409, b"not json", 7, DIGEST).expect("still a refusal");
        assert_eq!(stale.map_sha256, None);
    }

    #[test]
    fn only_a_conflict_is_a_stale_refusal() {
        for status in [200u16, 400, 404, 500, 503] {
            assert!(StaleRevision::from_http(status, b"{}", 7, DIGEST).is_none());
        }
    }

    /// 503 is also how the service reports that it is not ready and that it
    /// holds no shards. Neither is fixed by waiting, and only the capacity
    /// refusal names a delay — so the header, not the status, is the signal.
    #[test]
    fn an_overload_is_recognised_by_its_delay_not_its_status() {
        let overloaded = Overloaded::from_http(503, Some("1")).expect("a delay means capacity");
        assert_eq!(overloaded.retry_after, Some(Duration::from_secs(1)));
        assert!(
            Overloaded::from_http(503, None).is_none(),
            "a 503 without a delay is not retryable"
        );
        assert!(Overloaded::from_http(429, Some("1")).is_none());
        // The edge failing to reach a worker is a refusal with an assumed delay.
        let edge = Overloaded::from_http(502, None).expect("a 502 is retryable");
        assert_eq!(edge.retry_after, Some(Overloaded::EDGE_RETRY_AFTER));
        assert_eq!(
            Overloaded::from_http(504, Some("2"))
                .expect("a 504 is retryable")
                .retry_after,
            Some(Duration::from_secs(2))
        );
        assert!(Overloaded::from_http(500, None).is_none());
    }

    /// A delay in the HTTP-date form is legal and this service never sends it.
    /// Reading it as "no delay" keeps the refusal; reading it as "no refusal"
    /// would lose the retry entirely.
    #[test]
    fn an_unparsable_delay_is_still_an_overload() {
        let overloaded =
            Overloaded::from_http(503, Some("Wed, 21 Oct 2015 07:28:00 GMT")).expect("a refusal");
        assert_eq!(overloaded.retry_after, None);
    }

    #[derive(Debug, thiserror::Error)]
    #[error("wrapped")]
    struct Wrapper(#[source] BoxError);

    /// An implementor that wraps the refusal in an error of its own must not be
    /// silently missed: that looks exactly like a service that never refused.
    #[test]
    fn a_refusal_is_found_through_a_wrapping_error() {
        let inner = StaleRevision {
            shard_id: 3,
            revision: DIGEST.into(),
            map_sha256: None,
        }
        .boxed();
        let wrapped: BoxError = Box::new(Wrapper(inner));
        assert_eq!(
            StaleRevision::found_in(&wrapped).map(|stale| stale.shard_id),
            Some(3)
        );
        assert!(Overloaded::found_in(&wrapped).is_none());
    }

    #[test]
    fn an_ordinary_failure_is_neither_refusal() {
        let error: BoxError = "connection reset".into();
        assert!(StaleRevision::found_in(&error).is_none());
        assert!(Overloaded::found_in(&error).is_none());
    }

    #[test]
    fn refusal_dispatches_on_what_the_reply_says() {
        let stale = refusal(409, None, br#"{"map_sha256":"beef"}"#, 1, DIGEST).expect("stale");
        assert!(StaleRevision::found_in(&stale).is_some());
        let overloaded = refusal(503, Some("2"), b"{}", 1, DIGEST).expect("overloaded");
        assert!(Overloaded::found_in(&overloaded).is_some());
        assert!(refusal(500, None, b"{}", 1, DIGEST).is_none());
    }
}
