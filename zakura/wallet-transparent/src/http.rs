//! Blocking HTTP against the two services.
//!
//! Blocking because the work either side of a request is: `transparent_wallet`
//! is synchronous, and the PIR client is CPU-bound rather than IO-bound, so
//! there is nothing for an async runtime to interleave. The engine runs the
//! whole thing on a blocking task.
//!
//! # The routes
//!
//! Both halves are served, and by two different hosts, which is the property
//! the traits exist to preserve.
//!
//! The private routes are `transparent-shard-server`'s own:
//! `GET /v1/shards/init`, `GET /v1/shards/{id}/setup/{table}/{segment}` and
//! `POST /v1/shards/{id}/query/{table}`.
//!
//! The public routes sit under the filter host's `/v1/filters/` prefix. The
//! same service also publishes *per-block* filters under `/v1/filters/range`,
//! which are a different profile and not what a shard set is matched against; a
//! shard set needs the map and one filter per shard:
//!
//! - `GET /v1/filters/shards` — the [`ShardMap`](transparent_filter::ShardMap)
//!   as JSON. Already the documented shape of that route upstream.
//! - `GET /v1/filters/shards/{id}/filter` — that shard's raw filter bytes,
//!   the same bytes the map's `filter_hash` commits to.
//!
//! A wallet asks for every shard from its birthday forward whether or not it
//! will match, so which filters are requested is not a function of its scripts.
//! Asking shard by shard rather than in one batch costs round trips and reveals
//! no more: the span is the same either way.

use transparent_wallet::client::Table;
use transparent_wallet::transport::{BoxError, FilterSource, ShardTransport};

/// How long a single request may take.
///
/// Generous, because a private query is evaluated over a whole table and a
/// mobile connection is not fast. A wallet that timed out mid-run advances no
/// coverage and pays for the whole run again.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn client() -> Result<reqwest::blocking::Client, BoxError> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()?)
}

/// The public half: the shard map and the activity filters.
pub struct HttpFilters {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpFilters {
    /// Connects to the filter service at `base_url`.
    pub fn new(base_url: &str) -> Result<Self, BoxError> {
        Ok(Self {
            base: base_url.trim_end_matches('/').to_owned(),
            client: client()?,
        })
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, BoxError> {
        let url = format!("{}{path}", self.base);
        let bytes = self
            .client
            .get(&url)
            .send()
            .map_err(|e| format!("{url}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("{url}: {e}"))?
            .bytes()
            .map_err(|e| format!("{url}: {e}"))?;
        Ok(bytes.to_vec())
    }
}

impl FilterSource for HttpFilters {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self.get("/v1/filters/shards")?;
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self.get(&format!("/v1/filters/shards/{shard_id}/filter"))?;
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }
}

/// The private half: setup and queries against the shard tables.
pub struct HttpShards {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpShards {
    /// Connects to the shard service at `base_url`.
    pub fn new(base_url: &str) -> Result<Self, BoxError> {
        Ok(Self {
            base: base_url.trim_end_matches('/').to_owned(),
            client: client()?,
        })
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, BoxError> {
        let url = format!("{}{path}", self.base);
        let bytes = self
            .client
            .get(&url)
            .send()
            .map_err(|e| format!("{url}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("{url}: {e}"))?
            .bytes()
            .map_err(|e| format!("{url}: {e}"))?;
        Ok(bytes.to_vec())
    }
}

impl ShardTransport for HttpShards {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self.get("/v1/shards/init")?;
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }

    fn setup(
        &mut self,
        shard_id: u64,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        let bytes = self.get(&format!(
            "/v1/shards/{shard_id}/setup/{}/{segment}",
            table.as_str()
        ))?;
        let len = bytes.len() as u64;
        Ok((bytes, len))
    }

    fn query(&mut self, shard_id: u64, table: Table, body: &[u8]) -> Result<Vec<u8>, BoxError> {
        let url = format!("{}/v1/shards/{shard_id}/query/{}", self.base, table.as_str());
        let bytes = self
            .client
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(body.to_vec())
            .send()
            .map_err(|e| format!("{url}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("{url}: {e}"))?
            .bytes()
            .map_err(|e| format!("{url}: {e}"))?;
        Ok(bytes.to_vec())
    }
}
