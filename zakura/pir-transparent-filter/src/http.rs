//! HTTP transport and the service's JSON metadata shapes.
//!
//! The request carries chain identity, profile and a height range, and nothing
//! else. There is no field in which a script, address, outpoint or match could
//! travel, by construction rather than by convention.

use crate::envelope::FilterBatch;
use crate::error::FilterError;
use crate::transport::{ByteCharges, FilterTransport, RangeRequest};
use crate::wire::{ChainEntry, FilterServiceHealth, FilterServiceInfo};

/// Fetches ranges over HTTP.
pub struct HttpTransport {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, FilterError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|error| FilterError::Response(error.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, FilterError> {
        let url = format!("{}{path}", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|error| FilterError::Response(format!("{url}: {error}")))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .map_err(|error| FilterError::Response(format!("{url}: {error}")))?;
        if !status.is_success() {
            return Err(FilterError::Response(format!(
                "{url}: HTTP {status}: {}",
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        Ok(bytes.to_vec())
    }

    pub fn info(&self) -> Result<FilterServiceInfo, FilterError> {
        let bytes = self.get("/v1/filters/info")?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FilterError::Response(format!("info: {error}")))
    }

    pub fn health(&self) -> Result<FilterServiceHealth, FilterError> {
        let bytes = self.get("/v1/health")?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FilterError::Response(format!("health: {error}")))
    }

    /// Height-to-hash for a range.
    ///
    /// A real wallet has its own accepted chain and must not take this from the
    /// same service that supplies the filters. It exists so the reference
    /// client can be exercised end to end against a live service.
    pub fn chain(&self, start_height: u64, count: u64) -> Result<Vec<ChainEntry>, FilterError> {
        let bytes = self.get(&format!(
            "/v1/filters/chain?start_height={start_height}&count={count}"
        ))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FilterError::Response(format!("chain: {error}")))
    }
}

impl FilterTransport for HttpTransport {
    fn fetch_range(
        &mut self,
        request: &RangeRequest,
    ) -> Result<(FilterBatch, ByteCharges), FilterError> {
        let path = format!(
            "/v1/filters/range?start_height={}&stop_block_hash={}",
            request.start_height,
            request.stop_block_hash.to_display_hex()
        );
        let url_bytes = (self.base_url.len() + path.len()) as u64;
        let bytes = self.get(&path)?;
        let charges = ByteCharges {
            received: bytes.len() as u64,
            sent: url_bytes,
            requests: 1,
        };
        let batch = FilterBatch::decode(&bytes)?;
        Ok((batch, charges))
    }
}
