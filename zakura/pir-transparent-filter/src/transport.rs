//! Fetching filter ranges, and what a request is allowed to contain.
//!
//! A range request carries chain identity, profile and a block range. It never
//! carries addresses, scripts, matches, outpoints, or any partition choice
//! derived from them. The range itself does reveal which interval the wallet is
//! synchronizing and when; this profile does not hide that timing and coverage
//! information, and says so rather than implying otherwise.

use crate::envelope::{FilterBatch, RangeFilterBatch};
use crate::error::FilterError;
use crate::hash::BlockHash;

/// A public request for a contiguous run of filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRequest {
    /// Chain identity: genesis block hash.
    pub genesis: BlockHash,
    pub profile: String,
    /// First height wanted, inclusive.
    pub start_height: u64,
    /// The already-accepted block the overall range ends at.
    pub stop_block_hash: BlockHash,
}

/// What a transport actually spent to answer a request.
///
/// Delivered bytes are counted as delivered, including envelope and metadata
/// overhead and including bytes paid for on an attempt that later failed. A
/// measurement that counts only filter payloads understates what a wallet pays.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ByteCharges {
    /// Serialized bytes received, including envelope framing.
    pub received: u64,
    /// Bytes sent, including request framing.
    pub sent: u64,
    /// Requests issued, including retries.
    pub requests: u64,
}

impl ByteCharges {
    pub fn add(&mut self, other: ByteCharges) {
        self.received += other.received;
        self.sent += other.sent;
        self.requests += other.requests;
    }

    pub fn total(&self) -> u64 {
        self.received + self.sent
    }
}

/// Source of filter ranges.
pub trait FilterTransport {
    /// Fetches one bounded batch beginning at `request.start_height`.
    ///
    /// Returns the decoded batch and the bytes actually charged for it. An
    /// implementation must charge for what it transferred even when it then
    /// returns an error.
    fn fetch_range(
        &mut self,
        request: &RangeRequest,
    ) -> Result<(FilterBatch, ByteCharges), FilterError>;
}

/// A public request for a contiguous run of shard filters.
///
/// Like [`RangeRequest`], it carries chain identity, profile and a position —
/// here a shard index rather than a height. It cannot express a script, a
/// match, or any choice derived from one. What it does reveal is which span of
/// shards the wallet is synchronizing and when, and a wallet that asked only
/// for the shards it cared about would reveal considerably more than that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRangeRequest {
    /// Chain identity: genesis block hash.
    pub genesis: BlockHash,
    /// The range profile, not the per-block one.
    pub profile: String,
    /// First shard wanted, inclusive.
    pub start_shard: u64,
    /// How many shards to return, capped by the transport's batch limit.
    pub count: u64,
}

/// Source of shard filter ranges.
///
/// Separate from [`FilterTransport`] rather than an added method on it: the two
/// serve different profiles over different envelopes, and a transport that can
/// deliver one need not be able to deliver the other.
pub trait ShardFilterTransport {
    /// Fetches one bounded batch beginning at `request.start_shard`.
    ///
    /// Returns the decoded batch and the bytes actually charged for it. As with
    /// [`FilterTransport`], an implementation must charge for what it
    /// transferred even when it then returns an error.
    fn fetch_shards(
        &mut self,
        request: &ShardRangeRequest,
    ) -> Result<(RangeFilterBatch, ByteCharges), FilterError>;
}

/// Reads batches from a directory of pre-serialized envelopes.
///
/// Used for tests and offline replay. It is a local file reader and is not
/// evidence about any network protocol's behaviour or privacy.
pub struct FileTransport {
    directory: std::path::PathBuf,
}

impl FileTransport {
    pub fn new(directory: impl Into<std::path::PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// File name for the batch beginning at `start_height`.
    pub fn batch_path(&self, start_height: u64) -> std::path::PathBuf {
        self.directory.join(format!("batch-{start_height}.bin"))
    }
}

impl FilterTransport for FileTransport {
    fn fetch_range(
        &mut self,
        request: &RangeRequest,
    ) -> Result<(FilterBatch, ByteCharges), FilterError> {
        let path = self.batch_path(request.start_height);
        let bytes = std::fs::read(&path)
            .map_err(|error| FilterError::Response(format!("{}: {error}", path.display())))?;
        let charges = ByteCharges {
            received: bytes.len() as u64,
            sent: 0,
            requests: 1,
        };
        // Charge for the bytes even if decoding then fails.
        let batch = FilterBatch::decode(&bytes)?;
        Ok((batch, charges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{FilterRecord, ENVELOPE_VERSION};
    use crate::profile::PROFILE;

    #[test]
    fn charges_accumulate_across_requests() {
        let mut charges = ByteCharges::default();
        charges.add(ByteCharges {
            received: 10,
            sent: 3,
            requests: 1,
        });
        charges.add(ByteCharges {
            received: 5,
            sent: 2,
            requests: 1,
        });
        assert_eq!(charges.received, 15);
        assert_eq!(charges.requests, 2);
        assert_eq!(charges.total(), 20);
    }

    #[test]
    fn the_file_transport_reads_and_charges_a_batch() {
        let dir = std::env::temp_dir().join(format!("tf-transport-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let batch = FilterBatch {
            version: ENVELOPE_VERSION,
            genesis: BlockHash::from_internal_bytes([1; 32]),
            profile: PROFILE.to_string(),
            start_height: 100,
            stop_block_hash: BlockHash::from_internal_bytes([2; 32]),
            records: vec![FilterRecord {
                height: 100,
                block_hash: BlockHash::from_internal_bytes([3; 32]),
                filter: vec![0x00],
            }],
        };
        let bytes = batch.encode();
        let mut transport = FileTransport::new(&dir);
        std::fs::write(transport.batch_path(100), &bytes).unwrap();
        let request = RangeRequest {
            genesis: BlockHash::from_internal_bytes([1; 32]),
            profile: PROFILE.to_string(),
            start_height: 100,
            stop_block_hash: BlockHash::from_internal_bytes([2; 32]),
        };
        let (decoded, charges) = transport.fetch_range(&request).unwrap();
        assert_eq!(decoded, batch);
        assert_eq!(charges.received, bytes.len() as u64);
        assert_eq!(charges.requests, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_batch_is_a_response_error() {
        let mut transport = FileTransport::new("/nonexistent-transparent-filter-dir");
        let request = RangeRequest {
            genesis: BlockHash::from_internal_bytes([1; 32]),
            profile: PROFILE.to_string(),
            start_height: 1,
            stop_block_hash: BlockHash::from_internal_bytes([2; 32]),
        };
        assert!(matches!(
            transport.fetch_range(&request),
            Err(FilterError::Response(_))
        ));
    }
}
