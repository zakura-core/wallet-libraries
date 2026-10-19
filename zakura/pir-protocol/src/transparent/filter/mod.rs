//! BIP 158 transparent activity filters for Zcash.
//!
//! This crate implements the `zcash-transparent-basic-v1` application profile:
//! one deterministic filter per accepted block, covering the transparent
//! scripts a block creates and spends, so a wallet can test its own scripts
//! locally without revealing them.
//!
//! What it does not do: it does not prove a filter is complete. Matching a
//! filter against the wallet's accepted block hash binds where the filter
//! claims to be, not what it claims to contain. Advancing coverage on a
//! negative result is only sound if the filter's author is trusted to have
//! built it over the whole block.

pub mod digest;
pub mod envelope;
pub mod error;
pub mod experimental_parent;
pub mod gcs;
pub mod hash;
pub mod profile;
pub mod script;
pub mod validate;
pub mod wire;

pub use digest::{FilterHash, FilterHeader, GENESIS_PREDECESSOR, filter_hash, filter_header};
pub use envelope::{
    ENVELOPE_VERSION, FilterBatch, FilterRecord, MAX_RANGE_RECORDS_PER_BATCH,
    MAX_RECORDS_PER_BATCH, RANGE_ENVELOPE_VERSION, RangeFilterBatch, RangeFilterRecord,
};
pub use error::FilterError;
pub use hash::{BlockHash, FilterKeys, ShardKey};
pub use profile::{
    MAINNET_GENESIS_DISPLAY, NETWORK, PROFILE, RANGE_PROFILE, RANGE_PROFILE_V1, RANGE_PROFILE_V2,
    RANGE_PROFILES, RangeProfile, START_HEIGHT, range_profile,
};
pub use script::ScriptBytes;
pub use validate::{FilterLimits, ValidatedFilter, validate_filter, validate_range_filter};
pub use wire::{
    ChainEntry, FilterDigestEntry, FilterServiceHealth, FilterServiceInfo, Recut, SealParameters,
    ShardMap, ShardMapEntry, SupersededShard,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterBytes(pub Vec<u8>);

impl FilterBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for FilterBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "filter-matching")]
pub mod matching;

#[cfg(feature = "filter-matching")]
pub use matching::*;
