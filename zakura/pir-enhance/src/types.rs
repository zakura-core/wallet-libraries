use ipir_sp::YpirSchemeParams;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 5;
pub const PROTOCOL_REVISION: &str = "ironwood-enhance-pir-v1";
pub const NETWORK: &str = "main";
pub const POOL: &str = "ironwood";
pub const ACTIVATION_HEIGHT: u64 = 3_428_143;
pub const CONFIRMATIONS: u64 = 10;

pub const RECORD_BYTES: usize = 724;
pub const RECORDS_PER_ROW: usize = 9;
pub const ROW_BYTES: usize = RECORD_BYTES * RECORDS_PER_ROW;
pub const SHARD_ROWS: usize = 8_192;
pub const SHARD_POSITIONS: usize = SHARD_ROWS * RECORDS_PER_ROW;
/// Shards assigned to one logical worker group. Every replica in the group
/// holds the complete assignment; replicas are alternatives, not additive
/// contributors to a query.
pub const SHARDS_PER_GROUP: u64 = 6;
/// Backwards-compatible alias for callers compiled against the former
/// single-owner placement terminology.
pub const SHARDS_PER_WORKER: u64 = SHARDS_PER_GROUP;
pub const ITEM_SIZE_BITS: u64 = (ROW_BYTES * 8) as u64;

pub const RECORD_EPHEMERAL_KEY_OFFSET: usize = 0;
pub const RECORD_ENC_CIPHERTEXT_OFFSET: usize = 32;
pub const RECORD_CV_NET_OFFSET: usize = 612;
pub const RECORD_OUT_CIPHERTEXT_OFFSET: usize = 644;

/// Pinned deterministic setup seed for the Enhance PIR protocol.
pub const ENHANCE_SETUP_SEED: u64 = 0x7dc0_c1be_a8ed_2c29;

pub fn setup_seed_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&ENHANCE_SETUP_SEED.to_le_bytes());
    bytes
}

/// The private fields needed to enhance one compact Ironwood action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhanceRecord(pub [u8; RECORD_BYTES]);

pub struct EnhanceRecordParts {
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub cv_net: [u8; 32],
    pub out_ciphertext: [u8; 80],
}

impl EnhanceRecord {
    pub fn from_parts(parts: EnhanceRecordParts) -> Self {
        let mut bytes = [0; RECORD_BYTES];
        bytes[RECORD_EPHEMERAL_KEY_OFFSET..RECORD_ENC_CIPHERTEXT_OFFSET]
            .copy_from_slice(&parts.ephemeral_key);
        bytes[RECORD_ENC_CIPHERTEXT_OFFSET..RECORD_CV_NET_OFFSET]
            .copy_from_slice(&parts.enc_ciphertext);
        bytes[RECORD_CV_NET_OFFSET..RECORD_OUT_CIPHERTEXT_OFFSET].copy_from_slice(&parts.cv_net);
        bytes[RECORD_OUT_CIPHERTEXT_OFFSET..].copy_from_slice(&parts.out_ciphertext);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RECORD_BYTES] {
        &self.0
    }

    pub fn ephemeral_key(&self) -> &[u8; 32] {
        self.0[RECORD_EPHEMERAL_KEY_OFFSET..RECORD_ENC_CIPHERTEXT_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn enc_ciphertext(&self) -> &[u8; 580] {
        self.0[RECORD_ENC_CIPHERTEXT_OFFSET..RECORD_CV_NET_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn cv_net(&self) -> &[u8; 32] {
        self.0[RECORD_CV_NET_OFFSET..RECORD_OUT_CIPHERTEXT_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn out_ciphertext(&self) -> &[u8; 80] {
        self.0[RECORD_OUT_CIPHERTEXT_OFFSET..]
            .try_into()
            .expect("fixed slice")
    }
}

impl AsRef<[u8]> for EnhanceRecord {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardDescriptor {
    pub shard_id: u64,
    pub global_row_start: u64,
    pub populated_positions: u64,
    pub rows_sha256: String,
    pub sealed: bool,
    pub worker: String,
}

/// The complete public description of one answerable Enhance PIR generation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnhanceGeneration {
    pub schema_version: u16,
    pub protocol_revision: String,
    pub network: String,
    pub pool: String,
    pub anchor_height: u64,
    pub anchor_block_hash: String,
    pub ironwood_tree_size: u64,
    pub generation: u64,
    pub record_bytes: u32,
    pub records_per_row: u32,
    pub row_bytes: u32,
    pub shard_rows: u32,
    pub used_rows: u64,
    pub logical_rows: u64,
    pub parameter_id: String,
    pub setup_seed: u64,
    pub public_params_epoch: String,
    pub public_params_sha256: String,
    pub shards: Vec<ShardDescriptor>,
}

/// An atomic description of one answerable Enhance PIR generation.
///
/// The published parameters are base64-encoded so all material needed to
/// construct a query session is captured by one JSON response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EnhanceSession {
    pub generation: EnhanceGeneration,
    pub params: YpirSchemeParams,
    pub public_params_base64: String,
}

impl EnhanceGeneration {
    pub fn row_for_position(&self, position: u64) -> Option<(usize, usize)> {
        if position >= self.ironwood_tree_size {
            return None;
        }
        let row = position / RECORDS_PER_ROW as u64;
        (row < self.logical_rows).then_some((row as usize, position as usize % RECORDS_PER_ROW))
    }
}

pub const fn used_rows_for(positions: u64) -> u64 {
    positions.div_ceil(RECORDS_PER_ROW as u64)
}

pub fn logical_rows_for(used_rows: u64) -> u64 {
    used_rows.max(SHARD_ROWS as u64).next_power_of_two()
}

pub fn group_index_for_shard(shard_id: u64, group_count: usize) -> Option<usize> {
    if group_count == 0 {
        return None;
    }
    if group_count == 1 {
        return Some(0);
    }
    let index = usize::try_from(shard_id / SHARDS_PER_GROUP).ok()?;
    (index < group_count).then_some(index)
}

/// Backwards-compatible alias for the former single-owner placement helper.
pub fn worker_index_for_shard(shard_id: u64, worker_count: usize) -> Option<usize> {
    group_index_for_shard(shard_id, worker_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_layout_contains_only_enhancement_fields() {
        let record = EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key: [1; 32],
            enc_ciphertext: [2; 580],
            cv_net: [3; 32],
            out_ciphertext: [4; 80],
        });
        assert_eq!(RECORD_BYTES, 724);
        assert_eq!(ROW_BYTES, 6_516);
        assert_eq!(record.ephemeral_key(), &[1; 32]);
        assert_eq!(record.enc_ciphertext(), &[2; 580]);
        assert_eq!(record.cv_net(), &[3; 32]);
        assert_eq!(record.out_ciphertext(), &[4; 80]);
    }

    #[test]
    fn geometry_is_fixed_and_aligned() {
        assert_eq!(SHARD_POSITIONS, 73_728);
        assert_eq!(SHARD_ROWS % 2_048, 0);
        assert_eq!(used_rows_for(9), 1);
        assert_eq!(used_rows_for(10), 2);
        assert_eq!(logical_rows_for(0), 8_192);
    }
}
