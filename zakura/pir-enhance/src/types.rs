use ipir_sp::YpirSchemeParams;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 6;
pub const PROTOCOL_REVISION: &str = "ironwood-enhance-pir-v1";
pub const POOL: &str = "ironwood";

pub const RECORD_BYTES: usize = 725;
pub const RECORDS_PER_ROW: usize = 9;
pub const ROW_BYTES: usize = RECORD_BYTES * RECORDS_PER_ROW;
pub const SHARD_ROWS: usize = 8_192;
pub const SHARD_POSITIONS: usize = SHARD_ROWS * RECORDS_PER_ROW;
/// Shards assigned to one logical worker group. Every replica in the group
/// holds the complete assignment; replicas are alternatives, not additive
/// contributors to a query.
pub const SHARDS_PER_GROUP: u64 = 6;
pub const ITEM_SIZE_BITS: u64 = (ROW_BYTES * 8) as u64;

pub const RECORD_EPHEMERAL_KEY_OFFSET: usize = 0;
pub const RECORD_ENC_CIPHERTEXT_OFFSET: usize = 32;
pub const RECORD_CV_NET_OFFSET: usize = 612;
pub const RECORD_OUT_CIPHERTEXT_OFFSET: usize = 644;
pub const RECORD_FLAGS_OFFSET: usize = 724;
pub const FLAG_HAS_TRANSPARENT_INPUTS: u8 = 1 << 0;
pub const FLAG_HAS_TRANSPARENT_OUTPUTS: u8 = 1 << 1;
pub const KNOWN_FLAGS: u8 = FLAG_HAS_TRANSPARENT_INPUTS | FLAG_HAS_TRANSPARENT_OUTPUTS;

/// Pinned deterministic setup seed for the Enhance PIR protocol.
pub const ENHANCE_SETUP_SEED: u64 = 0x7dc0_c1be_a8ed_2c29;

pub fn setup_seed_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&ENHANCE_SETUP_SEED.to_le_bytes());
    bytes
}

/// The private fields needed to enhance one compact Ironwood action.
///
/// The bytes are private so that a record can only be built from a decoded PIR row or from a
/// complete set of parts; the wallet authenticates a record by decrypting it, and an arbitrary
/// byte string is not something any caller should be able to present as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhanceRecord([u8; RECORD_BYTES]);

pub struct EnhanceRecordParts {
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub cv_net: [u8; 32],
    pub out_ciphertext: [u8; 80],
    pub has_transparent_inputs: bool,
    pub has_transparent_outputs: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidEnhanceRecordFlags(pub u8);

impl std::fmt::Display for InvalidEnhanceRecordFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "reserved Enhance flag bits are set: 0x{:02x}",
            self.0
        )
    }
}

impl std::error::Error for InvalidEnhanceRecordFlags {}

impl EnhanceRecord {
    /// Wraps the bytes of one record extracted from a decoded PIR row.
    pub(crate) fn from_row_bytes(bytes: [u8; RECORD_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_parts(parts: EnhanceRecordParts) -> Self {
        let mut bytes = [0; RECORD_BYTES];
        bytes[RECORD_EPHEMERAL_KEY_OFFSET..RECORD_ENC_CIPHERTEXT_OFFSET]
            .copy_from_slice(&parts.ephemeral_key);
        bytes[RECORD_ENC_CIPHERTEXT_OFFSET..RECORD_CV_NET_OFFSET]
            .copy_from_slice(&parts.enc_ciphertext);
        bytes[RECORD_CV_NET_OFFSET..RECORD_OUT_CIPHERTEXT_OFFSET].copy_from_slice(&parts.cv_net);
        bytes[RECORD_OUT_CIPHERTEXT_OFFSET..RECORD_FLAGS_OFFSET]
            .copy_from_slice(&parts.out_ciphertext);
        bytes[RECORD_FLAGS_OFFSET] = (u8::from(parts.has_transparent_inputs)
            * FLAG_HAS_TRANSPARENT_INPUTS)
            | (u8::from(parts.has_transparent_outputs) * FLAG_HAS_TRANSPARENT_OUTPUTS);
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
        self.0[RECORD_OUT_CIPHERTEXT_OFFSET..RECORD_FLAGS_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn transparent_flags(&self) -> Result<u8, InvalidEnhanceRecordFlags> {
        let flags = self.0[RECORD_FLAGS_OFFSET];
        if flags & !KNOWN_FLAGS == 0 {
            Ok(flags)
        } else {
            Err(InvalidEnhanceRecordFlags(flags))
        }
    }

    pub fn has_transparent_inputs(&self) -> Result<bool, InvalidEnhanceRecordFlags> {
        self.transparent_flags()
            .map(|flags| flags & FLAG_HAS_TRANSPARENT_INPUTS != 0)
    }

    pub fn has_transparent_outputs(&self) -> Result<bool, InvalidEnhanceRecordFlags> {
        self.transparent_flags()
            .map(|flags| flags & FLAG_HAS_TRANSPARENT_OUTPUTS != 0)
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
        if row >= self.logical_rows {
            return None;
        }
        Some((
            usize::try_from(row).ok()?,
            usize::try_from(position % RECORDS_PER_ROW as u64).ok()?,
        ))
    }
}

pub const fn used_rows_for(positions: u64) -> u64 {
    positions.div_ceil(RECORDS_PER_ROW as u64)
}

pub fn logical_rows_for(used_rows: u64) -> u64 {
    checked_logical_rows_for(used_rows).expect("Enhance logical row count exceeds u64")
}

pub fn checked_logical_rows_for(used_rows: u64) -> Option<u64> {
    used_rows.max(SHARD_ROWS as u64).checked_next_power_of_two()
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
            has_transparent_inputs: true,
            has_transparent_outputs: false,
        });
        assert_eq!(RECORD_BYTES, 725);
        assert_eq!(ROW_BYTES, 6_525);
        assert_eq!(record.ephemeral_key(), &[1; 32]);
        assert_eq!(record.enc_ciphertext(), &[2; 580]);
        assert_eq!(record.cv_net(), &[3; 32]);
        assert_eq!(record.out_ciphertext(), &[4; 80]);
        assert_eq!(record.has_transparent_inputs(), Ok(true));
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
