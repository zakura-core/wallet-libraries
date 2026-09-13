use ipir_sp::YpirSchemeParams;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u16 = 1;
pub const PROTOCOL_REVISION: &str = "transparent-spend-pir-v1";
pub const NETWORK: &str = "main";
pub const WARM_BLOCKS: u64 = 100_000;

pub const ENTRY_BYTES: usize = 80;
pub const BUCKET_CAPACITY: usize = 88;
pub const ROW_BYTES: usize = ENTRY_BYTES * BUCKET_CAPACITY;
pub const SHARD_ROWS: usize = 8_192;
pub const ITEM_SIZE_BITS: u64 = (ROW_BYTES * 8) as u64;
pub const TARGET_LOAD_NUMERATOR: u64 = 55;
pub const TARGET_LOAD_DENOMINATOR: u64 = 100;

pub const COLD_SETUP_SEED: u64 = 0x7873_7063_6f6c_6431;
pub const WARM_SETUP_SEED: u64 = 0x7873_7077_6172_6d31;

const OCCUPIED: u8 = 1;
const KEY_OFFSET: usize = 1;
const INDEX_OFFSET: usize = 33;
const SPENDER_OFFSET: usize = 37;
const HEIGHT_OFFSET: usize = 69;
const TX_INDEX_OFFSET: usize = 73;
const RESERVED_OFFSET: usize = 75;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentSpendEntry {
    pub outpoint_txid: [u8; 32],
    pub outpoint_index: u32,
    pub spending_txid: [u8; 32],
    pub spend_height: u32,
    pub transaction_index: u16,
}

impl TransparentSpendEntry {
    pub fn to_bytes(self) -> [u8; ENTRY_BYTES] {
        let mut bytes = [0; ENTRY_BYTES];
        bytes[0] = OCCUPIED;
        bytes[KEY_OFFSET..INDEX_OFFSET].copy_from_slice(&self.outpoint_txid);
        bytes[INDEX_OFFSET..SPENDER_OFFSET].copy_from_slice(&self.outpoint_index.to_le_bytes());
        bytes[SPENDER_OFFSET..HEIGHT_OFFSET].copy_from_slice(&self.spending_txid);
        bytes[HEIGHT_OFFSET..TX_INDEX_OFFSET].copy_from_slice(&self.spend_height.to_le_bytes());
        bytes[TX_INDEX_OFFSET..RESERVED_OFFSET]
            .copy_from_slice(&self.transaction_index.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ENTRY_BYTES
            || bytes[0] != OCCUPIED
            || bytes[RESERVED_OFFSET..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        Some(Self {
            outpoint_txid: bytes[KEY_OFFSET..INDEX_OFFSET].try_into().ok()?,
            outpoint_index: u32::from_le_bytes(
                bytes[INDEX_OFFSET..SPENDER_OFFSET].try_into().ok()?,
            ),
            spending_txid: bytes[SPENDER_OFFSET..HEIGHT_OFFSET].try_into().ok()?,
            spend_height: u32::from_le_bytes(
                bytes[HEIGHT_OFFSET..TX_INDEX_OFFSET].try_into().ok()?,
            ),
            transaction_index: u16::from_le_bytes(
                bytes[TX_INDEX_OFFSET..RESERVED_OFFSET].try_into().ok()?,
            ),
        })
    }
}

pub fn bucket_for_outpoint(txid: &[u8; 32], index: u32, buckets: usize) -> Option<usize> {
    if buckets == 0 || !buckets.is_power_of_two() {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"transparent-spend-pir-v1/bucket");
    hash.update(txid);
    hash.update(index.to_le_bytes());
    let digest = hash.finalize();
    let prefix = u64::from_le_bytes(digest[..8].try_into().expect("fixed digest"));
    Some((prefix as usize) & (buckets - 1))
}

pub fn bucket_count(entries: u64) -> usize {
    let denominator = BUCKET_CAPACITY as u64 * TARGET_LOAD_NUMERATOR;
    let needed = entries
        .saturating_mul(TARGET_LOAD_DENOMINATOR)
        .div_ceil(denominator);
    usize::try_from(needed)
        .unwrap_or(usize::MAX / 2)
        .max(SHARD_ROWS)
        .next_power_of_two()
}

pub fn scan_bucket(
    row: &[u8],
    txid: &[u8; 32],
    index: u32,
) -> Result<Option<TransparentSpendEntry>, &'static str> {
    let row = row.get(..ROW_BYTES).ok_or("decoded bucket is too short")?;
    let mut found = None;
    for bytes in row.chunks_exact(ENTRY_BYTES) {
        if bytes.iter().all(|byte| *byte == 0) {
            continue;
        }
        let entry = TransparentSpendEntry::from_bytes(bytes).ok_or("malformed spend entry")?;
        if &entry.outpoint_txid == txid
            && entry.outpoint_index == index
            && found.replace(entry).is_some()
        {
            return Err("duplicate spend entry");
        }
    }
    Ok(found)
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentSpendGeneration {
    pub schema_version: u16,
    pub protocol_revision: String,
    pub network: String,
    pub tip_height: u64,
    pub tip_block_hash: String,
    pub ironwood_tree_size: u64,
    pub generation: u64,
    pub cold_end_height: u64,
    pub buckets: u64,
    pub row_bytes: u32,
    pub shard_rows: u32,
    pub logical_rows: u64,
    pub parameter_id: String,
    pub setup_seed: u64,
    pub public_params_epoch: String,
    pub public_params_sha256: String,
    pub shards: Vec<ShardDescriptor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransparentSpendTableSession {
    pub generation: TransparentSpendGeneration,
    pub params: YpirSchemeParams,
    pub public_params_base64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransparentSpendSession {
    pub tip_height: u64,
    pub tip_block_hash: String,
    pub ironwood_tree_size: u64,
    pub generation: u64,
    pub cold_end_height: u64,
    pub cold: TransparentSpendTableSession,
    pub warm: TransparentSpendTableSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendLookup {
    Spent(TransparentSpendEntry),
    Unspent { as_of_height: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(index: u32) -> TransparentSpendEntry {
        TransparentSpendEntry {
            outpoint_txid: [1; 32],
            outpoint_index: index,
            spending_txid: [2; 32],
            spend_height: 42,
            transaction_index: 7,
        }
    }

    #[test]
    fn entry_round_trip_and_reserved_validation() {
        let encoded = entry(3).to_bytes();
        assert_eq!(TransparentSpendEntry::from_bytes(&encoded), Some(entry(3)));
        let mut malformed = encoded;
        malformed[79] = 1;
        assert_eq!(TransparentSpendEntry::from_bytes(&malformed), None);
    }

    #[test]
    fn exact_scan_ignores_other_outputs_from_same_transaction() {
        let mut row = [0; ROW_BYTES];
        row[..ENTRY_BYTES].copy_from_slice(&entry(1).to_bytes());
        row[ENTRY_BYTES..2 * ENTRY_BYTES].copy_from_slice(&entry(2).to_bytes());
        assert_eq!(scan_bucket(&row, &[1; 32], 2), Ok(Some(entry(2))));
        assert_eq!(scan_bucket(&row, &[1; 32], 9), Ok(None));
    }

    #[test]
    fn minimum_table_is_one_shard() {
        assert_eq!(bucket_count(0), SHARD_ROWS);
        assert_eq!(bucket_count(100_000), SHARD_ROWS);
    }
}
