use serde::{Deserialize, Serialize};

/// The complete encrypted-note fields stored in one memo-PIR record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoPirRecord {
    ephemeral_key: [u8; 32],
    ciphertext: [u8; 580],
}

impl MemoPirRecord {
    pub(crate) fn from_parts(ephemeral_key: [u8; 32], ciphertext: [u8; 580]) -> Self {
        Self {
            ephemeral_key,
            ciphertext,
        }
    }

    /// Returns the ephemeral key bytes.
    pub fn ephemeral_key(&self) -> &[u8; 32] {
        &self.ephemeral_key
    }

    /// Returns the complete encrypted note ciphertext.
    pub fn ciphertext(&self) -> &[u8; 580] {
        &self.ciphertext
    }
}

/// Chain state to which a memo-PIR snapshot is anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoPirSnapshotAnchor {
    /// Snapshot block height.
    pub height: u32,
    /// Snapshot block hash in consensus wire order.
    pub block_hash: [u8; 32],
    /// Ironwood tree size at the end of the anchor block.
    pub ironwood_tree_size: u64,
}

/// Version of the memo-PIR wire schema.
pub const SCHEMA_VERSION: u16 = 1;
/// Seed for the deterministic public offline-query setup that this protocol version pins.
///
/// This is the first eight bytes, little-endian, of
/// `SHA-256("zcash/ironwood-memo-pir/setup-seed/v1")`, so it cannot collide with the seed of any
/// other iPIR deployment that picks its own value — in particular the nullifier-PIR
/// "spendability" domain, whose seed this client must never reuse. The derivation is checked by
/// `pins_a_domain_separated_setup_seed` rather than trusted to this comment.
pub const MEMO_SETUP_SEED: u64 = 0xaf1a_e284_ec07_131a;
/// Shielded pool served by this client.
pub const POOL: &str = "ironwood";
/// Bytes in one `(ephemeral_key, enc_ciphertext)` record.
pub const RECORD_BYTES: usize = 612;
/// Records packed into one PIR database row.
pub const RECORDS_PER_ROW: usize = 8;
/// Bytes in one decoded PIR row.
pub const ROW_BYTES: usize = RECORD_BYTES * RECORDS_PER_ROW;
/// Rows in one independently published server shard.
pub const SHARD_ROWS: usize = 8_192;
/// iPIR item size for one row.
pub const ITEM_SIZE_BITS: u64 = (ROW_BYTES * 8) as u64;

/// Coverage advertised by a memo-PIR snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Coverage {
    /// The snapshot contains every Ironwood position from the pool's start.
    Full {
        /// First covered position; production clients require this to be zero.
        covered_position_start: u64,
    },
    /// A bounded history window. Wallet clients reject this mode.
    Windowed {
        /// Requested source lookback.
        requested_lookback_blocks: u64,
        /// Maximum number of active shards.
        max_active_shards: u32,
        /// First covered commitment-tree position.
        covered_position_start: u64,
        /// Effective first covered block height.
        effective_start_height: u64,
    },
}

/// Immutable shard metadata advertised by the server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardDescriptor {
    /// Stable shard number.
    pub shard_id: u64,
    /// First global database row in the shard.
    pub global_row_start: u64,
    /// Number of real note positions represented by the shard.
    pub populated_positions: u64,
    /// SHA-256 digest of the raw row data.
    pub rows_sha256: String,
    /// Whether this shard will never be rebuilt.
    pub sealed: bool,
    /// Opaque worker identifier.
    pub worker: String,
}

/// Authenticated snapshot description returned by `/memo/metadata`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoSnapshotMetadata {
    /// Wire-schema version.
    pub schema_version: u16,
    /// Consensus network identifier.
    pub network: String,
    /// Shielded pool identifier.
    pub pool: String,
    /// Snapshot anchor block height.
    pub anchor_height: u64,
    /// Snapshot anchor block hash, hex encoded in server wire order.
    pub anchor_block_hash: String,
    /// Ironwood tree size at the anchor.
    pub ironwood_tree_size: u64,
    /// Positions represented by this snapshot.
    pub coverage: Coverage,
    /// Bytes per record.
    pub record_bytes: u32,
    /// Records packed per row.
    pub records_per_row: u32,
    /// Bytes per row.
    pub row_bytes: u32,
    /// Rows per shard.
    pub shard_rows: u32,
    /// Rows containing at least one real position.
    pub used_rows: u64,
    /// Power-of-two PIR row count, including padding.
    pub logical_rows: u64,
    /// First global row represented locally.
    pub first_global_row: u64,
    /// Monotonic snapshot generation.
    pub generation: u64,
    /// Server parameter-set identifier.
    pub parameter_id: String,
    /// Seed for the deterministic public offline-query setup.
    ///
    /// Carried on the wire so that a server built against a different setup is rejected with a
    /// clear error instead of returning rows this client silently fails to decrypt. Clients
    /// require it to equal [`MEMO_SETUP_SEED`]; it is deliberately not defaulted, so a server
    /// that omits the field fails loudly rather than agreeing on zero.
    pub setup_seed: u64,
    /// Short public-parameter digest used on query responses.
    pub public_params_epoch: String,
    /// Full public-parameter SHA-256 digest.
    pub public_params_sha256: String,
    /// Published shards comprising the snapshot.
    pub shards: Vec<ShardDescriptor>,
}

impl MemoSnapshotMetadata {
    pub(crate) fn row_for_position(&self, position: u64) -> Option<(usize, usize)> {
        if position >= self.ironwood_tree_size {
            return None;
        }
        let global_row = position / RECORDS_PER_ROW as u64;
        (global_row < self.logical_rows)
            .then_some((global_row as usize, position as usize % RECORDS_PER_ROW))
    }
}

/// A complete decoded PIR row. Returning a row lets a wallet satisfy all of
/// its pending positions in that row without issuing linkable duplicate queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoPirRow {
    global_row: u64,
    bytes: [u8; ROW_BYTES],
}

impl MemoPirRow {
    pub(crate) fn new(global_row: u64, bytes: [u8; ROW_BYTES]) -> Self {
        Self { global_row, bytes }
    }

    /// Returns the global row index.
    pub fn global_row(&self) -> u64 {
        self.global_row
    }

    /// Extracts the record for `position` if it belongs to this row.
    pub fn record(&self, position: u64) -> Option<MemoPirRecord> {
        if position / RECORDS_PER_ROW as u64 != self.global_row {
            return None;
        }
        let start = position as usize % RECORDS_PER_ROW * RECORD_BYTES;
        let ephemeral_key = self.bytes[start..start + 32]
            .try_into()
            .expect("fixed row geometry");
        let ciphertext = self.bytes[start + 32..start + RECORD_BYTES]
            .try_into()
            .expect("fixed row geometry");
        Some(MemoPirRecord::from_parts(ephemeral_key, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the derivation of [`MEMO_SETUP_SEED`], so that the literal cannot drift from the
    /// domain string the server is expected to derive it from.
    #[test]
    fn pins_a_domain_separated_setup_seed() {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(b"zcash/ironwood-memo-pir/setup-seed/v1");
        assert_eq!(
            MEMO_SETUP_SEED,
            u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes")),
        );
    }

    #[test]
    fn extracts_only_records_from_the_same_row() {
        let mut bytes = [0; ROW_BYTES];
        let slot = 3;
        let start = slot * RECORD_BYTES;
        bytes[start..start + 32].fill(7);
        bytes[start + 32..start + RECORD_BYTES].fill(9);
        let row = MemoPirRow::new(11, bytes);

        let position = 11 * RECORDS_PER_ROW as u64 + slot as u64;
        let record = row.record(position).expect("position belongs to row");
        assert_eq!(record.ephemeral_key(), &[7; 32]);
        assert_eq!(record.ciphertext(), &[9; 580]);
        assert!(row.record(position + RECORDS_PER_ROW as u64).is_none());
    }
}
