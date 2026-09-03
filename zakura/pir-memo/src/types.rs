use serde::{Deserialize, Serialize};

/// One Ironwood action as served by the PIR database. Layout, in order:
///
/// ```text
/// nf[32] ‖ ephemeralKey[32] ‖ encCiphertext[580] ‖ cv_net[32] ‖ outCiphertext[80] ‖ txid[32] ‖ height[4 LE]
/// ```
///
/// Memo completion uses only the ephemeral key and ciphertext. The other fields
/// exist for DAG-sync: `nullifier` is the action's spent nullifier (the output
/// note's `rho`), `cv_net` and `out_ciphertext` allow outgoing recovery, and
/// `txid` (internal byte order) plus `height` place the action without any
/// lightwalletd request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoPirRecord {
    nullifier: [u8; 32],
    ephemeral_key: [u8; 32],
    ciphertext: [u8; 580],
    cv_net: [u8; 32],
    out_ciphertext: [u8; 80],
    txid: [u8; 32],
    height: u32,
}

impl MemoPirRecord {
    pub(crate) fn from_bytes(bytes: &[u8; RECORD_BYTES]) -> Self {
        let field = |start: usize, len: usize| &bytes[start..start + len];
        Self {
            nullifier: field(RECORD_NULLIFIER_OFFSET, 32)
                .try_into()
                .expect("fixed record geometry"),
            ephemeral_key: field(RECORD_EPHEMERAL_KEY_OFFSET, 32)
                .try_into()
                .expect("fixed record geometry"),
            ciphertext: field(RECORD_ENC_CIPHERTEXT_OFFSET, 580)
                .try_into()
                .expect("fixed record geometry"),
            cv_net: field(RECORD_CV_NET_OFFSET, 32)
                .try_into()
                .expect("fixed record geometry"),
            out_ciphertext: field(RECORD_OUT_CIPHERTEXT_OFFSET, 80)
                .try_into()
                .expect("fixed record geometry"),
            txid: field(RECORD_TXID_OFFSET, 32)
                .try_into()
                .expect("fixed record geometry"),
            height: u32::from_le_bytes(
                field(RECORD_HEIGHT_OFFSET, 4)
                    .try_into()
                    .expect("fixed record geometry"),
            ),
        }
    }

    /// Returns the action's spent nullifier, which is `rho` of the output note.
    pub fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }

    /// Returns the ephemeral key bytes.
    pub fn ephemeral_key(&self) -> &[u8; 32] {
        &self.ephemeral_key
    }

    /// Returns the complete encrypted note ciphertext.
    pub fn ciphertext(&self) -> &[u8; 580] {
        &self.ciphertext
    }

    /// Returns the action's net value commitment.
    pub fn cv_net(&self) -> &[u8; 32] {
        &self.cv_net
    }

    /// Returns the outgoing ciphertext used for OVK recovery.
    pub fn out_ciphertext(&self) -> &[u8; 80] {
        &self.out_ciphertext
    }

    /// Returns the containing transaction's ID in internal byte order.
    pub fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    /// Returns the height of the block containing the action.
    pub fn height(&self) -> u32 {
        self.height
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

/// Version of the memo-PIR wire schema. Version 2 introduced the 792-byte action record.
pub const SCHEMA_VERSION: u16 = 2;
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
/// Bytes in one action record; see [`MemoPirRecord`] for the layout.
pub const RECORD_BYTES: usize = 792;
/// Byte offset of the nullifier within a record.
pub const RECORD_NULLIFIER_OFFSET: usize = 0;
/// Byte offset of the ephemeral key within a record.
pub const RECORD_EPHEMERAL_KEY_OFFSET: usize = 32;
/// Byte offset of the full encrypted note within a record.
pub const RECORD_ENC_CIPHERTEXT_OFFSET: usize = 64;
/// Byte offset of `cv_net` within a record.
pub const RECORD_CV_NET_OFFSET: usize = 644;
/// Byte offset of the outgoing ciphertext within a record.
pub const RECORD_OUT_CIPHERTEXT_OFFSET: usize = 676;
/// Byte offset of the transaction ID within a record.
pub const RECORD_TXID_OFFSET: usize = 756;
/// Byte offset of the little-endian block height within a record.
pub const RECORD_HEIGHT_OFFSET: usize = 788;
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
        let bytes: &[u8; RECORD_BYTES] = self.bytes[start..start + RECORD_BYTES]
            .try_into()
            .expect("fixed row geometry");
        Some(MemoPirRecord::from_bytes(bytes))
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
    fn record_geometry_is_pinned() {
        assert_eq!(RECORD_BYTES, 792);
        assert_eq!(ROW_BYTES, 6_336);
        assert_eq!(RECORD_HEIGHT_OFFSET + 4, RECORD_BYTES);
    }

    #[test]
    fn extracts_only_records_from_the_same_row() {
        let mut bytes = [0; ROW_BYTES];
        let slot = 3;
        let start = slot * RECORD_BYTES;
        bytes[start + RECORD_NULLIFIER_OFFSET..start + RECORD_EPHEMERAL_KEY_OFFSET].fill(6);
        bytes[start + RECORD_EPHEMERAL_KEY_OFFSET..start + RECORD_ENC_CIPHERTEXT_OFFSET].fill(7);
        bytes[start + RECORD_ENC_CIPHERTEXT_OFFSET..start + RECORD_CV_NET_OFFSET].fill(9);
        bytes[start + RECORD_CV_NET_OFFSET..start + RECORD_OUT_CIPHERTEXT_OFFSET].fill(10);
        bytes[start + RECORD_OUT_CIPHERTEXT_OFFSET..start + RECORD_TXID_OFFSET].fill(11);
        bytes[start + RECORD_TXID_OFFSET..start + RECORD_HEIGHT_OFFSET].fill(12);
        bytes[start + RECORD_HEIGHT_OFFSET..start + RECORD_BYTES]
            .copy_from_slice(&3_428_143u32.to_le_bytes());
        let row = MemoPirRow::new(11, bytes);

        let position = 11 * RECORDS_PER_ROW as u64 + slot as u64;
        let record = row.record(position).expect("position belongs to row");
        assert_eq!(record.nullifier(), &[6; 32]);
        assert_eq!(record.ephemeral_key(), &[7; 32]);
        assert_eq!(record.ciphertext(), &[9; 580]);
        assert_eq!(record.cv_net(), &[10; 32]);
        assert_eq!(record.out_ciphertext(), &[11; 80]);
        assert_eq!(record.txid(), &[12; 32]);
        assert_eq!(record.height(), 3_428_143);
        assert!(row.record(position + RECORDS_PER_ROW as u64).is_none());
    }
}
