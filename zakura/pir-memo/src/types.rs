use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One Ironwood action as served by the PIR database. Layout, in order:
///
/// ```text
/// nf[32] ‖ ephemeralKey[32] ‖ encCiphertext[580] ‖ cmx[32] ‖ cv_net[32] ‖ outCiphertext[80] ‖ txid[32] ‖ height[4 LE]
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
    cmx: [u8; 32],
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
            cmx: field(RECORD_CMX_OFFSET, 32)
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

    /// Returns the output note's extracted commitment, so a trial-decrypted
    /// note can be authenticated against the record itself.
    pub fn cmx(&self) -> &[u8; 32] {
        &self.cmx
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

/// Wire schema of [`GenerationManifest`] this client speaks.
pub const MANIFEST_SCHEMA_VERSION: u16 = 4;
/// Seed for the deterministic public offline-query setup of the ACTION table.
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
pub const RECORD_BYTES: usize = 824;
/// Byte offset of the nullifier within a record.
pub const RECORD_NULLIFIER_OFFSET: usize = 0;
/// Byte offset of the ephemeral key within a record.
pub const RECORD_EPHEMERAL_KEY_OFFSET: usize = 32;
/// Byte offset of the full encrypted note within a record.
pub const RECORD_ENC_CIPHERTEXT_OFFSET: usize = 64;
/// Byte offset of the extracted note commitment within a record.
pub const RECORD_CMX_OFFSET: usize = 644;
/// Byte offset of `cv_net` within a record.
pub const RECORD_CV_NET_OFFSET: usize = 676;
/// Byte offset of the outgoing ciphertext within a record.
pub const RECORD_OUT_CIPHERTEXT_OFFSET: usize = 708;
/// Byte offset of the transaction ID within a record.
pub const RECORD_TXID_OFFSET: usize = 788;
/// Byte offset of the little-endian block height within a record.
pub const RECORD_HEIGHT_OFFSET: usize = 820;
/// Records packed into one ACTION row.
pub const RECORDS_PER_ROW: usize = 8;
/// Bytes in one decoded ACTION row.
pub const ROW_BYTES: usize = RECORD_BYTES * RECORDS_PER_ROW;
/// Rows in one independently published ACTION shard.
pub const SHARD_ROWS: usize = 8_192;
/// iPIR item size for one ACTION row.
pub const ITEM_SIZE_BITS: u64 = (ROW_BYTES * 8) as u64;

/// Identity of one PIR table served by the coordinator. The wire name appears
/// in URLs and in the generation manifest, so it is fixed forever.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseId {
    /// One Ironwood action per record, indexed by commitment-tree position.
    Action,
    /// Note commitments, 256 per row: one row per sub-shard (tree levels 0 to 8).
    Witness,
    /// Completed sub-shard roots, 256 per row: one row per shard (levels 8 to 16).
    WitnessRoots,
    /// Nullifier hash buckets up to the cold checkpoint; one bucket per row.
    NfCold,
    /// Nullifier hash buckets since the cold checkpoint; one bucket per row.
    NfWarm,
}

impl DatabaseId {
    /// The name used in URLs and manifest keys.
    pub const fn as_str(&self) -> &'static str {
        match self {
            DatabaseId::Action => "action",
            DatabaseId::Witness => "witness",
            DatabaseId::WitnessRoots => "witness-roots",
            DatabaseId::NfCold => "nf-cold",
            DatabaseId::NfWarm => "nf-warm",
        }
    }
}

impl std::fmt::Display for DatabaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Row geometry of one table, as this client pins it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableLayout {
    /// Bytes in one record.
    pub record_bytes: usize,
    /// Records packed into one PIR row.
    pub records_per_row: usize,
    /// Rows in one published shard.
    pub shard_rows: usize,
}

impl TableLayout {
    /// Bytes in one row.
    pub const fn row_bytes(&self) -> usize {
        self.record_bytes * self.records_per_row
    }

    /// iPIR item size for one row.
    pub const fn item_size_bits(&self) -> u64 {
        (self.row_bytes() * 8) as u64
    }
}

/// What this client requires of one table before it will query it: the
/// geometry its decoder is built for and the setup seed its queries assume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableExpectation {
    /// Table the expectation applies to.
    pub table: DatabaseId,
    /// Required row geometry.
    pub layout: TableLayout,
    /// Required public setup seed.
    pub setup_seed: u64,
}

/// The ACTION table as this protocol version pins it.
pub const ACTION_EXPECTATION: TableExpectation = TableExpectation {
    table: DatabaseId::Action,
    layout: TableLayout {
        record_bytes: RECORD_BYTES,
        records_per_row: RECORDS_PER_ROW,
        shard_rows: SHARD_ROWS,
    },
    setup_seed: MEMO_SETUP_SEED,
};

/// Row geometry of the two witness tables: 256 hashes per row.
pub const WITNESS_LAYOUT: TableLayout = TableLayout {
    record_bytes: 32,
    records_per_row: 256,
    shard_rows: SHARD_ROWS,
};

/// Row geometry of the nullifier tables: one bucket of 112 × 41 bytes per row.
pub const NULLIFIER_LAYOUT: TableLayout = TableLayout {
    record_bytes: 4_592,
    records_per_row: 1,
    shard_rows: SHARD_ROWS,
};

/// First eight little-endian bytes of the SHA-256 of a domain string.
pub fn seed_from_domain(domain: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(domain.as_bytes());
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

impl TableExpectation {
    /// What this protocol version pins for `table`. ACTION keeps the memo
    /// seed; every other table is domain-separated by its wire name.
    pub fn for_table(table: DatabaseId) -> Self {
        let (layout, setup_seed) = match table {
            DatabaseId::Action => return ACTION_EXPECTATION,
            DatabaseId::Witness | DatabaseId::WitnessRoots => (WITNESS_LAYOUT, None),
            DatabaseId::NfCold | DatabaseId::NfWarm => (NULLIFIER_LAYOUT, None),
        };
        let setup_seed = setup_seed.unwrap_or_else(|| {
            seed_from_domain(&format!(
                "zcash/ironwood-pir/{}/setup-seed/v1",
                table.as_str()
            ))
        });
        Self {
            table,
            layout,
            setup_seed,
        }
    }
}

/// Fixed per-pass query budget every wallet issues, dummies included, so the
/// request count never depends on what a wallet found.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Bumped whenever any count changes; clients reject unknown versions.
    pub protocol_version: u16,
    /// Nullifier query pairs (one cold, one warm) per pass.
    pub k_nf: u16,
    /// ACTION row queries per pass.
    pub k_act: u16,
    /// Witness query pairs (one roots row, one leaves row) per pass.
    pub k_wit: u16,
}

/// The envelope protocol version this client implements.
pub const ENVELOPE_PROTOCOL_VERSION: u16 = 1;

/// Public, non-private tree summary served at `/v1/witness/cap`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessCap {
    /// Anchor block height.
    pub anchor_height: u64,
    /// Ironwood tree size at the anchor.
    pub tree_size: u64,
    /// Root of every shard with a leaf, hex, index = shard.
    pub shard_roots: Vec<String>,
    /// Root of the partial frontier sub-shard, hex, if any.
    pub frontier_subshard_root: Option<String>,
    /// Depth-32 tree root, hex.
    pub tree_root: String,
}

/// The rightmost tree path after one block, from `/v1/witness/frontier`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierUpdate {
    /// Block height.
    pub height: u64,
    /// Tree size after the block.
    pub tree_size: u64,
    /// Hex, level 0 first: for level `h`, the node at index `(tree_size - 1) >> h`.
    pub rightmost_nodes: Vec<String>,
}

/// Immutable shard metadata advertised by the server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardDescriptor {
    /// Stable shard number.
    pub shard_id: u64,
    /// First global database row in the shard.
    pub global_row_start: u64,
    /// Number of real positions represented by the shard.
    pub populated_positions: u64,
    /// SHA-256 digest of the raw row data.
    pub rows_sha256: String,
    /// Whether this shard will never be rebuilt.
    pub sealed: bool,
    /// Opaque worker identifier.
    pub worker: String,
}

/// One table as published in a generation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableManifest {
    /// Bytes per record.
    pub record_bytes: u32,
    /// Records packed per row.
    pub records_per_row: u32,
    /// Bytes per row.
    pub row_bytes: u32,
    /// Rows per shard.
    pub shard_rows: u32,
    /// Populated positions (records) in the table.
    pub positions: u64,
    /// Rows containing at least one real position.
    pub used_rows: u64,
    /// Power-of-two PIR row count, including padding.
    pub logical_rows: u64,
    /// Server parameter-set identifier.
    pub parameter_id: String,
    /// Seed for the deterministic public offline-query setup.
    ///
    /// Carried on the wire so that a server built against a different setup is rejected with a
    /// clear error instead of returning rows this client silently fails to decrypt. It is
    /// deliberately not defaulted, so a server that omits the field fails loudly rather than
    /// agreeing on zero.
    pub setup_seed: u64,
    /// Short public-parameter digest used on query responses.
    pub public_params_epoch: String,
    /// Full public-parameter SHA-256 digest.
    pub public_params_sha256: String,
    /// Published shards comprising the table.
    pub shards: Vec<ShardDescriptor>,
}

/// Every table at one anchor, returned by `/v1/generation`. A client pins one
/// generation for a whole pass; the coordinator keeps two answerable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationManifest {
    /// Wire-schema version.
    pub schema_version: u16,
    /// The pinned `ipir-sp` revision the server derives parameters from.
    pub protocol_revision: String,
    /// Consensus network identifier.
    pub network: String,
    /// Shielded pool identifier.
    pub pool: String,
    /// Snapshot anchor block height.
    pub anchor_height: u64,
    /// Snapshot anchor block hash, hex encoded in display order.
    pub anchor_block_hash: String,
    /// Ironwood tree size at the anchor.
    pub ironwood_tree_size: u64,
    /// Monotonic snapshot generation.
    pub generation: u64,
    /// Depth-32 root of the Ironwood commitment tree at the anchor, hex.
    pub anchor_tree_root: String,
    /// Height of the nullifier cold checkpoint this generation was built from.
    pub cold_checkpoint_height: u64,
    /// The fixed per-pass query budget.
    pub envelope: Envelope,
    /// Tables published in this generation, keyed by wire name.
    pub tables: BTreeMap<DatabaseId, TableManifest>,
}

/// A complete decoded PIR row of one table. Returning a row lets a wallet
/// satisfy all of its pending positions in that row without issuing
/// linkable duplicate queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirRow {
    table: DatabaseId,
    layout: TableLayout,
    global_row: u64,
    bytes: Vec<u8>,
}

/// The ACTION row type wallets consume for memo completion.
pub type MemoPirRow = PirRow;

impl PirRow {
    pub(crate) fn new(
        table: DatabaseId,
        layout: TableLayout,
        global_row: u64,
        bytes: Vec<u8>,
    ) -> Self {
        debug_assert_eq!(bytes.len(), layout.row_bytes());
        Self {
            table,
            layout,
            global_row,
            bytes,
        }
    }

    /// Returns the table the row belongs to.
    pub fn table(&self) -> DatabaseId {
        self.table
    }

    /// Returns the global row index.
    pub fn global_row(&self) -> u64 {
        self.global_row
    }

    /// Returns the raw row bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the row as 32-byte hashes (witness tables).
    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.bytes
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().expect("32-byte chunk"))
            .collect()
    }

    /// Extracts the action record for `position` if this is an ACTION row and the
    /// position belongs to it.
    pub fn record(&self, position: u64) -> Option<MemoPirRecord> {
        if self.table != DatabaseId::Action || self.layout.record_bytes != RECORD_BYTES {
            return None;
        }
        let records_per_row = self.layout.records_per_row as u64;
        if position / records_per_row != self.global_row {
            return None;
        }
        let start = (position % records_per_row) as usize * RECORD_BYTES;
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
        assert_eq!(RECORD_BYTES, 824);
        assert_eq!(ROW_BYTES, 6_592);
        assert_eq!(RECORD_HEIGHT_OFFSET + 4, RECORD_BYTES);
    }

    #[test]
    fn expectations_are_domain_separated_and_action_is_pinned() {
        assert_eq!(
            TableExpectation::for_table(DatabaseId::Action),
            ACTION_EXPECTATION
        );
        assert_eq!(
            seed_from_domain("zcash/ironwood-memo-pir/setup-seed/v1"),
            MEMO_SETUP_SEED
        );
        let tables = [
            DatabaseId::Action,
            DatabaseId::Witness,
            DatabaseId::WitnessRoots,
            DatabaseId::NfCold,
            DatabaseId::NfWarm,
        ];
        let mut seeds: Vec<u64> = tables
            .iter()
            .map(|table| TableExpectation::for_table(*table).setup_seed)
            .collect();
        seeds.sort_unstable();
        seeds.dedup();
        assert_eq!(seeds.len(), tables.len());
        assert_eq!(
            TableExpectation::for_table(DatabaseId::NfCold)
                .layout
                .row_bytes(),
            4_592
        );
        assert_eq!(DatabaseId::WitnessRoots.as_str(), "witness-roots");
    }

    #[test]
    fn table_names_and_manifest_keys_are_the_wire_names() {
        let mut tables = BTreeMap::new();
        tables.insert(DatabaseId::NfCold, 1u8);
        assert_eq!(serde_json::to_string(&tables).unwrap(), r#"{"nf-cold":1}"#);
        assert_eq!(DatabaseId::Action.to_string(), "action");
        assert_eq!(ACTION_EXPECTATION.layout.row_bytes(), ROW_BYTES);
        assert_eq!(ACTION_EXPECTATION.layout.item_size_bits(), ITEM_SIZE_BITS);
    }

    #[test]
    fn extracts_only_records_from_the_same_row() {
        let mut bytes = [0; ROW_BYTES];
        let slot = 3;
        let start = slot * RECORD_BYTES;
        bytes[start + RECORD_NULLIFIER_OFFSET..start + RECORD_EPHEMERAL_KEY_OFFSET].fill(6);
        bytes[start + RECORD_EPHEMERAL_KEY_OFFSET..start + RECORD_ENC_CIPHERTEXT_OFFSET].fill(7);
        bytes[start + RECORD_ENC_CIPHERTEXT_OFFSET..start + RECORD_CMX_OFFSET].fill(9);
        bytes[start + RECORD_CMX_OFFSET..start + RECORD_CV_NET_OFFSET].fill(8);
        bytes[start + RECORD_CV_NET_OFFSET..start + RECORD_OUT_CIPHERTEXT_OFFSET].fill(10);
        bytes[start + RECORD_OUT_CIPHERTEXT_OFFSET..start + RECORD_TXID_OFFSET].fill(11);
        bytes[start + RECORD_TXID_OFFSET..start + RECORD_HEIGHT_OFFSET].fill(12);
        bytes[start + RECORD_HEIGHT_OFFSET..start + RECORD_BYTES]
            .copy_from_slice(&3_428_143u32.to_le_bytes());
        let row = MemoPirRow::new(
            DatabaseId::Action,
            ACTION_EXPECTATION.layout,
            11,
            bytes.to_vec(),
        );

        let position = 11 * RECORDS_PER_ROW as u64 + slot as u64;
        let record = row.record(position).expect("position belongs to row");
        assert_eq!(record.nullifier(), &[6; 32]);
        assert_eq!(record.ephemeral_key(), &[7; 32]);
        assert_eq!(record.ciphertext(), &[9; 580]);
        assert_eq!(record.cmx(), &[8; 32]);
        assert_eq!(record.cv_net(), &[10; 32]);
        assert_eq!(record.out_ciphertext(), &[11; 80]);
        assert_eq!(record.txid(), &[12; 32]);
        assert_eq!(record.height(), 3_428_143);
        assert!(row.record(position + RECORDS_PER_ROW as u64).is_none());
    }
}
