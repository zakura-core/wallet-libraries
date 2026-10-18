//! Transparent profile identities and shared table setup.
pub use crate::native::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
/// Name of this profile, as the service publishes it: the 49-bit
/// nearest-rounded query.
pub const PROFILE: &str = "reinspiring-two-mask-m29-v1";
/// Name of the dithered-query profile: the same setup, masks and response, with
/// the selection uploaded at [`DITHERED_QUERY_BITS`] dithered bits.
pub const DITHERED_PROFILE: &str = "reinspiring-two-mask-m29-dq44-v1";

/// Name of the 8-bit profile: p = 2^8, one 27-bit `K_g` digit, masks rounded
/// to 22 bits, 28-bit dithered selections and 10-bit responses.
pub const P8_PROFILE: &str = "reinspiring-two-mask-p8-g27x1-m22-dq28-r10-v1";

/// The native parameters a table of kind `table` is served with: [`P8`] for
/// the history tables and the txid display table, [`P16`] for every other.
pub fn profile_for(table: &str) -> Profile {
    match table {
        "directory" | "pages" | "txdirectory" => P8,
        _ => P16,
    }
}

/// Upload bytes a wallet sends to a 16-bit `rows`-row table under the
/// dithered scheme, after the 8-byte binding: `K_g` then the 44-bit
/// selection.
pub const fn dithered_request_len(rows: usize) -> usize {
    request_len_bits(rows, DITHERED_QUERY_BITS)
}

/// Domain-separated 32-byte seeds for one geometry's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSeeds {
    /// Expands to the public first-dimension query masks.
    pub query_masks: [u8; 32],
    /// Seeds the packing setup the `K_g` key is generated under.
    pub packing: [u8; 32],
}

/// Seeds for `table` of `geometry` under `schema`.
///
/// Distinct per geometry and table, and domain-separated by the schema string
/// and this profile, so neither a future schema nor another profile reuses
/// them. Both sides derive them locally; the service's published identity is
/// checked against the derivation, never adopted.
pub fn table_seeds(schema: &str, geometry: &str, table: &str) -> TableSeeds {
    // Each profile has its own label, so a table that changes profile gets
    // new masks and setup; the 16-bit label is the one served before.
    let label: &[u8] = if profile_for(table) == P8 {
        b"/native-reinspiring-p8-g27x1/"
    } else {
        b"/native-reinspiring-m29/"
    };
    let derive = |purpose: &[u8]| -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(schema.as_bytes());
        hash.update(label);
        hash.update(purpose);
        hash.update(b"\0");
        hash.update(geometry.as_bytes());
        hash.update(b"\0");
        hash.update(table.as_bytes());
        hash.finalize().into()
    };
    TableSeeds {
        query_masks: derive(b"query-masks"),
        packing: derive(b"packing-setup"),
    }
}

/// What the service publishes about one table's native parameters.
///
/// Every field is re-derived by the client from the pinned geometry and
/// compared whole. A service that could move any field independently could
/// choose parameters for the wallet — and a mask seed or setup of its choosing
/// is a query it can read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeScheme {
    pub profile: String,
    pub d: usize,
    pub q_bits: usize,
    pub p_bits: usize,
    pub gadget_bits: usize,
    pub ell: usize,
    pub secret: String,
    pub mask_bits: usize,
    pub query_bits: usize,
    pub response_bits: usize,
    pub rows: u64,
    pub row_bytes: u32,
    pub cols: usize,
    /// `NativeParams::encoding`, hex.
    pub native_encoding: String,
    /// Seed of the public query masks, hex.
    pub query_mask_seed: String,
    /// Packing setup identifier, hex.
    pub packing_setup_id: String,
    /// Upload bytes after the 8-byte binding: `K_g` and the selection.
    pub request_bytes: usize,
    /// Published mask bytes per segment.
    pub public_bytes: usize,
    /// Response body bytes per segment, after the 16-byte header.
    pub response_bytes: usize,
}

impl NativeScheme {
    /// A stable digest of the whole identity.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("scheme serializes"),
        ))
    }
}

/// Everything one table's queries need on either side, derived once per
/// geometry and table.
pub struct TableProfile {
    pub rows: usize,
    pub row_bytes: usize,
    pub cols: usize,
    /// The native parameters: [`profile_for`] the table.
    pub native: Profile,
    pub setup: NativeSetup,
    pub masks: Vec<Vec<u64>>,
    /// The table's own scheme: for a 16-bit table the 49-bit nearest-rounded
    /// [`PROFILE`], for an 8-bit table its 28-bit dithered
    /// [`P8_PROFILE`].
    pub scheme: NativeScheme,
    /// A 16-bit table's 44-bit dithered scheme, [`DITHERED_PROFILE`]:
    /// `scheme` with only the profile name, query width and request length
    /// changed. An 8-bit table has none: its own scheme is dithered.
    pub dithered_scheme: Option<NativeScheme>,
}

impl TableProfile {
    /// Derives the profile for `table` of `geometry` at `rows` by `row_bytes`.
    pub fn new(
        schema: &str,
        geometry: &str,
        table: &str,
        rows: u64,
        row_bytes: u32,
    ) -> Result<Self, String> {
        let rows_usize = usize::try_from(rows).map_err(|_| "native rows exceed usize")?;
        let row_bytes_usize = row_bytes as usize;
        let native = profile_for(table);
        if rows_usize == 0 || !rows_usize.is_multiple_of(D) {
            return Err(format!(
                "{rows} rows: the native profile needs a positive multiple of {D}"
            ));
        }
        let instance = native.instance_bytes();
        if row_bytes_usize == 0 || !row_bytes_usize.is_multiple_of(instance) {
            return Err(format!(
                "{row_bytes}-byte rows: the native profile needs whole {instance}-byte instances"
            ));
        }
        let cols = row_bytes_usize / native.entry_bytes();
        let seeds = table_seeds(schema, geometry, table);
        let params = native.params();
        let setup = NativeSetup::new(params.clone(), seeds.packing);
        let masks = native.public_query_masks(seeds.query_masks, rows_usize, cols)?;
        let primary = native.primary_bits();
        let scheme = NativeScheme {
            profile: if native == P8 { P8_PROFILE } else { PROFILE }.to_string(),
            d: D,
            q_bits: Q_BITS,
            p_bits: native.p_bits,
            gadget_bits: native.gadget_bits,
            ell: native.ell,
            secret: "gaussian".to_string(),
            mask_bits: native.mask_bits,
            query_bits: primary,
            response_bits: native.response_bits,
            rows,
            row_bytes,
            cols,
            native_encoding: hex::encode(params.encoding()),
            query_mask_seed: hex::encode(seeds.query_masks),
            packing_setup_id: hex::encode(setup.id()),
            request_bytes: native.request_len_bits(rows_usize, primary),
            public_bytes: native.public_len(cols),
            response_bytes: native.response_len(cols),
        };
        let dithered_scheme = native.nearest_bits.map(|_| NativeScheme {
            profile: DITHERED_PROFILE.to_string(),
            query_bits: native.dithered_bits,
            request_bytes: native.request_len_bits(rows_usize, native.dithered_bits),
            ..scheme.clone()
        });
        Ok(Self {
            rows: rows_usize,
            row_bytes: row_bytes_usize,
            cols,
            native,
            setup,
            masks,
            scheme,
            dithered_scheme,
        })
    }

    pub fn blocks(&self) -> usize {
        self.cols / D
    }

    /// Whether an upload of `len` bytes, after the binding, has one of the two
    /// lengths this table accepts.
    pub fn accepts_request_len(&self, len: usize) -> bool {
        self.native.accepted_query_bits(self.rows, len).is_some()
    }

    /// Whether an upload of `len` bytes, after the binding, selects every row
    /// or only the first `query_rows` at an accepted width.
    pub fn accepts_selection_len(&self, query_rows: usize, len: usize) -> bool {
        self.native
            .accepted_query_shape(self.rows, query_rows, len)
            .is_some()
    }

    /// Bytes one segment's database occupies: one coefficient per entry.
    pub fn database_bytes(&self) -> u64 {
        self.rows as u64 * self.cols as u64 * self.native.entry_bytes() as u64
    }

    /// Upper bound on one segment's `prepared_native` encoding.
    pub fn prepared_max_bytes(&self) -> u64 {
        PREPARED_HEADER_BYTES + self.blocks() as u64 * self.native.prepared_block_max_bytes()
    }

    /// Lower bound on one segment's `prepared_native` encoding.
    pub fn prepared_min_bytes(&self) -> u64 {
        PREPARED_HEADER_BYTES + self.blocks() as u64 * self.native.prepared_block_min_bytes()
    }

    /// What one segment's `prepared_native` encoding plans to take: four-byte
    /// words for a two-digit key, eight-byte words for a one-digit key.
    pub fn prepared_planned_bytes(&self) -> u64 {
        PREPARED_HEADER_BYTES + self.blocks() as u64 * self.native.prepared_block_planned_bytes()
    }
}

/// Column-major u16 coefficients of a row-major table: coefficient `c` of row
/// `r` is the little-endian u16 at byte `r * row_bytes + 2 * c`, exactly the
/// bytes a client decodes. Rows shorter than `row_bytes` (never in practice)
/// read as zero.
pub fn row_coefficient(rows: &[u8], row_bytes: usize, row: usize, col: usize) -> u16 {
    let at = row * row_bytes + 2 * col;
    match rows.get(at..at + 2) {
        Some(bytes) => u16::from_le_bytes([bytes[0], bytes[1]]),
        None => 0,
    }
}
