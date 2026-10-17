//! Transparent's native PIR profiles: ReinspiRING packing with two public masks.
//!
//! The helpers themselves are the shared `zakura-pir-native` crate, which Enhance and
//! Status use as well; this crate re-exports them and adds what is
//! Transparent's own. Which parameters a table uses depends on its kind
//! ([`profile_for`]):
//!
//! - History tables (`directory`, `pages`) and the txid display table
//!   (`txdirectory`) use the 8-bit profile [`P8_PROFILE`]: one byte per
//!   coefficient, so a 4,096-byte row is two 2,048-coefficient packing blocks
//!   (and a display row of 8,192 bytes four), a one-digit `K_g` key of 13,824
//!   bytes, 22-bit masks, 28-bit dithered selections and 10-bit responses.
//! - Every other table keeps the 16-bit profile described below: one 16-bit
//!   coefficient per two bytes, so a 4,096-byte row is exactly one packing
//!   block.
//!
//! Unlike Enhance, the setup is not bound to a shard: query masks and the
//! packing setup are derived per geometry and table, so one query is answered
//! by every segment of every shard of that geometry. The masks use a zero
//! snapshot id, so they are stable across publications; each segment's
//! published masks follow from its own database.
//!
//! Every 16-bit table publishes two schemes over the same setup and masks,
//! differing only in how the selection is uploaded: [`PROFILE`] at 49 bits rounded to
//! nearest, which every wallet deployed before dithering sends, and
//! [`DITHERED_PROFILE`] at 44 dithered bits (see `zakura-pir-native`). A server
//! accepts both, telling them apart by the body's exact length, so a wallet
//! that does not know the dithered scheme is unaffected. A wallet that
//! re-derives the dithered scheme the service advertises sends 44 bits;
//! otherwise it sends 49.
//!
//! An 8-bit table publishes one scheme, its 28-bit dithered query.
//!
//! Correctness certificates are snapshot-specific, and a 16-bit snapshot is
//! served at both widths, so it needs both: see
//! `examples/native_certificate.rs` in the shard server.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zakura_pir_native::{request_len_bits, D, DITHERED_QUERY_BITS, Q_BITS};
pub use zakura_pir_native::{NativeSetup, Profile, P16, P8};

/// Domain-separated first-dimension masks for a `rows` by `cols` database
/// under [`P16`], with a refused shape returned as an error. This shadows
/// `zakura_pir_native`'s panicking function of the same name.
pub fn public_query_masks(
    seed: [u8; 32],
    rows: usize,
    cols: usize,
) -> Result<Vec<Vec<u64>>, String> {
    P16.public_query_masks(seed, rows, cols)
}

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pir_native::{public_len, request_len, response_len};

    #[test]
    fn sizes_are_the_deployed_profile() {
        assert_eq!(public_len(D), 14_848);
        assert_eq!(response_len(D), 5_632);
        // The 49-bit query every deployed wallet sends.
        assert_eq!(request_len(2_048), 27_648 + 12_544);
        assert_eq!(request_len(65_536), 27_648 + 401_408);
        // The 44-bit dithered query.
        assert_eq!(dithered_request_len(2_048), 27_648 + 11_264);
        assert_eq!(dithered_request_len(4_096), 27_648 + 22_528);
        assert_eq!(dithered_request_len(32_768), 27_648 + 180_224);
        assert_eq!(dithered_request_len(65_536), 27_648 + 360_448);
    }

    /// The dithered scheme is the legacy one with the query alone changed, and
    /// the legacy scheme is what it always was.
    #[test]
    fn the_dithered_scheme_differs_only_in_its_query() {
        let p = TableProfile::new("s", "g", "t", 8_192, 4_096).unwrap();
        let dithered = p.dithered_scheme.clone().unwrap();
        assert_eq!(p.scheme.profile, PROFILE);
        assert_eq!(p.scheme.query_bits, 49);
        assert_eq!(p.scheme.request_bytes, 27_648 + 50_176);
        assert_eq!(dithered.profile, "reinspiring-two-mask-m29-dq44-v1");
        assert_eq!(dithered.query_bits, 44);
        assert_eq!(dithered.request_bytes, 27_648 + 45_056);
        let mut back = dithered.clone();
        back.profile = p.scheme.profile.clone();
        back.query_bits = p.scheme.query_bits;
        back.request_bytes = p.scheme.request_bytes;
        assert_eq!(back, p.scheme);
        assert_ne!(dithered.digest(), p.scheme.digest());
    }

    #[test]
    fn seeds_are_distinct_per_geometry_table_and_schema() {
        let a = table_seeds("s", "g", "directory");
        assert_ne!(a, table_seeds("s", "g", "pages"));
        assert_ne!(a, table_seeds("s", "h", "directory"));
        assert_ne!(a, table_seeds("t", "g", "directory"));
        assert_ne!(a.query_masks, a.packing);
    }

    #[test]
    fn a_profile_refuses_shapes_the_scheme_would_not_serve() {
        assert!(TableProfile::new("s", "g", "t", 3_000, 4_096).is_err());
        assert!(TableProfile::new("s", "g", "t", 2_048, 3_584).is_err());
        let p = TableProfile::new("s", "g", "t", 4_096, 4_096).unwrap();
        assert_eq!(p.scheme.request_bytes, request_len(4_096));
        assert_eq!(p.masks.len(), 2);
    }

    /// History tables are 8-bit: one byte per coefficient, two blocks per
    /// 4,096-byte row, one 28-bit dithered scheme and no second one.
    #[test]
    fn history_tables_use_the_8_bit_scheme() {
        for table in ["directory", "pages"] {
            let p = TableProfile::new("s", "g", table, 2_048, 4_096).unwrap();
            assert_eq!(p.native, P8);
            assert_eq!((p.cols, p.blocks()), (4_096, 2));
            assert_eq!(p.scheme.profile, P8_PROFILE);
            assert_eq!(
                (p.scheme.p_bits, p.scheme.gadget_bits, p.scheme.ell),
                (8, 27, 1)
            );
            assert_eq!((p.scheme.mask_bits, p.scheme.query_bits), (22, 28));
            assert_eq!(p.scheme.response_bits, 10);
            assert_eq!(p.scheme.request_bytes, 13_824 + 7_168);
            assert_eq!(p.scheme.public_bytes, 22_528);
            assert_eq!(p.scheme.response_bytes, 5_120);
            assert!(p.dithered_scheme.is_none());
        }
        assert_ne!(
            table_seeds("s", "g", "directory"),
            table_seeds("s", "g", "txdirectory")
        );
    }

    /// The txid display table is 8-bit too: its 8,192-byte rows are four
    /// blocks, and its one scheme is the 28-bit dithered query.
    #[test]
    fn the_display_table_uses_the_8_bit_scheme() {
        let p = TableProfile::new("s", "txid-2k8", "txdirectory", 2_048, 8_192).unwrap();
        assert_eq!(p.native, P8);
        assert_eq!((p.cols, p.blocks()), (8_192, 4));
        assert_eq!(p.scheme.profile, P8_PROFILE);
        assert_eq!(p.scheme.request_bytes, 13_824 + 7_168);
        assert_eq!(p.scheme.public_bytes, 2 * 22_528);
        assert_eq!(p.scheme.response_bytes, 2 * 5_120);
        assert!(p.dithered_scheme.is_none());
    }
}
