//! Transparent operations for this role.
pub use crate::native::*;
pub use zakura_pir_protocol::transparent::native::*;
/// Operations owned by this role.
pub trait TableClientExt {
    /// Fresh secret and upload selecting row `target` under [`Self::scheme`]:
    /// 49 bits to nearest for a 16-bit table, 28 dithered bits for an 8-bit
    /// one.
    fn prepare(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String>;
    /// Fresh secret and dithered upload selecting row `target`: under
    /// [`Self::dithered_scheme`] for a 16-bit table, and the same as
    /// [`Self::prepare`] for an 8-bit one.
    fn prepare_dithered(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String>;
    /// [`Self::prepare`] selecting among only the first `query_rows`, under
    /// the leading full-shape masks. `query_rows` must be public and the same
    /// for every query to the table.
    fn prepare_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String>;
    /// [`Self::prepare_dithered`] selecting among only the first `query_rows`;
    /// see [`Self::prepare_prefix`].
    fn prepare_dithered_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String>;
    /// Decodes one segment's body under that segment's published masks,
    /// truncated to the row width.
    fn decode(&self, secret: &NativeSecret, public: &[u8], body: &[u8]) -> Result<Vec<u8>, String>;
}
impl TableClientExt for TableProfile {
    /// Fresh secret and upload selecting row `target` under [`Self::scheme`]:
    /// 49 bits to nearest for a 16-bit table, 28 dithered bits for an 8-bit
    /// one.
    fn prepare(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String> {
        self.native
            .prepare(&self.setup, &self.masks, self.rows, target)
    }

    /// Fresh secret and dithered upload selecting row `target`: under
    /// [`Self::dithered_scheme`] for a 16-bit table, and the same as
    /// [`Self::prepare`] for an 8-bit one.
    fn prepare_dithered(&self, target: usize) -> Result<(NativeSecret, Vec<u8>), String> {
        self.prepare_dithered_prefix(self.rows, target)
    }

    /// [`Self::prepare`] selecting among only the first `query_rows`, under
    /// the leading full-shape masks. `query_rows` must be public and the same
    /// for every query to the table.
    fn prepare_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        if query_rows > self.rows {
            return Err("native query shape".into());
        }
        self.native
            .prepare(&self.setup, &self.masks, query_rows, target)
    }

    /// [`Self::prepare_dithered`] selecting among only the first `query_rows`;
    /// see [`Self::prepare_prefix`].
    fn prepare_dithered_prefix(
        &self,
        query_rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        if query_rows > self.rows {
            return Err("native query shape".into());
        }
        self.native
            .prepare_dithered(&self.setup, &self.masks, query_rows, target)
    }

    /// Decodes one segment's body under that segment's published masks,
    /// truncated to the row width.
    fn decode(&self, secret: &NativeSecret, public: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
        let mut row = self.native.decode_cols(secret, public, body, self.cols)?;
        row.truncate(self.row_bytes);
        Ok(row)
    }
}
pub fn public_query_masks(
    seed: [u8; 32],
    rows: usize,
    cols: usize,
) -> Result<Vec<Vec<u64>>, String> {
    P16.public_query_masks(seed, rows, cols)
}
pub fn decode_cols(
    secret: &NativeSecret,
    public: &[u8],
    body: &[u8],
    cols: usize,
) -> Result<Vec<u8>, String> {
    P16.decode_cols(secret, public, body, cols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use zakura_pir_query_server::native::{ProfileQueryExt as _, pack};
    use zakura_pir_query_server::transparent::native::TableQueryExt as _;
    use zakura_pir_server_core::batched_hint;
    use zakura_pir_server_core::native::{ProfilePublicationExt as _, hint, preprocess, publish};

    fn database(rows: usize, cols: usize, seed: u8) -> Vec<u16> {
        // Column-major, deterministic, spanning the whole u16 range.
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        (0..rows * cols).map(|_| rng.next_u32() as u16).collect()
    }

    fn scan(db: &[u16], rows: usize, cols: usize, query: &[u64]) -> Vec<u64> {
        (0..cols)
            .map(|c| {
                db[c * rows..(c + 1) * rows]
                    .iter()
                    .zip(query)
                    .fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    })
                    & (Q - 1)
            })
            .collect()
    }

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

    /// End-to-end over the primitives the server and wallet use.
    #[test]
    fn two_mask_rounded_roundtrip() {
        let profile = TableProfile::new("test", "g", "t", 4_096, 4_096).unwrap();
        let (rows, cols) = (profile.rows, profile.cols);
        let db = database(rows, cols, 7);
        let hint = hint(&profile.masks, rows, cols, |c| {
            &db[c * rows..(c + 1) * rows]
        })
        .unwrap();
        let blocks = preprocess(&profile.setup, &hint).unwrap();
        let published = publish(&blocks).unwrap();
        assert_eq!(published.len(), profile.scheme.public_bytes);
        for target in [0, 1234, rows - 1] {
            let (secret, body) = profile.prepare(target).unwrap();
            assert_eq!(body.len(), profile.scheme.request_bytes);
            let (keys, query) = profile.parse(&body).unwrap();
            let response = pack(&blocks, &keys, &scan(&db, rows, cols, &query)).unwrap();
            assert_eq!(response.len(), profile.scheme.response_bytes);
            let row = profile.decode(&secret, &published, &response).unwrap();
            let expected: Vec<u8> = (0..cols)
                .flat_map(|c| db[c * rows + target].to_le_bytes())
                .collect();
            assert_eq!(row, expected, "target {target}");
        }
        // The dithered query decodes the same rows, through the same parse.
        for target in [0, 2_047, rows - 1] {
            let (secret, body) = profile.prepare_dithered(target).unwrap();
            assert_eq!(
                body.len(),
                profile.dithered_scheme.as_ref().unwrap().request_bytes
            );
            assert!(profile.accepts_request_len(body.len()));
            let (keys, query) = profile.parse(&body).unwrap();
            let response = pack(&blocks, &keys, &scan(&db, rows, cols, &query)).unwrap();
            let row = profile.decode(&secret, &published, &response).unwrap();
            let expected: Vec<u8> = (0..cols)
                .flat_map(|c| db[c * rows + target].to_le_bytes())
                .collect();
            assert_eq!(row, expected, "dithered target {target}");
        }
        // Only those two lengths parse.
        for len in [
            profile.scheme.request_bytes - 1,
            profile.scheme.request_bytes + 1,
            profile.dithered_scheme.as_ref().unwrap().request_bytes - 1,
            profile.dithered_scheme.as_ref().unwrap().request_bytes + 1,
        ] {
            assert!(!profile.accepts_request_len(len));
            assert!(profile.parse(&vec![0; len]).is_err(), "{len} bytes");
        }
        // A key from another table's setup is refused rather than packed.
        let other = TableProfile::new("test", "g", "txother", 4_096, 4_096).unwrap();
        let (_, body) = other.prepare(0).unwrap();
        let (keys, query) = other.parse(&body).unwrap();
        assert!(pack(&blocks, &keys, &scan(&db, rows, cols, &query)).is_err());
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
            assert_eq!(p.database_bytes(), 2_048 * 4_096);
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

    /// End to end over an 8-bit history table, full and prefix uploads.
    #[test]
    fn eight_bit_roundtrip() {
        let profile = TableProfile::new("test", "g", "pages", 4_096, 4_096).unwrap();
        let (rows, cols) = (profile.rows, profile.cols);
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        // Column-major bytes; rows from 2,048 on are zero, for the prefix.
        let mut db = vec![0u8; rows * cols];
        for c in 0..cols {
            for r in 0..D {
                db[c * rows + r] = rng.next_u32() as u8;
            }
        }
        let hint = hint(&profile.masks, rows, cols, |c| {
            &db[c * rows..(c + 1) * rows]
        })
        .unwrap();
        assert_eq!(
            hint,
            batched_hint::hint(&profile.masks, rows, cols, |c| &db
                [c * rows..(c + 1) * rows])
            .unwrap()
        );
        let blocks = preprocess(&profile.setup, &hint).unwrap();
        let published = profile.native.publish(&blocks).unwrap();
        assert_eq!(published.len(), profile.scheme.public_bytes);
        let scan = |query: &[u64]| -> Vec<u64> {
            (0..cols)
                .map(|c| {
                    db[c * rows..(c + 1) * rows]
                        .iter()
                        .zip(query)
                        .fold(0u64, |a, (&x, &q)| {
                            a.wrapping_add((x as u64).wrapping_mul(q))
                        })
                        & (Q - 1)
                })
                .collect()
        };
        for target in [0, 1_234, D - 1] {
            let expected: Vec<u8> = (0..cols).map(|c| db[c * rows + target]).collect();
            for (secret, body) in [
                profile.prepare(target).unwrap(),
                profile.prepare_prefix(D, target).unwrap(),
            ] {
                assert!(profile.accepts_selection_len(D, body.len()));
                let (keys, query) = profile.parse_selection(&body, D).unwrap();
                let response = profile.native.pack(&blocks, &keys, &scan(&query)).unwrap();
                assert_eq!(response.len(), profile.scheme.response_bytes);
                let row = profile.decode(&secret, &published, &response).unwrap();
                assert_eq!(row, expected, "target {target}");
            }
        }
        // The 16-bit lengths are refused.
        assert!(!profile.accepts_request_len(request_len(rows)));
        assert!(!profile.accepts_request_len(dithered_request_len(rows)));
    }

    /// Transparent's response decoder refuses an empty response for zero
    /// columns, as it always has, rather than taking `zakura-pir-native`'s.
    #[test]
    fn decode_cols_refuses_zero_columns() {
        let profile = TableProfile::new("test", "g", "t", 4_096, 4_096).unwrap();
        let (secret, _) = profile.prepare(0).unwrap();
        assert_eq!(
            decode_cols(&secret, &[], &[], 0),
            Err("native response shape".to_string())
        );
    }

    #[test]
    fn row_coefficients_match_the_bit_reader() {
        let rows: Vec<u8> = (0..2 * 4_096).map(|i| (i * 37 % 251) as u8).collect();
        for (row, col) in [(0, 0), (0, 2_047), (1, 5), (1, 2_047)] {
            assert_eq!(
                row_coefficient(&rows, 4_096, row, col) as u64,
                (0..16).fold(0u64, |value, bit| {
                    let offset = row * 4_096 * 8 + col * 16 + bit;
                    value | (u64::from((rows[offset / 8] >> (offset % 8)) & 1) << bit)
                })
            );
        }
    }
}
