//! Native operations owned by the client role.
use ipir_native_client::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use reinspiring::native::NativeTwoMaskCiphertext;
pub use reinspiring::native::{NativeKeys, NativePreprocessed, NativeSecret};
pub use zakura_pir_protocol::native::*;
/// Operations available only to this role.
pub trait ProfileClientExt {
    /// Fresh secret, one-key packing upload and the profile's own selection
    /// ([`Self::primary_bits`]): 49 bits to nearest for [`P16`], 28 dithered
    /// bits for [`P8`].
    fn prepare(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String>;
    /// Fresh secret, one-key packing upload and dithered selection.
    fn prepare_dithered(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String>;
    /// Fresh secret, one-key packing upload and dithered selection over a
    /// caller's generator; see the free [`prepare_dithered_with`].
    fn prepare_dithered_with(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        rng: &mut ChaCha20Rng,
    ) -> Result<(NativeSecret, Vec<u8>), String>;
    /// Decodes every plaintext coefficient of a two-mask response, each as
    /// `entry_bytes` little-endian bytes.
    fn decode_cols(
        &self,
        secret: &NativeSecret,
        public: &[u8],
        body: &[u8],
        cols: usize,
    ) -> Result<Vec<u8>, String>;
}
impl ProfileClientExt for Profile {
    /// Fresh secret, one-key packing upload and the profile's own selection
    /// ([`Self::primary_bits`]): 49 bits to nearest for [`P16`], 28 dithered
    /// bits for [`P8`].
    fn prepare(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        let mut entropy = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let rng = &mut ChaCha20Rng::from_seed(entropy);
        let (bits, dithered) = match self.nearest_bits {
            Some(bits) => (bits, false),
            None => (self.dithered_bits, true),
        };
        prepare_rounded(self, setup, masks, rows, target, (bits, dithered), rng)
    }

    /// Fresh secret, one-key packing upload and dithered selection.
    fn prepare_dithered(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        let mut entropy = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        self.prepare_dithered_with(
            setup,
            masks,
            rows,
            target,
            &mut ChaCha20Rng::from_seed(entropy),
        )
    }

    /// Fresh secret, one-key packing upload and dithered selection over a
    /// caller's generator; see the free [`prepare_dithered_with`].
    fn prepare_dithered_with(
        &self,
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        rng: &mut ChaCha20Rng,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        prepare_rounded(
            self,
            setup,
            masks,
            rows,
            target,
            (self.dithered_bits, true),
            rng,
        )
    }

    /// Decodes every plaintext coefficient of a two-mask response, each as
    /// `entry_bytes` little-endian bytes.
    fn decode_cols(
        &self,
        secret: &NativeSecret,
        public: &[u8],
        body: &[u8],
        cols: usize,
    ) -> Result<Vec<u8>, String> {
        if cols == 0
            || !cols.is_multiple_of(D)
            || public.len() != self.public_len(cols)
            || body.len() != self.response_len(cols)
        {
            return Err("native response shape".into());
        }
        let masks: Vec<_> = contiguous_bytes_to_u64s(public, self.mask_bits)
            .into_iter()
            .map(|x| x << (Q_BITS - self.mask_bits))
            .collect();
        let (a, a_other) = masks[..2 * cols].split_at(cols);
        let b: Vec<_> = contiguous_bytes_to_u64s(body, self.response_bits)
            .into_iter()
            .map(|x| x << (Q_BITS - self.response_bits))
            .collect();
        let params = self.params();
        let entry = self.entry_bytes();
        let mut out = Vec::with_capacity(cols * entry);
        for ((a, a_other), b) in a
            .as_chunks::<D>()
            .0
            .iter()
            .zip(a_other.as_chunks::<D>().0)
            .zip(b[..cols].as_chunks::<D>().0)
        {
            let ct = NativeTwoMaskCiphertext::from_rows(
                &params,
                a.to_vec(),
                a_other.to_vec(),
                b.to_vec(),
            )
            .map_err(|e| e.to_string())?;
            for x in secret.decrypt_two_mask(&ct).map_err(|e| e.to_string())? {
                out.extend(&(x as u16).to_le_bytes()[..entry]);
            }
        }
        Ok(out)
    }
}
/// Fresh secret, one-key packing upload and 49-bit selection query.
pub fn prepare_with(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    P16.prepare(setup, masks, rows, target)
}

/// Fresh secret, one-key packing upload and 44-bit dithered selection query.
pub fn prepare_dithered(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
) -> Result<(NativeSecret, Vec<u8>), String> {
    let mut entropy = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    prepare_dithered_with(
        setup,
        masks,
        rows,
        target,
        &mut ChaCha20Rng::from_seed(entropy),
    )
}

/// [`prepare_dithered`] over a caller's generator, which must be freshly and
/// secretly seeded for every query: it draws the secret, the packing key, the
/// selection's errors and then one rounding coin per row, in that order.
///
/// The coins are what makes the rounding errors independent and zero mean.
/// Coins an observer could predict would let it bias the errors, and coins
/// reused across queries would correlate them, so they come from the same
/// per-query generator as the secret.
pub fn prepare_dithered_with(
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
    rng: &mut ChaCha20Rng,
) -> Result<(NativeSecret, Vec<u8>), String> {
    P16.prepare_dithered_with(setup, masks, rows, target, rng)
}

/// Decodes every little-endian u16 plaintext coefficient of a two-mask response.
///
/// Unlike [`Profile::decode_cols`], zero columns with empty material decode to
/// nothing, as this function always has.
pub fn decode_cols(
    secret: &NativeSecret,
    public: &[u8],
    body: &[u8],
    cols: usize,
) -> Result<Vec<u8>, String> {
    if cols == 0 && public.is_empty() && body.is_empty() {
        return Ok(Vec::new());
    }
    P16.decode_cols(secret, public, body, cols)
}

/// Draws the secret, the packing key, the selection's errors and, when
/// dithered, one rounding coin per row, in that order.
fn prepare_rounded(
    profile: &Profile,
    setup: &NativeSetup,
    masks: &[Vec<u64>],
    rows: usize,
    target: usize,
    (bits, dithered): (usize, bool),
    rng: &mut ChaCha20Rng,
) -> Result<(NativeSecret, Vec<u8>), String> {
    if target >= rows || !rows.is_multiple_of(D) || masks.len() < rows / D {
        return Err("native query shape".into());
    }
    let secret = NativeSecret::sample(&profile.params(), rng);
    let keys = NativeKeys::generate_one_key(setup, &secret, rng).map_err(|e| e.to_string())?;
    let query = secret
        .encrypt_selection(&masks[..rows / D], target, rng)
        .map_err(|e| e.to_string())?;
    let mut bytes = u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS);
    let switched: Vec<_> = if dithered {
        query
            .iter()
            .map(|&x| round_dithered(x, bits, rng.next_u64()))
            .collect()
    } else {
        query.iter().map(|&x| round(x, bits)).collect()
    };
    bytes.extend(u64s_to_contiguous_bytes(&switched, bits));
    Ok((secret, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pir_query_server::native::test_server;

    use rand::Rng;

    /// The library's request construction over a caller's generator, at the
    /// nearest or dithered width.
    fn prepare_from(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        dithered: bool,
        rng: &mut ChaCha20Rng,
    ) -> Result<(NativeSecret, Vec<u8>), String> {
        if dithered {
            prepare_dithered_with(setup, masks, rows, target, rng)
        } else {
            prepare_rounded(&P16, setup, masks, rows, target, (QUERY_BITS, false), rng)
        }
    }

    /// One dithered rounding coin per word, drawn from `rng`.
    fn dither(words: &[u64], bits: usize, rng: &mut ChaCha20Rng) -> Vec<u64> {
        words
            .iter()
            .map(|&x| round_dithered(x, bits, rng.next_u64()))
            .collect()
    }

    /// End-to-end over the library primitives a server uses: two-mask
    /// preprocessing, one-key upload, 29-bit masks and 22-bit responses.
    #[test]
    fn two_mask_rounded_roundtrip() {
        let (rows, cols) = (D, D);
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let setup = packing_setup([9; 32]);
        let server = test_server::Database::new(db.clone(), &masks, [9; 32]);
        assert_eq!(server.public().len(), public_len(cols));
        let target = 1234;
        let (secret, body) = prepare_with(&setup, &masks, rows, target).unwrap();
        assert_eq!(body.len(), request_len(rows));
        let response = server.answer(&body);
        assert_eq!(response.len(), response_len(cols));
        let row = decode_cols(&secret, server.public(), &response, cols).unwrap();
        let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
        assert_eq!(row, expected);
    }

    /// Over a table whose second block is zero, a selection over only the
    /// first block, under the leading full-shape masks, decodes the target.
    #[test]
    fn prefix_selection_over_a_zero_tail_roundtrips() {
        let (rows, cols) = (2 * D, D);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| {
                (0..rows)
                    .map(|r| if r < D { rng.r#gen() } else { 0 })
                    .collect()
            })
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let setup = packing_setup([9; 32]);
        let server = test_server::Database::new(db.clone(), &masks, [9; 32]);
        let target = 1234;
        let (secret, body) = prepare_with(&setup, &masks, D, target).unwrap();
        assert_eq!(body.len(), request_len(D));
        let row = decode_cols(&secret, server.public(), &server.answer(&body), cols).unwrap();
        let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
        assert_eq!(row, expected);
    }

    #[test]
    fn rounding_and_shape_checks() {
        assert_eq!(round(0, QUERY_BITS), 0);
        assert_eq!(round(Q - 1, QUERY_BITS), 0);
        assert_eq!(round(Q / 2, MASK_BITS), 1 << (MASK_BITS - 1));
        assert_eq!(KEY_BYTES, 27_648);
        let setup = packing_setup([9; 32]);
        let masks = public_query_masks([3; 32], D, D);
        assert!(prepare_with(&setup, &masks, D, D).is_err());
        assert!(prepare_with(&setup, &masks, D + 1, 0).is_err());
        assert!(prepare_with(&setup, &masks, 2 * D, 0).is_err());
        let (secret, _) = prepare_with(&setup, &masks, D, D - 1).unwrap();
        assert!(decode_cols(&secret, &vec![0; public_len(D)], &[0; 1], D).is_err());
        assert!(decode_cols(&secret, &[0; 1], &vec![0; response_len(D)], D).is_err());
        assert!(
            decode_cols(
                &secret,
                &vec![0; public_len(D + 1)],
                &vec![0; response_len(D + 1)],
                D + 1
            )
            .is_err()
        );
    }

    /// The draws a request makes before rounding, rebuilt by hand from the RNG
    /// order: secret, packing key, selection. Returns the key bytes, the
    /// unrounded selection and the RNG positioned at the first rounding coin.
    fn draw(
        setup: &NativeSetup,
        masks: &[Vec<u64>],
        rows: usize,
        target: usize,
        seed: u64,
    ) -> (Vec<u8>, Vec<u64>, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let secret = NativeSecret::sample(&params(), &mut rng);
        let keys = NativeKeys::generate_one_key(setup, &secret, &mut rng).unwrap();
        let query = secret
            .encrypt_selection(&masks[..rows / D], target, &mut rng)
            .unwrap();
        (
            u64s_to_contiguous_bytes(&keys.kg_words(), Q_BITS),
            query,
            rng,
        )
    }

    #[test]
    fn requests_match_hand_rebuild_and_dithering_uses_its_coins() {
        let rows = 2 * D;
        let setup = packing_setup([9; 32]);
        let masks = public_query_masks([3; 32], rows, D);
        assert!(prepare_dithered(&setup, &masks, rows, rows).is_err());
        assert!(prepare_dithered(&setup, &masks, D + 1, 0).is_err());
        assert!(prepare_dithered(&setup, &masks, 2 * rows, 0).is_err());
        assert_eq!(request_len_bits(rows, QUERY_BITS), request_len(rows));
        assert_eq!(
            request_len_bits(rows, DITHERED_QUERY_BITS),
            KEY_BYTES + 22_528
        );
        let encode = |words: &[u64], bits| u64s_to_contiguous_bytes(words, bits);
        let nearest_at = |query: &[u64], bits: usize| -> Vec<u64> {
            let shift = Q_BITS - bits;
            query
                .iter()
                .map(|&x| ((x + (1 << (shift - 1))) >> shift) % (1 << bits))
                .collect()
        };
        for (target, seed) in [(0, 42), (rows - 1, 43)] {
            let prepare = |dithered| {
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                prepare_from(&setup, &masks, rows, target, dithered, &mut rng)
                    .unwrap()
                    .1
            };
            let (key, query, mut rng) = draw(&setup, &masks, rows, target, seed);
            // Nearest: the unchanged 49-bit request.
            let nearest = prepare(false);
            assert_eq!(
                nearest,
                [
                    key.clone(),
                    encode(&nearest_at(&query, QUERY_BITS), QUERY_BITS)
                ]
                .concat()
            );
            assert_eq!(nearest.len(), request_len(rows));
            // Dithered: the same draws, then one coin per row; round up when
            // the coin falls below the dropped fraction.
            let shift = Q_BITS - DITHERED_QUERY_BITS;
            let coins: Vec<u64> = query
                .iter()
                .map(|&x| {
                    let up = u64::from(rng.next_u64() % (1 << shift) < x % (1 << shift));
                    ((x >> shift) + up) % (1 << DITHERED_QUERY_BITS)
                })
                .collect();
            let dithered = prepare(true);
            assert_eq!(
                dithered,
                [key.clone(), encode(&coins, DITHERED_QUERY_BITS)].concat()
            );
            assert_eq!(dithered.len(), request_len_bits(rows, DITHERED_QUERY_BITS));
            // Nearest rounding at the same width differs only in the
            // selection, so this fails if the coins are ever skipped.
            let flat = [
                key,
                encode(
                    &nearest_at(&query, DITHERED_QUERY_BITS),
                    DITHERED_QUERY_BITS,
                ),
            ]
            .concat();
            assert_eq!(flat.len(), dithered.len());
            assert_eq!(flat[..KEY_BYTES], dithered[..KEY_BYTES]);
            assert_ne!(flat, dithered);
        }
    }

    #[test]
    fn dithered_rounding_is_unbiased_floor_or_ceiling() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for bits in [DITHERED_QUERY_BITS, QUERY_BITS] {
            let shift = Q_BITS - bits;
            let unit = 1u64 << shift;
            let mask = (1u64 << bits) - 1;
            // Exact multiples never move, whatever the coins.
            let exact = [0, unit, Q - unit];
            assert_eq!(
                dither(&exact, bits, &mut rng),
                exact.iter().map(|&x| x >> shift).collect::<Vec<_>>()
            );
            for x in [1, unit / 4, unit / 2, unit - 1, Q - 1, Q - unit / 3] {
                let trials = 1 << 16;
                let floor = x >> shift;
                let ups = dither(&vec![x; trials], bits, &mut rng)
                    .into_iter()
                    .filter(|&y| {
                        // Only floor or ceiling; the ceiling of Q-1 wraps to 0.
                        assert!(y == floor || y == (floor + 1) & mask);
                        y != floor
                    })
                    .count();
                // Round-up frequency matches the dropped fraction (zero-mean
                // error): within 6 binomial standard deviations at p = 1/2.
                let expected = trials as f64 * (x & (unit - 1)) as f64 / unit as f64;
                let sd = (trials as f64 / 4.0).sqrt();
                assert!(
                    (ups as f64 - expected).abs() <= 6.0 * sd,
                    "bits={bits} x={x}: {ups} round-ups, expected {expected}"
                );
            }
        }
    }

    /// One server answers both selection widths, chosen by exact length.
    #[test]
    fn dithered_and_nearest_requests_share_a_server() {
        let (rows, cols) = (D, D);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let db: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        let masks = public_query_masks([3; 32], rows, cols);
        let setup = packing_setup([9; 32]);
        let server = test_server::Database::new(db.clone(), &masks, [9; 32]);
        for (target, dithered) in [(1234, true), (0, true), (rows - 1, true), (77, false)] {
            let (secret, body) = if dithered {
                prepare_dithered(&setup, &masks, rows, target).unwrap()
            } else {
                prepare_with(&setup, &masks, rows, target).unwrap()
            };
            let bits = if dithered {
                DITHERED_QUERY_BITS
            } else {
                QUERY_BITS
            };
            assert_eq!(body.len(), request_len_bits(rows, bits));
            let response = server.answer(&body);
            assert_eq!(response.len(), response_len(cols));
            let row = decode_cols(&secret, server.public(), &response, cols).unwrap();
            let expected: Vec<u8> = db.iter().flat_map(|c| c[target].to_le_bytes()).collect();
            assert_eq!(row, expected, "target={target} dithered={dithered}");
        }
        let other = vec![0; request_len_bits(rows, 45)];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| server.answer(&other)))
                .is_err()
        );
    }

    /// Dithered rounding moves only to the floor or the ceiling, never moves an
    /// exact multiple, and rounds up as often as the dropped fraction says:
    /// the errors have zero mean. Six binomial standard deviations at p = 1/2.
    #[test]
    fn dithered_rounding_is_an_unbiased_floor_or_ceiling() {
        let mut rng = ChaCha20Rng::from_seed([21; 32]);
        for bits in [DITHERED_QUERY_BITS, QUERY_BITS] {
            let shift = Q_BITS - bits;
            let unit = 1u64 << shift;
            let mask = (1u64 << bits) - 1;
            for x in [0, unit, Q - unit] {
                for _ in 0..64 {
                    assert_eq!(round_dithered(x, bits, rng.next_u64()), x >> shift);
                }
            }
            for x in [
                1,
                unit / 4,
                unit / 2,
                unit - 1,
                Q - 1,
                Q - unit / 3,
                0x2a5f_0123_4567,
            ] {
                let trials = 1u32 << 16;
                let floor = x >> shift;
                let ups = (0..trials)
                    .filter(|_| {
                        let y = round_dithered(x, bits, rng.next_u64());
                        // The ceiling of the top coefficient wraps to zero, mod q.
                        assert!(y == floor || y == (floor + 1) & mask, "bits={bits} x={x}");
                        y != floor
                    })
                    .count() as f64;
                let expected = trials as f64 * (x & (unit - 1)) as f64 / unit as f64;
                let sd = (trials as f64 / 4.0).sqrt();
                assert!(
                    (ups - expected).abs() <= 6.0 * sd,
                    "bits={bits} x={x}: {ups} round-ups, expected {expected}"
                );
            }
        }
    }

    /// Exactly one width matches any length, and the 49-bit length is the
    /// legacy `request_len`.
    #[test]
    fn each_accepted_length_names_one_width() {
        for rows in [D, 2 * D, 4 * D, 16 * D, 32 * D] {
            let legacy = request_len(rows);
            let dithered = request_len_bits(rows, DITHERED_QUERY_BITS);
            assert_eq!(legacy, request_len_bits(rows, QUERY_BITS));
            assert_eq!(accepted_query_bits(rows, legacy), Some(QUERY_BITS));
            assert_eq!(
                accepted_query_bits(rows, dithered),
                Some(DITHERED_QUERY_BITS)
            );
            assert_eq!(legacy - dithered, rows * 5 / 8);
            for len in [
                dithered - 1,
                dithered + 1,
                legacy - 1,
                legacy + 1,
                KEY_BYTES,
                0,
            ] {
                assert_eq!(
                    accepted_query_bits(rows, len),
                    None,
                    "{rows} rows, {len} bytes"
                );
            }
        }
    }
}
