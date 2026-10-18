//! Native operations owned by the query-server role.
use rayon::prelude::*;
pub use reinspiring::native::{NativeKeys, NativePreprocessed, NativeSecret};
use std::borrow::Borrow;
use zakura_pir_protocol::native::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
pub use zakura_pir_protocol::native::*;
pub use zakura_pir_server_core::native::{ProfilePublicationExt, publish};
/// Operations available only to this role.
pub trait ProfileQueryExt {
    /// Parses an upload whose selection was sent at `bits`, one of the
    /// profile's widths, into its packing key and the selection lifted back
    /// to `q`.
    ///
    /// The lift is the same for either rounding rule: a coefficient sent at
    /// `bits` stands for itself times `2^(Q_BITS - bits)`.
    fn parse_bits(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        rows: usize,
        bits: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String>;
    /// Parses an upload at whichever width its exact length names.
    fn parse_accepted(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String>;
    /// Parses a full or prefix upload and returns the selection over every
    /// row; see the free [`parse_selection`].
    fn parse_selection(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        query_rows: usize,
        rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String>;
    /// Prepares one uploaded key for every block, then finishes each block
    /// with its scan result. Returns the switched response bodies.
    fn pack<B: Borrow<NativePreprocessed> + Sync>(
        &self,
        blocks: &[B],
        keys: &NativeKeys,
        intermediate: &[u64],
    ) -> Result<Vec<u8>, String>;
    /// Rounds response bodies to `response_bits` and bit-packs them.
    fn response(&self, bodies: &[u64]) -> Vec<u8>;
}
impl ProfileQueryExt for Profile {
    /// Parses an upload whose selection was sent at `bits`, one of the
    /// profile's widths, into its packing key and the selection lifted back
    /// to `q`.
    ///
    /// The lift is the same for either rounding rule: a coefficient sent at
    /// `bits` stands for itself times `2^(Q_BITS - bits)`.
    fn parse_bits(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        rows: usize,
        bits: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        if !(Some(bits) == self.nearest_bits || bits == self.dithered_bits)
            || rows == 0
            || !rows.is_multiple_of(D)
            || bytes.len() != self.request_len_bits(rows, bits)
        {
            return Err("native query framing".into());
        }
        let key_bytes = self.key_bytes();
        let keys = NativeKeys::from_kg_words(
            setup,
            &contiguous_bytes_to_u64s(&bytes[..key_bytes], Q_BITS),
        )
        .map_err(|e| e.to_string())?;
        let mut query: Vec<u64> = contiguous_bytes_to_u64s(&bytes[key_bytes..], bits)
            .into_iter()
            .map(|x| x << (Q_BITS - bits))
            .collect();
        // The packing leaves up to seven padding bits, which decode as one
        // extra coefficient when they fill a whole word. They are never part
        // of the query.
        query.truncate(rows);
        if query.len() != rows {
            return Err("native query framing".into());
        }
        Ok((keys, query))
    }

    /// Parses an upload at whichever width its exact length names.
    fn parse_accepted(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        let bits = self
            .accepted_query_bits(rows, bytes.len())
            .ok_or("native query framing")?;
        self.parse_bits(setup, bytes, rows, bits)
    }

    /// Parses a full or prefix upload and returns the selection over every
    /// row; see the free [`parse_selection`].
    fn parse_selection(
        &self,
        setup: &NativeSetup,
        bytes: &[u8],
        query_rows: usize,
        rows: usize,
    ) -> Result<(NativeKeys, Vec<u64>), String> {
        if rows == 0 || !rows.is_multiple_of(D) {
            return Err("native query framing".into());
        }
        let (sent, bits) = self
            .accepted_query_shape(rows, query_rows, bytes.len())
            .ok_or("native query framing")?;
        let (keys, mut query) = self.parse_bits(setup, bytes, sent, bits)?;
        query.resize(rows, 0);
        Ok((keys, query))
    }

    /// Prepares one uploaded key for every block, then finishes each block
    /// with its scan result. Returns the switched response bodies.
    fn pack<B: Borrow<NativePreprocessed> + Sync>(
        &self,
        blocks: &[B],
        keys: &NativeKeys,
        intermediate: &[u64],
    ) -> Result<Vec<u8>, String> {
        if blocks.is_empty()
            || intermediate.len() != blocks.len() * D
            || intermediate.iter().any(|&x| x >= Q)
        {
            return Err("native intermediate shape".into());
        }
        let prepared = blocks[0]
            .borrow()
            .prepare_keys(keys)
            .map_err(|e| e.to_string())?;
        let packed = blocks
            .par_iter()
            .zip(intermediate.par_chunks_exact(D))
            .map(|(p, b)| p.borrow().prepare_pack(&prepared)?.finish_two_mask(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let values = packed
            .iter()
            .flat_map(|ct| ct.rows().2.iter().copied())
            .collect::<Vec<_>>();
        Ok(self.response(&values))
    }

    /// Rounds response bodies to `response_bits` and bit-packs them.
    fn response(&self, bodies: &[u64]) -> Vec<u8> {
        let switched: Vec<_> = bodies
            .iter()
            .map(|&x| round(x, self.response_bits))
            .collect();
        u64s_to_contiguous_bytes(&switched, self.response_bits)
    }
}
/// Parses a 49-bit upload into its packing key and the selection lifted back
/// to `q`.
pub fn parse_with(
    setup: &NativeSetup,
    bytes: &[u8],
    rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    parse_bits(setup, bytes, rows, QUERY_BITS)
}

/// Parses an upload at whichever accepted width its exact length names; see
/// [`accepted_query_bits`]. Any other length is refused.
pub fn parse_accepted(
    setup: &NativeSetup,
    bytes: &[u8],
    rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    P16.parse_accepted(setup, bytes, rows)
}

/// Parses an upload whose selection was sent at `bits`, which must be
/// [`QUERY_BITS`] or [`DITHERED_QUERY_BITS`], into its packing key and the
/// selection lifted back to `q`.
///
/// The lift is the same for either rounding rule: a coefficient sent at
/// `bits` stands for itself times `2^(Q_BITS - bits)`.
pub fn parse_bits(
    setup: &NativeSetup,
    bytes: &[u8],
    rows: usize,
    bits: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    P16.parse_bits(setup, bytes, rows, bits)
}

/// Parses an upload over every one of `rows`, or over only the first
/// `query_rows`, at either accepted width ([`accepted_query_shape`]), and
/// returns the selection over every row, zero past what was sent.
///
/// A client may send the shorter upload when every row from `query_rows` on is
/// zero: those selection coefficients multiply zero rows, so the scan, and
/// therefore the response, is bit-identical to the full upload's. Encrypted
/// under a prefix of the full-shape masks and rounded to nearest, the shorter
/// upload is byte for byte the full one's prefix. `query_rows` must come from public,
/// session-bound geometry that every client of the table shares, never from
/// the target.
pub fn parse_selection(
    setup: &NativeSetup,
    bytes: &[u8],
    query_rows: usize,
    rows: usize,
) -> Result<(NativeKeys, Vec<u64>), String> {
    P16.parse_selection(setup, bytes, query_rows, rows)
}

/// Prepares one uploaded key for every block, then finishes each block with
/// its scan result. Returns the switched response bodies.
pub fn pack<B: Borrow<NativePreprocessed> + Sync>(
    blocks: &[B],
    keys: &NativeKeys,
    intermediate: &[u64],
) -> Result<Vec<u8>, String> {
    P16.pack(blocks, keys, intermediate)
}

/// Rounds response bodies to `RESPONSE_BITS` and bit-packs them.
pub fn response(bodies: &[u64]) -> Vec<u8> {
    P16.response(bodies)
}

#[cfg(any(test, feature = "testing"))]
pub mod test_server {
    use super::*;
    use zakura_pir_server_core::native::{hint, preprocess};

    /// An in-memory database of u16 coefficients, `db[col][row]`, with the
    /// preprocessing and published two-mask material a server would hold.
    pub struct Database {
        db: Vec<Vec<u16>>,
        setup: NativeSetup,
        blocks: Vec<NativePreprocessed>,
        public: Vec<u8>,
    }

    impl Database {
        /// `rows` and `cols` must be multiples of [`D`]; `masks` come from
        /// [`public_query_masks`] over the same shape, and `packing_seed` is
        /// the seed the client passes to [`packing_setup`].
        pub fn new(db: Vec<Vec<u16>>, masks: &[Vec<u64>], packing_seed: [u8; 32]) -> Self {
            let setup = packing_setup(packing_seed);
            let cols = db.len();
            let rows = db[0].len();
            assert!(cols.is_multiple_of(D) && rows.is_multiple_of(D));
            let hint = hint(masks, rows, cols, |c| db[c].as_slice()).unwrap();
            let blocks = preprocess(&setup, &hint).unwrap();
            let public = publish(&blocks).unwrap();
            Self {
                db,
                setup,
                blocks,
                public,
            }
        }

        /// Published two-mask material, [`public_len`] bytes.
        pub fn public(&self) -> &[u8] {
            &self.public
        }

        /// Answers a [`prepare_with`] or [`prepare_dithered`] payload with a
        /// [`response_len`] body. The selection may cover every row or, as a
        /// client omits rows that hold no data, a whole-block prefix; its
        /// row count and width come from the exact payload length, and any
        /// other length panics.
        pub fn answer(&self, payload: &[u8]) -> Vec<u8> {
            let (rows, bits) = (D..=self.db[0].len())
                .step_by(D)
                .find_map(|rows| accepted_query_bits(rows, payload.len()).map(|b| (rows, b)))
                .expect("a full or whole-block prefix selection at a supported width");
            let (keys, query) = parse_bits(&self.setup, payload, rows, bits).unwrap();
            let scan: Vec<u64> = self
                .db
                .iter()
                .map(|col| {
                    col.iter().zip(&query).fold(0u64, |a, (&x, &q)| {
                        a.wrapping_add((x as u64).wrapping_mul(q))
                    }) & (Q - 1)
                })
                .collect();
            pack(&self.blocks, &keys, &scan).unwrap()
        }
    }
}
