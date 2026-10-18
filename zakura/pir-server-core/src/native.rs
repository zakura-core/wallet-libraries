//! Native operations owned by the server-core role.
use rayon::prelude::*;
pub use reinspiring::native::{NativeKeys, NativePreprocessed, NativeSecret};
use std::borrow::Borrow;
use zakura_pir_protocol::native::bits::u64s_to_contiguous_bytes;
pub use zakura_pir_protocol::native::*;
/// Operations available only to this role.
pub trait ProfilePublicationExt {
    /// Canonical published bytes for two-mask blocks: every first mask, then
    /// every second mask, each coefficient rounded to `mask_bits`.
    fn publish<B: Borrow<NativePreprocessed>>(&self, blocks: &[B]) -> Result<Vec<u8>, String>;
}
impl ProfilePublicationExt for Profile {
    /// Canonical published bytes for two-mask blocks: every first mask, then
    /// every second mask, each coefficient rounded to `mask_bits`.
    fn publish<B: Borrow<NativePreprocessed>>(&self, blocks: &[B]) -> Result<Vec<u8>, String> {
        let others = blocks
            .iter()
            .map(|b| {
                b.borrow()
                    .other_mask()
                    .ok_or("one-mask native preprocessing")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let words: Vec<_> = blocks
            .iter()
            .flat_map(|b| b.borrow().mask().iter())
            .chain(others.into_iter().flatten())
            .map(|&x| round(x, self.mask_bits))
            .collect();
        Ok(u64s_to_contiguous_bytes(&words, self.mask_bits))
    }
}
/// Canonical published bytes for two-mask blocks: every first mask, then every
/// second mask, each coefficient rounded to `MASK_BITS`.
pub fn publish<B: Borrow<NativePreprocessed>>(blocks: &[B]) -> Result<Vec<u8>, String> {
    P16.publish(blocks)
}

/// The public hint `H = A * D` for one segment, one block of `D` rows per
/// packing block, using exact lifted native-ring products.
///
/// `column(c)` is column `c` of the database: `rows` plaintext coefficients,
/// u16 under [`P16`] and u8 under [`P8`].
pub fn hint<'a, T: Entry + 'a>(
    masks: &[Vec<u64>],
    rows: usize,
    cols: usize,
    column: impl Fn(usize) -> &'a [T] + Sync,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    if rows == 0 || !rows.is_multiple_of(D) || !cols.is_multiple_of(D) || masks.len() != rows / D {
        return Err("native hint shape".into());
    }
    let lift = reinspiring::lift_ntt::LiftContext::new(D, Q).map_err(|e| e.to_string())?;
    let public = lift
        .prepare_public_dot(masks, T::MAX)
        .map_err(|e| e.to_string())?;
    (0..cols)
        .step_by(D)
        .map(|start| {
            (start..start + D)
                .into_par_iter()
                .map(|col| {
                    let data = column(col);
                    if data.len() != rows {
                        return Err("native hint column length".to_string());
                    }
                    let polys = data
                        .as_chunks::<D>()
                        .0
                        .iter()
                        .map(|p| p.iter().map(|&x| x.into()).collect::<Vec<_>>())
                        .collect::<Vec<_>>();
                    lift.public_dot(&public, &polys).map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

/// Two-mask preprocessing for every block of a hint.
pub fn preprocess(
    setup: &NativeSetup,
    hint: &[Vec<Vec<u64>>],
) -> Result<Vec<NativePreprocessed>, String> {
    hint.par_iter()
        .map(|block| NativePreprocessed::build_two_mask(setup, block))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// A stored plaintext coefficient: u16 under [`P16`], u8 under [`P8`].
pub trait Entry: Copy + Into<u64> + Send + Sync {
    /// The largest value, which bounds the hint's lifted products.
    const MAX: u64;
}

impl Entry for u16 {
    const MAX: u64 = u16::MAX as u64;
}

impl Entry for u8 {
    const MAX: u64 = u8::MAX as u64;
}
