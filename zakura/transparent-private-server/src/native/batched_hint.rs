//! The public hint, computed exactly but batched across columns.
//!
//! [`zakura_pir_native::hint`] is the definition: `H = A * D`, one exact lifted
//! negacyclic product per mask block and column, reduced modulo `q`. It runs
//! each column alone through Reinspiring's lifted products, whose constant-time
//! scalar NTT over 42-bit primes is built for secret operands. A recent
//! worker rebuilds its tail hints at every publication, and nothing in a hint
//! is secret: the masks are expanded from published seeds and the plaintext
//! is the server's own table, both of which a client may reproduce or learn.
//! Timing here can reveal nothing a client does not already have. The output
//! is the reference's integers, so the published masks, their epoch and every
//! binding over them are unchanged.
//!
//! [`hint`] computes the same integers through three 30-bit NTT primes. One
//! transform runs over a tile of columns at once, so every butterfly applies a
//! single twiddle across contiguous lanes the compiler vectorises. The integer
//! sum is reconstructed whole by CRT and only then reduced modulo `q`. A shape
//! whose bound exceeds that capacity is handed to the reference ([`path`]).
//!
//! # Provenance
//!
//! Nothing here has been externally audited. The pieces are textbook:
//! - the transforms follow Algorithms 1 (Cooley–Tukey, standard order in,
//!   bit-reversed out) and 2 (Gentleman–Sande, bit-reversed in, standard out)
//!   of Longa and Naehrig, "Speeding up the Number Theoretic Transform for
//!   Faster Ideal Lattice-Based Cryptography", CANS 2016 (ePrint 2016/504),
//!   with powers of a primitive `2D`-th root merged into the twiddles;
//! - multiplication by a fixed twiddle is Shoup's precomputed-quotient method,
//!   as analysed in D. Harvey, "Faster arithmetic for number-theoretic
//!   transforms", J. Symbolic Computation 60 (2014);
//! - reconstruction is Garner's mixed-radix CRT (Knuth, TAOCP vol. 2, 4.3.2).
//!
//! Spiral's NTT, which the reference uses, transforms one polynomial at a time
//! over its own 42-bit moduli; batching lanes is the entire saving, so it is
//! not reused. The reference stays the definition: it is the fallback and the
//! oracle of the tests, beside fixed known-answer vectors computed without any
//! NTT or CRT by `testdata/batched_hint_kat.py`.
//!
//! # Derivation
//!
//! Notation: `D = 2^11`, `q = 2^54`, primes `p_i < 2^30` with
//! `p_i = 1 (mod 2D)`, `P = p_0 p_1 p_2 > 2^89.99`. Mask block `b` is `m_b`,
//! the column's block `b` is `x_b`, coefficients `u16`.
//!
//! 1. **Roots.** `psi = g^((p-1)/2D)` for the first `g` with `psi^D = -1`.
//!    Its order divides `2D = 2^12` but not `D` (else `psi^D = 1`), so it is
//!    exactly `2D`. Such `g` exists because the multiplicative group is cyclic
//!    and `2D | p - 1`; the search is checked, not assumed.
//! 2. **Evaluation order.** With `forward[k] = psi^brv(k)` (11-bit reversal),
//!    Algorithm 1 leaves `A(psi^(2 brv(k) + 1))` at index `k`: the polynomial
//!    evaluated at the `D` odd powers of `psi`, the roots of `X^D + 1`. So
//!    pointwise products are products modulo `X^D + 1`, i.e. negacyclic.
//!    Algorithm 2 with `psi^-1` inverts it up to the factor `D`, which is
//!    folded into each mask transform once (`D^-1 mod p`). Both are linear,
//!    so one inverse transform of the summed products gives
//!    `sum_b m_b * x_b mod (X^D + 1, p)`. Tests check the evaluation order
//!    by Horner and the exact inverse.
//! 3. **Residue ranges.** Every stored residue is canonical, in `[0, p)`.
//!    `add` forms `a + b < 2p < 2^31`; `sub` forms `a + p - b < 2p`; both
//!    subtract `p` once via `min(s, s - p)` (wrapping, so `s < p` keeps `s`).
//!    Shoup: with `w < p`, `w' = floor(w 2^32 / p)`, any `x < 2^32` and
//!    `e = floor(x w' / 2^32)`, `w 2^32 / p - 1 < w' <= w 2^32 / p` gives
//!    `x w / p - x / 2^32 - 1 < e <= x w / p`, so `r = x w - e p` lies in
//!    `[0, p (1 + x / 2^32)) ⊂ [0, 2p)`. As `2p < 2^32`,
//!    computing `r` modulo `2^32` with wrapping arithmetic is exact, and one
//!    conditional subtraction makes it canonical. Inputs: `u16` data and
//!    `centered(m) mod p` mask coefficients are both below `p`.
//! 4. **Signed bound.** Lift each mask coefficient to its centered value
//!    `c in (-q/2, q/2]`, congruent to it modulo `q`. Each output coefficient
//!    of the integer product is a signed sum of `D` terms `c x` per block, so
//!    `|S| <= D * 65535 * sum_b max |c_b| = B`. This is the bound
//!    `prepare_public_dot` checks in the reference.
//! 5. **CRT.** Garner yields the unique `X in [0, P)` with `X = S (mod p_i)`.
//!    If `2B < P` then `B <= floor(P/2)`, so `S >= 0` gives `X = S <= P/2`
//!    and `S < 0` gives `X = P + S > P/2`: mapping `X > P/2` to `X - P`
//!    recovers `S`. Intermediates: `v1 < p1`, `low < p0 p1 < 2^60`, and
//!    `low + p0 p1 v2 < P < 2^90`, all within `u64`/`u128`.
//! 6. **Modulo `q`.** `S` is congruent modulo `q` to the reference's result,
//!    since lifting changes each coefficient by a multiple of `q`. With
//!    `q = 2^54`, the two's-complement `u64` of `S` masked by `q - 1` is
//!    `S mod q` in `[0, q)`, the reference's canonical output.
//!
//! The capacity `2B < P` holds for decoupled-2k-8k (`B < 2^83`) and every registry
//! geometry (at most 32 blocks, `B < 2^86`); it fails from 512 blocks of
//! extreme masks.

use rayon::prelude::*;
use std::sync::OnceLock;
use zakura_pir_native::{D, Q};

const LOG_D: u32 = D.trailing_zeros();
/// NTT-friendly primes below 2^30, each 1 modulo 2D. Their product is just
/// under 2^90.
const PRIMES: [u32; 3] = [1_073_692_673, 1_073_668_097, 1_073_655_809];
/// Columns transformed together.
const LANES: usize = 32;
/// The largest plaintext coefficient: a u16. Byte columns are bounded by it
/// too, so the capacity check covers both.
const DATA_BOUND: u128 = u16::MAX as u128;

const _: () = assert!(D.is_power_of_two());

/// One prime's transform tables: Shoup pairs of the bit-reversed powers of a
/// primitive `2D`-th root and of its inverse.
struct Prime {
    p: u32,
    forward: Vec<(u32, u32)>,
    inverse: Vec<(u32, u32)>,
    /// `D^-1` modulo `p`.
    d_inverse: u32,
}

fn pow_mod(mut base: u64, mut exp: u64, p: u64) -> u64 {
    let mut out = 1u64;
    base %= p;
    while exp > 0 {
        if exp & 1 == 1 {
            out = out * base % p;
        }
        base = base * base % p;
        exp >>= 1;
    }
    out
}

fn shoup(w: u32, p: u32) -> (u32, u32) {
    (w, (((w as u64) << 32) / p as u64) as u32)
}

impl Prime {
    fn new(p: u32) -> Self {
        let p64 = p as u64;
        let order = 2 * D as u64;
        assert_eq!((p64 - 1) % order, 0, "prime is 1 mod 2D");
        // A primitive 2D-th root: psi^D = -1.
        let psi = (2..p64)
            .map(|g| pow_mod(g, (p64 - 1) / order, p64))
            .find(|&psi| pow_mod(psi, D as u64, p64) == p64 - 1)
            .expect("a primitive 2D-th root exists");
        let psi_inverse = pow_mod(psi, p64 - 2, p64);
        let reverse = |k: usize| (k.reverse_bits() >> (usize::BITS - LOG_D)) as u64;
        let table = |root: u64| -> Vec<(u32, u32)> {
            (0..D)
                .map(|k| shoup(pow_mod(root, reverse(k), p64) as u32, p))
                .collect()
        };
        Self {
            p,
            forward: table(psi),
            inverse: table(psi_inverse),
            d_inverse: pow_mod(D as u64, p64 - 2, p64) as u32,
        }
    }
}

fn primes() -> &'static [Prime; 3] {
    static TABLES: OnceLock<[Prime; 3]> = OnceLock::new();
    TABLES.get_or_init(|| PRIMES.map(Prime::new))
}

/// `x * w mod p` for `x < 2^32`, `w < p < 2^30`, with `ws` = floor(w 2^32 / p).
#[inline(always)]
fn mul(x: u32, (w, ws): (u32, u32), p: u32) -> u32 {
    let estimate = ((x as u64 * ws as u64) >> 32) as u32;
    let r = x.wrapping_mul(w).wrapping_sub(estimate.wrapping_mul(p));
    r.min(r.wrapping_sub(p))
}

#[inline(always)]
fn add(a: u32, b: u32, p: u32) -> u32 {
    let s = a + b;
    s.min(s.wrapping_sub(p))
}

#[inline(always)]
fn sub(a: u32, b: u32, p: u32) -> u32 {
    let s = a + p - b;
    s.min(s.wrapping_sub(p))
}

/// In-place negacyclic forward transform of `L` interleaved polynomials,
/// coefficients in `[0, p)`, bit-reversed output.
fn forward<const L: usize>(a: &mut [[u32; L]], prime: &Prime) {
    let p = prime.p;
    let mut t = D;
    let mut m = 1;
    while m < D {
        t >>= 1;
        for i in 0..m {
            let w = prime.forward[m + i];
            let (low, high) = a[2 * i * t..2 * (i + 1) * t].split_at_mut(t);
            for (x, y) in low.iter_mut().zip(high.iter_mut()) {
                for l in 0..L {
                    let u = x[l];
                    let v = mul(y[l], w, p);
                    x[l] = add(u, v, p);
                    y[l] = sub(u, v, p);
                }
            }
        }
        m <<= 1;
    }
}

/// The inverse of [`forward`] without the final `D^-1` scale, which callers
/// fold into an operand.
fn inverse<const L: usize>(a: &mut [[u32; L]], prime: &Prime) {
    let p = prime.p;
    let mut t = 1;
    let mut m = D;
    while m > 1 {
        let h = m >> 1;
        for i in 0..h {
            let w = prime.inverse[h + i];
            let (low, high) = a[2 * i * t..2 * (i + 1) * t].split_at_mut(t);
            for (x, y) in low.iter_mut().zip(high.iter_mut()) {
                for l in 0..L {
                    let (u, v) = (x[l], y[l]);
                    x[l] = add(u, v, p);
                    y[l] = mul(sub(u, v, p), w, p);
                }
            }
        }
        t <<= 1;
        m = h;
    }
}

/// Signed representative of a canonical residue modulo `q`.
fn centered(x: u64) -> i128 {
    if x > Q / 2 {
        x as i128 - Q as i128
    } else {
        x as i128
    }
}

/// Garner reconstruction of the signed integer with these residues, reduced
/// modulo `q`. Exact while its magnitude is below half the primes' product.
struct Crt {
    p0_inverse_mod_p1: u64,
    p01_inverse_mod_p2: u64,
    p01: u128,
    product: u128,
}

impl Crt {
    fn new() -> Self {
        let [p0, p1, p2] = PRIMES.map(|p| p as u64);
        let p01 = p0 as u128 * p1 as u128;
        Self {
            p0_inverse_mod_p1: pow_mod(p0 % p1, p1 - 2, p1),
            p01_inverse_mod_p2: pow_mod((p01 % p2 as u128) as u64, p2 - 2, p2),
            p01,
            product: p01 * p2 as u128,
        }
    }

    #[inline(always)]
    fn reduce(&self, r: [u32; 3]) -> u64 {
        let [p0, p1, p2] = PRIMES.map(|p| p as u64);
        let [r0, r1, r2] = r.map(|r| r as u64);
        let v1 = (r1 + p1 - r0 % p1) % p1 * self.p0_inverse_mod_p1 % p1;
        let low = r0 as u128 + p0 as u128 * v1 as u128;
        let v2 = (r2 + p2 - (low % p2 as u128) as u64) % p2 * self.p01_inverse_mod_p2 % p2;
        let x = low + self.p01 * v2 as u128;
        let signed = if x > self.product / 2 {
            x as i128 - self.product as i128
        } else {
            x as i128
        };
        signed as u64 & (Q - 1)
    }
}

/// Whether reconstruction below `capacity` is exact for masks whose largest
/// centered coefficients sum to `maxima`.
fn fits(maxima: u128, capacity: u128) -> bool {
    maxima
        .checked_mul(D as u128 * DATA_BOUND)
        .and_then(|b| b.checked_mul(2))
        .is_some_and(|b| b < capacity)
}

/// A hint: per `D`-column group, per column, `D` coefficients modulo `q`.
type Hint = Vec<Vec<Vec<u64>>>;

/// Which implementation computes a hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// The column-batched transforms of this module.
    Batched,
    /// [`zakura_pir_native::hint`], for masks beyond this module's capacity.
    Reference,
}

/// Validates `masks` and sums their largest centered coefficients.
fn maxima(masks: &[Vec<u64>]) -> Result<u128, String> {
    let mut maxima = 0u128;
    for mask in masks {
        if mask.len() != D || mask.iter().any(|&x| x >= Q) {
            return Err("noncanonical lifted polynomial or wrong degree".into());
        }
        maxima += mask
            .iter()
            .map(|&x| centered(x).unsigned_abs())
            .max()
            .unwrap();
    }
    Ok(maxima)
}

/// The implementation [`hint`] uses for these masks: batched when the sum's
/// bound is within three-prime capacity, otherwise the reference.
pub fn path(masks: &[Vec<u64>]) -> Result<Path, String> {
    Ok(if fits(maxima(masks)?, Crt::new().product) {
        Path::Batched
    } else {
        Path::Reference
    })
}

/// The public hint `H = A * D` for one segment, byte for byte
/// [`zakura_pir_native::hint`]'s, with its shape checks and arguments.
pub fn hint<'a, T: zakura_pir_native::Entry + 'a>(
    masks: &[Vec<u64>],
    rows: usize,
    cols: usize,
    column: impl Fn(usize) -> &'a [T] + Sync,
) -> Result<Vec<Vec<Vec<u64>>>, String> {
    hint_within(masks, rows, cols, column, Crt::new().product).map(|(hint, _)| hint)
}

/// [`hint`] with reconstruction capacity `capacity` instead of the primes'
/// product, and the path taken. Only tests pass a smaller one, to exercise
/// the reference fallback without a multi-gigabyte table.
fn hint_within<'a, T: zakura_pir_native::Entry + 'a>(
    masks: &[Vec<u64>],
    rows: usize,
    cols: usize,
    column: impl Fn(usize) -> &'a [T] + Sync,
    capacity: u128,
) -> Result<(Hint, Path), String> {
    if rows == 0 || !rows.is_multiple_of(D) || !cols.is_multiple_of(D) || masks.len() != rows / D {
        return Err("native hint shape".into());
    }
    let crt = Crt::new();
    debug_assert!(capacity <= crt.product);
    // Every output coefficient is a sum of D * blocks products, each at most
    // a mask coefficient times a u16. Reconstruction is exact below half the
    // product; beyond it the reference decides, including its own refusal.
    if !fits(maxima(masks)?, capacity) {
        return zakura_pir_native::hint(masks, rows, cols, column)
            .map(|hint| (hint, Path::Reference));
    }
    let primes = primes();
    // Mask transforms with D^-1 folded in, as Shoup pairs: [prime][block][row].
    let masks: Vec<Vec<Vec<(u32, u32)>>> = primes
        .iter()
        .map(|prime| {
            let p = prime.p as i128;
            masks
                .iter()
                .map(|mask| {
                    let mut poly: Vec<[u32; 1]> = mask
                        .iter()
                        .map(|&x| [centered(x).rem_euclid(p) as u32])
                        .collect();
                    forward(&mut poly, prime);
                    poly.iter()
                        .map(|[x]| {
                            let scaled =
                                (*x as u64 * prime.d_inverse as u64 % prime.p as u64) as u32;
                            shoup(scaled, prime.p)
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let blocks = rows / D;
    let tiles: Vec<Vec<Vec<u64>>> = (0..cols / LANES)
        .into_par_iter()
        .map(|tile| -> Result<Vec<Vec<u64>>, String> {
            let first = tile * LANES;
            let data: Vec<&[T]> = (first..first + LANES).map(&column).collect();
            if data.iter().any(|col| col.len() != rows) {
                return Err("native hint column length".into());
            }
            let mut plain = vec![[0u32; LANES]; D];
            let mut work = vec![[0u32; LANES]; D];
            let mut sums = vec![vec![[0u32; LANES]; D]; primes.len()];
            for block in 0..blocks {
                for (r, row) in plain.iter_mut().enumerate() {
                    for (lane, col) in data.iter().enumerate() {
                        row[lane] = Into::<u64>::into(col[block * D + r]) as u32;
                    }
                }
                for ((prime, mask), sum) in primes.iter().zip(&masks).zip(&mut sums) {
                    let p = prime.p;
                    work.copy_from_slice(&plain);
                    forward(&mut work, prime);
                    for ((acc, x), &w) in sum.iter_mut().zip(&work).zip(&mask[block]) {
                        for l in 0..LANES {
                            acc[l] = add(acc[l], mul(x[l], w, p), p);
                        }
                    }
                }
            }
            for (prime, sum) in primes.iter().zip(&mut sums) {
                inverse(sum, prime);
            }
            Ok((0..LANES)
                .map(|lane| {
                    (0..D)
                        .map(|r| crt.reduce([sums[0][r][lane], sums[1][r][lane], sums[2][r][lane]]))
                        .collect()
                })
                .collect())
        })
        .collect::<Result<_, _>>()?;
    let mut columns = tiles.into_iter().flatten();
    let hint = (0..cols / D)
        .map(|_| columns.by_ref().take(D).collect())
        .collect();
    Ok((hint, Path::Batched))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    /// Schoolbook negacyclic product modulo `q`.
    fn negacyclic(a: &[u64], b: &[u16]) -> Vec<u64> {
        let mut out = vec![0u64; D];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                let term = x.wrapping_mul(y as u64);
                let k = i + j;
                if k < D {
                    out[k] = out[k].wrapping_add(term);
                } else {
                    out[k - D] = out[k - D].wrapping_sub(term);
                }
            }
        }
        out.iter().map(|x| x & (Q - 1)).collect()
    }

    #[test]
    fn transforms_invert_exactly() {
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        for prime in primes() {
            let p = prime.p;
            let a: Vec<u32> = (0..D).map(|_| rng.gen_range(0..p)).collect();
            let mut t: Vec<[u32; 1]> = a.iter().map(|&x| [x]).collect();
            forward(&mut t, prime);
            inverse(&mut t, prime);
            let back: Vec<u32> = t
                .iter()
                .map(|[x]| (*x as u64 * prime.d_inverse as u64 % p as u64) as u32)
                .collect();
            assert_eq!(back, a, "prime {p}");
        }
    }

    #[test]
    fn crt_reconstructs_signed_values_at_the_capacity_edges() {
        let crt = Crt::new();
        let half = (crt.product / 2) as i128;
        for value in [
            0i128,
            1,
            -1,
            half,
            -half + 1,
            1 << 83,
            -(1 << 83),
            12_345_678_901_234_567,
        ] {
            let residues = PRIMES.map(|p| value.rem_euclid(p as i128) as u32);
            assert_eq!(crt.reduce(residues), value as u64 & (Q - 1), "{value}");
        }
    }

    /// Masks at both extremes of the centered range and data at both u16
    /// extremes, against an independent schoolbook product.
    #[test]
    fn extreme_operands_match_schoolbook_products() {
        let cols = D;
        let rows = 2 * D;
        let masks = vec![vec![Q / 2; D], vec![Q / 2 + 1; D]];
        let mut rng = ChaCha20Rng::from_seed([5; 32]);
        let data: Vec<Vec<u16>> = (0..cols)
            .map(|c| match c % 3 {
                0 => vec![u16::MAX; rows],
                1 => (0..rows).map(|_| rng.r#gen()).collect(),
                _ => vec![0; rows],
            })
            .collect();
        let fast = hint(&masks, rows, cols, |c| &data[c]).unwrap();
        for c in [0, 1, 2, 1_000, 2_047] {
            let mut expected = vec![0u64; D];
            for (block, mask) in masks.iter().enumerate() {
                let product = negacyclic(mask, &data[c][block * D..(block + 1) * D]);
                for (dst, x) in expected.iter_mut().zip(product) {
                    *dst = dst.wrapping_add(x) & (Q - 1);
                }
            }
            assert_eq!(fast[0][c], expected, "column {c}");
        }
    }

    #[test]
    fn matches_the_reference_hint_and_its_shape_refusals() {
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let (rows, cols) = (4 * D, 2 * D);
        let masks: Vec<Vec<u64>> = (0..rows / D)
            .map(|_| (0..D).map(|_| rng.gen_range(0..Q)).collect())
            .collect();
        let data: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        assert_eq!(
            hint(&masks, rows, cols, |c| &data[c]).unwrap(),
            zakura_pir_native::hint(&masks, rows, cols, |c| &data[c]).unwrap()
        );
        assert!(hint(&masks, rows + D, cols, |c| &data[c]).is_err());
        assert!(hint(&masks, rows, cols + 1, |c| &data[c]).is_err());
        assert!(hint(&masks, rows, cols, |c| &data[c][1..]).is_err());
        let mut noncanonical = masks.clone();
        noncanonical[1][7] = Q;
        assert!(hint(&noncanonical, rows, cols, |c| &data[c]).is_err());
    }

    /// The capacity edge from actual masks: 511 blocks at the centered
    /// extreme take the batched path, 512 the reference. Every registry
    /// geometry has at most 32 blocks per table.
    #[test]
    fn capacity_edge_selects_the_path() {
        let product = Crt::new().product;
        let extreme = |blocks: usize| vec![vec![Q / 2; D]; blocks];
        assert_eq!(path(&extreme(32)).unwrap(), Path::Batched);
        assert_eq!(path(&extreme(511)).unwrap(), Path::Batched);
        assert_eq!(path(&extreme(512)).unwrap(), Path::Reference);
        let edge = (product - 1) / (2 * D as u128 * DATA_BOUND);
        assert!(fits(edge, product));
        assert!(!fits(edge + 1, product));
        assert!(!fits(u128::MAX / 2, product));
        let mut noncanonical = extreme(1);
        noncanonical[0][0] = Q;
        assert!(path(&noncanonical).is_err());
    }

    fn is_prime(n: u64) -> bool {
        n >= 2
            && (2..)
                .take_while(|f| f * f <= n)
                .all(|f| !n.is_multiple_of(f))
    }

    /// The numeric premises of the derivation in the module documentation.
    #[test]
    fn primes_and_roots_satisfy_the_derivation() {
        for prime in primes() {
            let p = prime.p as u64;
            assert!(is_prime(p) && p < 1 << 30 && (p - 1).is_multiple_of(2 * D as u64));
            let psi = prime.forward[1 << (LOG_D - 1)].0 as u64;
            // forward[brv(1)] = psi^1; its order is exactly 2D.
            assert_eq!(pow_mod(psi, D as u64, p), p - 1);
            assert_eq!(pow_mod(psi, 2 * D as u64, p), 1);
            assert_eq!(prime.forward[0].0, 1);
            assert_eq!(
                prime.inverse[1 << (LOG_D - 1)].0 as u64 * psi % p,
                1,
                "inverse table uses psi^-1"
            );
            assert_eq!(prime.d_inverse as u64 * D as u64 % p, 1);
            for &(w, ws) in prime.forward.iter().chain(&prime.inverse) {
                assert!(w < prime.p);
                assert_eq!(ws as u64, ((w as u64) << 32) / p);
            }
        }
        assert!(Crt::new().product > 1 << 89);
    }

    /// Forward output index `k` is the input evaluated at
    /// `psi^(2 brv(k) + 1)`, the odd powers of psi: the roots of `X^D + 1`.
    #[test]
    fn forward_evaluates_at_odd_powers_in_bit_reversed_order() {
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        for prime in primes() {
            let p = prime.p as u64;
            let psi = prime.forward[1 << (LOG_D - 1)].0 as u64;
            let a: Vec<u32> = (0..D).map(|_| rng.gen_range(0..prime.p)).collect();
            let mut t: Vec<[u32; 1]> = a.iter().map(|&x| [x]).collect();
            forward(&mut t, prime);
            for k in [0, 1, 2, 3, 1_000, D / 2, D - 1] {
                let brv = (k.reverse_bits() >> (usize::BITS - LOG_D)) as u64;
                let point = pow_mod(psi, 2 * brv + 1, p);
                let value = a
                    .iter()
                    .rev()
                    .fold(0, |acc, &c| (acc * point + c as u64) % p);
                assert_eq!(t[k][0] as u64, value, "prime {p} index {k}");
            }
        }
    }

    /// Shoup multiplication is canonical `x w mod p` across the whole `u32`
    /// range of `x`, including the extremes, for every prime.
    #[test]
    fn shoup_products_are_canonical() {
        let mut rng = ChaCha20Rng::from_seed([13; 32]);
        for prime in primes() {
            let p = prime.p;
            let ws = [0, 1, 2, p / 2, p - 2, p - 1];
            let xs = [0, 1, p - 1, p, 2 * p - 1, u32::MAX - 1, u32::MAX];
            for &w in &ws {
                for &x in &xs {
                    let expected = (x as u64 * w as u64 % p as u64) as u32;
                    assert_eq!(mul(x, shoup(w, p), p), expected, "{x} * {w} mod {p}");
                }
            }
            for _ in 0..100_000 {
                let (x, w) = (rng.r#gen::<u32>(), rng.gen_range(0..p));
                assert_eq!(
                    mul(x, shoup(w, p), p) as u64,
                    x as u64 * w as u64 % p as u64
                );
            }
            for (a, b) in [(0, 0), (p - 1, p - 1), (0, p - 1), (p - 1, 0)] {
                assert_eq!(add(a, b, p) as u64, (a as u64 + b as u64) % p as u64);
                assert_eq!(
                    sub(a, b, p) as u64,
                    (a as u64 + p as u64 - b as u64) % p as u64
                );
            }
        }
    }

    /// `testdata/batched_hint_kat.py`'s splitmix64, its inputs mirrored.
    struct SplitMix(u64);

    impl SplitMix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    type Case = (Vec<Vec<u64>>, Vec<Vec<u16>>);

    fn case_basis() -> Case {
        let blocks = 2;
        let mut masks = vec![vec![0; D]; blocks];
        masks[0][D - 1] = 1;
        masks[1][5] = Q - 1;
        let data = (0..D)
            .map(|c| {
                let mut col = vec![0; blocks * D];
                col[c % D] = 1;
                col[D + (3 * c + 1) % D] = 0xffff;
                col
            })
            .collect();
        (masks, data)
    }

    fn case_mixed() -> Case {
        let blocks = 3;
        let mut rng = SplitMix(0x7472_616E_7370_6172);
        let boundary = [
            0,
            1,
            Q / 2 - 1,
            Q / 2,
            Q / 2 + 1,
            Q - 2,
            Q - 1,
            (1 << 53) + 12_345,
        ];
        let mut masks = Vec::new();
        for b in 0..blocks {
            let mut mask: Vec<u64> = (0..D).map(|_| rng.next() % Q).collect();
            for (i, &value) in boundary.iter().enumerate() {
                mask[(b * 701 + i * 257) % D] = value;
            }
            masks.push(mask);
        }
        let data = (0..D)
            .map(|c| match c % 4 {
                0 => vec![0xffff; blocks * D],
                1 => {
                    let mut col = vec![0; blocks * D];
                    col[(c * 7) % (blocks * D)] = 0xffff;
                    col
                }
                2 => (0..blocks * D).map(|_| rng.next() as u16).collect(),
                _ => (0..blocks * D)
                    .map(|_| if rng.next() & 1 == 1 { 0xffff } else { 0 })
                    .collect(),
            })
            .collect();
        (masks, data)
    }

    fn case_extreme() -> Case {
        let blocks = 4;
        let masks = (0..blocks)
            .map(|b| vec![if b % 2 == 0 { Q / 2 } else { Q / 2 + 1 }; D])
            .collect();
        let mut rng = SplitMix(0x6578_7472_656D_6521);
        let data = (0..D)
            .map(|c| {
                if c % 2 == 0 {
                    vec![0xffff; blocks * D]
                } else {
                    (0..blocks * D).map(|_| rng.next() as u16).collect()
                }
            })
            .collect();
        (masks, data)
    }

    fn digest(hint: &[Vec<Vec<u64>>]) -> String {
        let mut sha = Sha256::new();
        for x in hint.iter().flatten().flatten() {
            sha.update(x.to_le_bytes());
        }
        hex::encode(sha.finalize())
    }

    /// Fixed vectors computed independently in Python, by exact big-integer
    /// products (Kronecker substitution, cross-checked by schoolbook), with no
    /// NTT and no CRT: monomials with negacyclic wrap, full-width masks with
    /// every boundary coefficient, and decoupled-2k-8k's four blocks at the
    /// centered extremes. The batched path and the forced reference fallback
    /// must both reproduce them.
    #[test]
    fn known_answer_vectors() {
        let kat: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/batched_hint_kat.json")).unwrap();
        assert_eq!(kat["d"].as_u64(), Some(D as u64));
        assert_eq!(kat["q"].as_u64(), Some(Q));
        let cases = kat["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let (masks, data) = match name {
                "basis" => case_basis(),
                "mixed" => case_mixed(),
                "extreme" => case_extreme(),
                other => panic!("unknown case {other}"),
            };
            let rows = masks.len() * D;
            assert_eq!(case["blocks"].as_u64(), Some(masks.len() as u64));
            for (capacity, expected_path) in
                [(Crt::new().product, Path::Batched), (0, Path::Reference)]
            {
                let (out, taken) = hint_within(&masks, rows, D, |c| &data[c], capacity).unwrap();
                assert_eq!(taken, expected_path, "{name}");
                assert_eq!(
                    digest(&out),
                    case["sha256"].as_str().unwrap(),
                    "{name} {taken:?}"
                );
                for sample in case["samples"].as_array().unwrap() {
                    let [c, k, v] = [0, 1, 2].map(|i| sample[i].as_u64().unwrap());
                    assert_eq!(
                        out[0][c as usize][k as usize], v,
                        "{name} {taken:?} {c} {k}"
                    );
                }
            }
        }
    }

    /// Masks over capacity go to the reference, which answers the same
    /// hint, and its refusals are returned as they are. A capacity of zero
    /// forces the fallback on a small table; at the real capacity it would
    /// need 512 blocks of extreme masks (`capacity_edge_selects_the_path`).
    #[test]
    fn over_capacity_falls_back_to_the_reference() {
        let mut rng = ChaCha20Rng::from_seed([17; 32]);
        let (rows, cols) = (2 * D, D);
        let masks: Vec<Vec<u64>> = (0..rows / D)
            .map(|_| (0..D).map(|_| rng.gen_range(0..Q)).collect())
            .collect();
        let data: Vec<Vec<u16>> = (0..cols)
            .map(|_| (0..rows).map(|_| rng.r#gen()).collect())
            .collect();
        let reference = zakura_pir_native::hint(&masks, rows, cols, |c| &data[c]).unwrap();
        let (fallback, taken) = hint_within(&masks, rows, cols, |c| &data[c], 0).unwrap();
        assert_eq!(taken, Path::Reference);
        assert_eq!(fallback, reference);
        let (batched, taken) =
            hint_within(&masks, rows, cols, |c| &data[c], Crt::new().product).unwrap();
        assert_eq!(taken, Path::Batched);
        assert_eq!(batched, reference);
        // Just below the bound these masks need: still batched. At it: not.
        let need = 2 * maxima(&masks).unwrap() * D as u128 * DATA_BOUND;
        assert_eq!(
            hint_within(&masks, rows, cols, |c| &data[c], need + 1)
                .unwrap()
                .1,
            Path::Batched
        );
        assert_eq!(
            hint_within(&masks, rows, cols, |c| &data[c], need)
                .unwrap()
                .1,
            Path::Reference
        );
        // Refusals through the fallback are the reference's own.
        let short = |c: usize| &data[c][1..];
        assert_eq!(
            hint_within(&masks, rows, cols, short, 0).unwrap_err(),
            zakura_pir_native::hint(&masks, rows, cols, short).unwrap_err()
        );
        assert_eq!(
            hint_within(&masks, rows, cols, short, 0).unwrap_err(),
            "native hint column length"
        );
        // Shape and mask checks refuse before any path is chosen.
        assert_eq!(
            hint_within(&masks, rows + D, cols, |c| &data[c], 0).unwrap_err(),
            "native hint shape"
        );
        let mut noncanonical = masks.clone();
        noncanonical[0][3] = Q;
        assert!(hint_within(&noncanonical, rows, cols, |c| &data[c], 0).is_err());
        assert!(zakura_pir_native::hint(&noncanonical, rows, cols, |c| &data[c]).is_err());
    }
}
