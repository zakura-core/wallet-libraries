use std::collections::BTreeSet;

use super::*;

/// Draws over this many seeds.
const SEEDS: u64 = 10_000;

/// The chi-square value a statistic with `df` degrees of freedom exceeds with
/// probability 0.001, by the Wilson-Hilferty approximation.
fn critical(df: usize) -> f64 {
    let df = df as f64;
    let z = 3.090_232;
    let c = 2.0 / (9.0 * df);
    df * (1.0 - c + z * c.sqrt()).powi(3)
}

/// Pearson's statistic for `observed` counts against `expected` counts.
fn chi_square(observed: &[u64], expected: &[f64]) -> f64 {
    observed
        .iter()
        .zip(expected)
        .map(|(o, e)| (*o as f64 - e).powi(2) / e)
        .sum()
}

/// In a shard of ten page tables, over 10,000 seeds: `C` has three tables
/// with odds 0.7 and otherwise a size uniform from four to ten, always holds
/// the real table, and the real query's slot in its sweep is uniform.
#[test]
fn cover_size_and_the_real_slot_follow_their_distributions() {
    const TABLES: u32 = 10;
    const REAL: u32 = 4;
    let mut sizes = vec![0u64; TABLES as usize + 1];
    // Per cover size, how often the real query took each slot.
    let mut slots = vec![vec![0u64; TABLES as usize]; TABLES as usize + 1];
    for seed in 0..SEEDS {
        let mut rng = StdRng::seed_from_u64(seed);
        let tables: Vec<u32> = (0..TABLES).collect();
        let cover = draw(&mut rng, &tables, &BTreeSet::from([REAL]));
        assert!(cover.contains(&REAL), "the real table is in its cover");
        assert!(cover.iter().all(|table| *table < TABLES));
        sizes[cover.len()] += 1;
        let order = sweep_order(&mut rng, &cover);
        assert_eq!(
            order.iter().copied().collect::<BTreeSet<_>>(),
            cover,
            "a sweep queries every table of its cover once"
        );
        let slot = order.iter().position(|table| *table == REAL).unwrap();
        slots[cover.len()][slot] += 1;
    }

    assert!(
        sizes[1] == 0 && sizes[2] == 0,
        "a shard of ten tables never covers fewer than three: {sizes:?}"
    );
    let observed = &sizes[3..];
    let expected: Vec<f64> = (3..=TABLES)
        .map(|size| {
            let odds = if size == BASE_SIZE {
                0.7
            } else {
                0.3 / f64::from(TABLES - BASE_SIZE)
            };
            odds * SEEDS as f64
        })
        .collect();
    let statistic = chi_square(observed, &expected);
    assert!(
        statistic < critical(observed.len() - 1),
        "cover sizes {observed:?} against {expected:?}: chi-square {statistic}"
    );

    let (mut statistic, mut df) = (0.0, 0);
    for (size, by_slot) in slots.iter().enumerate().skip(3) {
        let total: u64 = by_slot.iter().sum();
        let expected = vec![total as f64 / size as f64; size];
        statistic += chi_square(&by_slot[..size], &expected);
        df += size - 1;
    }
    assert!(
        statistic < critical(df),
        "real slots: chi-square {statistic} over {df} degrees of freedom"
    );
}

/// A shard of at most three queryable page tables covers every one, and a larger one
/// keeps every table already known to be needed, even past the drawn size.
#[test]
fn small_shards_cover_every_table_and_known_tables_stay() {
    for seed in 0..64 {
        let mut rng = StdRng::seed_from_u64(seed);
        for tables in 1..=3 {
            let all: Vec<u32> = (0..tables).collect();
            assert_eq!(
                draw(&mut rng, &all, &BTreeSet::from([0])),
                all.iter().copied().collect::<BTreeSet<_>>()
            );
        }
        let known: BTreeSet<u32> = [0, 2, 5, 7, 9].into();
        let cover = draw(&mut rng, &(0..10).collect::<Vec<_>>(), &known);
        assert!(cover.is_superset(&known));
        assert!(cover.len() >= known.len());
    }
}

/// A shard's sweeps are padded to the next power of two.
#[test]
fn sweeps_pad_to_a_power_of_two() {
    let padded: Vec<u64> = [1, 2, 3, 4, 5, 8, 9].map(padded).to_vec();
    assert_eq!(padded, [1, 2, 4, 4, 8, 8, 16]);
}
