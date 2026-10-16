//! Building and verifying one display shard's tables.
//!
//! Each bucket's table places every entry in exactly one row,
//! [`placement_row`] under the bucket's placement seed. The publisher tries
//! seeds `0, 1, 2, ...` below [`MAX_PLACEMENT_SEEDS`] and keeps the first that
//! leaves no row over its capacity, so the table is one segment and the same
//! entry set always gets the same seed. When no seed fits, it keeps the seed
//! whose fullest row is emptiest (the smallest among equals) and spills each
//! row's overflow, in tag order, into the same row of further segments. A
//! query for a row is answered by every segment of its table, so a lookup
//! still sends one query.

use super::{bucket, placement_row, DisplayTable, MAX_BUCKETS, MAX_PLACEMENT_SEEDS};
use crate::layout::Geometry;
use crate::txid::{encode_row, row_entries, slots_per_row, DisplayEntry, Error, Tag};
use std::collections::BTreeSet;
use transparent_events::Txid;

fn bad(s: &str) -> Error {
    Error(s.into())
}

/// One bucket's table.
#[derive(Clone, Debug)]
pub struct BuiltBucket {
    /// One `rows × row_bytes` segment per entry; at least one.
    pub directory: Vec<Vec<u8>>,
    pub records: u64,
    /// The seed every entry's row is derived under.
    pub placement_seed: u32,
    /// Seeds tried before this one was kept: `placement_seed + 1` when it
    /// fits, [`MAX_PLACEMENT_SEEDS`] when the table overflows.
    pub seed_tries: u32,
}

/// A display shard's tables.
#[derive(Clone, Debug)]
pub struct BuiltDisplay {
    pub buckets: Vec<BuiltBucket>,
    pub records: u64,
}

impl BuiltDisplay {
    /// The smallest bucket, which is the shard's anonymity floor.
    pub fn min_bucket_records(&self) -> u64 {
        self.buckets.iter().map(|b| b.records).min().unwrap_or(0)
    }

    /// Segment bytes of `table`.
    pub fn segments(&self, table: DisplayTable) -> &[Vec<u8>] {
        &self.buckets[table.bucket() as usize].directory
    }

    /// Every table, in bucket order.
    pub fn tables(&self) -> Vec<DisplayTable> {
        (0..self.buckets.len() as u32)
            .map(DisplayTable::Directory)
            .collect()
    }

    /// Whether any bucket needed more than one segment.
    pub fn overflowed(&self) -> bool {
        self.buckets.iter().any(|b| b.directory.len() > 1)
    }
}

/// Where one bucket's entries go: the seed and every entry's row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub seed: u32,
    pub tries: u32,
    /// Entries of the fullest row.
    pub max_load: usize,
    /// Segments the table needs: one unless `max_load` exceeds a row.
    pub segments: usize,
}

/// Chooses the placement seed of one bucket's entries. Deterministic in the
/// tag set, the shard id, the bucket and the geometry.
pub fn place_bucket(tags: &[Tag], shard_id: u64, b: u32, geometry: &Geometry) -> Placement {
    let rows = geometry.directory_rows;
    let slots = slots_per_row(geometry.directory_row_bytes);
    let mut loads = vec![0usize; rows as usize];
    let mut best: Option<(usize, u32)> = None;
    for seed in 0..MAX_PLACEMENT_SEEDS {
        loads.fill(0);
        for tag in tags {
            loads[placement_row(tag, seed, shard_id, b, rows) as usize] += 1;
        }
        let max_load = loads.iter().copied().max().unwrap_or(0);
        if max_load <= slots {
            return Placement {
                seed,
                tries: seed + 1,
                max_load,
                segments: 1,
            };
        }
        if best.is_none_or(|(load, _)| max_load < load) {
            best = Some((max_load, seed));
        }
    }
    let (max_load, seed) = best.expect("at least one seed is tried");
    Placement {
        seed,
        tries: MAX_PLACEMENT_SEEDS,
        max_load,
        segments: max_load.div_ceil(slots),
    }
}

/// Lays out one shard: each entry in its bucket's table, at its one row.
///
/// Deterministic in the entry set, the shard id, the geometry and the bucket
/// count, so rebuilding a sealed range reproduces its bytes.
pub fn build_shard(
    shard_id: u64,
    geometry: &Geometry,
    n_buckets: u32,
    entries: &[impl AsRef<DisplayEntry>],
) -> Result<BuiltDisplay, Error> {
    if n_buckets == 0 || n_buckets > MAX_BUCKETS {
        return Err(bad("bucket count"));
    }
    let rows = geometry.directory_rows;
    let row_bytes = geometry.directory_row_bytes;
    let slots = slots_per_row(row_bytes);
    let mut sorted: Vec<DisplayEntry> = entries.iter().map(|e| *e.as_ref()).collect();
    sorted.sort_by_key(|e| e.tag);
    if sorted.windows(2).any(|w| w[0].tag == w[1].tag) {
        return Err(bad("duplicate transaction identity"));
    }
    let mut members: Vec<Vec<DisplayEntry>> = vec![Vec::new(); n_buckets as usize];
    for entry in &sorted {
        members[bucket(&entry.tag, n_buckets) as usize].push(*entry);
    }
    let buckets = members
        .into_iter()
        .enumerate()
        .map(|(b, members)| {
            let b = b as u32;
            let tags: Vec<Tag> = members.iter().map(|e| e.tag).collect();
            let placement = place_bucket(&tags, shard_id, b, geometry);
            // Entries arrive in tag order, so each row's spill into later
            // segments is in tag order too.
            let mut by_row: Vec<Vec<DisplayEntry>> = vec![Vec::new(); rows as usize];
            for entry in &members {
                by_row[placement_row(&entry.tag, placement.seed, shard_id, b, rows) as usize]
                    .push(*entry);
            }
            let directory = (0..placement.segments)
                .map(|segment| {
                    let mut bytes = Vec::with_capacity(rows as usize * row_bytes);
                    for row in &by_row {
                        let from = (segment * slots).min(row.len());
                        let to = ((segment + 1) * slots).min(row.len());
                        bytes.extend(encode_row(&row[from..to], row_bytes)?);
                    }
                    Ok(bytes)
                })
                .collect::<Result<_, Error>>()?;
            Ok(BuiltBucket {
                directory,
                records: members.len() as u64,
                placement_seed: placement.seed,
                seed_tries: placement.tries,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(BuiltDisplay {
        buckets,
        records: sorted.len() as u64,
    })
}

/// Checks every row of a shard, streaming rows.
///
/// Every row must be canonical, each entry must sit in its own bucket at its
/// one row under that bucket's seed, no tag may appear twice in the shard,
/// the per-bucket counts must match, and an overflow segment must hold an
/// entry: an empty one would only add a reply frame to every query of its
/// table. Returns the counts.
pub fn verify_rows(
    shard_id: u64,
    geometry: &Geometry,
    directory_segments: &[usize],
    bucket_records: &[u64],
    placement_seeds: &[u32],
    mut row_at: impl FnMut(DisplayTable, usize, usize) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u64>, Error> {
    let n_buckets = directory_segments.len() as u32;
    if n_buckets == 0
        || n_buckets > MAX_BUCKETS
        || bucket_records.len() != directory_segments.len()
        || placement_seeds.len() != directory_segments.len()
        || placement_seeds.iter().any(|s| *s >= MAX_PLACEMENT_SEEDS)
        || directory_segments.contains(&0)
    {
        return Err(bad("display shard shape"));
    }
    let rows = geometry.directory_rows;
    let mut seen = BTreeSet::new();
    let mut counts = vec![0u64; n_buckets as usize];
    for (b, segments) in directory_segments.iter().enumerate() {
        let table = DisplayTable::Directory(b as u32);
        let seed = placement_seeds[b];
        for segment in 0..*segments {
            let before = counts[b];
            for row in 0..rows as usize {
                let bytes = row_at(table, segment, row)?;
                if bytes.len() != geometry.directory_row_bytes {
                    return Err(bad("row width"));
                }
                for entry in row_entries(&bytes)? {
                    if bucket(&entry.tag, n_buckets) != b as u32
                        || placement_row(&entry.tag, seed, shard_id, b as u32, rows) != row as u64
                        || !seen.insert(entry.tag)
                    {
                        return Err(bad("entry bucket/placement/duplicate"));
                    }
                    counts[b] += 1;
                }
            }
            if segment > 0 && counts[b] == before {
                return Err(bad("empty overflow segment"));
            }
        }
    }
    if counts != bucket_records {
        return Err(bad("bucket record count"));
    }
    Ok(counts)
}

/// [`verify_rows`] over tables held in memory.
pub fn verify(shard_id: u64, geometry: &Geometry, built: &BuiltDisplay) -> Result<Vec<u64>, Error> {
    let segments: Vec<usize> = built.buckets.iter().map(|b| b.directory.len()).collect();
    let records: Vec<u64> = built.buckets.iter().map(|b| b.records).collect();
    let seeds: Vec<u32> = built.buckets.iter().map(|b| b.placement_seed).collect();
    let width = geometry.directory_row_bytes;
    verify_rows(
        shard_id,
        geometry,
        &segments,
        &records,
        &seeds,
        |table, segment, row| {
            built
                .segments(table)
                .get(segment)
                .and_then(|s| s.get(row * width..(row + 1) * width))
                .map(<[u8]>::to_vec)
                .ok_or_else(|| bad("table row bounds"))
        },
    )
}

/// What a client would retrieve for `txid`: its bucket, its row, and that
/// row of every segment of the bucket's table. For tests and tooling.
pub fn row_for(
    built: &BuiltDisplay,
    shard_id: u64,
    geometry: &Geometry,
    txid: &Txid,
) -> (u32, u64, Vec<Vec<u8>>) {
    let tag = Tag::of(txid);
    let b = bucket(&tag, built.buckets.len() as u32);
    let bucket = &built.buckets[b as usize];
    let row = placement_row(
        &tag,
        bucket.placement_seed,
        shard_id,
        b,
        geometry.directory_rows,
    );
    let width = geometry.directory_row_bytes;
    let at = row as usize * width;
    let copies = bucket
        .directory
        .iter()
        .map(|segment| segment[at..at + width].to_vec())
        .collect();
    (b, row, copies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::TXID_2K8;
    use crate::txid::{find_entry, DisplayFacts, DisplayOutput};
    use sha2::{Digest, Sha256};

    fn txid(id: u32) -> Txid {
        Txid(Sha256::digest(id.to_le_bytes()).into())
    }

    fn entry(id: u32) -> DisplayEntry {
        let p2pkh = |b: u8| [&[0x76, 0xa9, 0x14][..], &[b; 20], &[0x88, 0xac]].concat();
        DisplayFacts {
            txid: txid(id),
            coinbase: false,
            fee: 1_000,
            has_shielded_components: false,
            spent: vec![DisplayOutput {
                value: 6_000,
                script: p2pkh(1),
            }],
            outputs: vec![DisplayOutput {
                value: 5_000,
                script: p2pkh(id as u8),
            }],
        }
        .entry()
        .unwrap()
    }

    /// Looks `id` up as a client does: one row, every segment, every entry
    /// checked against its placement.
    fn lookup(built: &BuiltDisplay, shard: u64, g: &Geometry, id: u32) -> Option<DisplayEntry> {
        let (b, row, copies) = row_for(built, shard, g, &txid(id));
        let seed = built.buckets[b as usize].placement_seed;
        let in_row = |tag: &Tag| placement_row(tag, seed, shard, b, g.directory_rows) == row;
        find_entry(&copies, &txid(id), in_row).unwrap()
    }

    #[test]
    fn entries_are_found_in_their_own_bucket_and_row() {
        let g = TXID_2K8;
        let entries: Vec<_> = (0..3_000).map(entry).collect();
        for n in [1, 4] {
            let built = build_shard(7, &g, n, &entries).unwrap();
            assert_eq!(built.records, entries.len() as u64);
            assert_eq!(built.buckets.len(), n as usize);
            assert!(built.buckets.iter().all(|b| b.directory.len() == 1));
            assert!(built
                .buckets
                .iter()
                .all(|b| b.directory[0].len() == 2_048 * 8_192));
            // A light table fits the first seed.
            assert!(built.buckets.iter().all(|b| b.placement_seed == 0));
            let counts = verify(7, &g, &built).unwrap();
            assert_eq!(counts.iter().sum::<u64>(), 3_000);
            for (id, e) in entries.iter().enumerate() {
                assert_eq!(lookup(&built, 7, &g, id as u32).as_ref(), Some(e));
            }
            assert_eq!(lookup(&built, 7, &g, 1_000_000), None);
        }
    }

    #[test]
    fn layout_is_deterministic_in_the_entry_set() {
        let g = TXID_2K8;
        let entries: Vec<_> = (0..500).map(entry).collect();
        let mut shuffled = entries.clone();
        shuffled.reverse();
        let a = build_shard(3, &g, 4, &entries).unwrap();
        let b = build_shard(3, &g, 4, &shuffled).unwrap();
        for table in a.tables() {
            assert_eq!(a.segments(table), b.segments(table));
        }
        assert!(build_shard(3, &g, 4, &[entries[0], entries[0]]).is_err());
        assert!(build_shard(3, &g, 0, &entries).is_err());
        assert!(build_shard(3, &g, MAX_BUCKETS + 1, &entries).is_err());
    }

    /// A small table filled so that the first seed often leaves a row over
    /// capacity: 64 rows of 72 slots at 76% fill. Each table keeps the
    /// smallest fitting seed and stays one segment.
    #[test]
    fn the_smallest_fitting_seed_is_kept() {
        let g = Geometry {
            directory_rows: 64,
            ..TXID_2K8
        };
        let mut searched = 0;
        for set in 0..20u32 {
            let entries: Vec<_> = (set * 10_000..set * 10_000 + 3_500).map(entry).collect();
            let built = build_shard(5, &g, 1, &entries).unwrap();
            let bucket = &built.buckets[0];
            assert_eq!(bucket.directory.len(), 1, "set {set}");
            assert_eq!(bucket.seed_tries, bucket.placement_seed + 1);
            verify(5, &g, &built).unwrap();
            let tags: Vec<Tag> = entries.iter().map(|e| e.tag).collect();
            for seed in 0..bucket.placement_seed {
                let mut loads = vec![0usize; 64];
                for tag in &tags {
                    loads[placement_row(tag, seed, 5, 0, 64) as usize] += 1;
                }
                assert!(loads.iter().any(|l| *l > 72), "seed {seed} fits");
            }
            searched += usize::from(bucket.placement_seed > 0);
            for id in [set * 10_000, set * 10_000 + 3_499] {
                assert!(lookup(&built, 5, &g, id).is_some());
            }
        }
        assert!(searched > 0, "the fixture exercises the seed search");
    }

    #[test]
    fn a_table_no_seed_fits_overflows_into_segments_per_bucket() {
        // More entries than one row holds overflow a one-row table under
        // every seed.
        let one_row = Geometry {
            directory_rows: 1,
            ..TXID_2K8
        };
        let entries: Vec<_> = (0..160).map(entry).collect();
        let tags: Vec<Tag> = entries.iter().map(|e| e.tag).collect();
        let placement = place_bucket(&tags, 0, 0, &one_row);
        assert_eq!(
            (placement.tries, placement.max_load, placement.segments),
            (MAX_PLACEMENT_SEEDS, 160, 3)
        );
        let built = build_shard(0, &one_row, 2, &entries).unwrap();
        assert!(built.overflowed());
        assert!(built.buckets.iter().all(|b| b.directory.len() > 1));
        verify(0, &one_row, &built).unwrap();
        for id in 0..160 {
            assert!(lookup(&built, 0, &one_row, id).is_some());
        }
        assert_eq!(lookup(&built, 0, &one_row, 1_000), None);
    }

    #[test]
    fn verification_refuses_moved_duplicated_and_miscounted_entries() {
        let g = TXID_2K8;
        let entries: Vec<_> = (0..200).map(entry).collect();
        let built = build_shard(1, &g, 2, &entries).unwrap();
        verify(1, &g, &built).unwrap();

        // The wrong shard id moves every row.
        assert!(verify(2, &g, &built).is_err());

        // So does the wrong seed.
        let mut reseeded = built.clone();
        reseeded.buckets[0].placement_seed += 1;
        assert!(verify(1, &g, &reseeded).is_err());
        let mut unbounded = built.clone();
        unbounded.buckets[0].placement_seed = MAX_PLACEMENT_SEEDS;
        assert!(verify(1, &g, &unbounded).is_err());

        // A bucket's table presented as the other bucket's.
        let mut swapped = built.clone();
        swapped.buckets.swap(0, 1);
        assert!(verify(1, &g, &swapped).is_err());

        // A wrong count.
        let mut miscounted = built.clone();
        miscounted.buckets[0].records += 1;
        assert!(verify(1, &g, &miscounted).is_err());

        // An empty overflow segment, which the builder never writes.
        let mut padded_out = built.clone();
        let empty = vec![0; padded_out.buckets[0].directory[0].len()];
        padded_out.buckets[0].directory.push(empty);
        assert!(verify(1, &g, &padded_out).is_err());

        // An extra copy of a segment duplicates every entry in it.
        let mut duplicated = built.clone();
        let extra = duplicated.buckets[0].directory[0].clone();
        duplicated.buckets[0].directory.push(extra);
        assert!(verify(1, &g, &duplicated).is_err());

        // A noncanonical row: one byte of padding.
        let mut padded = built.clone();
        padded.buckets[0].directory[0][g.directory_row_bytes - 1] = 1;
        assert!(verify(1, &g, &padded).is_err());

        // A client refuses a fetched row holding an entry placed elsewhere.
        let (b, row, copies) = row_for(&built, 1, &g, &txid(0));
        let seed = built.buckets[b as usize].placement_seed;
        let other_row = |tag: &Tag| placement_row(tag, seed, 1, b, g.directory_rows) != row;
        assert!(find_entry(&copies, &txid(0), other_row).is_err());
    }
}
