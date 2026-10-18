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

use super::{DisplayTable, MAX_BUCKETS, MAX_PLACEMENT_SEEDS, bucket, placement_row};
use crate::transparent::events::Txid;
use crate::transparent::shard::layout::Geometry;
use crate::transparent::shard::txid::{Error, Tag, row_entries};
use std::collections::BTreeSet;

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
