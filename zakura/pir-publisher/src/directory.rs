//! Two-choice directory placement and its checks, shared by Transparent and
//! Receiver.
//!
//! Everything here is a deterministic function of its inputs: keys are
//! placed in the order given and relocation breaks ties by a fixed rule, so
//! two operators with the same input publish byte-identical tables. Each format
//! supplies its own bucket salts, entry sizes, order and overflow policy.

use zakura_pir_protocol::directory::bucket::{DIRECTORY_CHOICES, candidates};

/// What two-choice placement costs a key set.
///
/// Byte density alone is a lower bound; this reports the actual weighted
/// two-choice placement and segment count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// Segments the placement rule needed.
    pub segments: u32,
    /// Entries in the fullest row, for diagnostics. Bytes constrain capacity.
    pub max_row_load: u64,
    /// Maximum occupied payload bytes in any row.
    pub max_row_bytes: u64,
}

/// Places `keys`, in order, into fresh [`FixedRows`] of `capacity` bytes.
///
/// Rows are `rows_per_segment` times the segment count: a key that does not
/// fit places every key again over one more segment, up to `max_segments`.
/// Returns the placement and each key's logical row, or the index of the key
/// that could not be placed (see [`FixedRows::insert`]) at `max_segments`.
pub fn place(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    keys: &[&[u8]],
    sizes: &[usize],
    rows_per_segment: u64,
    capacity: usize,
    max_segments: u32,
) -> Result<(Placement, Vec<u32>), usize> {
    let mut segments = 1;
    loop {
        let mut rows = FixedRows::new(*salts, rows_per_segment * u64::from(segments), capacity);
        match rows.insert(keys, sizes) {
            Ok(()) => {
                let placement = Placement {
                    segments,
                    max_row_load: rows
                        .occupants
                        .iter()
                        .map(|r| r.len() as u64)
                        .max()
                        .unwrap_or(0),
                    max_row_bytes: rows.used.iter().copied().max().unwrap_or(0) as u64,
                };
                return Ok((placement, rows.assignment()));
            }
            Err(index) if segments < max_segments && (1..=capacity).contains(&sizes[index]) => {
                segments += 1;
            }
            Err(index) => return Err(index),
        }
    }
}

/// Fixed rows filled by two-choice placement, kept between batches so a
/// caller can add entries to an existing placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedRows {
    salts: [[u8; 32]; DIRECTORY_CHOICES],
    capacity: usize,
    /// Each row's entries, in the order they arrived.
    occupants: Vec<Vec<u32>>,
    /// Bytes used in each row.
    used: Vec<usize>,
    entries: Vec<Entry>,
}

/// One placed entry: its candidate rows, its size and the row holding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    candidates: [u32; DIRECTORY_CHOICES],
    size: usize,
    row: u32,
}

/// A relocation move a batch made, undone if the batch fails. `placed` is the
/// entry count when it was made, so entries placed after it are removed first.
struct Move {
    placed: u32,
    entry: u32,
    from: u32,
    position: usize,
}

impl FixedRows {
    /// Empty rows: `rows` rows of `capacity` bytes, with candidate rows drawn
    /// under `salts`.
    pub fn new(salts: [[u8; 32]; DIRECTORY_CHOICES], rows: u64, capacity: usize) -> Self {
        Self {
            salts,
            capacity,
            occupants: vec![Vec::new(); rows as usize],
            used: vec![0; rows as usize],
            entries: Vec::new(),
        }
    }

    /// Places a batch of keys, in order, after the entries already placed.
    ///
    /// Each key takes the emptier of its two candidate rows that has room for
    /// its size, or else frees room in one by relocation. If a key has a size
    /// of zero or above the capacity, or fits nowhere even after relocation,
    /// returns its index within the batch and leaves the rows exactly as they
    /// were before the call, relocation moves included.
    pub fn insert(&mut self, keys: &[&[u8]], sizes: &[usize]) -> Result<(), usize> {
        assert_eq!(keys.len(), sizes.len());
        if let Some(i) = sizes
            .iter()
            .position(|size| *size == 0 || *size > self.capacity)
        {
            return Err(i);
        }
        let rows = self.used.len() as u64;
        let first = self.entries.len();
        self.entries.reserve(keys.len());
        let mut moves = Vec::new();
        for (index, (key, &size)) in keys.iter().zip(sizes).enumerate() {
            let candidates = candidates(&self.salts, key, rows).map(|row| row as u32);
            let [a, b] = candidates.map(|row| row as usize);
            let direct = if self.used[a] <= self.used[b] {
                [a, b]
            } else {
                [b, a]
            };
            let row = direct
                .into_iter()
                .find(|row| self.used[*row] + size <= self.capacity)
                .or_else(|| self.relocate([a, b], size, &mut moves));
            let Some(row) = row else {
                self.undo(first, moves);
                return Err(index);
            };
            self.occupants[row].push(self.entries.len() as u32);
            self.used[row] += size;
            self.entries.push(Entry {
                candidates,
                size,
                row: row as u32,
            });
        }
        Ok(())
    }

    /// Each entry's row, in insertion order.
    pub fn assignment(&self) -> Vec<u32> {
        self.entries.iter().map(|entry| entry.row).collect()
    }

    /// Reverts a failed batch to `first` entries: newest first, each move
    /// after the entries placed since it, so each sees the state it left.
    fn undo(&mut self, first: usize, moves: Vec<Move>) {
        for Move {
            placed,
            entry,
            from,
            position,
        } in moves.into_iter().rev()
        {
            self.truncate(placed as usize);
            let moved = &mut self.entries[entry as usize];
            let to = moved.row as usize;
            self.occupants[to].pop();
            self.occupants[from as usize].insert(position, entry);
            self.used[to] -= moved.size;
            self.used[from as usize] += moved.size;
            moved.row = from;
        }
        self.truncate(first);
    }

    /// Removes the entries placed after the first `len`, newest first.
    fn truncate(&mut self, len: usize) {
        while self.entries.len() > len {
            let entry = self.entries.pop().expect("more than `len` entries");
            self.occupants[entry.row as usize].pop();
            self.used[entry.row as usize] -= entry.size;
        }
    }
}

/// The choice table's entries for a placement: each key with the index of
/// the candidate its assigned row is, out of `rows` rows. A key whose two
/// candidates name the same row takes 0; either answer names that row.
pub fn choice_bits<'a>(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    keys: &[&'a [u8]],
    assignment: &[u32],
    rows: u64,
) -> Vec<(&'a [u8], u8)> {
    keys.iter()
        .zip(assignment)
        .map(|(key, row)| {
            let [first, _] = candidates(salts, key, rows);
            (*key, u8::from(u64::from(*row) != first))
        })
        .collect()
}

/// Rows a relocation search may visit before giving up and taking a segment.
///
/// A bound rather than a budget for the whole shard: the search is per key,
/// and the shortest path to a row with space is a handful of hops even at high
/// load. The bound and single-resident moves may miss a feasible packing;
/// retrying with another segment preserves correctness in that case.
const MAX_RELOCATION_VISITS: usize = 512;

impl FixedRows {
    /// Frees enough bytes in a root by moving residents to their other candidate.
    ///
    /// Breadth-first, so the path taken is the shortest available and the search
    /// cannot cycle — a depth-first walk with a kick budget can revisit rows
    /// forever at high load, and a random walk would not be reproducible. Ties are
    /// broken by the order rows enter the frontier and, within a row, by the order
    /// entries were placed, both of which are functions of the key set alone.
    /// Two operators therefore relocate identically or the published digests stop
    /// being comparable, which is the property this whole module exists to keep.
    ///
    /// Returns the row left with space, having applied every move on the path and
    /// recorded it in `moves`.
    fn relocate(
        &mut self,
        roots: [usize; 2],
        incoming: usize,
        moves: &mut Vec<Move>,
    ) -> Option<usize> {
        // Each edge moves one resident large enough to satisfy its predecessor's
        // byte deficit. A path may never revisit a row. Failed searches mutate nothing.
        struct Node {
            row: usize,
            need: usize,
            parent: Option<(usize, u32)>,
        }
        let mut nodes = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for row in roots {
            if seen.insert((row, incoming)) {
                nodes.push(Node {
                    row,
                    need: incoming,
                    parent: None,
                });
            }
        }
        let mut cursor = 0;
        while cursor < nodes.len() && cursor < MAX_RELOCATION_VISITS {
            let row = nodes[cursor].row;
            let need = nodes[cursor].need;
            if self.used[row] + need <= self.capacity {
                let mut at = cursor;
                while let Some((parent, moved)) = nodes[at].parent {
                    let from = nodes[parent].row;
                    let to = nodes[at].row;
                    let position = self.occupants[from]
                        .iter()
                        .position(|e| *e == moved)
                        .expect("resident");
                    self.occupants[from].remove(position);
                    self.occupants[to].push(moved);
                    let entry = &mut self.entries[moved as usize];
                    self.used[from] -= entry.size;
                    self.used[to] += entry.size;
                    entry.row = to as u32;
                    moves.push(Move {
                        placed: self.entries.len() as u32,
                        entry: moved,
                        from: from as u32,
                        position,
                    });
                    at = parent;
                }
                return Some(nodes[at].row);
            }
            for &resident in &self.occupants[row] {
                let entry = self.entries[resident as usize];
                if self.used[row] - entry.size + need > self.capacity {
                    continue;
                }
                let alternate = entry
                    .candidates
                    .into_iter()
                    .map(|r| r as usize)
                    .find(|r| *r != row);
                let Some(alternate) = alternate else {
                    continue;
                };
                let mut ancestor = Some(cursor);
                let mut cyclic = false;
                while let Some(at) = ancestor {
                    if nodes[at].row == alternate {
                        cyclic = true;
                        break;
                    }
                    ancestor = nodes[at].parent.map(|(p, _)| p);
                }
                if !cyclic
                    && seen.insert((alternate, entry.size))
                    && nodes.len() < MAX_RELOCATION_VISITS
                {
                    nodes.push(Node {
                        row: alternate,
                        need: entry.size,
                        parent: Some((cursor, resident)),
                    });
                }
            }
            cursor += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pir_protocol::directory::bucket::bucket_salts;

    /// Keys whose two candidate rows, out of 4, both lie in `rows`.
    fn keys_in(salts: &[[u8; 32]; 2], rows: &[u64], count: usize, skip: u32) -> Vec<[u8; 14]> {
        (skip..)
            .map(|i| std::array::from_fn(|at| i.to_le_bytes().get(at).copied().unwrap_or(0)))
            .filter(|key: &[u8; 14]| {
                let [a, b] = candidates(salts, key, 4);
                a != b && rows.contains(&a) && rows.contains(&b)
            })
            .take(count)
            .collect()
    }

    fn refs(keys: &[[u8; 14]]) -> Vec<&[u8]> {
        keys.iter().map(|key| &key[..]).collect()
    }

    /// Receiver's shape: 22-byte entries in 4,092-byte rows, so 186 a row.
    /// Keys confined to rows 0 and 1 overflow those two rows while rows 2
    /// and 3 still have room. The refused batch leaves the rows exactly as
    /// they were, including the relocations it made before failing.
    #[test]
    fn a_candidate_bottleneck_is_refused_and_rolled_back() {
        let salts = bucket_salts(b"directory-placement-test\0", &[3; 8]);
        // 100 keys between rows 0 and 2, then 373 confined to rows 0 and 1.
        let spread = keys_in(&salts, &[0, 2], 100, 0);
        let confined = keys_in(&salts, &[0, 1], 373, 1 << 20);
        let (spread, confined) = (refs(&spread), refs(&confined));
        let sizes = vec![22; confined.len()];

        let mut rows = FixedRows::new(salts, 4, 4_092);
        rows.insert(&spread, &sizes[..100]).unwrap();
        assert!(!rows.occupants[0].is_empty() && rows.used[3] == 0);
        let before = rows.clone();

        // 372 confined keys fit only by moving every spread key out of row 0.
        let mut fits = rows.clone();
        fits.insert(&confined[..372], &sizes[..372]).unwrap();
        assert!(fits.occupants[0].iter().all(|entry| *entry >= 100));

        assert_eq!(rows.insert(&confined, &sizes), Err(372));
        assert_eq!(rows, before);
        assert!(rows.used.iter().sum::<usize>() + 22 * 373 < 4 * 4_092);

        let all = [spread, confined].concat();
        let sizes = vec![22; all.len()];
        assert_eq!(place(&salts, &all, &sizes, 4, 4_092, 1).unwrap_err(), 472);
        let (grown, _) = place(&salts, &all, &sizes, 4, 4_092, 8).unwrap();
        assert!(grown.segments > 1);
    }

    /// Adding entries batch by batch places them as one batch would, and a
    /// placement's choice bits route every key.
    #[test]
    fn batches_place_like_one_batch() {
        let salts = bucket_salts(b"directory-placement-test\0", &[4; 8]);
        let owned: Vec<[u8; 14]> = (0..600u32)
            .map(|i| std::array::from_fn(|at| i.to_le_bytes().get(at).copied().unwrap_or(0)))
            .collect();
        let keys = refs(&owned);
        let sizes = vec![22; keys.len()];
        let mut whole = FixedRows::new(salts, 4, 4_092);
        whole.insert(&keys, &sizes).unwrap();
        let mut batched = FixedRows::new(salts, 4, 4_092);
        for (keys, sizes) in keys.chunks(97).zip(sizes.chunks(97)) {
            batched.insert(keys, sizes).unwrap();
        }
        assert_eq!(batched, whole);

        let assignment = whole.assignment();
        let bits: std::collections::BTreeMap<_, _> = choice_bits(&salts, &keys, &assignment, 4)
            .into_iter()
            .collect();
        assert!(keys.iter().zip(&assignment).all(|(key, row)| {
            candidates(&salts, key, 4)[usize::from(bits[key])] == u64::from(*row)
        }));
        let held = whole.occupants.iter().map(Vec::len).sum::<usize>();
        assert_eq!(held, keys.len());
    }
}
