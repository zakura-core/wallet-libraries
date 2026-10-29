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

/// What placement does when a key fits in neither candidate row, even after
/// relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overflow {
    /// Add a segment and place every key again over the larger row space, up
    /// to this many segments.
    Grow(u32),
    /// Fail at one segment and leave the decision to the caller.
    Refuse,
}

/// Places `keys`, in order, into fresh [`FixedRows`] of `capacity` bytes.
///
/// Rows are `rows_per_segment` times the segment count, which `overflow`
/// decides: a key that does not fit places every key again over one more
/// segment. Returns the placement and each key's logical row, or the index of
/// the key that could not be placed (see [`FixedRows::insert`]) once `overflow`
/// allows no more segments.
pub fn place(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    keys: &[&[u8]],
    sizes: &[usize],
    rows_per_segment: u64,
    capacity: usize,
    overflow: Overflow,
) -> Result<(Placement, Vec<u32>), usize> {
    let max_segments = match overflow {
        Overflow::Grow(max) => max,
        Overflow::Refuse => 1,
    };
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

/// One change a batch made, undone in reverse if the batch fails.
enum Step {
    Placed,
    Moved {
        entry: u32,
        from: u32,
        position: usize,
    },
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
        let mut steps = Vec::new();
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
                .or_else(|| self.relocate([a, b], size, &mut steps));
            let Some(row) = row else {
                self.undo(steps);
                return Err(index);
            };
            self.occupants[row].push(self.entries.len() as u32);
            self.used[row] += size;
            self.entries.push(Entry {
                candidates,
                size,
                row: row as u32,
            });
            steps.push(Step::Placed);
        }
        Ok(())
    }

    /// Each entry's row, in insertion order.
    pub fn assignment(&self) -> Vec<u32> {
        self.entries.iter().map(|entry| entry.row).collect()
    }

    /// Each row's entries, as insertion indices in the order they arrived.
    pub fn into_rows(self) -> Vec<Vec<u32>> {
        self.occupants
    }

    /// Reverts `steps`, newest first, so each sees the state it left.
    fn undo(&mut self, steps: Vec<Step>) {
        for step in steps.into_iter().rev() {
            match step {
                Step::Placed => {
                    let entry = self.entries.pop().expect("a placed entry is the newest");
                    self.occupants[entry.row as usize].pop();
                    self.used[entry.row as usize] -= entry.size;
                }
                Step::Moved {
                    entry,
                    from,
                    position,
                } => {
                    let moved = &mut self.entries[entry as usize];
                    let to = moved.row as usize;
                    self.occupants[to].pop();
                    self.occupants[from as usize].insert(position, entry);
                    self.used[to] -= moved.size;
                    self.used[from as usize] += moved.size;
                    moved.row = from;
                }
            }
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

/// The index of the first key whose chosen candidate, `choose(key)`, is not
/// `row_of(index)`, or `None` if every key is routed to its row.
pub fn misrouted(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    keys: &[&[u8]],
    rows: u64,
    choose: impl Fn(&[u8]) -> usize,
    row_of: impl Fn(usize) -> u64,
) -> Option<usize> {
    keys.iter()
        .enumerate()
        .position(|(index, key)| candidates(salts, key, rows)[choose(key)] != row_of(index))
}

/// Why encoded rows disagree with a placement. See [`verify_assignment`].
#[derive(Debug, PartialEq, Eq)]
pub enum AssignmentError<E> {
    /// The caller's decoder refused a row.
    Decode(E),
    /// `tags` and `assignment` differ in length.
    Lengths { tags: usize, assignment: usize },
    /// A tag appears twice, in the rows or among the expected tags.
    Duplicate,
    /// The rows hold `held` tags where `placed` entries were placed.
    Count { held: usize, placed: usize },
    /// Entry `index` is not in its assigned row `row`.
    Misplaced { index: usize, row: u32 },
}

/// Checks the encoded rows, not the placer's intent.
///
/// `rows` are the encoded rows in logical order and `decode` returns the tags
/// one holds. Entry `i` has tag `tags[i]` and was placed in row
/// `assignment[i]`. Both must have one item per entry and the expected tags
/// must be distinct. Every entry's tag must decode from its row, no tag may
/// appear twice, and the rows must hold exactly the entries placed.
pub fn verify_assignment<'a, T: Copy + Eq + std::hash::Hash, E>(
    rows: impl IntoIterator<Item = &'a [u8]>,
    mut decode: impl FnMut(&[u8]) -> Result<Vec<T>, E>,
    tags: &[T],
    assignment: &[u32],
) -> Result<(), AssignmentError<E>> {
    if tags.len() != assignment.len() {
        return Err(AssignmentError::Lengths {
            tags: tags.len(),
            assignment: assignment.len(),
        });
    }
    let mut seen = std::collections::HashSet::with_capacity(tags.len());
    if !tags.iter().all(|tag| seen.insert(*tag)) {
        return Err(AssignmentError::Duplicate);
    }
    seen.clear();
    let mut decoded = Vec::new();
    for raw in rows {
        let row = decode(raw).map_err(AssignmentError::Decode)?;
        if !row.iter().all(|tag| seen.insert(*tag)) {
            return Err(AssignmentError::Duplicate);
        }
        decoded.push(row);
    }
    if seen.len() != tags.len() {
        return Err(AssignmentError::Count {
            held: seen.len(),
            placed: tags.len(),
        });
    }
    for (index, (tag, row)) in tags.iter().zip(assignment).enumerate() {
        if !decoded
            .get(*row as usize)
            .is_some_and(|held| held.contains(tag))
        {
            return Err(AssignmentError::Misplaced { index, row: *row });
        }
    }
    Ok(())
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
    /// recorded it in `steps`.
    fn relocate(
        &mut self,
        roots: [usize; 2],
        incoming: usize,
        steps: &mut Vec<Step>,
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
                    steps.push(Step::Moved {
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
        assert_eq!(
            place(&salts, &all, &sizes, 4, 4_092, Overflow::Refuse).unwrap_err(),
            472
        );
        let (grown, _) = place(&salts, &all, &sizes, 4, 4_092, Overflow::Grow(8)).unwrap();
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
        let row_of = |i: usize| u64::from(assignment[i]);
        assert_eq!(
            misrouted(&salts, &keys, 4, |key| bits[key].into(), row_of),
            None
        );
        let rows = whole.into_rows();
        assert_eq!(rows.iter().map(Vec::len).sum::<usize>(), keys.len());
    }

    /// A caller's decoder: each row is two one-byte tags, zero for empty, and
    /// `0xff` is malformed.
    #[test]
    fn assignment_is_checked_through_the_callers_decoder() {
        let decode = |raw: &[u8]| -> Result<Vec<u8>, ()> {
            if raw.contains(&0xff) {
                return Err(());
            }
            Ok(raw.iter().copied().filter(|tag| *tag != 0).collect())
        };
        let check_tags = |rows: &[u8], tags: &[u8], assignment: &[u32]| {
            let rows = rows.as_chunks::<2>().0.iter().map(|row| &row[..]);
            verify_assignment(rows, decode, tags, assignment)
        };
        let check = |rows: &[u8], assignment: &[u32]| check_tags(rows, &[1, 2, 3], assignment);
        assert_eq!(check(&[1, 0, 2, 3], &[0, 1, 1]), Ok(()));
        assert_eq!(
            check(&[1, 0, 0xff, 3], &[0, 1, 1]),
            Err(AssignmentError::Decode(()))
        );
        assert_eq!(
            check(&[1, 1, 2, 3], &[0, 1, 1]),
            Err(AssignmentError::Duplicate)
        );
        assert_eq!(
            check(&[1, 0, 2, 0], &[0, 1, 1]),
            Err(AssignmentError::Count { held: 2, placed: 3 })
        );
        assert_eq!(
            check(&[1, 0, 2, 3], &[1, 1, 1]),
            Err(AssignmentError::Misplaced { index: 0, row: 1 })
        );
        // An assignment missing an entry, which `zip` would have skipped.
        assert_eq!(
            check_tags(&[1, 2], &[1, 2], &[0]),
            Err(AssignmentError::Lengths {
                tags: 2,
                assignment: 1
            })
        );
        // A repeated expected tag hiding the substituted 3.
        assert_eq!(
            check_tags(&[1, 3], &[1, 1], &[0, 0]),
            Err(AssignmentError::Duplicate)
        );
    }
}
