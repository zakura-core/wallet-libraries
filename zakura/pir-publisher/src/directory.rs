//! Two-choice directory placement and its checks, shared by Transparent and
//! Receiver.
//!
//! Every function here is a deterministic function of its inputs: keys are
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

/// Places `keys`, in order, into rows of `capacity` bytes.
///
/// Each key takes the emptier of its two candidate rows that has room for its
/// size, or else frees room in one by relocation. Rows are `rows_per_segment`
/// times the segment count, which `overflow` decides. Returns the placement and
/// each key's logical row, or the index of the key that could not be placed: a
/// key of zero size or larger than `capacity`, or the first key that overflowed
/// once `overflow` allowed no more segments.
pub fn place(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    keys: &[&[u8]],
    sizes: &[usize],
    rows_per_segment: u64,
    capacity: usize,
    overflow: Overflow,
) -> Result<(Placement, Vec<u32>), usize> {
    assert_eq!(keys.len(), sizes.len());
    if let Some(i) = sizes.iter().position(|size| *size == 0 || *size > capacity) {
        return Err(i);
    }
    let max_segments = match overflow {
        Overflow::Grow(max) => max,
        Overflow::Refuse => 1,
    };
    let mut segments = 1;
    loop {
        let rows = (rows_per_segment * u64::from(segments)) as usize;
        let mut occupants: Vec<Vec<u32>> = vec![Vec::new(); rows];
        let mut used = vec![0usize; rows];
        let mut assignment = vec![u32::MAX; keys.len()];
        let mut overflowed = None;
        for (index, key) in keys.iter().enumerate() {
            let [a, b] = candidates(salts, key, rows as u64).map(|row| row as usize);
            let direct = if used[a] <= used[b] { [a, b] } else { [b, a] };
            let row = direct
                .into_iter()
                .find(|row| used[*row] + sizes[index] <= capacity)
                .or_else(|| {
                    relocate(
                        salts,
                        keys,
                        sizes,
                        &mut occupants,
                        &mut used,
                        &mut assignment,
                        [a, b],
                        sizes[index],
                        capacity,
                    )
                });
            if let Some(row) = row {
                occupants[row].push(index as u32);
                used[row] += sizes[index];
                assignment[index] = row as u32;
            } else {
                overflowed = Some(index);
                break;
            }
        }
        if let Some(index) = overflowed {
            segments += 1;
            if segments > max_segments {
                return Err(index);
            }
        } else {
            return Ok((
                Placement {
                    segments,
                    max_row_load: occupants.iter().map(|r| r.len() as u64).max().unwrap_or(0),
                    max_row_bytes: used.iter().copied().max().unwrap_or(0) as u64,
                },
                assignment,
            ));
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
    /// A tag appears twice.
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
/// `assignment[i]`. Every entry's tag must decode from that row, no tag may
/// appear twice, and the rows must hold exactly the entries placed.
pub fn verify_assignment<'a, T: Copy + Eq + std::hash::Hash, E>(
    rows: impl IntoIterator<Item = &'a [u8]>,
    mut decode: impl FnMut(&[u8]) -> Result<Vec<T>, E>,
    tags: &[T],
    assignment: &[u32],
) -> Result<(), AssignmentError<E>> {
    let mut decoded = Vec::new();
    let mut seen = std::collections::HashSet::with_capacity(tags.len());
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
/// Returns the row left with space, having applied every move on the path.
#[allow(clippy::too_many_arguments)]
fn relocate(
    salts: &[[u8; 32]; DIRECTORY_CHOICES],
    keys: &[&[u8]],
    sizes: &[usize],
    occupants: &mut [Vec<u32>],
    used: &mut [usize],
    assignment: &mut [u32],
    roots: [usize; 2],
    incoming: usize,
    capacity: usize,
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
        if used[row] + need <= capacity {
            let mut at = cursor;
            while let Some((parent, moved)) = nodes[at].parent {
                let from = nodes[parent].row;
                let to = nodes[at].row;
                let position = occupants[from]
                    .iter()
                    .position(|e| *e == moved)
                    .expect("resident");
                occupants[from].remove(position);
                occupants[to].push(moved);
                used[from] -= sizes[moved as usize];
                used[to] += sizes[moved as usize];
                assignment[moved as usize] = to as u32;
                at = parent;
            }
            return Some(nodes[at].row);
        }
        for &resident in &occupants[row] {
            let size = sizes[resident as usize];
            if used[row] - size + need > capacity {
                continue;
            }
            let alternate = candidates(salts, keys[resident as usize], occupants.len() as u64)
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
            if !cyclic && seen.insert((alternate, size)) && nodes.len() < MAX_RELOCATION_VISITS {
                nodes.push(Node {
                    row: alternate,
                    need: size,
                    parent: Some((cursor, resident)),
                });
            }
        }
        cursor += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pir_protocol::directory::bucket::bucket_salts;

    /// Receiver's shape: 22-byte entries in 4,092-byte rows, here 4 rows of
    /// 186 entries' bytes. A key set that needs a second segment is refused,
    /// naming the key that overflowed, where growth would add a segment.
    #[test]
    fn a_refusing_policy_fails_where_growth_adds_a_segment() {
        let salts = bucket_salts(b"directory-placement-test\0", &[3; 8]);
        let owned: Vec<[u8; 14]> = (0..40u32)
            .map(|i| std::array::from_fn(|at| i.to_le_bytes()[at % 4]))
            .collect();
        let keys: Vec<&[u8]> = owned.iter().map(|key| &key[..]).collect();
        let sizes = vec![22; keys.len()];
        let (grown, _) = place(&salts, &keys, &sizes, 4, 186, Overflow::Grow(8)).unwrap();
        assert!(grown.segments > 1);
        let refused = place(&salts, &keys, &sizes, 4, 186, Overflow::Refuse).unwrap_err();
        assert!(refused < keys.len());

        // A set that fits is placed, and its choice bits route every key.
        let (keys, sizes) = (&keys[..16], &sizes[..16]);
        let (fits, assignment) = place(&salts, keys, sizes, 4, 186, Overflow::Refuse).unwrap();
        assert_eq!(fits.segments, 1);
        let bits: std::collections::BTreeMap<_, _> = choice_bits(&salts, keys, &assignment, 4)
            .into_iter()
            .collect();
        let row_of = |i: usize| u64::from(assignment[i]);
        assert_eq!(
            misrouted(&salts, keys, 4, |key| bits[key].into(), row_of),
            None
        );
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
        let check = |rows: &[u8], assignment: &[u32]| {
            let rows = rows.as_chunks::<2>().0.iter().map(|row| &row[..]);
            verify_assignment(rows, decode, &[1, 2, 3], assignment)
        };
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
    }
}
