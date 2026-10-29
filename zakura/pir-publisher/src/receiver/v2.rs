//! Receiver v2 construction: projecting blocks into a segment's directory under
//! its tag salt, and building the segment's tables from its payments.
pub use zakura_pir_protocol::receiver::v2::*;

use crate::directory::{Overflow, place};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use zakura_pir_protocol::directory::{bucket::DIRECTORY_CHOICES, tag::resolve_salt};
use zakura_pir_protocol::receiver::{Hash, ReceiverBytes};

#[cfg(test)]
mod tests;

/// Fixed-row placement of a segment's tags in insertion order, refusing
/// overflow. [`Rows::insert`] commits a batch or changes nothing.
#[derive(Clone)]
struct Rows {
    salts: [Hash; DIRECTORY_CHOICES],
    rows: u64,
    entries: usize,
    tags: Vec<Tag>,
    assignment: Vec<u32>,
}

impl Rows {
    /// No tags yet, in `rows` rows of `entries` entries, under `salt`.
    fn new(salt: &Hash, rows: u64, entries: usize) -> Self {
        let salts = bucket_salts(salt);
        let (tags, assignment) = (Vec::new(), Vec::new());
        Self {
            salts,
            rows,
            entries,
            tags,
            assignment,
        }
    }

    /// Places `tags` after those already placed, relocating as needed, or
    /// changes nothing and returns false.
    fn insert(&mut self, tags: &[Tag]) -> bool {
        let all: Vec<Tag> = self.tags.iter().chain(tags).copied().collect();
        let keys: Vec<&[u8]> = all.iter().map(|tag| &tag[..]).collect();
        let sizes = vec![ENTRY_BYTES; keys.len()];
        let capacity = self.entries * ENTRY_BYTES;
        let Ok((_, assignment)) = place(
            &self.salts,
            &keys,
            &sizes,
            self.rows,
            capacity,
            Overflow::Refuse,
        ) else {
            return false;
        };
        (self.tags, self.assignment) = (all, assignment);
        true
    }
}

/// A segment's directory as blocks are projected into it: the committed tag
/// salt, each receiver's tag and the placement.
///
/// Projection, publication and replay after a restart all apply
/// [`Projection::project`] block by block, so they agree on the salt and rows
/// however often publication runs.
#[derive(Clone)]
pub struct Projection {
    salt: Hash,
    tags: BTreeMap<ReceiverBytes, Tag>,
    taken: HashSet<Tag>,
    rows: Rows,
}

/// A block that collides or fails placement under all of its attempts: the
/// segment seals before it.
#[derive(Debug, PartialEq, Eq)]
pub struct SealBefore;

impl Projection {
    /// An empty segment under its committed salt, at first [`initial_salt`].
    pub fn new(salt: Hash) -> Self {
        Self::with_rows(salt, DIRECTORY_ROWS.into(), ROW_ENTRIES)
    }

    /// An empty segment over a directory of `rows` rows of `entries` entries.
    fn with_rows(salt: Hash, rows: u64, entries: usize) -> Self {
        let rows = Rows::new(&salt, rows, entries);
        Self {
            salt,
            tags: BTreeMap::new(),
            taken: HashSet::new(),
            rows,
        }
    }

    /// The committed tag salt.
    pub fn salt(&self) -> &Hash {
        &self.salt
    }

    /// Each receiver's tag and directory row, in placement order.
    pub fn placement(&self) -> impl Iterator<Item = (&Tag, u32)> {
        self.rows
            .tags
            .iter()
            .zip(self.rows.assignment.iter().copied())
    }

    /// Projects one block: `paid` lists every receiver it pays, in any order
    /// and with repeats, and `block` is its hash.
    ///
    /// The block's new receivers are placed, in tag order, under the committed
    /// salt. If a tag collides or placement fails, the whole segment is placed
    /// again under the first of [`retry_salt`] 1 to [`MAX_SALT_RETRIES`] whose
    /// tags are distinct and fit, which becomes the committed salt. Every block
    /// has its own budget. Returns the retry used, 0 for none; on [`SealBefore`]
    /// nothing changes.
    pub fn project(&mut self, paid: &[ReceiverBytes], block: &Hash) -> Result<u32, SealBefore> {
        self.project_by(paid, block, tag)
    }

    /// [`Projection::project`] with tags from `tag_of`, which tests use to force
    /// collisions.
    fn project_by(
        &mut self,
        paid: &[ReceiverBytes],
        block: &Hash,
        mut tag_of: impl FnMut(&Hash, &[u8]) -> Tag,
    ) -> Result<u32, SealBefore> {
        let new: BTreeSet<ReceiverBytes> = paid
            .iter()
            .filter(|r| !self.tags.contains_key(*r))
            .copied()
            .collect();
        let fresh = tagged(&self.salt, new.iter(), &mut tag_of);
        let distinct = fresh.windows(2).all(|w| w[0].0 != w[1].0)
            && fresh.iter().all(|(t, _)| !self.taken.contains(t));
        if distinct && self.insert(&fresh) {
            return Ok(0);
        }
        let all: Vec<ReceiverBytes> = self.tags.keys().chain(&new).copied().collect();
        let keys: Vec<&[u8]> = all.iter().map(|r| &r[..]).collect();
        let committed = self.salt;
        let mut from = 1;
        while let Some((retry, salt)) = resolve_salt(
            from..=MAX_SALT_RETRIES,
            |r| retry_salt(&committed, r, block),
            &keys,
            &mut tag_of,
        ) {
            let mut next = Self::with_rows(salt, self.rows.rows, self.rows.entries);
            if next.insert(&tagged(&salt, all.iter(), &mut tag_of)) {
                *self = next;
                return Ok(retry);
            }
            from = retry + 1;
        }
        Err(SealBefore)
    }

    /// Places `tagged`, sorted by tag, after the placed receivers and records
    /// them, or changes nothing and returns false.
    fn insert(&mut self, tagged: &[(Tag, ReceiverBytes)]) -> bool {
        let tags: Vec<Tag> = tagged.iter().map(|(t, _)| *t).collect();
        if !self.rows.insert(&tags) {
            return false;
        }
        self.taken.extend(tags);
        self.tags.extend(tagged.iter().map(|(t, r)| (*r, *t)));
        true
    }
}

/// `receivers` and their tags under `salt`, sorted by tag.
fn tagged<'a>(
    salt: &Hash,
    receivers: impl Iterator<Item = &'a ReceiverBytes>,
    tag_of: &mut impl FnMut(&Hash, &[u8]) -> Tag,
) -> Vec<(Tag, ReceiverBytes)> {
    let mut tagged: Vec<_> = receivers.map(|r| (tag_of(salt, r), *r)).collect();
    tagged.sort_unstable();
    tagged
}
