//! Receiver v2 construction: projecting blocks into a segment's directory under
//! its tag salt, and building the segment's tables from its payments.
pub use zakura_pir_protocol::receiver::v2::*;

use crate::directory::{Overflow, choice_bits, place};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use zakura_pir_protocol::directory::{
    bucket::DIRECTORY_CHOICES, choice::ChoiceTable, tag::resolve_salt,
};
use zakura_pir_protocol::receiver::{
    Error, Hash, Payment, RawRecord, ReceiverBytes, wire::PAYLOAD_BYTES,
};

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

/// One payment a segment holds: its receiver, the payment and its witness
/// payload at the companion's tree.
pub type Paid = (ReceiverBytes, Payment, [u8; PAYLOAD_BYTES]);

/// A segment's two tables.
#[derive(Clone)]
pub struct Segment {
    pub directory: DirectoryTable,
    pub companion: CompanionTable,
}

/// Builds a segment's directory, choice object and companion of `rows` rows
/// from its `payments` and the [`Projection`] of its blocks.
///
/// Slots go in tag order, then note position, with pages, totals and ordinals
/// from the slots. The choice seeds come from `seed_block` over `seed_attempts`
/// attempts ([`OPEN_SEED_ATTEMPTS`], or [`SEAL_SEED_ATTEMPTS`] at a seal). The
/// result passes the whole-segment checks a server repeats at preparation.
/// Fails with [`Error::Capacity`] past a limit, [`Error::Choice`] if no seed
/// builds, and [`Error::Malformed`] if the payments and projection disagree.
pub fn build(
    projection: &Projection,
    coverage: Coverage,
    seed_block: &Hash,
    seed_attempts: u32,
    rows: u32,
    tree: Tree,
    payments: &[Paid],
) -> Result<Segment, Error> {
    validate_companion_rows(rows)?;
    let mut by_receiver: BTreeMap<&ReceiverBytes, Vec<&Paid>> = BTreeMap::new();
    for paid in payments {
        by_receiver.entry(&paid.0).or_default().push(paid);
    }
    if payments.len() > (rows * ROW_SLOTS).min(CAPACITY) as usize
        || by_receiver
            .values()
            .any(|p| p.len() > MAX_RECEIVER_PAYMENTS as usize)
    {
        return Err(Error::Capacity);
    }
    if by_receiver.len() != projection.tags.len() {
        return Err(Error::Malformed);
    }
    let mut extents = by_receiver
        .into_iter()
        .map(|(receiver, mut paid)| {
            paid.sort_unstable_by_key(|p| p.1.position);
            Ok((
                *projection.tags.get(receiver).ok_or(Error::Malformed)?,
                paid,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    extents.sort_unstable_by_key(|(tag, _)| *tag);

    let row_of: HashMap<&Tag, u32> = projection.placement().collect();
    let mut directory_rows = vec![Vec::new(); DIRECTORY_ROWS as usize];
    let mut companion = vec![0; rows as usize * ROW_BYTES];
    let mut slot = 0;
    for (tag, paid) in &extents {
        // At most MAX_RECEIVER_PAYMENTS, checked above.
        let count = paid.len() as u16;
        let last = paid[paid.len() - 1]
            .1
            .height
            .checked_sub(coverage.start_height);
        let first = slot;
        let entry = Entry {
            tag: *tag,
            first,
            count,
            last: last.ok_or(Error::Malformed)?,
        };
        // Extents go in tag order, so each row's entries stay sorted.
        directory_rows[row_of[tag] as usize].push(entry);
        for (receiver, payment, payload) in paid.iter().copied() {
            let record = RawRecord {
                receiver: *receiver,
                page: slot - first,
                total: count.into(),
                payment: payment.clone(),
                ordinal: slot,
            };
            let at = slot_row(slot) as usize * ROW_BYTES + (slot % ROW_SLOTS) as usize * SLOT_BYTES;
            companion[at..at + SLOT_BYTES].copy_from_slice(&encode_slot(&record, payload)?);
            slot += 1;
        }
    }
    let mut data = Vec::with_capacity(DIRECTORY_ROWS as usize * ROW_BYTES);
    for entries in &directory_rows {
        data.extend_from_slice(&encode_row(entries)?);
    }

    let salt = projection.salt;
    let keys: Vec<&[u8]> = projection.rows.tags.iter().map(|tag| &tag[..]).collect();
    let bits = choice_bits(
        &projection.rows.salts,
        &keys,
        &projection.rows.assignment,
        DIRECTORY_ROWS.into(),
    );
    let seeds = candidate_seeds(&salt, seed_block, 0..seed_attempts);
    let choice = ChoiceTable::build(CHOICE_DOMAIN, &salt, seeds, &bits)
        .map_err(|_| Error::Choice)?
        .encode();

    let keys = extents.len() as u32;
    let choice_ref = ChoiceRef {
        digest: Sha256::digest(&choice).into(),
        bytes: choice.len() as u32,
        keys,
    };
    let directory = Directory {
        schema: SCHEMA.into(),
        coverage: coverage.clone(),
        salt,
        entries: keys,
        payments: slot,
        choice: choice_ref,
        data_sha256: Sha256::digest(&data).into(),
    };
    let companion_manifest = Companion {
        schema: SCHEMA.into(),
        coverage,
        directory: directory.revision()?,
        rows,
        query_rows: query_rows(slot),
        payments: slot,
        tree,
        data_sha256: Sha256::digest(&companion).into(),
    };
    let segment = Segment {
        directory: DirectoryTable {
            manifest: directory,
            data,
            choice,
        },
        companion: CompanionTable {
            manifest: companion_manifest,
            data: companion,
        },
    };
    let entries = segment.directory.validate()?;
    segment
        .companion
        .validate(&segment.directory.manifest, &entries)?;
    Ok(segment)
}
