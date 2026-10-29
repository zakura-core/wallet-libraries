//! Receiver v2: each segment is a 2,048-row directory of salted receiver tags and
//! one companion of full records and witness payloads, both P8 tables.
//!
//! A directory entry names a receiver's consecutive companion slots, so a lookup
//! is one directory query per segment, then one companion query per record on a
//! hit. A per-segment choice table, served as its own digest-addressed object,
//! says which of a tag's two candidate rows holds it. This lives alongside v1
//! until the wallet switches over.
use super::{Error, Hash, RECORD_BYTES, RawRecord, record, wire};
use crate::directory::{
    bucket::{self, DIRECTORY_CHOICES},
    choice::{CHOICE_HEADER_BYTES, ChoiceTable, segment_length},
    tag::{self as tags, TAG_BYTES},
};
use sha2::{Digest, Sha256};
use std::ops::Range;

#[cfg(feature = "native")]
pub mod native;
mod table;
pub use table::*;
#[cfg(test)]
mod tests;

/// The format every v2 manifest names; v1 readers refuse it and v2 refuses v1.
pub const SCHEMA: &str = "ironwood-zero-ovk-receiver-v2";
/// Bytes per row of either table: two P8 packing blocks.
pub const ROW_BYTES: usize = 4096;
/// A directory entry: tag, first slot (u24), count (u16), last height offset (u24).
pub const ENTRY_BYTES: usize = TAG_BYTES + 3 + 2 + 3;
/// Entries per directory row. The 4 trailing bytes are zero.
pub const ROW_ENTRIES: usize = ROW_BYTES / ENTRY_BYTES;
/// Rows in every directory.
pub const DIRECTORY_ROWS: u32 = 2048;
/// A companion slot: the record, then its witness payload.
pub const SLOT_BYTES: usize = RECORD_BYTES + wire::PAYLOAD_BYTES;
/// Slots per companion row. The 91 trailing bytes are zero.
pub const ROW_SLOTS: u32 = (ROW_BYTES / SLOT_BYTES) as u32;
/// The row quantum of a companion and of its trimmed query.
pub const QUERY_BLOCK_ROWS: u32 = 2048;
/// The v2 policy limit on companion rows. Not a P8 limit.
pub const MAX_COMPANION_ROWS: u32 = 65_536;
/// Payments one segment holds.
pub const CAPACITY: u32 = MAX_COMPANION_ROWS * ROW_SLOTS;
/// A segment seals after the block that reaches 31/32 of its capacity.
pub const SEAL_TARGET: u32 = CAPACITY / 32 * 31;
/// Payments one receiver may have in one segment: an entry's `u16` count.
pub const MAX_RECEIVER_PAYMENTS: u32 = u16::MAX as u32;
/// The largest height offset from a shard's start an entry can carry (u24).
pub const MAX_HEIGHT_OFFSET: u32 = (1 << 24) - 1;
/// Choice seeds an open publication tries.
pub const OPEN_SEED_ATTEMPTS: u32 = 64;
/// Choice seeds a seal tries.
pub const SEAL_SEED_ATTEMPTS: u32 = 1 << 16;
/// Salts a forcing block tries after the committed one.
pub const MAX_SALT_RETRIES: u32 = 8;

const _: () = assert!(ENTRY_BYTES == 22 && ROW_ENTRIES == 186 && SLOT_BYTES == 801);
const _: () = assert!(ROW_SLOTS == 5 && CAPACITY == 327_680 && SEAL_TARGET == 317_440);

const SALT_DOMAIN: &[u8] = b"ironwood-receiver-v2/tag-salt\0";
const RETRY_DOMAIN: &[u8] = b"ironwood-receiver-v2/tag-salt-retry\0";
const TAG_DOMAIN: &[u8] = b"ironwood-receiver-v2/tag\0";
const BUCKET_DOMAIN: &[u8] = b"ironwood-receiver-v2/bucket\0";
/// The choice table's hash domain. Its context is the segment's tag salt.
pub const CHOICE_DOMAIN: &[u8] = b"ironwood-receiver-v2/choice\0";
const SEED_DOMAIN: &[u8] = b"ironwood-receiver-v2/choice-seed\0";

/// A receiver's salted tag: what entries store, place and key the choice on.
pub type Tag = [u8; TAG_BYTES];

/// The committed salt segment `segment` of a shard starts with, from the block
/// before the shard. Retries replace a counter (see [`retry_salt`]).
pub fn initial_salt(start_parent: &Hash, segment: u32) -> Hash {
    tags::salt(SALT_DOMAIN, &[start_parent, &segment.to_le_bytes()])
}

/// Attempt `retry` of a block whose new receivers collide or fail placement
/// under `committed`: the committed salt itself at 0, else SHA-256 of the
/// domain, the committed salt, `retry` and the forcing block's hash, which the
/// block's own payments could not have been ground against.
pub fn retry_salt(committed: &Hash, retry: u32, block: &Hash) -> Hash {
    match retry {
        0 => *committed,
        r => tags::salt(RETRY_DOMAIN, &[committed, &r.to_le_bytes(), block]),
    }
}

/// `receiver`'s tag under a segment's `salt`: SHA-256 of the domain, the
/// salt and the bare 43-byte receiver, truncated.
pub fn tag(salt: &Hash, receiver: &[u8]) -> Tag {
    tags::tag(TAG_DOMAIN, salt, &[receiver])
}

/// The bucket salts of a segment under `salt`; placement and the choice table
/// key on the tag.
pub fn bucket_salts(salt: &Hash) -> [Hash; DIRECTORY_CHOICES] {
    bucket::bucket_salts(BUCKET_DOMAIN, salt)
}

/// The choice seeds for a segment under `salt` with seed block `block` (the
/// publication's tip, or the sealing block): the first 4 little-endian bytes of
/// SHA-256 of the domain, the salt, the block and each of `attempts`, skipping
/// any seed already drawn.
pub fn candidate_seeds(
    salt: &Hash,
    block: &Hash,
    attempts: Range<u32>,
) -> impl Iterator<Item = u32> {
    let (salt, block) = (*salt, *block);
    let mut seen = std::collections::HashSet::new();
    attempts
        .map(move |attempt| {
            let digest = Sha256::new()
                .chain_update(SEED_DOMAIN)
                .chain_update(salt)
                .chain_update(block)
                .chain_update(attempt.to_le_bytes())
                .finalize();
            u32::from_le_bytes(digest[..4].try_into().expect("4 bytes"))
        })
        .filter(move |seed| seen.insert(*seed))
}

/// The directory row a lookup for `tag` queries in a segment under `salt`.
pub fn choose_row(salt: &Hash, choice: &ChoiceTable, tag: &Tag) -> u32 {
    let rows = bucket::candidates(&bucket_salts(salt), tag, u64::from(DIRECTORY_ROWS));
    rows[choice.choice(CHOICE_DOMAIN, salt, tag)] as u32
}

/// Exact encoded bytes of a choice table over `keys` keys.
pub fn choice_bytes(keys: u32) -> usize {
    CHOICE_HEADER_BYTES + (3 * segment_length(keys) as usize).div_ceil(8)
}

/// Whether a segment can take a block: `payments` and `receiver_payments` (its
/// most paid receiver's) count the segment through the block, and the block at
/// `height` is within a u24 offset of the shard's `start_height`. A block that
/// fails seals the segment before it.
pub fn within_limits(
    payments: u64,
    receiver_payments: u64,
    start_height: u32,
    height: u32,
) -> bool {
    payments <= u64::from(CAPACITY)
        && receiver_payments <= u64::from(MAX_RECEIVER_PAYMENTS)
        && height
            .checked_sub(start_height)
            .is_some_and(|offset| offset <= MAX_HEIGHT_OFFSET)
}

/// The companion rows a query must cover for `payments` occupied slots: whole
/// [`QUERY_BLOCK_ROWS`] blocks, at least one, so an empty companion has 2,048.
pub fn query_rows(payments: u32) -> u32 {
    payments
        .div_ceil(ROW_SLOTS)
        .div_ceil(QUERY_BLOCK_ROWS)
        .max(1)
        * QUERY_BLOCK_ROWS
}

/// Refuses a companion row count that is not whole query blocks up to
/// [`MAX_COMPANION_ROWS`].
pub fn validate_companion_rows(rows: u32) -> Result<(), Error> {
    if rows == 0 || !rows.is_multiple_of(QUERY_BLOCK_ROWS) || rows > MAX_COMPANION_ROWS {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// A receiver's entry in a segment's directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub tag: Tag,
    /// The first of the receiver's consecutive companion slots.
    pub first: u32,
    /// Its payments in the segment, at least one.
    pub count: u16,
    /// Its last payment's height, as an offset from the shard's start height.
    pub last: u32,
}

impl Entry {
    /// The companion slots holding the receiver's payments, in page order.
    pub fn slots(&self) -> Range<u32> {
        self.first..self.first + u32::from(self.count)
    }

    /// Encodes the entry, refusing a zero count or a field past its width.
    pub fn encode(&self) -> Result<[u8; ENTRY_BYTES], Error> {
        if self.count == 0 || self.first >= 1 << 24 || self.last > MAX_HEIGHT_OFFSET {
            return Err(Error::Malformed);
        }
        let mut out = [0; ENTRY_BYTES];
        out[..TAG_BYTES].copy_from_slice(&self.tag);
        out[14..17].copy_from_slice(&self.first.to_le_bytes()[..3]);
        out[17..19].copy_from_slice(&self.count.to_le_bytes());
        out[19..22].copy_from_slice(&self.last.to_le_bytes()[..3]);
        Ok(out)
    }

    /// Decodes an entry. All zero is empty; a zero count otherwise is malformed.
    pub fn decode(bytes: &[u8; ENTRY_BYTES]) -> Result<Option<Self>, Error> {
        if bytes.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let u24 = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], 0]);
        let entry = Self {
            tag: bytes[..TAG_BYTES].try_into().expect("14 bytes"),
            first: u24(14),
            count: u16::from_le_bytes([bytes[17], bytes[18]]),
            last: u24(19),
        };
        if entry.count == 0 {
            return Err(Error::Malformed);
        }
        Ok(Some(entry))
    }
}

/// Encodes one directory row from at most [`ROW_ENTRIES`] entries, sorted by tag.
pub fn encode_row(entries: &[Entry]) -> Result<[u8; ROW_BYTES], Error> {
    if entries.len() > ROW_ENTRIES || !entries.is_sorted_by(|a, b| a.tag < b.tag) {
        return Err(Error::Capacity);
    }
    let mut row = [0; ROW_BYTES];
    for (slot, entry) in row.as_chunks_mut::<ENTRY_BYTES>().0.iter_mut().zip(entries) {
        *slot = entry.encode()?;
    }
    Ok(row)
}

/// Decodes one directory row: entries sorted strictly by tag, then only empty
/// entries and zero padding.
pub fn decode_row(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    if bytes.len() != ROW_BYTES || bytes[ROW_ENTRIES * ENTRY_BYTES..].iter().any(|b| *b != 0) {
        return Err(Error::Malformed);
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut ended = false;
    for raw in bytes.as_chunks::<ENTRY_BYTES>().0 {
        match Entry::decode(raw)? {
            None => ended = true,
            Some(entry) if !ended && entries.last().is_none_or(|p| p.tag < entry.tag) => {
                entries.push(entry)
            }
            Some(_) => return Err(Error::Malformed),
        }
    }
    Ok(entries)
}

/// Encodes one companion slot: the record, then its payload.
pub fn encode_slot(
    record: &RawRecord,
    payload: &[u8; wire::PAYLOAD_BYTES],
) -> Result<[u8; SLOT_BYTES], Error> {
    let mut out = [0; SLOT_BYTES];
    out[..RECORD_BYTES].copy_from_slice(&record::encode(record)?);
    out[RECORD_BYTES..].copy_from_slice(payload);
    Ok(out)
}

/// Decodes one companion slot structurally. All zero is empty; a payload
/// without a record is malformed. The payload is checked by the caller.
pub fn decode_slot(bytes: &[u8]) -> Result<Option<(RawRecord, [u8; wire::PAYLOAD_BYTES])>, Error> {
    if bytes.len() != SLOT_BYTES {
        return Err(Error::Malformed);
    }
    let payload = bytes[RECORD_BYTES..].try_into().expect("512 bytes");
    match record::decode(&bytes[..RECORD_BYTES])? {
        Some(record) => Ok(Some((record, payload))),
        None if bytes.iter().all(|b| *b == 0) => Ok(None),
        None => Err(Error::Malformed),
    }
}

/// The companion row holding `slot`.
pub fn slot_row(slot: u32) -> u32 {
    slot / ROW_SLOTS
}
