//! Variable-length entries inside fixed-width schema-v12 directory rows.
//!
//! An entry is `tag[14] | flags_child u8 | head_row u32 | inline events`. The
//! two newest events of a script in a directory shard are inline; everything
//! older was pushed out into runs in the shard's page shards, and the entry
//! points at the newest run only. Each run's first fragment points back to the
//! run before it (see [`crate::transparent::shard::page_row`]).
//!
//! `flags_child` packs two things. Bits 0-4 name the page shard `j` holding
//! the newest run. Bit 7 set means exactly one inline event. Bits 5-6 are
//! reserved and zero. The count still has to be encoded because entries sit
//! back to back and the next one starts with a random-looking tag; one bit is
//! enough because an entry with pages always carries two inline events.
use crate::transparent::events::{EventError, TransparentEvent};
use crate::transparent::shard::compact;
use crate::transparent::shard::layout::{
    DIRECTORY_ROW_BYTES, EVENTS_PER_PAGE, INLINE_EVENTS, MAX_PAGE_CHILDREN,
};
use crate::transparent::shard::tag::SCRIPT_TAG_BYTES;

pub const MAX_SCRIPT_BYTES: usize = 40;
pub const DIRECTORY_ENTRY_HEADER_BYTES: usize = SCRIPT_TAG_BYTES + 1 + 4;
pub const DIRECTORY_ROW_HEADER_BYTES: usize = 4;
pub const MAX_DIRECTORY_ENTRY_BYTES: usize =
    DIRECTORY_ENTRY_HEADER_BYTES + INLINE_EVENTS as usize * (compact::SPEND_BYTES + 15);
/// Maximum count, attained with one receive per entry. Actual capacity is bytes.
pub const DIRECTORY_SLOTS: usize = (DIRECTORY_ROW_BYTES - DIRECTORY_ROW_HEADER_BYTES)
    / (DIRECTORY_ENTRY_HEADER_BYTES + compact::RECEIVE_BYTES);
const DE_TAG: usize = 0;
const DE_FLAGS_CHILD: usize = SCRIPT_TAG_BYTES;
const DE_HEAD_ROW: usize = DE_FLAGS_CHILD + 1;
const DE_INLINE_EVENTS: usize = DE_HEAD_ROW + 4;

const _: () = assert!(DE_INLINE_EVENTS == DIRECTORY_ENTRY_HEADER_BYTES);

/// `flags_child` bit 7: the entry carries exactly one inline event.
pub const FLAG_ONE_INLINE: u8 = 0x80;
/// `flags_child` bits 0-4: the page shard holding the newest run.
pub const CHILD_MASK: u8 = 0x1f;
/// `flags_child` bits 5-6: reserved, zero.
pub const RESERVED_FLAGS: u8 = 0x60;

const _: () = assert!(MAX_PAGE_CHILDREN <= CHILD_MASK as u32 + 1);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("record is {got} bytes, expected {want}")]
    Length { got: usize, want: usize },
    #[error("script is {0} bytes, more than a private table can hold")]
    ScriptTooLong(usize),
    #[error("reserved bytes are not zero")]
    Reserved,
    #[error("{0}")]
    Malformed(String),
    #[error("event: {0}")]
    Event(#[from] EventError),
    #[error("too many entries: {0}")]
    TooManyEntries(usize),
    #[error("a fragment holds at most {EVENTS_PER_PAGE} events, was given {0}")]
    TooManyEvents(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Placement key, omitted from the wire. Decoding leaves it empty.
    pub script: Vec<u8>,
    pub tag: [u8; SCRIPT_TAG_BYTES],
    /// Builder metadata, omitted from the wire.
    pub event_count: u32,
    /// The one or two newest events, oldest first.
    pub inline: Vec<TransparentEvent>,
    /// The page shard `j` holding the newest run. Zero when `head_row` is zero.
    pub head_child: u8,
    /// 1-based row of the newest run's first fragment in `pages-<head_child>`;
    /// zero means the script has no pages in this directory shard.
    pub head_row: u32,
}

impl DirectoryEntry {
    /// The newest run's page shard and 0-based row, if the script has pages.
    pub fn head(&self) -> Option<(u8, u32)> {
        self.head_row
            .checked_sub(1)
            .map(|row| (self.head_child, row))
    }

    pub fn encoded_len(&self) -> usize {
        DIRECTORY_ENTRY_HEADER_BYTES + compact::encoded_len(&self.inline)
    }

    fn flags_child(&self) -> u8 {
        self.head_child
            | if self.inline.len() == 1 {
                FLAG_ONE_INLINE
            } else {
                0
            }
    }

    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        if self.script.len() > MAX_SCRIPT_BYTES {
            return Err(RecordError::ScriptTooLong(self.script.len()));
        }
        if self.inline.is_empty()
            || self.inline.len() > INLINE_EVENTS as usize
            || self.head_row != 0 && self.inline.len() != INLINE_EVENTS as usize
        {
            return Err(RecordError::Malformed("invalid inline count".into()));
        }
        if u32::from(self.head_child) >= MAX_PAGE_CHILDREN
            || self.head_row == 0 && self.head_child != 0
        {
            return Err(RecordError::Malformed("invalid page shard number".into()));
        }
        if self
            .inline
            .windows(2)
            .any(|w| w[0].sort_key() > w[1].sort_key())
        {
            return Err(RecordError::Malformed("inline events out of order".into()));
        }
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.tag);
        bytes.push(self.flags_child());
        bytes.extend_from_slice(&self.head_row.to_le_bytes());
        compact::encode(&self.inline, &mut bytes)?;
        Ok(bytes)
    }

    /// Decodes one occupied entry from a row prefix and reports its exact
    /// length. `children` is the number of page shards the directory shard
    /// declares; an entry naming one at or past it is refused.
    pub fn decode(bytes: &[u8], children: u32) -> Result<(Self, usize), RecordError> {
        if bytes.len() < DIRECTORY_ENTRY_HEADER_BYTES {
            return Err(RecordError::Malformed("truncated directory entry".into()));
        }
        let tag = bytes[DE_TAG..DE_FLAGS_CHILD].try_into().expect("14 bytes");
        let flags = bytes[DE_FLAGS_CHILD];
        let head_row = u32::from_le_bytes(
            bytes[DE_HEAD_ROW..DE_INLINE_EVENTS]
                .try_into()
                .expect("4 bytes"),
        );
        if flags & RESERVED_FLAGS != 0 {
            return Err(RecordError::Malformed(format!(
                "reserved directory flag bits are set: {flags:#04x}"
            )));
        }
        let one = flags & FLAG_ONE_INLINE != 0;
        let head_child = flags & CHILD_MASK;
        if head_row == 0 && head_child != 0 {
            return Err(RecordError::Malformed(
                "an entry without pages names a page shard".into(),
            ));
        }
        if head_row != 0 && one {
            return Err(RecordError::Malformed(
                "an entry with pages carries one inline event".into(),
            ));
        }
        if head_row != 0 && u32::from(head_child) >= children {
            return Err(RecordError::Malformed(format!(
                "an entry names page shard {head_child} of {children}"
            )));
        }
        let count = if one { 1 } else { INLINE_EVENTS as usize };
        let (inline, used) = compact::decode(&bytes[DE_INLINE_EVENTS..], count)?;
        if inline.windows(2).any(|w| w[0].sort_key() > w[1].sort_key()) {
            return Err(RecordError::Malformed("inline events out of order".into()));
        }
        Ok((
            Self {
                script: Vec::new(),
                tag,
                event_count: count as u32,
                inline,
                head_child,
                head_row,
            },
            DE_INLINE_EVENTS + used,
        ))
    }
}

pub fn encode_directory_row(entries: &[DirectoryEntry]) -> Result<Vec<u8>, RecordError> {
    if entries.len() > DIRECTORY_SLOTS {
        return Err(RecordError::TooManyEntries(entries.len()));
    }
    let mut row = Vec::with_capacity(DIRECTORY_ROW_BYTES);
    row.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (i, entry) in entries.iter().enumerate() {
        if entries[..i].iter().any(|other| other.tag == entry.tag) {
            return Err(RecordError::Malformed("duplicate directory tag".into()));
        }
        row.extend_from_slice(&entry.encode()?);
    }
    if row.len() > DIRECTORY_ROW_BYTES {
        return Err(RecordError::Malformed(
            "directory row byte capacity exceeded".into(),
        ));
    }
    row.resize(DIRECTORY_ROW_BYTES, 0);
    Ok(row)
}

/// Decodes one directory row of a shard that declares `children` page shards.
pub fn decode_directory_row(row: &[u8], children: u32) -> Result<Vec<DirectoryEntry>, RecordError> {
    if row.len() != DIRECTORY_ROW_BYTES {
        return Err(RecordError::Length {
            got: row.len(),
            want: DIRECTORY_ROW_BYTES,
        });
    }
    let count = u32::from_le_bytes(row[..4].try_into().expect("4 bytes")) as usize;
    if count > DIRECTORY_SLOTS {
        return Err(RecordError::TooManyEntries(count));
    }
    let mut entries: Vec<DirectoryEntry> = Vec::with_capacity(count);
    let mut at = DIRECTORY_ROW_HEADER_BYTES;
    for _ in 0..count {
        let (entry, used) = DirectoryEntry::decode(&row[at..], children)?;
        if entries.iter().any(|other| other.tag == entry.tag) {
            return Err(RecordError::Malformed("duplicate directory tag".into()));
        }
        entries.push(entry);
        at += used;
    }
    if row[at..].iter().any(|b| *b != 0) {
        return Err(RecordError::Reserved);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::events::{ReceiveEvent, Txid};

    fn script(tag: u8) -> Vec<u8> {
        let mut bytes = vec![0x76, 0xa9, 0x14];
        bytes.extend_from_slice(&[tag; 20]);
        bytes.extend_from_slice(&[0x88, 0xac]);
        bytes
    }

    fn event(height: u32, nonce: u8) -> TransparentEvent {
        TransparentEvent::Receive(ReceiveEvent {
            metadata: None,
            height,
            txid: Txid([nonce; 32]),
            transaction_index: 0,
            output_index: nonce as u32,
            value: 1_000,
            coinbase: false,
        })
    }

    fn entry(byte: u8, inline: usize, head: Option<(u8, u32)>) -> DirectoryEntry {
        let mut tag = [0u8; crate::transparent::shard::tag::SCRIPT_TAG_BYTES];
        tag[0] = byte;
        DirectoryEntry {
            script: script(byte),
            tag,
            event_count: inline as u32,
            inline: (0..inline)
                .map(|i| event(100 + i as u32, i as u8))
                .collect(),
            head_child: head.map_or(0, |(child, _)| child),
            head_row: head.map_or(0, |(_, row)| row),
        }
    }

    fn decoded_eq(decoded: &DirectoryEntry, built: &DirectoryEntry) {
        assert_eq!(decoded.tag, built.tag);
        assert_eq!(decoded.inline, built.inline);
        assert_eq!(decoded.head_child, built.head_child);
        assert_eq!(decoded.head_row, built.head_row);
        assert!(decoded.script.is_empty());
    }

    /// The pinned numbers, restated so a change to the layout has to be a
    /// deliberate edit here rather than a silent shift in every table. The
    /// header is 19 bytes, as it was before the entry named a page shard.
    #[test]
    fn the_geometry_is_what_the_layout_promises() {
        assert_eq!(DIRECTORY_ENTRY_HEADER_BYTES, 19);
        assert_eq!(MAX_DIRECTORY_ENTRY_BYTES, 207);
        assert_eq!(DIRECTORY_SLOTS, 58);
        assert_eq!(entry(1, 1, None).encoded_len(), 70);
        assert_eq!(entry(1, 2, None).encoded_len(), 121);
    }

    #[test]
    fn a_directory_entry_round_trips() {
        for e in [
            entry(1, 2, None),
            entry(2, 2, Some((0, 8))),
            entry(3, 1, None),
            entry(4, 2, Some((31, u32::MAX))),
        ] {
            let encoded = e.encode().unwrap();
            let (decoded, used) = DirectoryEntry::decode(&encoded, 32).unwrap();
            assert_eq!(used, encoded.len());
            decoded_eq(&decoded, &e);
        }
    }

    /// The design's example: head run at row 37 of `pages-2`, two inline
    /// events, so `flags_child` is 0x02 and `head_row` is 37 little-endian.
    #[test]
    fn the_header_bytes_are_the_documented_ones() {
        let encoded = entry(9, 2, Some((2, 37))).encode().unwrap();
        assert_eq!(encoded[DE_FLAGS_CHILD], 0x02);
        assert_eq!(&encoded[DE_HEAD_ROW..DE_INLINE_EVENTS], &[37, 0, 0, 0]);
        let single = entry(9, 1, None).encode().unwrap();
        assert_eq!(single[DE_FLAGS_CHILD], FLAG_ONE_INLINE);
        assert_eq!(&single[DE_HEAD_ROW..DE_INLINE_EVENTS], &[0, 0, 0, 0]);
    }

    #[test]
    fn an_empty_slot_decodes_as_absent() {
        assert!(
            decode_directory_row(&[0; DIRECTORY_ROW_BYTES], 1)
                .unwrap()
                .is_empty()
        );
    }

    /// A slot that hid a payload behind a zero length would be a channel a
    /// server could use and a client would never inspect.
    #[test]
    fn an_empty_slot_carrying_content_is_refused() {
        let mut empty = [0u8; MAX_DIRECTORY_ENTRY_BYTES];
        empty[MAX_DIRECTORY_ENTRY_BYTES - 1] = 1;
        assert!(DirectoryEntry::decode(&empty, 1).is_err());
    }

    /// Every row is the same size regardless of how full it is. A row whose
    /// occupancy showed in its geometry would leak how many scripts share a
    /// bucket, which is information about the scripts themselves.
    #[test]
    fn every_directory_row_is_the_same_size_however_full() {
        let full: Vec<DirectoryEntry> = (0..DIRECTORY_SLOTS)
            .map(|i| entry(i as u8 + 1, 1, None))
            .collect();
        for entries in [vec![], vec![entry(1, 2, None)], full] {
            assert_eq!(
                encode_directory_row(&entries).unwrap().len(),
                DIRECTORY_ROW_BYTES
            );
        }
    }

    #[test]
    fn a_directory_row_round_trips_and_rejects_overfill() {
        let entries: Vec<DirectoryEntry> = (0..DIRECTORY_SLOTS)
            .map(|i| entry(i as u8 + 1, 1, None))
            .collect();
        let row = encode_directory_row(&entries).unwrap();
        let decoded = decode_directory_row(&row, 1).unwrap();
        assert_eq!(decoded.len(), entries.len());
        for (got, want) in decoded.iter().zip(&entries) {
            decoded_eq(got, want);
        }

        let too_many: Vec<DirectoryEntry> = (0..DIRECTORY_SLOTS + 1)
            .map(|i| entry((i + 1) as u8, 2, None))
            .collect();
        assert_eq!(
            encode_directory_row(&too_many),
            Err(RecordError::TooManyEntries(DIRECTORY_SLOTS + 1))
        );
    }

    /// A count that understated the row would leave entries a client never
    /// decodes, which is indistinguishable from those scripts having no history.
    #[test]
    fn a_row_with_content_past_its_count_is_refused() {
        let mut row = encode_directory_row(&[entry(1, 2, None)]).unwrap();
        row[DIRECTORY_ROW_BYTES - 1] = 1;
        assert!(decode_directory_row(&row, 1).is_err());
    }

    /// Reserved bits are zero, the one-event flag never accompanies pages, an
    /// entry without pages names no page shard, and the page shard it names
    /// must be one the directory shard declares.
    #[test]
    fn the_decoder_refuses_bad_flag_bits() {
        let paged = entry(1, 2, Some((3, 9))).encode().unwrap();
        assert!(DirectoryEntry::decode(&paged, 4).is_ok());
        for bit in [0x20u8, 0x40] {
            let mut bad = paged.clone();
            bad[DE_FLAGS_CHILD] |= bit;
            assert!(
                DirectoryEntry::decode(&bad, 4).is_err(),
                "reserved bit {bit:#04x}"
            );
        }
        let mut one_with_pages = paged.clone();
        one_with_pages[DE_FLAGS_CHILD] |= FLAG_ONE_INLINE;
        assert!(DirectoryEntry::decode(&one_with_pages, 4).is_err());
        // The page shard number is checked against the declared count.
        assert!(DirectoryEntry::decode(&paged, 3).is_err());
        assert!(DirectoryEntry::decode(&paged, 0).is_err());

        let mut unpaged = entry(1, 2, None).encode().unwrap();
        unpaged[DE_FLAGS_CHILD] = 0x01;
        assert!(DirectoryEntry::decode(&unpaged, 4).is_err());
    }

    /// The encoder refuses what the decoder would refuse, so a builder cannot
    /// publish an entry no wallet reads.
    #[test]
    fn the_encoder_refuses_entries_the_decoder_would() {
        assert!(entry(1, 1, Some((0, 4))).encode().is_err());
        assert!(entry(1, 0, None).encode().is_err());
        assert!(entry(1, 3, None).encode().is_err());
        assert!(entry(1, 2, Some((32, 1))).encode().is_err());
        let mut stray = entry(1, 2, None);
        stray.head_child = 5;
        assert!(stray.encode().is_err());
    }

    #[test]
    fn a_duplicate_tag_in_a_row_is_refused() {
        assert!(encode_directory_row(&[entry(1, 1, None), entry(1, 1, None)]).is_err());
        let mut row = encode_directory_row(&[entry(1, 1, None), entry(2, 1, None)]).unwrap();
        row[4 + 70] = 1;
        assert!(decode_directory_row(&row, 1).is_err());
    }

    #[test]
    fn a_script_too_long_for_a_private_table_is_refused_not_truncated() {
        let entry = DirectoryEntry {
            script: vec![0xab; MAX_SCRIPT_BYTES + 1],
            tag: [1; crate::transparent::shard::tag::SCRIPT_TAG_BYTES],
            event_count: 1,
            inline: vec![event(100, 0)],
            head_child: 0,
            head_row: 0,
        };
        assert_eq!(
            entry.encode(),
            Err(RecordError::ScriptTooLong(MAX_SCRIPT_BYTES + 1))
        );
    }
}
