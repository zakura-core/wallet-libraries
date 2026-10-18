//! Compact page entries sharing one fixed-width PIR row.
//!
//! Each entry has a 40-byte header and a variable byte stream of complete
//! events. A fragment is the longest canonical prefix that fits 4,052 event
//! bytes; receive/spend mix determines its count, bounded by 86. A local
//! outpoint reference never crosses an entry boundary.
//!
//! Long histories occupy contiguous rows. Short histories use descending
//! best-fit packing, including spare space in long histories' final rows.
//! The builder uses equal-byte-size groups instead if they require fewer rows.
//!
//! A script's history in a directory shard is a chain of runs, at most one per
//! page shard. The directory entry names the newest run's first row. Every
//! run's first fragment (ordinal 0) reports the run's fragment count `K` and
//! links back to the previous run: `prev_child`, the earlier page shard
//! holding it, `prev_row`, the 1-based row of its first fragment there (zero
//! ends the chain), and `older_runs`, how many runs are older than this one.
//! On every later fragment all three are zero. A run's fragments occupy
//! consecutive rows, and the wallet checks each greedy boundary.
//! A reader selects only its own tag within the row. Even two of a wallet's
//! scripts sharing a row cost separate fetches: response reuse would make the
//! request transcript depend on which scripts share a row.
//!
//! # What a decoder must not trust
//!
//! These bytes come from a PIR response, so every field is a claim by the
//! server. The entry count is bounded before any offset is computed from it,
//! which is what keeps the arithmetic unreachable by malformed input rather than
//! merely checked; every read goes through [`take`]; and no two entries in a row
//! may name the same script tag, which is what makes "select the one entry
//! matching my tag" a well-defined operation rather than a choice.

use crate::transparent::events::TransparentEvent;
use crate::transparent::shard::layout::{
    EVENTS_PER_PAGE, MAX_ENTRIES_PER_ROW, MAX_PAGE_CHILDREN, PAGE_ENTRY_HEADER_BYTES,
    PAGE_ROW_BYTES, PAGE_ROW_HEADER_BYTES,
};
use crate::transparent::shard::records::RecordError;
use crate::transparent::shard::tag::SCRIPT_TAG_BYTES;
use crate::transparent::shard::{compact, packing::FRAGMENT_PAYLOAD};

// Entry header field offsets, relative to the start of the entry.
const PE_TAG: usize = 0;
const PE_ORDINAL: usize = SCRIPT_TAG_BYTES;
const PE_FRAGMENT_COUNT: usize = PE_ORDINAL + 4;
const PE_EVENT_COUNT: usize = PE_FRAGMENT_COUNT + 4;
const PE_MIN_HEIGHT: usize = PE_EVENT_COUNT + 4;
const PE_MAX_HEIGHT: usize = PE_MIN_HEIGHT + 4;
const PE_PREV_CHILD: usize = PE_MAX_HEIGHT + 4;
const PE_PREV_ROW: usize = PE_PREV_CHILD + 1;
const PE_OLDER_RUNS: usize = PE_PREV_ROW + 4;
const PE_END: usize = PE_OLDER_RUNS + 1;

/// The header must be exactly the width the layout reserves for it: the entry
/// size formula and every capacity derived from it depend on this being true, so
/// a field added without widening the header should fail the build.
const _: () = assert!(PE_END == PAGE_ENTRY_HEADER_BYTES);

/// A run's link to the run before it, carried on its first fragment.
///
/// Pointers only go backwards, to page shards that sealed before this run
/// started receiving events, so a run's contents and its link are fixed when
/// its page shard seals. All zero on a later fragment and on a script's oldest
/// run in the directory shard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunLink {
    /// The page shard holding the previous run.
    pub prev_child: u8,
    /// 1-based row of the previous run's first fragment; zero ends the chain.
    pub prev_row: u32,
    /// Runs older than this one in the directory shard.
    pub older_runs: u8,
}

impl RunLink {
    /// The previous run's page shard and 0-based row, if there is one.
    pub fn previous(&self) -> Option<(u8, u32)> {
        self.prev_row
            .checked_sub(1)
            .map(|row| (self.prev_child, row))
    }

    /// Whether this is a link a first fragment may carry: either the end of
    /// the chain, all zero, or a pointer with at least one older run.
    pub fn is_well_formed(&self) -> bool {
        if self.prev_row == 0 {
            self.prev_child == 0 && self.older_runs == 0
        } else {
            self.older_runs != 0 && u32::from(self.prev_child) < MAX_PAGE_CHILDREN
        }
    }
}

/// One fragment of one script's history, as it sits inside a shared row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageEntry {
    pub tag: [u8; SCRIPT_TAG_BYTES],
    pub ordinal: u32,
    /// How many page fragments this history occupies. The directory stores
    /// the first page only; the wallet reads this count from ordinal 0.
    pub fragment_count: u32,
    pub events: Vec<TransparentEvent>,
    /// Bounds over this entry's own events, so a client can navigate to the
    /// first fragment newer than its checkpoint without a plaintext index.
    pub min_height: u32,
    pub max_height: u32,
    /// The previous run, on ordinal 0 only.
    pub link: RunLink,
}

impl PageEntry {
    /// Builds an entry from events, deriving its height bounds from them.
    pub fn new(
        tag: [u8; SCRIPT_TAG_BYTES],
        ordinal: u32,
        fragment_count: u32,
        events: Vec<TransparentEvent>,
    ) -> Result<Self, RecordError> {
        if events.is_empty() {
            return Err(RecordError::Malformed("an entry holds no events".into()));
        }
        if events.len() > EVENTS_PER_PAGE as usize
            || compact::encoded_len(&events) > FRAGMENT_PAYLOAD
        {
            return Err(RecordError::TooManyEvents(events.len()));
        }
        if fragment_count == 0 || ordinal >= fragment_count {
            return Err(RecordError::Malformed(format!(
                "fragment {ordinal} of {fragment_count}"
            )));
        }
        let min_height = events.iter().map(|e| e.height()).min().expect("nonempty");
        let max_height = events.iter().map(|e| e.height()).max().expect("nonempty");
        Ok(Self {
            tag,
            ordinal,
            fragment_count,
            events,
            min_height,
            max_height,
            link: RunLink::default(),
        })
    }

    /// The same fragment carrying `link`, which only a run's first fragment
    /// may hold.
    pub fn with_link(mut self, link: RunLink) -> Result<Self, RecordError> {
        if !link.is_well_formed() || self.ordinal != 0 && link != RunLink::default() {
            return Err(RecordError::Malformed(format!(
                "fragment {} cannot carry link {link:?}",
                self.ordinal
            )));
        }
        self.link = link;
        Ok(self)
    }

    /// Bytes this entry occupies inside a row.
    pub fn encoded_len(&self) -> usize {
        PAGE_ENTRY_HEADER_BYTES + compact::encoded_len(&self.events)
    }
}

/// Reads `len` bytes at `at`, or fails.
///
/// Every read of untrusted row bytes goes through here. Offsets are computed
/// from a count the server chose, so the addition itself has to be checked
/// rather than the result.
fn take(row: &[u8], at: usize, len: usize) -> Result<&[u8], RecordError> {
    let end = at
        .checked_add(len)
        .ok_or_else(|| RecordError::Malformed("entry offset overflows".into()))?;
    row.get(at..end)
        .ok_or_else(|| RecordError::Malformed("entry runs past the row".into()))
}

fn u32_at(row: &[u8], at: usize) -> Result<u32, RecordError> {
    Ok(u32::from_le_bytes(take(row, at, 4)?.try_into().expect("4")))
}

/// Encodes entries into one full page row.
///
/// The caller has already decided what shares this row; this refuses only what
/// cannot be represented — more bytes than a row holds, or two entries claiming
/// the same script, which would make selection ambiguous for every reader.
pub fn encode_page_row(entries: &[PageEntry]) -> Result<Vec<u8>, RecordError> {
    if entries.len() > MAX_ENTRIES_PER_ROW {
        return Err(RecordError::TooManyEntries(entries.len()));
    }
    let mut used = PAGE_ROW_HEADER_BYTES;
    for entry in entries {
        if entry.events.is_empty() || entry.events.len() > EVENTS_PER_PAGE as usize {
            return Err(RecordError::TooManyEvents(entry.events.len()));
        }
        if !entry.link.is_well_formed() || entry.ordinal != 0 && entry.link != RunLink::default() {
            return Err(RecordError::Malformed(
                "a fragment carries a malformed run link".into(),
            ));
        }
        used += entry.encoded_len();
    }
    if used > PAGE_ROW_BYTES {
        return Err(RecordError::Malformed(format!(
            "{} entries need {used} bytes, a row holds {PAGE_ROW_BYTES}",
            entries.len()
        )));
    }
    for (index, entry) in entries.iter().enumerate() {
        if entries[..index].iter().any(|other| other.tag == entry.tag) {
            return Err(RecordError::Malformed(
                "a page row holds a script tag twice".into(),
            ));
        }
    }

    let mut row = vec![0u8; PAGE_ROW_BYTES];
    row[..PAGE_ROW_HEADER_BYTES].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut at = PAGE_ROW_HEADER_BYTES;
    for entry in entries {
        let head = &mut row[at..at + PAGE_ENTRY_HEADER_BYTES];
        head[PE_TAG..PE_ORDINAL].copy_from_slice(&entry.tag);
        head[PE_ORDINAL..PE_FRAGMENT_COUNT].copy_from_slice(&entry.ordinal.to_le_bytes());
        head[PE_FRAGMENT_COUNT..PE_EVENT_COUNT]
            .copy_from_slice(&entry.fragment_count.to_le_bytes());
        head[PE_EVENT_COUNT..PE_MIN_HEIGHT]
            .copy_from_slice(&(entry.events.len() as u32).to_le_bytes());
        head[PE_MIN_HEIGHT..PE_MAX_HEIGHT].copy_from_slice(&entry.min_height.to_le_bytes());
        head[PE_MAX_HEIGHT..PE_PREV_CHILD].copy_from_slice(&entry.max_height.to_le_bytes());
        head[PE_PREV_CHILD] = entry.link.prev_child;
        head[PE_PREV_ROW..PE_OLDER_RUNS].copy_from_slice(&entry.link.prev_row.to_le_bytes());
        head[PE_OLDER_RUNS] = entry.link.older_runs;
        at += PAGE_ENTRY_HEADER_BYTES;
        let mut encoded = Vec::with_capacity(compact::encoded_len(&entry.events));
        compact::encode(&entry.events, &mut encoded)?;
        row[at..at + encoded.len()].copy_from_slice(&encoded);
        at += encoded.len();
    }
    Ok(row)
}

/// Decodes a page row into its entries, or an empty vector for an unused row.
///
/// An unused row and a full one are the same size and are indistinguishable in
/// a response; only the decoded content differs. That is the point.
pub fn decode_page_row(row: &[u8]) -> Result<Vec<PageEntry>, RecordError> {
    if row.len() != PAGE_ROW_BYTES {
        return Err(RecordError::Length {
            got: row.len(),
            want: PAGE_ROW_BYTES,
        });
    }
    let count = u32::from_le_bytes(row[..PAGE_ROW_HEADER_BYTES].try_into().expect("4")) as usize;
    if count == 0 {
        // An unused row must be entirely zero. A payload hidden behind a zero
        // count would be a channel a server could use and a client never reads.
        if row.iter().any(|byte| *byte != 0) {
            return Err(RecordError::Malformed(
                "an unused page row is not all zero".into(),
            ));
        }
        return Ok(Vec::new());
    }
    // Bounded before any offset is derived from it, so the arithmetic below
    // cannot be driven anywhere by a chosen count.
    if count > MAX_ENTRIES_PER_ROW {
        return Err(RecordError::TooManyEntries(count));
    }

    let mut entries: Vec<PageEntry> = Vec::with_capacity(count);
    let mut at = PAGE_ROW_HEADER_BYTES;
    for _ in 0..count {
        let tag: [u8; SCRIPT_TAG_BYTES] = take(row, at + PE_TAG, SCRIPT_TAG_BYTES)?
            .try_into()
            .expect("14 bytes");
        let ordinal = u32_at(row, at + PE_ORDINAL)?;
        let fragment_count = u32_at(row, at + PE_FRAGMENT_COUNT)?;
        let event_count = u32_at(row, at + PE_EVENT_COUNT)? as usize;
        let min_height = u32_at(row, at + PE_MIN_HEIGHT)?;
        let max_height = u32_at(row, at + PE_MAX_HEIGHT)?;
        let link = RunLink {
            prev_child: take(row, at + PE_PREV_CHILD, 1)?[0],
            prev_row: u32_at(row, at + PE_PREV_ROW)?,
            older_runs: take(row, at + PE_OLDER_RUNS, 1)?[0],
        };

        if event_count == 0 || event_count > EVENTS_PER_PAGE as usize {
            return Err(RecordError::Malformed(format!(
                "an entry claims {event_count} events"
            )));
        }
        if fragment_count == 0 || ordinal >= fragment_count {
            return Err(RecordError::Malformed(format!(
                "fragment {ordinal} of {fragment_count}"
            )));
        }

        // Only a run's first fragment links anywhere, and a link either ends
        // the chain with all three fields zero or names an older run. Whether
        // it points backwards, and at the right shard, is the walk's check.
        if ordinal != 0 && link != RunLink::default() || !link.is_well_formed() {
            return Err(RecordError::Malformed(format!(
                "fragment {ordinal} carries run link {link:?}"
            )));
        }

        let body = at + PAGE_ENTRY_HEADER_BYTES;
        let (events, event_bytes) = compact::decode(
            row.get(body..)
                .ok_or_else(|| RecordError::Malformed("entry runs past row".into()))?,
            event_count,
        )?;

        // Ordering is what a replay depends on, and what lets a client stop
        // reading once it is past its checkpoint. A row that arrived shuffled
        // would replay the same events in a different order.
        if events.windows(2).any(|w| w[0].sort_key() > w[1].sort_key()) {
            return Err(RecordError::Malformed(
                "an entry's events are not in canonical order".into(),
            ));
        }
        // The header's bounds are a claim about the entry's own events, and a
        // client navigates by them. Bounds that disagreed could steer it past
        // history it needed.
        let actual_min = events.iter().map(|e| e.height()).min().expect("nonempty");
        let actual_max = events.iter().map(|e| e.height()).max().expect("nonempty");
        if actual_min != min_height || actual_max != max_height {
            return Err(RecordError::Malformed(format!(
                "an entry claims heights {min_height}-{max_height} but holds \
                 {actual_min}-{actual_max}"
            )));
        }
        // Two entries for one script would make "the entry matching my script"
        // a choice rather than a selection, for every reader of this row.
        if entries.iter().any(|other| other.tag == tag) {
            return Err(RecordError::Malformed(
                "a page row holds a script tag twice".into(),
            ));
        }

        at = body + event_bytes;
        entries.push(PageEntry {
            tag,
            ordinal,
            fragment_count,
            events,
            min_height,
            max_height,
            link,
        });
    }

    if row[at..].iter().any(|byte| *byte != 0) {
        return Err(RecordError::Malformed(
            "a page row has content past its entries".into(),
        ));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::events::{ReceiveEvent, Txid};

    fn tag_of(n: u8) -> [u8; SCRIPT_TAG_BYTES] {
        let mut tag = [0u8; SCRIPT_TAG_BYTES];
        tag[0] = n;
        tag
    }

    fn event(height: u32, nonce: u32) -> TransparentEvent {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&nonce.to_le_bytes());
        TransparentEvent::Receive(ReceiveEvent {
            metadata: None,
            height,
            txid: Txid(txid),
            transaction_index: 0,
            output_index: 0,
            value: 1,
            coinbase: false,
        })
    }

    fn entry(tag: u8, events: u32) -> PageEntry {
        PageEntry::new(
            tag_of(tag),
            0,
            1,
            (0..events).map(|i| event(100 + i, i)).collect(),
        )
        .expect("valid entry")
    }

    #[test]
    fn an_unused_row_decodes_as_empty() {
        assert_eq!(decode_page_row(&vec![0u8; PAGE_ROW_BYTES]).unwrap(), vec![]);
    }

    #[test]
    fn a_row_round_trips_whatever_it_holds() {
        for count in [1usize, 2, 7, MAX_ENTRIES_PER_ROW] {
            let entries: Vec<PageEntry> = (0..count).map(|i| entry(i as u8 + 1, 1)).collect();
            let row = encode_page_row(&entries).expect("encodes");
            assert_eq!(row.len(), PAGE_ROW_BYTES);
            assert_eq!(decode_page_row(&row).unwrap(), entries);
        }
    }

    /// Every class from one paged event to a full fragment, at both a full row
    /// and a partly full one. The capacities are the whole point of the format,
    /// so each is exercised rather than sampled.
    #[test]
    fn every_class_fills_a_row_to_its_capacity() {
        for p in 1..=79 {
            let per = 4092 / (40 + p as usize * 51);
            assert!(per >= 1, "class {p} must fit at least one entry");
            let full: Vec<PageEntry> = (0..per).map(|i| entry(i as u8 + 1, p)).collect();
            let row = encode_page_row(&full).expect("a full class row encodes");
            assert_eq!(decode_page_row(&row).unwrap(), full);

            // One more must not fit; that is what `entries_per_row` asserts.
            let over: Vec<PageEntry> = (0..per + 1).map(|i| entry(i as u8 + 1, p)).collect();
            assert!(encode_page_row(&over).is_err(), "class {p} overfilled");

            if per > 1 {
                let partial = &full[..per - 1];
                let row = encode_page_row(partial).expect("a partial row encodes");
                assert_eq!(decode_page_row(&row).unwrap(), partial.to_vec());
            }
        }
    }

    #[test]
    fn a_full_fragment_uses_the_bytes_the_layout_promises() {
        let one = entry(1, 79);
        assert_eq!(one.encoded_len(), 4_069);
        let row = encode_page_row(std::slice::from_ref(&one)).unwrap();
        assert_eq!(row[4_073..].iter().filter(|b| **b != 0).count(), 0);
        assert_eq!(decode_page_row(&row).unwrap(), vec![one]);
    }

    #[test]
    fn a_row_of_the_wrong_length_is_refused() {
        assert!(matches!(
            decode_page_row(&[0u8; 16]),
            Err(RecordError::Length { .. })
        ));
    }

    #[test]
    fn a_payload_behind_a_zero_count_is_refused() {
        let mut row = vec![0u8; PAGE_ROW_BYTES];
        row[PAGE_ROW_BYTES - 1] = 1;
        assert!(decode_page_row(&row).is_err());
    }

    #[test]
    fn an_impossible_entry_count_is_refused_before_it_is_used() {
        let mut row = vec![0u8; PAGE_ROW_BYTES];
        row[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode_page_row(&row),
            Err(RecordError::TooManyEntries(_))
        ));
    }

    /// A count within the hard bound but past what the declared entries fit.
    /// The row cannot hold them, so the walk must stop rather than read past.
    #[test]
    fn a_count_larger_than_the_row_holds_is_refused() {
        let entries: Vec<PageEntry> = (0..3).map(|i| entry(i as u8 + 1, 79)).collect();
        let mut row = encode_page_row(&[entry(1, 79)]).unwrap();
        row[..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode_page_row(&row).is_err());
        let _ = entries;
    }

    #[test]
    fn an_impossible_event_count_is_refused() {
        for claimed in [0u32, EVENTS_PER_PAGE + 1] {
            let mut row = encode_page_row(&[entry(1, 2)]).unwrap();
            row[PAGE_ROW_HEADER_BYTES + PE_EVENT_COUNT..PAGE_ROW_HEADER_BYTES + PE_EVENT_COUNT + 4]
                .copy_from_slice(&claimed.to_le_bytes());
            assert!(decode_page_row(&row).is_err(), "claimed {claimed}");
        }
    }

    #[test]
    fn an_ordinal_outside_its_fragment_count_is_refused() {
        let mut row = encode_page_row(&[entry(1, 2)]).unwrap();
        row[PAGE_ROW_HEADER_BYTES + PE_ORDINAL..PAGE_ROW_HEADER_BYTES + PE_ORDINAL + 4]
            .copy_from_slice(&5u32.to_le_bytes());
        assert!(decode_page_row(&row).is_err());
        assert!(PageEntry::new(tag_of(1), 3, 3, vec![event(1, 0)]).is_err());
        assert!(PageEntry::new(tag_of(1), 0, 0, vec![event(1, 0)]).is_err());
    }

    #[test]
    fn heights_that_disagree_with_the_events_are_refused() {
        let mut row = encode_page_row(&[entry(1, 3)]).unwrap();
        row[PAGE_ROW_HEADER_BYTES + PE_MAX_HEIGHT..PAGE_ROW_HEADER_BYTES + PE_MAX_HEIGHT + 4]
            .copy_from_slice(&9_999u32.to_le_bytes());
        assert!(decode_page_row(&row).is_err());
    }

    /// Ordering is what a replay depends on, so a shuffled entry must fail
    /// rather than replay the same events in a different order.
    #[test]
    fn events_out_of_canonical_order_are_refused() {
        let mut e = entry(1, 3);
        e.events.reverse();
        let row = encode_page_row(&[e]).unwrap();
        assert!(decode_page_row(&row).is_err());
    }

    #[test]
    fn content_past_the_last_entry_is_refused() {
        let mut row = encode_page_row(&[entry(1, 2)]).unwrap();
        row[PAGE_ROW_BYTES - 1] = 1;
        assert!(decode_page_row(&row).is_err());
    }

    /// Two entries for one script would make "the entry matching my script" a
    /// choice rather than a selection. Refused at both ends, because the client
    /// check that depends on it cannot be the only thing enforcing it.
    #[test]
    fn a_script_may_not_appear_twice_in_a_row() {
        let twice = vec![entry(1, 2), entry(1, 3)];
        assert!(encode_page_row(&twice).is_err());

        // Built by hand, since the encoder refuses to produce it.
        let mut row = encode_page_row(&[entry(1, 2), entry(2, 2)]).unwrap();
        let second = PAGE_ROW_HEADER_BYTES + entry(1, 2).encoded_len();
        let first_tag = row
            [PAGE_ROW_HEADER_BYTES + PE_TAG..PAGE_ROW_HEADER_BYTES + PE_TAG + SCRIPT_TAG_BYTES]
            .to_vec();
        row[second + PE_TAG..second + PE_TAG + SCRIPT_TAG_BYTES].copy_from_slice(&first_tag);
        assert!(decode_page_row(&row).is_err());
    }

    /// Arbitrary bytes must produce an error, never a panic. Seeded so a
    /// failure reproduces exactly, and without a property-testing dependency
    /// the rest of the workspace does not have.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        for _ in 0..2_000 {
            let mut row = vec![0u8; PAGE_ROW_BYTES];
            for chunk in row.chunks_mut(8) {
                let bytes = next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            // Keep the count in range most of the time, so the walk is actually
            // entered rather than rejected at the first bound.
            row[..4].copy_from_slice(&((next() % 30) as u32).to_le_bytes());
            let _ = decode_page_row(&row);
        }
    }

    fn linked(tag: u8, events: u32, link: RunLink) -> PageEntry {
        entry(tag, events)
            .with_link(link)
            .expect("a first fragment may link")
    }

    /// A first fragment's link round-trips in the header, at the documented
    /// offsets, and costs nothing in event payload.
    #[test]
    fn a_run_link_round_trips_in_the_header() {
        let link = RunLink {
            prev_child: 3,
            prev_row: 0x0102_0304,
            older_runs: 7,
        };
        let row = encode_page_row(&[linked(1, 2, link), entry(2, 1)]).unwrap();
        let at = PAGE_ROW_HEADER_BYTES;
        assert_eq!(row[at + 34], 3);
        assert_eq!(&row[at + 35..at + 39], &[4, 3, 2, 1]);
        assert_eq!(row[at + 39], 7);
        let decoded = decode_page_row(&row).unwrap();
        assert_eq!(decoded[0].link, link);
        assert_eq!(decoded[0].link.previous(), Some((3, 0x0102_0303)));
        assert_eq!(decoded[1].link, RunLink::default());
        assert_eq!(decoded[1].link.previous(), None);
    }

    /// Only a run's first fragment links, a link that ends the chain is all
    /// zero, and one that does not names at least one older run.
    #[test]
    fn malformed_links_are_refused_at_both_ends() {
        let at = PAGE_ROW_HEADER_BYTES;
        let ends = |prev_child, prev_row, older_runs| RunLink {
            prev_child,
            prev_row,
            older_runs,
        };
        for bad in [ends(1, 0, 0), ends(0, 0, 1), ends(0, 5, 0), ends(32, 5, 1)] {
            assert!(entry(1, 1).with_link(bad).is_err(), "{bad:?}");
            let mut row = encode_page_row(&[entry(1, 1)]).unwrap();
            row[at + 34] = bad.prev_child;
            row[at + 35..at + 39].copy_from_slice(&bad.prev_row.to_le_bytes());
            row[at + 39] = bad.older_runs;
            assert!(decode_page_row(&row).is_err(), "{bad:?}");
        }
        // A later fragment carries no link, even a well-formed one.
        let later = PageEntry::new(tag_of(1), 1, 2, vec![event(5, 0)]).unwrap();
        assert!(later.clone().with_link(ends(0, 4, 1)).is_err());
        let mut row = encode_page_row(&[later]).unwrap();
        row[at + 35..at + 39].copy_from_slice(&4u32.to_le_bytes());
        row[at + 39] = 1;
        assert!(decode_page_row(&row).is_err());
    }

    /// Frozen encodings. A change to the event width, the script limit or any
    /// offset shifts these, and shifting them without republishing is what
    /// would make two builds disagree about a row while both call it valid.
    #[test]
    fn the_encoding_is_frozen() {
        use sha2::{Digest, Sha256};
        for (label, entries, want) in [
            (
                "empty",
                vec![],
                "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
            ),
            (
                "one class-1 entry",
                vec![entry(1, 1)],
                "53a70f6e1b27be31dd7e9dbad6a02746e03c0545c5b7259bf14d8d6089f0d442",
            ),
            (
                "a full class-1 row",
                (0..44).map(|i| entry(i as u8 + 1, 1)).collect(),
                "b1ee60014d9157ce32d06c2f21594e2d6ce7a32573ced10213a05688320e01ee",
            ),
            (
                "a full class-2 row",
                (0..28).map(|i| entry(i as u8 + 1, 2)).collect(),
                "0d6d329de890365e0176d4202b72721488e379fa99fef7e49a7b38efc8317c88",
            ),
            (
                "a full fragment",
                vec![entry(1, 79)],
                "a8410c05db4b7f3495fce4b616d6e5f17c23a081abbf94b99a854e85e4d8b5cc",
            ),
        ] {
            let row = encode_page_row(&entries).expect("encodes");
            let digest = hex::encode(Sha256::digest(&row));
            assert_eq!(digest, want, "{label}");
            assert_eq!(decode_page_row(&row).unwrap(), entries, "{label}");
        }
    }
}
