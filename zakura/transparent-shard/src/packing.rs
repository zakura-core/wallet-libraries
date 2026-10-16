//! Exact byte demand and deterministic best-fit packing, shared by census and builder.
use crate::{
    compact,
    layout::{PAGE_ENTRY_HEADER_BYTES, PAGE_ROW_BYTES, PAGE_ROW_HEADER_BYTES},
    records::DIRECTORY_ENTRY_HEADER_BYTES,
};
use std::collections::BTreeMap;
use transparent_events::TransparentEvent;

pub const ROW_PAYLOAD: usize = PAGE_ROW_BYTES - PAGE_ROW_HEADER_BYTES;
pub const FRAGMENT_PAYLOAD: usize = ROW_PAYLOAD - PAGE_ENTRY_HEADER_BYTES;

/// Constant-size history summary apart from the configured inline allowance.
/// Appending events only changes the last fragment and the inline suffix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryLayout {
    pub events: u32,
    pub inline: Vec<TransparentEvent>,
    pub fragments: u32,
    pub tail_bytes: usize,
    pub paged_bytes: u64,
    last_paged: Option<TransparentEvent>,
}

impl HistoryLayout {
    pub fn push(&mut self, event: TransparentEvent, inline: u32) {
        self.push_with_payload(event, inline, FRAGMENT_PAYLOAD);
    }

    /// [`Self::push`] for a page entry whose header leaves `payload` bytes of
    /// a row for events: the decoupled layout's 40-byte header leaves fewer.
    pub fn push_with_payload(&mut self, event: TransparentEvent, inline: u32, payload: usize) {
        self.events = self
            .events
            .checked_add(1)
            .expect("history exceeds u32 event limit");
        self.inline.push(event);
        if self.inline.len() <= inline as usize {
            return;
        }
        let older = self.inline.remove(0);
        let mut len = compact::event_len(&older, self.last_paged.as_ref());
        if self.fragments == 0 || self.tail_bytes + len > payload {
            self.fragments += 1;
            self.tail_bytes = 0;
            len = compact::event_len(&older, None);
        }
        self.tail_bytes += len;
        self.paged_bytes += len as u64;
        self.last_paged = Some(older);
    }

    pub fn directory_bytes(&self) -> usize {
        DIRECTORY_ENTRY_HEADER_BYTES + compact::encoded_len(&self.inline)
    }
}

/// Greedy maximal fragments; every fragment resets the compact reference context.
pub fn fragments(events: &[TransparentEvent]) -> Vec<&[TransparentEvent]> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (i, event) in events.iter().enumerate() {
        let previous = if i > start {
            Some(&events[i - 1])
        } else {
            None
        };
        let mut len = compact::event_len(event, previous);
        if bytes + len > FRAGMENT_PAYLOAD {
            result.push(&events[start..i]);
            start = i;
            bytes = 0;
            len = compact::event_len(event, None);
        }
        bytes += len;
    }
    if start < events.len() {
        result.push(&events[start..]);
    }
    result
}

/// Bins counted by free payload bytes, `0..=ROW_PAYLOAD`, with a bitmap of the
/// values that have any, so the tightest bin that fits is a short word scan.
struct FreeSpace {
    bins: Vec<u64>,
    occupied: [u64; ROW_PAYLOAD / 64 + 1],
}

impl Default for FreeSpace {
    fn default() -> Self {
        Self {
            bins: vec![0; ROW_PAYLOAD + 1],
            occupied: [0; ROW_PAYLOAD / 64 + 1],
        }
    }
}

impl FreeSpace {
    fn add(&mut self, space: usize, bins: u64) {
        self.bins[space] += bins;
        self.occupied[space / 64] |= 1 << (space % 64);
    }

    /// Removes and returns every bin at the smallest space of at least `size`.
    fn take_at_least(&mut self, size: usize) -> Option<(usize, u64)> {
        let mut word = size / 64;
        let mut bits = *self.occupied.get(word)? & (u64::MAX << (size % 64));
        while bits == 0 {
            word += 1;
            bits = *self.occupied.get(word)?;
        }
        let space = word * 64 + bits.trailing_zeros() as usize;
        self.occupied[word] &= !(1 << (space % 64));
        Some((space, std::mem::take(&mut self.bins[space])))
    }
}

fn change(map: &mut BTreeMap<usize, u64>, key: usize, add: bool) {
    if add {
        *map.entry(key).or_default() += 1;
    } else {
        let count = map.get_mut(&key).expect("removing existing demand");
        *count -= 1;
        if *count == 0 {
            map.remove(&key);
        }
    }
}

#[derive(Clone, Debug)]
pub struct PackedDemand {
    /// Complete single-fragment entries, including their header, by byte length.
    short: BTreeMap<usize, u64>,
    /// Spare bytes in the final row of each long history.
    tails: BTreeMap<usize, u64>,
    long_rows: u64,
    long_scripts: u64,
    event_bytes: u64,
    /// Page entry header bytes, which decide a fragment's event payload.
    entry_header: usize,
    cached_rows: std::cell::OnceCell<(u64, u64)>,
}

impl Default for PackedDemand {
    fn default() -> Self {
        Self::with_entry_header(PAGE_ENTRY_HEADER_BYTES)
    }
}

impl PartialEq for PackedDemand {
    fn eq(&self, other: &Self) -> bool {
        self.short == other.short
            && self.tails == other.tails
            && self.long_rows == other.long_rows
            && self.long_scripts == other.long_scripts
            && self.event_bytes == other.event_bytes
            && self.entry_header == other.entry_header
    }
}
impl Eq for PackedDemand {}

impl PackedDemand {
    /// Demand for page entries with an `entry_header`-byte header.
    pub fn with_entry_header(entry_header: usize) -> Self {
        assert!(
            entry_header < ROW_PAYLOAD,
            "a header must leave room for events"
        );
        Self {
            short: BTreeMap::new(),
            tails: BTreeMap::new(),
            long_rows: 0,
            long_scripts: 0,
            event_bytes: 0,
            entry_header,
            cached_rows: std::cell::OnceCell::new(),
        }
    }

    /// Event bytes one fragment holds under this header.
    pub fn fragment_payload(&self) -> usize {
        ROW_PAYLOAD - self.entry_header
    }

    pub fn entry_header(&self) -> usize {
        self.entry_header
    }

    pub fn shift(&mut self, old: &HistoryLayout, new: &HistoryLayout) {
        self.cached_rows.take();
        self.update(old, false);
        self.update(new, true);
    }

    fn update(&mut self, history: &HistoryLayout, add: bool) {
        if history.fragments == 0 {
            return;
        }
        if add {
            self.event_bytes += history.paged_bytes;
        } else {
            self.event_bytes -= history.paged_bytes;
        }
        if history.fragments == 1 {
            change(&mut self.short, self.entry_header + history.tail_bytes, add);
        } else {
            let payload = self.fragment_payload();
            change(&mut self.tails, payload - history.tail_bytes, add);
            if add {
                self.long_rows += u64::from(history.fragments);
                self.long_scripts += 1;
            } else {
                self.long_rows -= u64::from(history.fragments);
                self.long_scripts -= 1;
            }
        }
    }

    pub fn classes(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.short.iter().map(|(size, count)| (*size, *count))
    }
    pub fn long_rows(&self) -> u64 {
        self.long_rows
    }
    pub fn long_scripts(&self) -> u64 {
        self.long_scripts
    }
    pub fn paged_scripts(&self) -> u64 {
        self.short.values().sum::<u64>() + self.long_scripts
    }
    pub fn event_bytes(&self) -> u64 {
        self.event_bytes
    }
    pub fn fragments(&self) -> u64 {
        self.short.values().sum::<u64>() + self.long_rows
    }

    fn calculate_grouped_rows(&self) -> u64 {
        self.long_rows
            + self
                .short
                .iter()
                .map(|(size, count)| count.div_ceil((ROW_PAYLOAD / size) as u64))
                .sum::<u64>()
    }

    /// Run the same descending best-fit rule as the builder, in count batches.
    /// Filling equal-sized entries into the tightest bin leaves that bin the
    /// tightest until it no longer fits; this permits exact multiplicity batching.
    ///
    /// The sealer asks for this after every block, so it runs over a dense
    /// count per free-space value rather than a cloned map: every space is at
    /// most one row's payload. The steps and their order are exactly those of
    /// [`Self::calculate_mixed_rows_sparse`], which remains the definition and
    /// handles any space outside that bound.
    fn calculate_mixed_rows(&self) -> u64 {
        let bounded =
            |map: &BTreeMap<usize, u64>| map.keys().next_back().is_none_or(|k| *k <= ROW_PAYLOAD);
        if !bounded(&self.tails) || !bounded(&self.short) || self.short.contains_key(&0) {
            return self.calculate_mixed_rows_sparse();
        }
        let mut free = FreeSpace::default();
        for (&space, &bins) in &self.tails {
            free.add(space, bins);
        }
        let mut rows = self.long_rows;
        for (&size, &count) in self.short.iter().rev() {
            let mut remaining = count;
            while remaining != 0 {
                let (space, bins) = match free.take_at_least(size) {
                    Some(found) => found,
                    None => {
                        let bins = remaining.div_ceil((ROW_PAYLOAD / size) as u64);
                        rows += bins;
                        (ROW_PAYLOAD, bins)
                    }
                };
                let per = (space / size) as u64;
                let full = bins.min(remaining / per);
                if full != 0 {
                    free.add(space % size, full);
                }
                remaining -= full * per;
                let mut unused = bins - full;
                if unused != 0 && remaining != 0 {
                    free.add(space - remaining as usize * size, 1);
                    remaining = 0;
                    unused -= 1;
                }
                if unused != 0 {
                    free.add(space, unused);
                }
            }
        }
        rows
    }

    /// The reference form of [`Self::calculate_mixed_rows`], over a map of
    /// free-space values.
    fn calculate_mixed_rows_sparse(&self) -> u64 {
        let mut free = self.tails.clone();
        let mut rows = self.long_rows;
        for (&size, &count) in self.short.iter().rev() {
            let mut remaining = count;
            while remaining != 0 {
                let (space, bins) = match free.range(size..).next() {
                    Some((&space, &bins)) => {
                        free.remove(&space);
                        (space, bins)
                    }
                    None => {
                        let bins = remaining.div_ceil((ROW_PAYLOAD / size) as u64);
                        rows += bins;
                        (ROW_PAYLOAD, bins)
                    }
                };
                let per = (space / size) as u64;
                let full = bins.min(remaining / per);
                if full != 0 {
                    *free.entry(space % size).or_default() += full;
                }
                remaining -= full * per;
                let mut unused = bins - full;
                if unused != 0 && remaining != 0 {
                    *free.entry(space - remaining as usize * size).or_default() += 1;
                    remaining = 0;
                    unused -= 1;
                }
                if unused != 0 {
                    *free.entry(space).or_default() += unused;
                }
            }
        }
        rows
    }

    fn row_counts(&self) -> (u64, u64) {
        *self
            .cached_rows
            .get_or_init(|| (self.calculate_mixed_rows(), self.calculate_grouped_rows()))
    }
    pub fn mixed_rows(&self) -> u64 {
        self.row_counts().0
    }
    pub fn grouped_rows(&self) -> u64 {
        self.row_counts().1
    }

    /// Ties use mixed packing, so publication and census choose identically.
    pub fn use_mixed(&self) -> bool {
        self.mixed_rows() <= self.grouped_rows()
    }
    pub fn rows(&self) -> u64 {
        self.mixed_rows().min(self.grouped_rows())
    }
    pub fn ordinary_rows(&self) -> u64 {
        let mut ordinary = self.clone();
        ordinary.cached_rows.take();
        ordinary.long_rows = 0;
        ordinary.tails.clear();
        ordinary.rows()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compact::tests::pair,
        page_row::{decode_page_row, encode_page_row, PageEntry},
    };

    #[test]
    fn fragment_boundaries_reset_references_and_reconstruct_every_event() {
        let events: Vec<_> = (0..100).flat_map(|i| pair(i + 100, i)).collect();
        let parts = fragments(&events);
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [86, 86, 28]
        );
        let mut recovered = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let entry =
                PageEntry::new([1; 14], i as u32, parts.len() as u32, part.to_vec()).unwrap();
            let row = encode_page_row(&[entry]).unwrap();
            recovered.extend(decode_page_row(&row).unwrap().remove(0).events);
        }
        assert_eq!(recovered, events);
        // 78 receives leave 80 bytes, allowing the next receive but not its
        // local spend. The next fragment must start with an ordinary spend.
        let mut split: Vec<_> = (0..78).map(|i| pair(i, i)[0]).collect();
        split.extend(pair(100, 100));
        let parts = fragments(&split);
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [79, 1]);
        assert_eq!(compact::encoded_len(parts[1]), 79);
    }

    #[test]
    fn incremental_summaries_equal_whole_history_fragmentation() {
        let mut history = Vec::new();
        let mut state = HistoryLayout::default();
        for i in 0..700u32 {
            let event = pair(i, i)[if i % 3 == 0 { 1 } else { 0 }];
            history.push(event);
            state.push(event, 2);
            let old = &history[..history.len().saturating_sub(2)];
            let parts = fragments(old);
            assert_eq!(state.fragments as usize, parts.len());
            assert_eq!(
                state.paged_bytes,
                parts
                    .iter()
                    .map(|p| compact::encoded_len(p) as u64)
                    .sum::<u64>()
            );
            assert_eq!(
                state.tail_bytes,
                parts.last().map_or(0, |p| compact::encoded_len(p))
            );
            assert_eq!(state.inline, history[history.len().saturating_sub(2)..]);
        }
    }

    /// The dense packer is the map packer, step for step: equal row counts
    /// over arbitrary demand, including bins at every boundary space, counts
    /// far past one row, and spaces outside the dense bound.
    #[test]
    fn dense_best_fit_equals_the_map_reference() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        for case in 0..2_000 {
            let mut demand = PackedDemand::default();
            let classes = 1 + next(if case % 4 == 0 { 2_000 } else { 40 });
            for _ in 0..classes {
                let size = match next(8) {
                    0 => PAGE_ENTRY_HEADER_BYTES,
                    1 => ROW_PAYLOAD,
                    2 => ROW_PAYLOAD / 2 + next(3) as usize,
                    _ => PAGE_ENTRY_HEADER_BYTES + next(FRAGMENT_PAYLOAD as u64 + 1) as usize,
                };
                let count = if next(10) == 0 {
                    1 + next(100_000)
                } else {
                    1 + next(30)
                };
                *demand.short.entry(size).or_default() += count;
            }
            for _ in 0..next(if case % 4 == 0 { 2_000 } else { 40 }) {
                let space = match next(6) {
                    0 => 0,
                    1 => FRAGMENT_PAYLOAD,
                    _ => next(FRAGMENT_PAYLOAD as u64 + 1) as usize,
                };
                *demand.tails.entry(space).or_default() += 1 + next(5);
                demand.long_rows += 2;
            }
            assert_eq!(
                demand.calculate_mixed_rows(),
                demand.calculate_mixed_rows_sparse(),
                "case {case}"
            );
        }
        // A free space outside the dense bound is left to the map packer.
        let mut demand = PackedDemand::default();
        demand.short.insert(ROW_PAYLOAD, 3);
        demand.short.insert(PAGE_ENTRY_HEADER_BYTES, 500);
        demand.tails.insert(ROW_PAYLOAD + 7, 1);
        assert_eq!(
            demand.calculate_mixed_rows(),
            demand.calculate_mixed_rows_sparse()
        );
    }

    #[test]
    fn batched_best_fit_matches_an_independent_item_by_item_packer() {
        for seed in 0..50usize {
            let mut demand = PackedDemand::default();
            let mut sizes = Vec::new();
            let mut free = Vec::new();
            let mut full_rows = 0;
            for script in 0..150usize {
                let mut history = HistoryLayout::default();
                for i in 0..((script * 17 + seed * 31) % 300 + 1) {
                    for event in pair(i as u32, i as u32) {
                        history.push(event, 2);
                    }
                }
                demand.shift(&HistoryLayout::default(), &history);
                if history.fragments == 1 {
                    sizes.push(34 + history.tail_bytes);
                }
                if history.fragments > 1 {
                    full_rows += history.fragments as usize - 1;
                    free.push(FRAGMENT_PAYLOAD - history.tail_bytes);
                }
            }
            sizes.sort_unstable_by(|a, b| b.cmp(a));
            for size in sizes {
                free.sort_unstable();
                if let Some(i) = free.iter().position(|space| *space >= size) {
                    free[i] -= size;
                } else {
                    free.push(ROW_PAYLOAD - size);
                }
            }
            assert_eq!(demand.mixed_rows(), (full_rows + free.len()) as u64);
            assert!(demand.rows() <= demand.fragments());
        }
    }
}
