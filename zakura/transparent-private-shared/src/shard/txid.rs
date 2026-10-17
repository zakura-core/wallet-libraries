//! Fixed-size txid display entries: what a wallet shows for a transparent
//! transaction, and which of its facts the entry leaves out.
//!
//! An entry is a trusted publisher's summary, not transaction authentication
//! or financial coverage. It holds the regular cases whole: any number of
//! inputs shown by their first address-shaped source, and up to two outputs.
//! Everything else is a named omission, so a wallet can show the known facts
//! and say what is missing instead of guessing. Every entry is
//! [`ENTRY_BYTES`] long, so every lookup costs the same.
use crate::events::{Txid, MAX_MONEY};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CODEC: &str = "transparent-txid-display-v2";
/// Bytes of one encoded entry.
pub const ENTRY_BYTES: usize = 113;
pub const TAG_BYTES: usize = 16;
/// Domain of the entry tag.
pub const TAG_DOMAIN: &[u8] = b"transparent-txid-display/tag/v2";
/// Outputs an entry holds; a transaction with more names the omission.
pub const OUTPUT_SLOTS: usize = 2;
/// Bounds implied by the supported 2 MB transaction ceiling: an input is at
/// least 41 bytes and an output at least 9.
pub const MAX_INPUTS: u32 = 2_000_000 / 41;
pub const MAX_OUTPUTS: u32 = 2_000_000 / 9;

#[derive(Debug, thiserror::Error)]
#[error("invalid txid display data: {0}")]
pub struct Error(pub String);
fn bad(s: &str) -> Error {
    Error(s.into())
}

/// The first 16 bytes of a domain-separated hash of the txid.
///
/// The entry stores the tag, not the txid. An accidental match is about 2⁻¹²⁸
/// per comparison, and buckets and rows are derived from the tag, so a server
/// verifies placement without learning txids it does not already hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(pub [u8; TAG_BYTES]);

impl Tag {
    pub fn of(txid: &Txid) -> Self {
        let digest = Sha256::new()
            .chain_update(TAG_DOMAIN)
            .chain_update(txid.0)
            .finalize();
        Self(digest[..TAG_BYTES].try_into().unwrap())
    }
}

/// What an address slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    /// No input or output occupies the slot.
    Absent = 0,
    P2pkh = 1,
    P2sh = 2,
    /// A script that is not P2PKH or P2SH (P2PK, OP_RETURN, empty, other):
    /// present, but with no address to show.
    Other = 3,
}

/// A transparent address, or why a slot has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub kind: AddressKind,
    /// The script hash for P2PKH and P2SH; zero otherwise.
    pub hash: [u8; 20],
}

impl Address {
    pub const ABSENT: Self = Self {
        kind: AddressKind::Absent,
        hash: [0; 20],
    };
    pub const OTHER: Self = Self {
        kind: AddressKind::Other,
        hash: [0; 20],
    };

    /// Classifies a locking script. Only the exact standard templates carry
    /// an address; anything else is [`AddressKind::Other`].
    pub fn from_script(script: &[u8]) -> Self {
        match script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => Self {
                kind: AddressKind::P2pkh,
                hash: hash.try_into().unwrap(),
            },
            [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => Self {
                kind: AddressKind::P2sh,
                hash: hash.try_into().unwrap(),
            },
            _ => Self::OTHER,
        }
    }

    /// The locking script this address stands for, if it has one.
    pub fn script(&self) -> Option<Vec<u8>> {
        match self.kind {
            AddressKind::P2pkh => {
                Some([&[0x76, 0xa9, 0x14][..], &self.hash, &[0x88, 0xac]].concat())
            }
            AddressKind::P2sh => Some([&[0xa9, 0x14][..], &self.hash, &[0x87]].concat()),
            AddressKind::Absent | AddressKind::Other => None,
        }
    }

    pub fn is_address(&self) -> bool {
        matches!(self.kind, AddressKind::P2pkh | AddressKind::P2sh)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.kind as u8);
        out.extend(self.hash);
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let kind = match bytes[0] {
            0 => AddressKind::Absent,
            1 => AddressKind::P2pkh,
            2 => AddressKind::P2sh,
            3 => AddressKind::Other,
            _ => return Err(bad("address kind")),
        };
        let hash: [u8; 20] = bytes[1..21].try_into().unwrap();
        if !matches!(kind, AddressKind::P2pkh | AddressKind::P2sh) && hash != [0; 20] {
            return Err(bad("hash without an address"));
        }
        Ok(Self { kind, hash })
    }
}

/// One of the first two transparent outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryOutput {
    pub value: u64,
    pub address: Address,
}

/// Flag bits. Facts first, then what the entry leaves out.
pub mod flags {
    pub const COINBASE: u16 = 1 << 0;
    pub const SHIELDED_COMPONENTS: u16 = 1 << 1;
    /// The inputs spend two or more distinct scripts; the source is the first
    /// address-shaped one in input order, the rest are omitted.
    pub const MULTIPLE_SOURCE_SCRIPTS: u16 = 1 << 2;
    /// Outputs 0 and 1 are given; the output count says how many exist.
    pub const MORE_THAN_TWO_OUTPUTS: u16 = 1 << 3;
    /// There are transparent inputs and the shielded pools also contributed
    /// net value to the transaction.
    pub const SHIELDED_AND_TRANSPARENT_FUNDING: u16 = 1 << 4;
    pub const KNOWN: u16 = (1 << 5) - 1;
}

/// The display facts of one transaction, as one fixed-size entry.
///
/// Fields are public for construction; [`DisplayEntry::encode`] refuses any
/// combination [`DisplayEntry::decode`] would refuse, so a published entry is
/// always canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayEntry {
    pub tag: Tag,
    pub coinbase: bool,
    pub shielded_components: bool,
    pub multiple_source_scripts: bool,
    pub shielded_and_transparent_funding: bool,
    /// The exact whole-transaction fee; zero for coinbase.
    pub fee: u64,
    /// Transparent inputs, excluding a coinbase input.
    pub input_count: u32,
    /// Every transparent output, including any the entry omits.
    pub output_count: u32,
    /// The first input, in input order, whose spent script is address-shaped;
    /// [`AddressKind::Other`] when inputs exist but none is.
    pub source: Address,
    /// Outputs 0 and 1, as far as they exist.
    pub outputs: [Option<EntryOutput>; OUTPUT_SLOTS],
}

impl DisplayEntry {
    pub fn more_than_two_outputs(&self) -> bool {
        self.output_count as usize > OUTPUT_SLOTS
    }

    /// Whether the entry holds every fact the wallet displays, that is, no
    /// omission flag is set and no address slot is [`AddressKind::Other`].
    pub fn is_complete(&self) -> bool {
        !self.multiple_source_scripts
            && !self.more_than_two_outputs()
            && !self.shielded_and_transparent_funding
            && self.source.kind != AddressKind::Other
            && self
                .outputs
                .iter()
                .flatten()
                .all(|o| o.address.kind != AddressKind::Other)
    }

    pub fn flags(&self) -> u16 {
        let mut flags = 0;
        for (set, bit) in [
            (self.coinbase, flags::COINBASE),
            (self.shielded_components, flags::SHIELDED_COMPONENTS),
            (self.multiple_source_scripts, flags::MULTIPLE_SOURCE_SCRIPTS),
            (self.more_than_two_outputs(), flags::MORE_THAN_TWO_OUTPUTS),
            (
                self.shielded_and_transparent_funding,
                flags::SHIELDED_AND_TRANSPARENT_FUNDING,
            ),
        ] {
            if set {
                flags |= bit;
            }
        }
        flags
    }

    /// Checks the entry is one a publisher could have derived: what
    /// [`Self::encode`] and [`Self::decode`] require of every entry.
    pub fn validate(&self) -> Result<(), Error> {
        if self.tag.0 == [0; TAG_BYTES] {
            return Err(bad("zero tag"));
        }
        if self.fee > MAX_MONEY || self.input_count > MAX_INPUTS || self.output_count > MAX_OUTPUTS
        {
            return Err(bad("fee or count bound"));
        }
        let held = (self.output_count as usize).min(OUTPUT_SLOTS);
        let mut total = 0u64;
        for (i, slot) in self.outputs.iter().enumerate() {
            match slot {
                Some(output) if i < held => {
                    if output.address.kind == AddressKind::Absent {
                        return Err(bad("present output without a kind"));
                    }
                    total = total
                        .checked_add(output.value)
                        .filter(|t| *t <= MAX_MONEY)
                        .ok_or_else(|| bad("output value total"))?;
                }
                None if i >= held => {}
                _ => return Err(bad("output slots and count disagree")),
            }
        }
        let has_inputs = self.input_count > 0;
        if has_inputs == (self.source.kind == AddressKind::Absent) {
            return Err(bad("source and input count disagree"));
        }
        if self.multiple_source_scripts && self.input_count < 2 {
            return Err(bad("multiple sources need two inputs"));
        }
        if self.shielded_and_transparent_funding && !(has_inputs && self.shielded_components) {
            return Err(bad("mixed funding needs both pools"));
        }
        if self.coinbase && (self.fee != 0 || has_inputs) {
            return Err(bad("coinbase spends nothing and pays no fee"));
        }
        // A non-coinbase transaction without transparent inputs is funded by
        // the shielded pools, so it must have shielded components.
        if !self.coinbase && !has_inputs && !self.shielded_components {
            return Err(bad("unfunded transaction"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; ENTRY_BYTES], Error> {
        self.validate()?;
        let mut out = Vec::with_capacity(ENTRY_BYTES);
        out.extend(self.tag.0);
        out.extend(self.flags().to_le_bytes());
        out.extend(self.fee.to_le_bytes());
        out.extend(self.input_count.to_le_bytes());
        out.extend(self.output_count.to_le_bytes());
        self.source.encode(&mut out);
        for slot in &self.outputs {
            let output = slot.unwrap_or(EntryOutput {
                value: 0,
                address: Address::ABSENT,
            });
            out.extend(output.value.to_le_bytes());
            output.address.encode(&mut out);
        }
        Ok(out.try_into().expect("fixed entry width"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENTRY_BYTES {
            return Err(bad("entry width"));
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let flags = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
        if flags & !flags::KNOWN != 0 {
            return Err(bad("reserved flag"));
        }
        let mut outputs = [None; OUTPUT_SLOTS];
        for (i, slot) in outputs.iter_mut().enumerate() {
            let at = 55 + 29 * i;
            let value = u64_at(at);
            let address = Address::decode(&bytes[at + 8..at + 29])?;
            if address.kind == AddressKind::Absent {
                if value != 0 {
                    return Err(bad("value in an absent slot"));
                }
            } else {
                *slot = Some(EntryOutput { value, address });
            }
        }
        let entry = Self {
            tag: Tag(bytes[..16].try_into().unwrap()),
            coinbase: flags & flags::COINBASE != 0,
            shielded_components: flags & flags::SHIELDED_COMPONENTS != 0,
            multiple_source_scripts: flags & flags::MULTIPLE_SOURCE_SCRIPTS != 0,
            shielded_and_transparent_funding: flags & flags::SHIELDED_AND_TRANSPARENT_FUNDING != 0,
            fee: u64_at(18),
            input_count: u32_at(26),
            output_count: u32_at(30),
            source: Address::decode(&bytes[34..55])?,
            outputs,
        };
        entry.validate()?;
        if entry.flags() != flags {
            return Err(bad("omission flag and output count disagree"));
        }
        Ok(entry)
    }
}

impl AsRef<DisplayEntry> for DisplayEntry {
    fn as_ref(&self) -> &DisplayEntry {
        self
    }
}

/// Entries in one row of `row_bytes`; the rest of the row is zero padding.
pub const fn slots_per_row(row_bytes: usize) -> usize {
    row_bytes / ENTRY_BYTES
}

/// The entries of one row, in slot order, after checking the row is
/// canonical: occupied slots first in ascending tag order, then empty
/// (all-zero) slots, then zero padding. The row's length is its width.
pub fn row_entries(row: &[u8]) -> Result<Vec<DisplayEntry>, Error> {
    let slots = slots_per_row(row.len());
    if slots == 0 {
        return Err(bad("row width"));
    }
    let mut out: Vec<DisplayEntry> = Vec::new();
    let mut empty = false;
    for slot in row[..slots * ENTRY_BYTES].chunks(ENTRY_BYTES) {
        if slot.iter().all(|b| *b == 0) {
            empty = true;
            continue;
        }
        let entry = DisplayEntry::decode(slot)?;
        if empty || out.last().is_some_and(|last| last.tag >= entry.tag) {
            return Err(bad("row slot order"));
        }
        out.push(entry);
    }
    if row[slots * ENTRY_BYTES..].iter().any(|b| *b != 0) {
        return Err(bad("nonzero row padding"));
    }
    Ok(out)
}

/// One canonical row of `row_bytes` from at most [`slots_per_row`] entries.
pub fn encode_row(entries: &[DisplayEntry], row_bytes: usize) -> Result<Vec<u8>, Error> {
    if entries.len() > slots_per_row(row_bytes) {
        return Err(bad("row capacity"));
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.tag);
    if sorted.windows(2).any(|w| w[0].tag == w[1].tag) {
        return Err(bad("duplicate tag in row"));
    }
    let mut row = Vec::with_capacity(row_bytes);
    for entry in &sorted {
        row.extend(entry.encode()?);
    }
    row.resize(row_bytes, 0);
    Ok(row)
}

/// The entry for `txid` in the fetched copies of one row: the same row index
/// of every segment of a table. Every entry in them must be placed in that
/// row, which `in_row` decides from its tag, and the same entry in two
/// segments is refused.
pub fn find_entry(
    rows: &[Vec<u8>],
    txid: &Txid,
    in_row: impl Fn(&Tag) -> bool,
) -> Result<Option<DisplayEntry>, Error> {
    let tag = Tag::of(txid);
    let mut found = None;
    for row in rows {
        for entry in row_entries(row)? {
            if !in_row(&entry.tag) {
                return Err(bad("entry outside its row"));
            }
            if entry.tag == tag {
                if found.is_some() {
                    return Err(bad("duplicate tag"));
                }
                found = Some(entry);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2pkh(byte: u8) -> Vec<u8> {
        [&[0x76, 0xa9, 0x14][..], &[byte; 20], &[0x88, 0xac]].concat()
    }
    fn p2sh(byte: u8) -> Vec<u8> {
        [&[0xa9, 0x14][..], &[byte; 20], &[0x87]].concat()
    }

    #[test]
    fn layout_constants() {
        assert_eq!(slots_per_row(4096), 36);
        assert_eq!(slots_per_row(8192), 72);
        assert_eq!(16 + 2 + 8 + 4 + 4 + 21 + 29 * OUTPUT_SLOTS, ENTRY_BYTES);
    }

    #[test]
    fn addresses_are_only_the_exact_standard_templates() {
        let a = Address::from_script(&p2pkh(1));
        assert_eq!((a.kind, a.hash), (AddressKind::P2pkh, [1; 20]));
        assert_eq!(a.script().unwrap(), p2pkh(1));
        let s = Address::from_script(&p2sh(2));
        assert_eq!((s.kind, s.hash), (AddressKind::P2sh, [2; 20]));
        assert_eq!(s.script().unwrap(), p2sh(2));
        let mut long = p2pkh(1);
        long.push(0x00);
        let p2pk = [&[0x21][..], &[2; 33], &[0xac]].concat();
        for other in [
            vec![],
            vec![0x6a, 0x01, 0x02],
            p2pk,
            long,
            p2pkh(1)[..24].to_vec(),
        ] {
            assert_eq!(Address::from_script(&other), Address::OTHER);
        }
    }
}
