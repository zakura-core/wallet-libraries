//! v2 manifests, sessions and the segment publication, with the checks a
//! publisher, a server's preparation and a wallet apply to them.
use super::*;
use crate::directory::choice::SeedPolicy;
use crate::receiver::{
    Payment,
    session::MAX_MANIFEST_BYTES,
    snapshot::{PageMeta, TREE_SIZE, check_pages},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A segment's chain coverage, shared by its directory and companion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub genesis: Hash,
    /// Operator correction generation, independent of reorgs.
    pub history_revision: u64,
    pub start_height: u32,
    pub start_parent: Hash,
    pub start_position: u64,
    pub end_height: u32,
    pub end_hash: Hash,
    pub end_position: u64,
}

impl Coverage {
    /// Checks order, the tree bound and that the shard spans less than 2^24
    /// heights, which every entry's last-height offset relies on.
    fn validate(&self) -> Result<(), Error> {
        if self.start_height > self.end_height
            || self.end_height - self.start_height > MAX_HEIGHT_OFFSET
            || self.start_position > self.end_position
            || self.end_position > TREE_SIZE
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Hashes every field at fixed width.
    fn hash(&self, h: &mut Sha256) {
        h.update(self.genesis);
        h.update(self.history_revision.to_le_bytes());
        h.update(self.start_height.to_le_bytes());
        h.update(self.start_parent);
        h.update(self.start_position.to_le_bytes());
        h.update(self.end_height.to_le_bytes());
        h.update(self.end_hash);
        h.update(self.end_position.to_le_bytes());
    }

    /// Whether `p` lies in these blocks and positions, outside coinbase.
    pub fn contains(&self, p: &Payment) -> bool {
        p.tx_index != 0
            && (self.start_height..=self.end_height).contains(&p.height)
            && (self.start_position..self.end_position).contains(&p.position)
            && (p.height != self.end_height || p.block_hash == self.end_hash)
    }
}

/// The commitment tree a companion's payloads were built at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub height: u32,
    pub hash: Hash,
    pub size: u64,
}

/// A segment's choice object: served by digest, bound here by digest, exact
/// length and key count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceRef {
    pub digest: Hash,
    pub bytes: u32,
    pub keys: u32,
}

/// A segment's directory: its tag salt, entry and payment counts, choice object
/// and rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub schema: String,
    pub coverage: Coverage,
    pub salt: Hash,
    /// Receivers, one entry each.
    pub entries: u32,
    /// Payments: the sum of the entries' counts and the companion's occupied slots.
    pub payments: u32,
    pub choice: ChoiceRef,
    pub data_sha256: Hash,
}

/// A segment's companion: the directory revision it serves, its geometry and
/// the tree its payloads were built at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Companion {
    pub schema: String,
    pub coverage: Coverage,
    /// [`Directory::revision`] of the directory whose entries address these slots.
    pub directory: Hash,
    pub rows: u32,
    /// The only prefix a query may be trimmed to; see [`query_rows`].
    pub query_rows: u32,
    pub payments: u32,
    pub tree: Tree,
    pub data_sha256: Hash,
}

/// Which table of a segment a session serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Directory,
    Companion,
}

impl Kind {
    /// The table kind's name in seeds and session IDs.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Directory => "directory",
            Kind::Companion => "companion",
        }
    }
}

/// What a session needs from either table's manifest.
pub trait Table {
    const KIND: Kind;
    /// Checks the manifest alone.
    fn validate(&self) -> Result<(), Error>;
    /// The immutable revision binding every field.
    fn revision(&self) -> Result<Hash, Error>;
    fn rows(&self) -> u32;
    /// The rows a query may be trimmed to; equal to [`Table::rows`] when it may not.
    fn query_rows(&self) -> u32;
}

/// Checks `schema`; another is [`Error::Unsupported`].
fn check_schema(schema: &str) -> Result<(), Error> {
    if schema != SCHEMA {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// A domain-separated hasher whose first input is the length-prefixed schema.
fn hasher(domain: &[u8], schema: &str) -> Sha256 {
    let mut h = Sha256::new();
    h.update(domain);
    h.update((schema.len() as u64).to_le_bytes());
    h.update(schema.as_bytes());
    h
}

impl Table for Directory {
    const KIND: Kind = Kind::Directory;

    /// Checks the schema, coverage and counts, and that the choice reference has
    /// one key per entry and the exact length that implies.
    fn validate(&self) -> Result<(), Error> {
        check_schema(&self.schema)?;
        self.coverage.validate()?;
        let (entries, payments) = (u64::from(self.entries), u64::from(self.payments));
        if self.payments > CAPACITY
            || entries > payments
            || payments > entries * u64::from(MAX_RECEIVER_PAYMENTS)
            || payments > self.coverage.end_position - self.coverage.start_position
            || self.choice.keys != self.entries
            || self.choice.bytes as usize != choice_bytes(self.entries)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn revision(&self) -> Result<Hash, Error> {
        self.validate()?;
        let mut h = hasher(b"ironwood-receiver/v2/directory\0", &self.schema);
        self.coverage.hash(&mut h);
        h.update(self.salt);
        h.update(self.entries.to_le_bytes());
        h.update(self.payments.to_le_bytes());
        h.update(self.choice.digest);
        h.update(self.choice.bytes.to_le_bytes());
        h.update(self.choice.keys.to_le_bytes());
        h.update(self.data_sha256);
        Ok(h.finalize().into())
    }

    fn rows(&self) -> u32 {
        DIRECTORY_ROWS
    }

    fn query_rows(&self) -> u32 {
        DIRECTORY_ROWS
    }
}

impl Table for Companion {
    const KIND: Kind = Kind::Companion;

    /// Checks the schema, coverage, geometry and tree bound, and that
    /// `query_rows` is the one [`query_rows`] gives for the occupied slots.
    fn validate(&self) -> Result<(), Error> {
        check_schema(&self.schema)?;
        self.coverage.validate()?;
        validate_companion_rows(self.rows)?;
        if u64::from(self.payments) > u64::from(self.rows) * u64::from(ROW_SLOTS)
            || self.query_rows != query_rows(self.payments)
            || self.query_rows > self.rows
            || self.tree.size > TREE_SIZE
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn revision(&self) -> Result<Hash, Error> {
        self.validate()?;
        let mut h = hasher(b"ironwood-receiver/v2/companion\0", &self.schema);
        self.coverage.hash(&mut h);
        h.update(self.directory);
        h.update(self.rows.to_le_bytes());
        h.update(self.query_rows.to_le_bytes());
        h.update(self.payments.to_le_bytes());
        h.update(self.tree.height.to_le_bytes());
        h.update(self.tree.hash);
        h.update(self.tree.size.to_le_bytes());
        h.update(self.data_sha256);
        Ok(h.finalize().into())
    }

    fn rows(&self) -> u32 {
        self.rows
    }

    fn query_rows(&self) -> u32 {
        self.query_rows
    }
}

impl Companion {
    /// Checks that this companion serves `directory`: the same network,
    /// correction and coverage, its revision, one slot per payment, and a tree
    /// at or after the coverage end that equals it at the same height.
    pub fn check_directory(&self, directory: &Directory) -> Result<(), Error> {
        self.validate()?;
        let c = &directory.coverage;
        let t = &self.tree;
        if self.coverage != *c
            || self.directory != directory.revision()?
            || self.payments != directory.payments
            || t.height < c.end_height
            || t.size < c.end_position
            || (t.height == c.end_height && (t.hash != c.end_hash || t.size != c.end_position))
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }
}

/// A table's PIR session: its manifest and the digest of its public setup.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session<M> {
    pub manifest: M,
    pub public_digest: Hash,
}

impl<M: Table> Session<M> {
    /// The session ID that pins every request: a domain-separated SHA-256 of
    /// the table kind, the revision and the public setup digest.
    pub fn id(&self) -> Result<Hash, Error> {
        let mut h = hasher(b"ironwood-receiver-pir/v2/session\0", M::KIND.label());
        h.update(self.manifest.revision()?);
        h.update(self.public_digest);
        Ok(h.finalize().into())
    }
}

/// One segment as an inventory lists it: its directory and companion sessions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub directory: Session<Directory>,
    pub companion: Session<Companion>,
}

impl Publication {
    /// Checks both manifests, that the companion serves the directory, and the
    /// serialized size, at most [`MAX_MANIFEST_BYTES`].
    pub fn validate(&self) -> Result<(), Error> {
        self.directory.manifest.validate()?;
        self.companion
            .manifest
            .check_directory(&self.directory.manifest)?;
        if serde_json::to_vec(self)?.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// Decodes a fetched choice object, refusing one whose digest, length or key
/// count differs from `directory`'s reference. Any seed is accepted.
pub fn decode_choice(directory: &Directory, bytes: &[u8]) -> Result<ChoiceTable, Error> {
    let r = &directory.choice;
    if bytes.len() != r.bytes as usize || Hash::from(Sha256::digest(bytes)) != r.digest {
        return Err(Error::Malformed);
    }
    let table = ChoiceTable::decode(bytes, SeedPolicy::Any).map_err(|_| Error::Malformed)?;
    if table.keys() != r.keys {
        return Err(Error::Malformed);
    }
    Ok(table)
}

/// The entry for `tag` in a privately retrieved directory row, checked against
/// `directory`'s counts and coverage. `None` means the segment pays no receiver
/// with this tag.
pub fn lookup_entry(directory: &Directory, row: &[u8], tag: &Tag) -> Result<Option<Entry>, Error> {
    let c = &directory.coverage;
    let found = decode_row(row)?.into_iter().find(|e| e.tag == *tag);
    if found.is_some_and(|e| {
        e.slots().end > directory.payments || e.last > c.end_height - c.start_height
    }) {
        return Err(Error::Malformed);
    }
    Ok(found)
}

/// Checks a record against the entry whose slot `slot` it was read from: it
/// hashes to the entry's tag, its page, total and ordinal are the slot's, it
/// lies in the coverage, and its height is at most the entry's last height,
/// equal to it on the last page. A caller still compares the receiver.
pub fn check_record(
    directory: &Directory,
    entry: &Entry,
    slot: u32,
    record: &RawRecord,
) -> Result<(), Error> {
    let c = &directory.coverage;
    let page = slot
        .checked_sub(entry.first)
        .filter(|p| *p < u32::from(entry.count));
    let last = c.start_height.checked_add(entry.last);
    let height = record.payment.height;
    if page != Some(record.page)
        || tag(&directory.salt, &record.receiver) != entry.tag
        || record.total != u32::from(entry.count)
        || record.ordinal != slot
        || !c.contains(&record.payment)
        || last
            .is_none_or(|last| height > last || (record.page + 1 == record.total && height != last))
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// The record and structurally checked payload in slot `slot` of a privately
/// retrieved companion row, checked against `entry` with [`check_record`].
pub fn lookup_slot(
    directory: &Directory,
    companion: &Companion,
    entry: &Entry,
    slot: u32,
    row: &[u8],
) -> Result<(RawRecord, [u8; wire::PAYLOAD_BYTES]), Error> {
    let at = (slot % ROW_SLOTS) as usize * SLOT_BYTES;
    if row.len() != ROW_BYTES || slot >= companion.payments {
        return Err(Error::Malformed);
    }
    let (record, payload) = decode_slot(&row[at..at + SLOT_BYTES])?.ok_or(Error::Malformed)?;
    check_record(directory, entry, slot, &record)?;
    wire::decode_payload(&payload, record.payment.position, companion.tree.size)
        .map_err(|_| Error::Malformed)?;
    Ok((record, payload))
}

/// A directory, its rows and its choice object.
#[derive(Clone)]
pub struct DirectoryTable {
    pub manifest: Directory,
    pub data: Vec<u8>,
    pub choice: Vec<u8>,
}

impl DirectoryTable {
    /// Checks the whole directory: digest and length, the choice object, every
    /// row's encoding, every entry routed by the choice to the row holding it,
    /// distinct tags, and extents that tile the payments in tag order. Returns
    /// the entries in tag order.
    pub fn validate(&self) -> Result<Vec<Entry>, Error> {
        let m = &self.manifest;
        m.validate()?;
        if self.data.len() != DIRECTORY_ROWS as usize * ROW_BYTES
            || Hash::from(Sha256::digest(&self.data)) != m.data_sha256
        {
            return Err(Error::Malformed);
        }
        let choice = decode_choice(m, &self.choice)?;
        let mut entries = Vec::with_capacity(m.entries as usize);
        for (row, bytes) in self.data.as_chunks::<ROW_BYTES>().0.iter().enumerate() {
            for entry in decode_row(bytes)? {
                if choose_row(&m.salt, &choice, &entry.tag) != row as u32
                    || entries.len() == m.entries as usize
                {
                    return Err(Error::Malformed);
                }
                entries.push(entry);
            }
        }
        entries.sort_unstable_by_key(|e| e.tag);
        let span = m.coverage.end_height - m.coverage.start_height;
        let mut next = 0u32;
        for (i, e) in entries.iter().enumerate() {
            if e.first != next || e.last > span || (i > 0 && entries[i - 1].tag == e.tag) {
                return Err(Error::Malformed);
            }
            next += u32::from(e.count);
        }
        if entries.len() != m.entries as usize || next != m.payments {
            return Err(Error::Malformed);
        }
        Ok(entries)
    }
}

/// A companion and its rows.
#[derive(Clone)]
pub struct CompanionTable {
    pub manifest: Companion,
    pub data: Vec<u8>,
}

impl CompanionTable {
    /// Checks the whole companion against its directory and that directory's
    /// `entries` from [`DirectoryTable::validate`]: the S1.7 binding, digest and
    /// length, zero rows past `query_rows` and zero slots past the payments,
    /// every record and payload by [`lookup_slot`], and across the segment
    /// complete page runs, unique outputs and positions, and one block hash per
    /// height and one transaction per `(height, tx_index)`, whichever
    /// receivers the records pay.
    pub fn validate(&self, directory: &Directory, entries: &[Entry]) -> Result<(), Error> {
        let m = &self.manifest;
        m.check_directory(directory)?;
        let query_end = m.query_rows as usize * ROW_BYTES;
        if self.data.len() != m.rows as usize * ROW_BYTES
            || Hash::from(Sha256::digest(&self.data)) != m.data_sha256
            || self.data[query_end..].iter().any(|b| *b != 0)
        {
            return Err(Error::Malformed);
        }
        let rows = self.data[..query_end].as_chunks::<ROW_BYTES>().0;
        let mut pages = Vec::with_capacity(m.payments as usize);
        let mut identities = Identities::default();
        for entry in entries {
            for slot in entry.slots() {
                let (record, _) =
                    lookup_slot(directory, m, entry, slot, &rows[slot_row(slot) as usize])?;
                identities.add(&record.payment)?;
                pages.push(PageMeta::from(&record));
            }
        }
        let occupied = rows.iter().enumerate().all(|(row, bytes)| {
            let used = (m.payments.saturating_sub(row as u32 * ROW_SLOTS)).min(ROW_SLOTS);
            bytes[used as usize * SLOT_BYTES..].iter().all(|b| *b == 0)
        });
        if pages.len() != m.payments as usize || !occupied {
            return Err(Error::Malformed);
        }
        check_pages(pages)
    }
}

/// The block and transaction identities a segment's records have named so far.
#[derive(Default)]
struct Identities {
    blocks: HashMap<u32, Hash>,
    transactions: HashMap<(u32, u32), Hash>,
    locations: HashMap<Hash, (u32, u32)>,
}

impl Identities {
    /// Records `p`'s block and transaction, refusing a second block hash at
    /// one height, a second txid at one `(height, tx_index)`, or one txid at
    /// two locations.
    fn add(&mut self, p: &Payment) -> Result<(), Error> {
        let at = (p.height, p.tx_index);
        let consistent = *self.blocks.entry(p.height).or_insert(p.block_hash) == p.block_hash
            && *self.transactions.entry(at).or_insert(p.txid) == p.txid
            && *self.locations.entry(p.txid).or_insert(at) == at;
        consistent.then_some(()).ok_or(Error::Malformed)
    }
}
