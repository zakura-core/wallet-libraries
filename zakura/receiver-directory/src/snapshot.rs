//! Immutable publications: manifests, row placement and row decoding.
use crate::{
    filter::{self, Filter, Filters},
    record, Error, Hash, RawRecord, ReceiverBytes, RECORD_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The directory format a manifest commits to.
pub const PROFILE: &str = "ironwood-zero-ovk-receiver-v1";
/// Bytes per row. Unused trailing bytes are zero.
pub const ROW_BYTES: usize = 4096;
/// Records per row.
pub const SLOTS: usize = ROW_BYTES / RECORD_BYTES;
/// Smallest supported row count, which the PIR client, server and indexer enforce.
/// Publications start here and double.
pub const MIN_ROWS: u32 = 8192;
/// Largest supported row count.
pub const MAX_ROWS: u32 = 65536;
/// Leaves in a full depth-32 note commitment tree, the largest valid note position
/// end. The last leaf's position is one less.
pub const TREE_SIZE: u64 = 1 << 32;

/// The record slots in a table of `rows` rows. A row count that is not a power of two
/// up to [`MAX_ROWS`] is [`Error::Malformed`]. Smaller tables than [`MIN_ROWS`] are
/// accepted here, for tests; publishers and clients enforce the floor.
pub fn capacity(rows: u32) -> Result<u64, Error> {
    if !rows.is_power_of_two() || rows > MAX_ROWS {
        return Err(Error::Malformed);
    }
    Ok(u64::from(rows) * SLOTS as u64)
}

/// Coverage includes empty blocks and excludes coinbase recipients, not their note positions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub profile: String,
    pub genesis: Hash,
    pub start_height: u32,
    pub start_parent: Hash,
    pub start_position: u64,
    pub end_height: u32,
    pub end_hash: Hash,
    pub end_position: u64,
    pub rows: u32,
    pub salt: Hash,
    pub records: u64,
    pub data_sha256: Hash,
    /// The sets in the publication's [`Filters`] file, in label order.
    pub filters: Vec<FilterSet>,
    /// Commits to the publication's [`Filters`] file.
    pub filters_sha256: Hash,
    /// Commits to the publication's [`CatalogHead`](crate::catalog::CatalogHead), by
    /// its digest.
    pub catalog_sha256: Hash,
}

/// One labeled set in a publication's [`Filters`] file; see [`crate::filter`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterSet {
    /// [`filter::PAID`], or `<provider>/recent` or `<provider>/seen`.
    pub label: String,
    /// Distinct receivers in the set.
    pub count: u32,
    /// For a recent set, how far back the provider's swaps reach from `until_unix`, in
    /// seconds.
    pub window_secs: Option<u64>,
    /// For a provider set, when the provider's feed started, in Unix seconds. Receivers
    /// the provider was given earlier are missing from it.
    pub since_unix: Option<i64>,
    /// For a provider set, when the feed's last complete read of the provider began, in
    /// Unix seconds. Receivers the provider was given later are missing from it.
    pub until_unix: Option<i64>,
}

/// Receivers from a swap provider's feed for one labeled set; see [`FilterSet`].
pub struct ProviderSet {
    /// `<provider>/recent` or `<provider>/seen`.
    pub label: String,
    /// See [`FilterSet::window_secs`]; required for a recent set.
    pub window_secs: Option<u64>,
    /// See [`FilterSet::since_unix`].
    pub since_unix: i64,
    /// See [`FilterSet::until_unix`].
    pub until_unix: i64,
    pub receivers: Vec<ReceiverBytes>,
}

impl Manifest {
    /// Check the profile, coverage order and geometry bounds, at most [`MAX_ROWS`]
    /// rows.
    pub fn validate(&self) -> Result<(), Error> {
        let labels_ordered = self
            .filters
            .windows(2)
            .all(|pair| pair[0].label < pair[1].label);
        let sets_valid = self.filters.iter().all(|set| {
            let recent = set.label.ends_with(&format!("/{}", filter::RECENT));
            let span = match (set.since_unix, set.until_unix) {
                (Some(since), Some(until)) => set.label != filter::PAID && since <= until,
                (None, None) => set.label == filter::PAID,
                _ => false,
            };
            filter::valid_label(&set.label) && span && recent == set.window_secs.is_some()
        });
        if self.profile != PROFILE
            || !labels_ordered
            || !sets_valid
            || !self.filters.iter().any(|set| set.label == filter::PAID)
            || self.start_height > self.end_height
            || self.start_position > self.end_position
            || self.end_position > TREE_SIZE
            // Each record has its own note position in the covered span.
            || self.records > self.end_position - self.start_position
            || !capacity(self.rows).is_ok_and(|slots| self.records <= slots)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Checks that `filters` holds exactly the sets this manifest declares. Its bytes must
    /// already match [`Self::filters_sha256`].
    pub fn check_filters(&self, filters: &Filters) -> Result<(), Error> {
        let mut sets = filters.iter();
        for declared in &self.filters {
            match sets.next() {
                Some((label, set)) if label == declared.label && set.count() == declared.count => {}
                _ => return Err(Error::Malformed),
            }
        }
        if sets.next().is_some() {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Bind row data, coverage, network, geometry, filters and catalog into one
    /// immutable revision: a domain-separated SHA-256 of every field at fixed width,
    /// with strings and the set list length-prefixed and each optional value tagged, as
    /// Enhance and Status hash their manifests.
    pub fn revision(&self) -> Result<Hash, Error> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver/v1/manifest\0");
        update_str(&mut h, &self.profile);
        h.update(self.genesis);
        h.update(self.start_height.to_le_bytes());
        h.update(self.start_parent);
        h.update(self.start_position.to_le_bytes());
        h.update(self.end_height.to_le_bytes());
        h.update(self.end_hash);
        h.update(self.end_position.to_le_bytes());
        h.update(self.rows.to_le_bytes());
        h.update(self.salt);
        h.update(self.records.to_le_bytes());
        h.update(self.data_sha256);
        h.update((self.filters.len() as u64).to_le_bytes());
        for set in &self.filters {
            update_str(&mut h, &set.label);
            h.update(set.count.to_le_bytes());
            for value in [
                set.window_secs.map(u64::to_le_bytes),
                set.since_unix.map(i64::to_le_bytes),
                set.until_unix.map(i64::to_le_bytes),
            ] {
                match value {
                    Some(bytes) => {
                        h.update([1]);
                        h.update(bytes);
                    }
                    None => h.update([0]),
                }
            }
        }
        h.update(self.filters_sha256);
        h.update(self.catalog_sha256);
        Ok(h.finalize().into())
    }

    /// The caller supplies an independently accepted chain anchor and required history start.
    pub fn accept(&self, genesis: Hash, start: u32, height: u32, hash: Hash) -> Result<(), Error> {
        self.validate()?;
        if start > height
            || self.genesis != genesis
            || self.start_height > start
            || self.end_height != height
            || self.end_hash != hash
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }
}

/// Stable receiver identity; derivation index and purpose never leave the wallet.
fn receiver_tag(genesis: &Hash, receiver: &ReceiverBytes) -> Hash {
    let mut h = Sha256::new();
    h.update(b"ironwood-receiver/v1/tag\0");
    h.update(genesis);
    h.update(receiver);
    h.finalize().into()
}

/// This row number must be selected inside PIR, never in a public HTTP route.
pub fn row_for(manifest: &Manifest, receiver: &ReceiverBytes, page: u32) -> Result<usize, Error> {
    Ok(Placement::new(manifest)?.row(receiver, page))
}

/// Row placement in one validated manifest's table, so callers placing many records
/// validate the manifest once.
struct Placement {
    genesis: Hash,
    salt: Hash,
    mask: u32,
}

impl Placement {
    /// Validates `m` and keeps what placement reads from it.
    fn new(m: &Manifest) -> Result<Self, Error> {
        m.validate()?;
        Ok(Self {
            genesis: m.genesis,
            salt: m.salt,
            mask: m.rows - 1,
        })
    }

    /// The row holding `receiver`'s page `page`; see [`row_for`].
    fn row(&self, receiver: &ReceiverBytes, page: u32) -> usize {
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver/v1/bucket\0");
        h.update(self.salt);
        h.update(receiver_tag(&self.genesis, receiver));
        h.update(page.to_le_bytes());
        let digest = h.finalize();
        (u32::from_le_bytes(digest[..4].try_into().unwrap()) & self.mask) as usize
    }
}

/// A manifest and the row data and filters it commits to.
#[derive(Clone)]
pub struct Snapshot {
    pub manifest: Manifest,
    pub data: Vec<u8>,
    /// The encoded [`Filters`].
    pub filters: Vec<u8>,
}

impl Snapshot {
    /// More records than the table has slots, or bucket overflow, fails the whole
    /// candidate with [`Error::Capacity`]. It never drops records or coverage. A filter
    /// file over [`filter::MAX_FILTERS_BYTES`] is [`Error::Malformed`]. The paid filter
    /// holds the records' receivers; `provider` sets come from the publisher's swap
    /// provider feeds (see [`crate::filter`]).
    pub fn build(
        mut manifest: Manifest,
        records: &[RawRecord],
        provider: &[ProviderSet],
    ) -> Result<Self, Error> {
        manifest.records = records.len() as u64;
        if manifest.records > capacity(manifest.rows)? {
            return Err(Error::Capacity);
        }
        let filters = Filters::new(
            Filter::build(&manifest.salt, records.iter().map(|r| &r.receiver)),
            provider.iter().map(|set| {
                (
                    set.label.clone(),
                    Filter::build(&manifest.salt, &set.receivers),
                )
            }),
        )?;
        manifest.filters = filters
            .iter()
            .map(|(label, set)| {
                let declared = provider.iter().find(|p| p.label == label);
                FilterSet {
                    label: label.to_owned(),
                    count: set.count(),
                    window_secs: declared.and_then(|p| p.window_secs),
                    since_unix: declared.map(|p| p.since_unix),
                    until_unix: declared.map(|p| p.until_unix),
                }
            })
            .collect();
        let placement = Placement::new(&manifest)?;
        let mut data = vec![0; manifest.rows as usize * ROW_BYTES];
        let mut counts = vec![0; manifest.rows as usize];
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by_key(|r| (r.receiver, r.page));
        check_pages(sorted.iter().map(|&r| PageMeta::from(r)))?;
        for record in sorted {
            validate_location(&manifest, record)?;
            let row = placement.row(&record.receiver, record.page);
            if counts[row] == SLOTS {
                return Err(Error::Capacity);
            }
            let offset = row * ROW_BYTES + counts[row] * RECORD_BYTES;
            data[offset..offset + RECORD_BYTES].copy_from_slice(&record::encode(record)?);
            counts[row] += 1;
        }
        manifest.data_sha256 = Sha256::digest(&data).into();
        let filters = filters.encode()?;
        manifest.filters_sha256 = Sha256::digest(&filters).into();
        Ok(Self {
            manifest,
            data,
            filters,
        })
    }

    /// Checks a supplied publication whole, as [`Self::build`] would have made it.
    pub fn validate(&self) -> Result<(), Error> {
        let m = &self.manifest;
        let placement = Placement::new(m)?;
        if self.data.len() != m.rows as usize * ROW_BYTES
            || Hash::from(Sha256::digest(&self.data)) != m.data_sha256
            || Hash::from(Sha256::digest(&self.filters)) != m.filters_sha256
        {
            return Err(Error::Malformed);
        }
        let filters = Filters::decode(&self.filters)?;
        m.check_filters(&filters)?;
        let mut pages = Vec::new();
        for (row, bytes) in self.data.as_chunks::<ROW_BYTES>().0.iter().enumerate() {
            for record in row_records(m, &placement, row, bytes)? {
                if pages.len() as u64 == m.records {
                    return Err(Error::Malformed);
                }
                pages.push(PageMeta::from(&record));
            }
        }
        if pages.len() as u64 != m.records {
            return Err(Error::Malformed);
        }
        pages.sort_unstable_by_key(|p| (p.receiver, p.page));
        check_pages(pages.iter().copied())?;
        let paid = pages.iter().filter(|p| p.page == 0).map(|p| &p.receiver);
        if filters.get(filter::PAID) != Some(&Filter::build(&m.salt, paid)) {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// The fields of a [`RawRecord`] that [`check_pages`] reads, so validating a publication
/// need not hold its records whole.
#[derive(Clone, Copy)]
struct PageMeta {
    receiver: ReceiverBytes,
    page: u32,
    total: u32,
    position: u64,
    txid: Hash,
    action_index: u32,
    height: u32,
    tx_index: u32,
    block_hash: Hash,
}

impl From<&RawRecord> for PageMeta {
    /// Projects `r` onto the fields page checks read.
    fn from(r: &RawRecord) -> Self {
        Self {
            receiver: r.receiver,
            page: r.page,
            total: r.total,
            position: r.payment.position,
            txid: r.payment.txid,
            action_index: r.payment.action_index,
            height: r.payment.height,
            tx_index: r.payment.tx_index,
            block_hash: r.payment.block_hash,
        }
    }
}

impl PageMeta {
    /// Whether `next` can follow `self`; see [`check_next`].
    fn continues(&self, next: &Self) -> bool {
        let same_block = next.height == self.height;
        next.receiver == self.receiver
            && self.page.checked_add(1) == Some(next.page)
            && next.total == self.total
            && next.position > self.position
            && (next.height, next.tx_index, next.action_index)
                > (self.height, self.tx_index, self.action_index)
            && (!same_block || next.block_hash == self.block_hash)
            && (!same_block || next.tx_index != self.tx_index || next.txid == self.txid)
    }
}

/// Checks that `next` can follow `previous` as the same receiver's next page: the
/// same receiver and total, the next page number, a later note position, a later
/// output by height, transaction index and action index, the same block hash at the
/// same height, and the same txid in the same transaction.
pub fn check_next(previous: &RawRecord, next: &RawRecord) -> Result<(), Error> {
    if !PageMeta::from(previous).continues(&PageMeta::from(next)) {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Checks records sorted by receiver and page: every receiver has pages zero to its
/// total, each continuing the last as [`check_next`] requires, and no two records
/// share an output or note position. Beyond that uniqueness, different receivers'
/// records are not checked against each other: a wallet reads only its own pages.
fn check_pages(sorted: impl IntoIterator<Item = PageMeta>) -> Result<(), Error> {
    let mut previous: Option<PageMeta> = None;
    let mut outputs = BTreeSet::new();
    let mut positions = BTreeSet::new();
    for record in sorted {
        // Every advertised page must exist in this revision, in chain order.
        match previous {
            Some(p) if p.receiver == record.receiver => {
                if !p.continues(&record) {
                    return Err(Error::Malformed);
                }
            }
            p => {
                if record.page != 0 || p.is_some_and(|r| r.page + 1 != r.total) {
                    return Err(Error::Malformed);
                }
            }
        }
        previous = Some(record);
        if !outputs.insert((record.txid, record.action_index)) || !positions.insert(record.position)
        {
            return Err(Error::Malformed);
        }
    }
    if previous.is_some_and(|r| r.page + 1 != r.total) {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Rejects a record whose payment lies outside the manifest's blocks or positions, or
/// in a coinbase transaction, which the directory excludes.
fn validate_location(m: &Manifest, r: &RawRecord) -> Result<(), Error> {
    let p = &r.payment;
    if p.tx_index == 0
        || p.height < m.start_height
        || p.height > m.end_height
        || p.position < m.start_position
        || p.position >= m.end_position
        || (p.height == m.end_height && p.block_hash != m.end_hash)
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Decode a privately retrieved row from an accepted revision. None is scheme-scoped absence.
/// Subsequent pages must also repeat page zero's total before recovery can complete.
pub fn lookup_row(
    m: &Manifest,
    receiver: &ReceiverBytes,
    page: u32,
    bytes: &[u8],
) -> Result<Option<RawRecord>, Error> {
    let placement = Placement::new(m)?;
    let mut found = None;
    for record in row_records(m, &placement, placement.row(receiver, page), bytes)? {
        if &record.receiver == receiver && record.page == page {
            if found.is_some() {
                return Err(Error::Malformed);
            }
            found = Some(record);
        }
    }
    if page != 0 && found.is_none() {
        return Err(Error::MissingPage);
    }
    Ok(found)
}

/// Decodes the records in row `row` of `m`'s table, checking the row's length and zero
/// padding, and that each record lies within `m`'s coverage, has no more pages than
/// `m` has records, and belongs in this row by `placement`, made from `m`.
fn row_records(
    m: &Manifest,
    placement: &Placement,
    row: usize,
    bytes: &[u8],
) -> Result<Vec<RawRecord>, Error> {
    if bytes.len() != ROW_BYTES || bytes[SLOTS * RECORD_BYTES..].iter().any(|b| *b != 0) {
        return Err(Error::Malformed);
    }
    let mut records = Vec::new();
    for slot in bytes[..SLOTS * RECORD_BYTES].as_chunks::<RECORD_BYTES>().0 {
        if let Some(record) = record::decode(slot)? {
            validate_location(m, &record)?;
            // A receiver cannot have more pages than the publication has records.
            if u64::from(record.total) > m.records
                || placement.row(&record.receiver, record.page) != row
            {
                return Err(Error::Malformed);
            }
            records.push(record);
        }
    }
    Ok(records)
}

/// Hashes `value` with its length, so adjacent strings cannot run together.
fn update_str(h: &mut Sha256, value: &str) {
    h.update((value.len() as u64).to_le_bytes());
    h.update(value.as_bytes());
}
