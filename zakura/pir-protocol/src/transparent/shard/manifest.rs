//! What a shard publishes about itself, and how it is named.
//!
//! A shard's identity is the digest of its own canonical manifest, and the
//! directory holding it must be named by that digest. Recomputing the digest on
//! load is what makes a manifest edited after publication a load failure rather
//! than a shard served under the identity of the one it replaced.
//!
//! The manifest binds everything a consumer needs to decide whether the bytes
//! it received are the bytes that were published: the chain, the range, the
//! geometry, and a digest per segment of each table. It does not, and cannot,
//! establish that the indexer included every event — that stays a separate
//! trust decision.
//!
//! # Directory shards and their page shards
//!
//! A shard is a *directory shard*: one directory table over its whole range,
//! and up to [`crate::transparent::shard::layout::MAX_PAGE_CHILDREN`] page shards, each its own
//! table over a consecutive part of the range. The manifest lists the page
//! shards as [`PageChild`] entries. The directory shard is the only lineage:
//! revisions, staleness and routing are per directory shard, and a page
//! shard is addressed as the table `pages-<j>` of a directory shard revision.
//! A sealed page shard never changes, so it appears unchanged in every later
//! revision of its directory shard, and its [`PageChild::digest`] is stable.
//!
//! # Revisions
//!
//! A shard is *open* while it is being built, which is not a published state.
//! What is published is either a **provisional** revision of a tail — immutable
//! under its own digest, expected to be superseded by a revision covering more
//! blocks — or a **sealed** shard, which is final and is the only kind that
//! enters the parent-digest chain. Superseding publishes a new digest beside
//! the old one rather than changing bytes under one that has been served.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Identifies the layout this manifest describes.
///
/// An opaque string, refused rather than guessed at: a shard whose entry or
/// page encoding changed would decode to plausible nonsense instead of failing.
pub const SCHEMA: &str = "transparent-shard-v12";
pub fn supported_schema(schema: &str) -> bool {
    schema == SCHEMA
}

/// The table name a query addresses for page shard `child`.
pub fn pages_table(child: u32) -> String {
    format!("pages-{child}")
}

/// The page shard a `pages-<j>` table name addresses, or `None` for any
/// other name. Leading zeros and signs are refused, so one table has one name.
pub fn parse_pages_table(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("pages-")?;
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.len() > 1 && digits.starts_with('0')
    {
        return None;
    }
    let child: u32 = digits.parse().ok()?;
    (child < crate::transparent::shard::layout::MAX_PAGE_CHILDREN).then_some(child)
}

/// Geometry and digest of one table.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TableGeometry {
    pub rows: u64,
    pub row_bytes: u32,
    /// SHA-256 of the table file, in hex.
    pub sha256: String,
}

/// What a shard actually holds. Published so an operator's boundary can be
/// checked against the seal parameters rather than taken on trust.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManifestOccupancy {
    pub scripts: u64,
    /// Page rows across every page shard, after packing.
    pub page_rows: u64,
    /// Fragments across every run in every page shard, which is what a
    /// wallet's page queries count. Larger than `page_rows`, because short
    /// runs share rows.
    pub fragments: u64,
    pub events: u64,
    pub blocks: u64,
    /// Distinct transaction ids in supported script histories. Display coverage
    /// is counted separately because it also includes unindexed raw scripts.
    pub txids: u64,
    /// Scripts present in the filter but absent from the directory because they
    /// exceed `max_script_bytes`.
    ///
    /// A wallet holding such a script is outside coverage and must not read a
    /// directory miss as absence. Publishing the count makes the gap a measured
    /// quantity rather than a silent one.
    pub excluded_scripts: u64,
}

/// The pinned geometry, restated per shard.
///
/// Redundant with the schema by design. A consumer checks these against its own
/// constants before decoding anything, so a build that changed a width fails
/// loudly at the first shard instead of returning misaligned records.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManifestLayout {
    pub max_script_bytes: u32,
    pub inline_events: u32,
    /// Decoder bound on events in a fragment, not a fixed full-fragment count.
    pub events_per_page: u32,
    /// Bytes at the head of a page row, before its first entry.
    pub page_row_header_bytes: u32,
    /// Bytes of header on each entry within a page row. Event widths and the
    /// greedy fragmentation rule are fixed by the shard schema.
    pub page_entry_header_bytes: u32,
    pub directory_choices: u32,
}

impl ManifestLayout {
    pub fn current() -> Self {
        Self {
            max_script_bytes: crate::transparent::shard::MAX_SCRIPT_BYTES as u32,
            inline_events: crate::transparent::shard::INLINE_EVENTS,
            events_per_page: crate::transparent::shard::EVENTS_PER_PAGE,
            page_row_header_bytes: crate::transparent::shard::PAGE_ROW_HEADER_BYTES as u32,
            page_entry_header_bytes: crate::transparent::shard::PAGE_ENTRY_HEADER_BYTES as u32,
            directory_choices: crate::transparent::shard::choice::DIRECTORY_CHOICES as u32,
        }
    }
}

/// Seal parameters, as schema rather than tuning.
///
/// The directory limits close the directory shard; the page-row limits close
/// each page shard inside it; `max_page_children` closes the directory shard
/// with its last page shard.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManifestSeal {
    pub scripts_target: u64,
    pub scripts_capacity: u64,
    pub directory_bytes_target: u64,
    pub directory_bytes_capacity: u64,
    pub page_rows_target: u64,
    pub page_rows_capacity: u64,
    pub max_page_children: u32,
}

/// What one page shard holds.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PageChildOccupancy {
    /// Page rows the page shard's table holds, after packing.
    pub page_rows: u64,
    /// Fragments across every run it holds.
    pub fragments: u64,
    /// Scripts with a run in it.
    pub runs: u64,
    /// Events pushed into it.
    pub events: u64,
}

/// One page shard of a directory shard.
///
/// Its tags are salted with [`crate::transparent::shard::tag::page_tag_salt`] over its own end
/// height and terminal block, never the directory shard's, so a sealed page
/// shard keeps its bytes while the directory shard around it grows.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PageChild {
    /// Position `j` within the directory shard; the table is `pages-<j>`.
    pub index: u32,
    pub start_height: u64,
    pub end_height: u64,
    /// The block at `end_height`, in display hex.
    pub terminal_block_hash: String,
    /// Counter mixed into this page shard's tag salt.
    pub tag_salt_counter: u32,
    /// False only for the page shard still open in a tail revision.
    pub sealed: bool,
    /// One entry per segment, in segment order. Empty when the page shard
    /// holds no rows: nothing can point into it, so nothing is queried.
    pub page_segments: Vec<TableGeometry>,
    pub occupancy: PageChildOccupancy,
}

/// Domain for a page shard's identity.
pub const PAGE_CHILD_DOMAIN: &[u8] = b"transparent-shard-page-child-v1\0";

impl PageChild {
    /// Rows a query of this page shard selects over.
    ///
    /// For a page shard in one segment, the rows it holds rounded up to whole
    /// [`QUERY_ROW_QUANTUM`] blocks: page rows are written from row zero and
    /// every later row is zero, so the selection coefficients a wallet omits
    /// cannot change the answer. Sealed or open alike, since a sealed page
    /// shard's rows are fixed. A multi-segment page shard's query, which every
    /// segment answers, selects over each whole segment. Only digest-bound
    /// fields decide it, so wallet and server derive the same count, and it
    /// never depends on the row a query selects.
    pub fn query_rows(&self) -> u64 {
        let full = self.page_segments.first().map_or(0, |segment| segment.rows);
        if self.page_segments.len() != 1 {
            return full;
        }
        self.occupancy
            .page_rows
            .max(1)
            .next_multiple_of(QUERY_ROW_QUANTUM)
            .min(full)
    }

    /// This page shard's identity, chained to everything before it.
    ///
    /// `previous` is the identity of page shard `index - 1`, or for page shard
    /// zero the identity of the directory shard's position: its shard id,
    /// start, parent block and parent manifest. Chaining is what lets a wallet
    /// treat a cached run as final: equal identities mean this page shard and
    /// every older one in the directory shard are unchanged, so nothing a run
    /// points back to can have moved.
    pub fn digest(&self, previous: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PAGE_CHILD_DOMAIN);
        hasher.update(previous);
        hasher.update(serde_json::to_vec(self).expect("a page child serializes"));
        hasher.finalize().into()
    }
}

/// One shard's complete public description.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ShardManifest {
    pub schema: String,
    /// The range filter profile, distinct from the per-block one.
    ///
    /// Not the table geometry: this string is keyed into the shard's filter and
    /// into its directory bucket salt, and it names the *filter* profile. The
    /// geometry has its own field below, and confusing the two would silently
    /// change where a script hashes to.
    pub profile: String,
    /// The table geometry this shard was built at, by registry name.
    ///
    /// A set may mix them — archive geometry for old history, a narrower recent
    /// geometry for the window wallets synchronise constantly — so a consumer
    /// cannot infer one shard's shape from another's. The name selects one
    /// validated parameter set; the per-segment `rows` and `row_bytes` below
    /// remain, and are checked against it, so a manifest that named one shape
    /// and published another is refused rather than served.
    pub geometry: String,
    pub network: String,
    /// Chain identity, in display hex.
    pub genesis_hash: String,
    pub shard_id: u64,
    pub start_height: u64,
    pub end_height: u64,
    /// The block before `start_height`, in display hex.
    pub parent_block_hash: String,
    /// The block at `end_height`, in display hex.
    pub terminal_block_hash: String,
    /// Counter mixed into the script-tag salt.
    ///
    /// Starts at 0. The builder increments it only when a tag collision
    /// forces a rebuild. Bound by the manifest digest. The wallet recomputes
    /// the salt from `shard_id`, `terminal_block_hash` and this counter.
    pub tag_salt_counter: u32,
    /// Digest of the preceding shard's manifest, or empty for shard zero.
    ///
    /// This is what makes the shard set a committed sequence rather than a bag
    /// of independently published ranges: a consumer can walk it and see that
    /// nothing was substituted or omitted between two shards it accepts.
    pub parent_manifest_digest: String,
    /// False for the tail, whose published form is a provisional revision.
    ///
    /// A consumer may use a provisional revision for a current balance, but the
    /// coverage it takes from one is provisional: recorded with this manifest's
    /// digest, never cached as immutable, and re-derived when a later revision
    /// or the sealed shard appears.
    pub sealed: bool,
    /// Which published revision of this shard this manifest describes.
    ///
    /// Zero for a shard published once. A tail's revision advances each time it
    /// is republished with more blocks; sealing is the last such publication.
    pub revision: u32,
    /// Digest of the revision this one supersedes, or empty for the first.
    ///
    /// A wallet holding the superseded revision can see that what it covered
    /// has been replaced rather than extended, and re-derive rather than merge.
    pub supersedes: String,
    pub seal: ManifestSeal,
    pub layout: ManifestLayout,
    /// Double-SHA-256 of the serialized filter bytes, in display hex.
    pub filter_hash: String,
    /// One entry per directory segment, in segment order.
    ///
    /// Ordinarily one. More means this shard's content did not fit a single
    /// segment of the pinned geometry, and the digest binds the whole list, so
    /// a shard cannot gain, lose or reorder a segment without becoming a
    /// different shard.
    pub directory_segments: Vec<TableGeometry>,
    /// The page shards, in order: consecutive ranges tiling this shard's.
    ///
    /// Every page shard but the last is sealed; the last is sealed when this
    /// shard is. A directory entry names one of these by index.
    pub page_children: Vec<PageChild>,
    pub occupancy: ManifestOccupancy,
    /// The shard's directory choice table, base64 encoded, if it publishes one.
    ///
    /// Which of each placed script's two candidate rows holds it (see
    /// [`crate::transparent::shard::choice`]). A wallet that reads it sends one directory query per
    /// matched script instead of two; the rows themselves are the same
    /// two-choice rows either way. Absent, it is not serialized, so every
    /// manifest published before it keeps its bytes and its digest, and a set
    /// published without tables is served to old and new consumers alike.
    ///
    /// Present, it is **not** backward compatible. A consumer built before
    /// this field parses the manifest, drops the field it does not know, and
    /// recomputes the digest from what remains, which no longer matches. Such
    /// a wallet stops with a digest mismatch and such a server refuses to load
    /// the shard. Every server and wallet must understand this field before any
    /// publication carries it.
    ///
    /// Bound by the manifest digest like everything else here. A consumer that
    /// reads it must decode it with [`crate::transparent::shard::choice::ChoiceTable::decode`],
    /// check its key count against `occupancy.scripts`, and refuse the shard
    /// if either fails, rather than fall back to two queries: a table that does
    /// not decode is a malformed publication, not an absent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_choice: Option<String>,
}

/// Why a published choice table cannot be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DirectoryChoiceError {
    #[error("directory choice is not base64: {0}")]
    Encoding(String),
    #[error("directory choice: {0}")]
    Table(#[from] crate::transparent::shard::choice::ChoiceError),
    #[error("directory choice indexes {table} scripts where the shard places {placed}")]
    Keys { table: u32, placed: u64 },
}

impl ShardManifest {
    /// The published choice table, decoded and checked against this manifest.
    ///
    /// `Ok(None)` when the shard publishes none, which means two directory
    /// queries per matched script. Any published table that does not decode,
    /// or whose key count is not the shard's placed script count, is an error.
    pub fn directory_choice(
        &self,
    ) -> Result<Option<crate::transparent::shard::choice::ChoiceTable>, DirectoryChoiceError> {
        use base64::Engine;
        let Some(encoded) = &self.directory_choice else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| DirectoryChoiceError::Encoding(error.to_string()))?;
        let table = crate::transparent::shard::choice::ChoiceTable::decode(&bytes)?;
        if u64::from(table.keys()) != self.occupancy.scripts {
            return Err(DirectoryChoiceError::Keys {
                table: table.keys(),
                placed: self.occupancy.scripts,
            });
        }
        Ok(Some(table))
    }

    /// The page shard `child`, if the shard declares it.
    pub fn child(&self, child: u32) -> Option<&PageChild> {
        self.page_children.get(child as usize)
    }

    /// The chained identity of every page shard, in order; see
    /// [`PageChild::digest`].
    pub fn child_digests(&self) -> Vec<[u8; 32]> {
        let mut previous: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(PAGE_CHILD_DOMAIN);
            hasher.update(self.shard_id.to_le_bytes());
            hasher.update(self.start_height.to_le_bytes());
            hasher.update(self.parent_block_hash.as_bytes());
            hasher.update(b"\0");
            hasher.update(self.parent_manifest_digest.as_bytes());
            hasher.finalize().into()
        };
        self.page_children
            .iter()
            .map(|child| {
                previous = child.digest(&previous);
                previous
            })
            .collect()
    }

    /// Checks the page shard list against the shard: contiguous ranges tiling
    /// the shard's, indices in order, at most `max_page_children`, every one
    /// sealed but an open last one of an unsealed shard, the last ending on
    /// the shard's terminal block, rows consistent with segments, and every
    /// segment shaped `page_rows` x `page_row_bytes`.
    pub fn check_children(&self, page_rows: u64, page_row_bytes: u32) -> Result<(), String> {
        let children = &self.page_children;
        if children.is_empty() {
            return Err("declares no page shards".into());
        }
        if children.len() as u64 > u64::from(self.seal.max_page_children)
            || children.len() as u64
                > u64::from(crate::transparent::shard::layout::MAX_PAGE_CHILDREN)
        {
            return Err(format!("declares {} page shards", children.len()));
        }
        let mut next = self.start_height;
        for (index, child) in children.iter().enumerate() {
            let last = index + 1 == children.len();
            if child.index != index as u32 {
                return Err(format!("page shard {index} is numbered {}", child.index));
            }
            if child.start_height != next
                || child.end_height < child.start_height
                || child.end_height > self.end_height
            {
                return Err(format!("page shard {index} does not continue the range"));
            }
            if last {
                if child.end_height != self.end_height {
                    return Err("page shards do not cover the shard's range".into());
                }
            } else {
                next = child
                    .end_height
                    .checked_add(1)
                    .ok_or_else(|| format!("page shard {index} range has no successor"))?;
            }
            if !child.sealed && (!last || self.sealed) {
                return Err(format!("page shard {index} is open"));
            }
            if child.tag_salt_counter > crate::transparent::shard::tag::MAX_TAG_SALT_COUNTER {
                return Err(format!("page shard {index} tag salt counter"));
            }
            for segment in &child.page_segments {
                if segment.rows != page_rows || segment.row_bytes != page_row_bytes {
                    return Err(format!("page shard {index} segment shape"));
                }
            }
            let capacity = (child.page_segments.len() as u64)
                .checked_mul(page_rows)
                .ok_or_else(|| format!("page shard {index} capacity overflows"))?;
            if child.occupancy.page_rows > capacity
                || (child.occupancy.page_rows == 0) != child.page_segments.is_empty()
                || child.page_segments.len() > 1
                    && child.occupancy.page_rows <= capacity - page_rows
            {
                return Err(format!(
                    "page shard {index} rows disagree with its segments"
                ));
            }
            if last && child.terminal_block_hash != self.terminal_block_hash {
                return Err("the last page shard does not end on the shard's terminal".into());
            }
        }
        let rows = children
            .iter()
            .try_fold(0u64, |sum, c| sum.checked_add(c.occupancy.page_rows))
            .ok_or("page shard row total overflows")?;
        let fragments = children
            .iter()
            .try_fold(0u64, |sum, c| sum.checked_add(c.occupancy.fragments))
            .ok_or("page shard fragment total overflows")?;
        if rows != self.occupancy.page_rows || fragments != self.occupancy.fragments {
            return Err("page shard occupancy disagrees with the shard's".into());
        }
        Ok(())
    }
}

/// Pages queries select over whole blocks of this many rows: the native ring
/// degree.
pub const QUERY_ROW_QUANTUM: u64 = 2048;

/// The manifest field for a choice table.
pub fn encode_directory_choice(table: &crate::transparent::shard::choice::ChoiceTable) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(table.encode())
}

/// Binds a private query to the revision and table it names.
///
/// Carried in a fixed-width prefix of every query body and echoed in every
/// response. The revision is already public — it is in the map and in the
/// request path — so this discloses nothing; what it buys is that a query
/// routed to the wrong revision, or a response returned from one, fails a
/// check instead of decoding into plausible rows from a range the wallet never
/// asked about.
///
/// Eight bytes because it is a consistency check, not an authenticator: the
/// server has already matched the full digest from the path, and both ends
/// re-derive this from data they hold. Fixed width, so it leaks nothing about
/// the selection.
pub fn query_binding(manifest_digest: &str, table: &str) -> [u8; 8] {
    query_binding_for_schema(SCHEMA, manifest_digest, table)
}

pub fn query_binding_for_schema(schema: &str, manifest_digest: &str, table: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(schema.as_bytes());
    hasher.update(b"/query-binding\0");
    hasher.update(manifest_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(table.as_bytes());
    let digest = hasher.finalize();
    digest[..8].try_into().expect("eight bytes")
}

/// What a shard id already has published, as the publisher reads it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedRevision {
    pub digest: String,
    pub revision: u32,
    pub supersedes: String,
    pub sealed: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevisionError {
    #[error("shard {0} is sealed; a sealed shard's content cannot change")]
    SealedChanged(u64),
}

impl PublishedRevision {
    /// The revision numbering a publication of this shard takes.
    ///
    /// `reproduced` says whether rebuilding under the published numbering
    /// produced the published digest — whether this is the same shard being
    /// published again, or a tail that has grown since.
    ///
    /// Republishing something identical must reproduce the identity it already
    /// has, or an idempotent re-run over the same journal would publish the
    /// same content under a second digest and the map would name the new one.
    /// A tail that has grown takes the next revision and records what it
    /// supersedes. A *sealed* shard whose content changed is neither: sealed
    /// shards are immutable, so that is an error rather than a revision.
    pub fn next(
        shard_id: u64,
        previous: Option<&PublishedRevision>,
        reproduced: bool,
    ) -> Result<(u32, String), RevisionError> {
        match previous {
            None => Ok((0, String::new())),
            Some(previous) if reproduced => Ok((previous.revision, previous.supersedes.clone())),
            Some(previous) if previous.sealed => Err(RevisionError::SealedChanged(shard_id)),
            Some(previous) => Ok((previous.revision + 1, previous.digest.clone())),
        }
    }
}

impl ShardManifest {
    /// The canonical bytes this manifest digests to.
    ///
    /// Field order is the struct's declaration order, which serde preserves, so
    /// the encoding is stable without needing a separate canonicalization pass.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a manifest serializes")
    }

    /// The shard's identity: the digest of its canonical bytes.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ShardManifest {
        ShardManifest {
            schema: SCHEMA.to_string(),
            profile: "zcash-transparent-range-v1".to_string(),
            geometry: "decoupled-2k-8k".to_string(),
            network: "main".to_string(),
            genesis_hash: "00".repeat(32),
            shard_id: 3,
            start_height: 3_428_143,
            end_height: 3_430_000,
            parent_block_hash: "11".repeat(32),
            terminal_block_hash: "22".repeat(32),
            tag_salt_counter: 0,
            parent_manifest_digest: "33".repeat(32),
            sealed: true,
            revision: 0,
            supersedes: String::new(),
            seal: ManifestSeal {
                scripts_target: 8_192,
                scripts_capacity: 16_384,
                directory_bytes_target: 7_000_000,
                directory_bytes_capacity: 8_000_000,
                page_rows_target: 2_048,
                page_rows_capacity: 4_096,
                max_page_children: 32,
            },
            layout: ManifestLayout {
                max_script_bytes: 40,
                inline_events: 2,
                events_per_page: crate::transparent::shard::EVENTS_PER_PAGE,
                page_row_header_bytes: 4,
                page_entry_header_bytes: 40,
                directory_choices: 2,
            },
            filter_hash: "44".repeat(32),
            directory_segments: vec![TableGeometry {
                rows: 2_048,
                row_bytes: 4_096,
                sha256: "55".repeat(32),
            }],
            page_children: vec![
                child(0, 3_428_143, 3_429_000, "77", 1_000, 1_500),
                child(1, 3_429_001, 3_430_000, "22", 879, 1_704),
            ],
            occupancy: ManifestOccupancy {
                scripts: 8_193,
                page_rows: 1_879,
                fragments: 3_204,
                events: 39_088,
                blocks: 1_858,
                txids: 10_355,
                excluded_scripts: 0,
            },
            directory_choice: None,
        }
    }

    fn child(
        index: u32,
        start_height: u64,
        end_height: u64,
        terminal: &str,
        page_rows: u64,
        fragments: u64,
    ) -> PageChild {
        PageChild {
            index,
            start_height,
            end_height,
            terminal_block_hash: terminal.repeat(32),
            tag_salt_counter: 0,
            sealed: true,
            page_segments: vec![TableGeometry {
                rows: 4_096,
                row_bytes: 4_096,
                sha256: format!("{:02x}", 0x66 + index).repeat(32),
            }],
            occupancy: PageChildOccupancy {
                page_rows,
                fragments,
                runs: 10,
                events: 20,
            },
        }
    }

    fn published(revision: u32, sealed: bool) -> PublishedRevision {
        PublishedRevision {
            digest: "aa".repeat(32),
            revision,
            supersedes: if revision == 0 {
                String::new()
            } else {
                "bb".repeat(32)
            },
            sealed,
        }
    }

    /// A page shard in one segment selects over whole blocks covering every
    /// row it holds, sealed or open; a multi-segment one over whole segments.
    #[test]
    fn a_single_segment_page_shard_selects_a_prefix() {
        let mut page = manifest().page_children[1].clone();
        for sealed in [true, false] {
            page.sealed = sealed;
            for (page_rows, rows) in [
                (0, 2_048),
                (1, 2_048),
                (1_879, 2_048),
                (2_048, 2_048),
                (2_049, 4_096),
                (4_096, 4_096),
            ] {
                page.occupancy.page_rows = page_rows;
                assert_eq!(page.query_rows(), rows, "{page_rows}");
            }
        }
        page.occupancy.page_rows = 1_879;
        let mut segmented = page.clone();
        segmented
            .page_segments
            .push(segmented.page_segments[0].clone());
        assert_eq!(segmented.query_rows(), 4_096);
        segmented.page_segments.clear();
        assert_eq!(segmented.query_rows(), 0);
    }

    #[test]
    fn a_pages_table_has_one_name() {
        assert_eq!(pages_table(0), "pages-0");
        assert_eq!(pages_table(31), "pages-31");
        assert_eq!(parse_pages_table("pages-0"), Some(0));
        assert_eq!(parse_pages_table("pages-31"), Some(31));
        for bad in [
            "pages",
            "pages-",
            "pages-01",
            "pages-+1",
            "pages-32",
            "pages--1",
            "directory",
        ] {
            assert_eq!(parse_pages_table(bad), None, "{bad}");
        }
    }

    /// The page shard list must tile the directory shard, in order, with only
    /// an unsealed shard's last page shard open.
    #[test]
    fn page_children_must_tile_the_shard() {
        manifest().check_children(4_096, 4_096).unwrap();
        type Mutation = Box<dyn Fn(&mut ShardManifest)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|m| m.page_children.clear()),
            Box::new(|m| m.page_children[1].index = 2),
            Box::new(|m| m.page_children[1].start_height += 1),
            Box::new(|m| m.page_children[1].end_height -= 1),
            Box::new(|m| m.page_children[0].sealed = false),
            Box::new(|m| m.page_children[1].sealed = false),
            Box::new(|m| m.page_children[1].terminal_block_hash = "99".repeat(32)),
            Box::new(|m| m.page_children[0].page_segments.clear()),
            Box::new(|m| m.page_children[0].occupancy.page_rows = 5_000),
            Box::new(|m| m.page_children[0].page_segments[0].rows = 8_192),
            Box::new(|m| m.occupancy.fragments += 1),
            Box::new(|m| m.seal.max_page_children = 1),
            Box::new(|m| m.page_children[0].tag_salt_counter = 99),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut changed = manifest();
            mutate(&mut changed);
            assert!(
                changed.check_children(4_096, 4_096).is_err(),
                "mutation {index} was accepted"
            );
        }
        // The last page shard of a tail may be open, and an empty one has no
        // segments.
        let mut tail = manifest();
        tail.sealed = false;
        tail.page_children[1].sealed = false;
        tail.check_children(4_096, 4_096).unwrap();
        tail.page_children[1].page_segments.clear();
        tail.occupancy.page_rows -= tail.page_children[1].occupancy.page_rows;
        tail.page_children[1].occupancy.page_rows = 0;
        tail.check_children(4_096, 4_096).unwrap();
    }

    #[test]
    fn page_children_reject_endpoints_outside_the_shard() {
        let mut changed = manifest();
        changed.page_children[0].end_height = u64::MAX;
        changed.page_children[1].start_height = 0;
        assert!(changed.check_children(4_096, 4_096).is_err());
    }

    #[test]
    fn page_children_can_end_at_the_largest_height() {
        let mut changed = manifest();
        changed.end_height = u64::MAX;
        changed.page_children[1].end_height = u64::MAX;
        changed.check_children(4_096, 4_096).unwrap();
    }

    #[test]
    fn page_children_reject_overflowing_fragment_totals() {
        let mut changed = manifest();
        changed.page_children[0].occupancy.fragments = u64::MAX;
        changed.page_children[1].occupancy.fragments = 1;
        changed.occupancy.fragments = 0;
        assert!(changed.check_children(4_096, 4_096).is_err());
    }

    /// A page shard's identity chains through every older one and the
    /// directory shard's position, and ignores the directory shard's own
    /// growth: a sealed page shard keeps its identity across revisions.
    #[test]
    fn page_shard_identities_chain_and_survive_tail_growth() {
        let base = manifest();
        let digests = base.child_digests();
        assert_eq!(digests.len(), 2);
        assert_ne!(digests[0], digests[1]);

        let mut grown = base.clone();
        grown.revision += 1;
        grown.end_height += 5;
        grown.terminal_block_hash = "88".repeat(32);
        grown.directory_segments[0].sha256 = "99".repeat(32);
        grown.page_children[1].end_height += 5;
        grown.page_children[1].terminal_block_hash = "88".repeat(32);
        let regrown = grown.child_digests();
        assert_eq!(regrown[0], digests[0], "the sealed page shard is unchanged");
        assert_ne!(regrown[1], digests[1]);

        let mut moved = base.clone();
        moved.page_children[0].page_segments[0].sha256 = "aa".repeat(32);
        let moved = moved.child_digests();
        assert_ne!(moved[0], digests[0]);
        assert_ne!(
            moved[1], digests[1],
            "a change below moves every identity above"
        );

        for mutate in [
            |m: &mut ShardManifest| m.shard_id += 1,
            |m: &mut ShardManifest| m.start_height += 1,
            |m: &mut ShardManifest| m.parent_block_hash = "aa".repeat(32),
            |m: &mut ShardManifest| m.parent_manifest_digest = "aa".repeat(32),
        ] {
            let mut other = base.clone();
            mutate(&mut other);
            assert_ne!(other.child_digests()[0], digests[0]);
        }
    }

    /// A first publication supersedes nothing.
    /// A manifest without a choice table serializes exactly as manifests did
    /// before the field existed, so no published digest moves; one with a
    /// table round-trips and is a different shard.
    #[test]
    fn an_absent_choice_table_leaves_the_canonical_bytes_unchanged() {
        let plain = manifest();
        let bytes = plain.canonical_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("\"directory_choice\""));
        let parsed: ShardManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.directory_choice, None);
        assert_eq!(parsed.digest(), plain.digest());

        let mut tabled = plain.clone();
        tabled.occupancy.scripts = 1;
        tabled.directory_choice = Some(encode_directory_choice(
            &crate::transparent::shard::choice::ChoiceTable::build(3, &[(&[0x51][..], 1)]).unwrap(),
        ));
        let parsed: ShardManifest = serde_json::from_slice(&tabled.canonical_bytes()).unwrap();
        assert_eq!(parsed, tabled);
        assert!(parsed.directory_choice().unwrap().is_some());
        assert_ne!(tabled.digest(), plain.digest());
    }

    #[test]
    fn a_shard_published_for_the_first_time_is_revision_zero() {
        assert_eq!(
            PublishedRevision::next(3, None, false).unwrap(),
            (0, String::new())
        );
    }

    /// Re-running over the same journal must reproduce the identity already
    /// published, not publish the same content again under a new digest.
    #[test]
    fn republishing_the_same_shard_keeps_its_revision() {
        let previous = published(2, false);
        assert_eq!(
            PublishedRevision::next(3, Some(&previous), true).unwrap(),
            (2, previous.supersedes.clone())
        );
    }

    /// A tail that has grown is a new revision beside the old one, recording
    /// what it replaces so a wallet can tell replacement from extension.
    #[test]
    fn a_grown_tail_takes_the_next_revision_and_names_its_predecessor() {
        let previous = published(2, false);
        assert_eq!(
            PublishedRevision::next(3, Some(&previous), false).unwrap(),
            (3, previous.digest.clone())
        );
    }

    /// Sealed shards are immutable. Content that disagrees with a sealed shard
    /// is a build or journal fault, and publishing it as a revision would hide
    /// that behind a version number.
    #[test]
    fn a_sealed_shard_whose_content_changed_is_refused() {
        let previous = published(1, true);
        assert_eq!(
            PublishedRevision::next(3, Some(&previous), false),
            Err(RevisionError::SealedChanged(3))
        );
    }

    #[test]
    fn a_manifest_round_trips_through_its_canonical_bytes() {
        let original = manifest();
        let decoded: ShardManifest =
            serde_json::from_slice(&original.canonical_bytes()).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn the_digest_is_stable_across_encodings() {
        assert_eq!(manifest().digest(), manifest().digest());
        assert_eq!(manifest().digest().len(), 64);
    }

    /// Every field must reach the digest. A field that fell out of it could be
    /// changed after publication without changing the shard's identity, which
    /// is exactly what naming the directory by the digest is meant to prevent.
    #[test]
    fn changing_any_field_changes_the_identity() {
        let base = manifest().digest();
        type Mutation = Box<dyn Fn(&mut ShardManifest)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|m| m.shard_id += 1),
            Box::new(|m| m.start_height += 1),
            Box::new(|m| m.end_height += 1),
            Box::new(|m| m.parent_block_hash = "99".repeat(32)),
            Box::new(|m| m.terminal_block_hash = "99".repeat(32)),
            Box::new(|m| m.parent_manifest_digest = "99".repeat(32)),
            Box::new(|m| m.sealed = false),
            Box::new(|m| m.revision += 1),
            Box::new(|m| m.supersedes = "99".repeat(32)),
            Box::new(|m| m.filter_hash = "99".repeat(32)),
            Box::new(|m| m.directory_segments[0].sha256 = "99".repeat(32)),
            Box::new(|m| m.page_children[0].page_segments[0].sha256 = "99".repeat(32)),
            Box::new(|m| m.page_children[1].tag_salt_counter += 1),
            Box::new(|m| m.page_children[1].occupancy.runs += 1),
            Box::new(|m| m.seal.max_page_children += 1),
            Box::new(|m| m.seal.directory_bytes_target += 1),
            Box::new(|m| m.directory_segments[0].rows += 1),
            // A shard cannot gain a segment without becoming a different
            // shard: the segment list is what a wallet asks every segment of.
            Box::new(|m| {
                let extra = m.directory_segments[0].clone();
                m.directory_segments.push(extra);
            }),
            Box::new(|m| {
                let extra = m.page_children[0].page_segments[0].clone();
                m.page_children[0].page_segments.push(extra);
            }),
            Box::new(|m| {
                m.page_children.pop();
            }),
            Box::new(|m| m.seal.scripts_target += 1),
            Box::new(|m| m.layout.inline_events += 1),
            Box::new(|m| m.occupancy.scripts += 1),
            Box::new(|m| m.occupancy.fragments += 1),
            Box::new(|m| m.layout.page_entry_header_bytes += 1),
            Box::new(|m| m.layout.page_row_header_bytes += 1),
            Box::new(|m| m.occupancy.excluded_scripts += 1),
            Box::new(|m| m.genesis_hash = "99".repeat(32)),
            Box::new(|m| m.profile = "other".to_string()),
        ];
        for mutate in mutations {
            let mut changed = manifest();
            mutate(&mut changed);
            assert_ne!(
                changed.digest(),
                base,
                "a mutation did not change the digest"
            );
        }
    }
}
