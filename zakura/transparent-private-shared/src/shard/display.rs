//! Time-tiered, hash-bucketed txid display tables (proof of concept).
//!
//! A display publication is its own sequence of shards, independent of the
//! history shards: sealed archive shards that are built once, and one recent
//! shard covering the tip that is rebuilt as blocks arrive. Inside a shard,
//! every entry belongs to exactly one bucket, `H(domain, tag) mod N`, and each
//! bucket is a separate native table of fixed-size entries, so a lookup scans
//! and downloads only its own bucket. Inside that table an entry has exactly
//! one row, chosen by a hash keyed with the bucket's published placement
//! seed, and a lookup is always exactly one query for that row.
//!
//! The entry codec and row format are the ones in [`crate::shard::txid`]; only
//! placement, table identity and the manifest are here. The bucket a lookup
//! names, the tier its shard belongs to, the range and timing are disclosed
//! to the server; with fixed-size entries nothing about the transaction's
//! size is.

pub mod geometry;
pub mod manifest;
pub mod seal;
pub mod split;

pub use geometry::{display_by_name, DISPLAY_PROFILES, TXID_2K8, TXID_4K8};
pub use manifest::{
    DisplayBucket, DisplayLayout, DisplayManifest, DisplayMap, DisplayMapEntry, ManifestHeader,
};
pub use seal::DisplaySealParams;
pub use split::{
    chunk_base, DisplayChunkRef, DisplayIndexChunk, DisplayRecentMap, INDEX_CHUNK_SHARDS,
};

use crate::shard::layout::Geometry;
use crate::shard::txid::Tag;
use sha2::{Digest, Sha256};

/// Identifies the display shard layout: one bucketed table of fixed-size
/// entries per bucket, each entry in the one row its seeded hash names, with
/// the `txid` entry codec inside.
pub const DISPLAY_SCHEMA: &str = "transparent-txid-display-shard-v3";
/// Domain of the bucket hash. Shard-independent, so an entry's bucket is the
/// same whichever shard its height selects.
pub const BUCKET_DOMAIN: &[u8] = b"transparent-txid-display/bucket/v2";
/// Upper bound on buckets per shard; a decoder bound, not a target.
pub const MAX_BUCKETS: u32 = 64;
/// The native profile and setup seeds of every display table are derived
/// under this name, display's own and independent of the history schema, so
/// history schema changes never move display's native parameters.
/// `/v2/txid/init` publishes it as its `native_schema`.
///
/// It names the 8-bit profile display tables are served with. The 16-bit
/// one-query tables were derived under `transparent-shard-v11`; a client
/// pinned to that name sees this one as unsupported rather than failing to
/// re-derive the 8-bit scheme.
pub const NATIVE_SCHEMA: &str = "transparent-txid-display-p8-v1";

/// The bucket of the entry tagged `tag` among `n_buckets`.
pub fn bucket(tag: &Tag, n_buckets: u32) -> u32 {
    assert!(n_buckets > 0, "a shard has at least one bucket");
    let digest = Sha256::new()
        .chain_update(BUCKET_DOMAIN)
        .chain_update(tag.0)
        .finalize();
    (u64::from_le_bytes(digest[..8].try_into().unwrap()) % u64::from(n_buckets)) as u32
}

/// Domain of the row hash. Short enough that the whole hash input, 51 bytes,
/// is one SHA-256 block: the publisher hashes every tag once per seed tried.
pub const PLACEMENT_DOMAIN: &[u8] = b"txid-display/row/v3";
/// Placement seeds a publisher tries per bucket, `0..MAX_PLACEMENT_SEEDS`.
/// The smallest seed that leaves no row over capacity is kept; when none
/// does, the bucket overflows into further segments (see [`tables`]).
pub const MAX_PLACEMENT_SEEDS: u32 = 64;

/// The one row of the entry tagged `tag` in its bucket's table, under the
/// bucket's placement seed.
pub fn placement_row(tag: &Tag, seed: u32, shard_id: u64, bucket: u32, rows: u64) -> u64 {
    let digest = Sha256::new()
        .chain_update(PLACEMENT_DOMAIN)
        .chain_update(seed.to_le_bytes())
        .chain_update(shard_id.to_le_bytes())
        .chain_update(bucket.to_le_bytes())
        .chain_update(tag.0)
        .finalize();
    u64::from_le_bytes(digest[..8].try_into().unwrap()) % rows
}

/// One private table of a display shard: the entries of one bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DisplayTable {
    Directory(u32),
}

impl DisplayTable {
    /// Wire and binding name: `directory-{b}`.
    pub fn label(&self) -> String {
        match self {
            Self::Directory(bucket) => format!("directory-{bucket}"),
        }
    }

    /// Parses a canonical label; leading zeros and out-of-range buckets are
    /// refused so one table never has two names.
    pub fn parse(label: &str) -> Option<Self> {
        let digits = label.strip_prefix("directory-")?;
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return None;
        }
        let bucket: u32 = digits.parse().ok()?;
        (bucket < MAX_BUCKETS).then_some(Self::Directory(bucket))
    }

    /// Segment file name inside a revision directory.
    pub fn file_name(&self, segment: usize) -> String {
        format!("{}.{segment}.bin", self.label())
    }

    pub fn bucket(&self) -> u32 {
        match self {
            Self::Directory(bucket) => *bucket,
        }
    }

    /// The native table kind this table is served as.
    pub fn kind(&self) -> DisplayKind {
        DisplayKind::TxDirectory
    }
}

/// The history table kind whose native parameters a display table uses. Seeds
/// are derived from the history schema, this kind's name and the display
/// geometry's name; rows and row width are the display geometry's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DisplayKind {
    TxDirectory,
}

impl DisplayKind {
    /// The history table name, which the native seeds are derived from.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TxDirectory => "txdirectory",
        }
    }

    /// Rows in one segment of this table, at `geometry`.
    pub fn rows(self, geometry: &Geometry) -> u64 {
        geometry.directory_rows
    }

    /// Bytes in one row of this table, at `geometry`.
    pub fn row_bytes(self, geometry: &Geometry) -> u32 {
        geometry.directory_row_bytes as u32
    }
}

/// The published seed a native table's public query setup is derived from,
/// for the table named `table` (history or display kind) of `geometry_name`.
///
/// Distinct per geometry *and* per table. The two tables of one geometry have
/// different row counts, so their public parameters already differ; two
/// geometries have different row counts again. Deriving the seed from both
/// names means a client that mixed any of them up fails its own re-derivation
/// check rather than decoding a row against the wrong table's setup — which
/// would not error, it would return plausible nonsense.
///
/// Domain-separated by the history schema string, so a future schema reusing
/// these names does not reuse their seeds.
pub fn setup_seed_named(geometry_name: &str, table: &str) -> u64 {
    setup_seed_in(crate::shard::manifest::SCHEMA, geometry_name, table)
}

/// [`setup_seed_named`] under `schema`: the history schema for history
/// tables, [`NATIVE_SCHEMA`] for display tables.
pub fn setup_seed_in(schema: &str, geometry_name: &str, table: &str) -> u64 {
    let digest = Sha256::new()
        .chain_update(schema.as_bytes())
        .chain_update(b"/setup-seed\0")
        .chain_update(geometry_name.as_bytes())
        .chain_update(b"\0")
        .chain_update(table.as_bytes())
        .finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

/// The setup seed of a display table kind at `geometry`, as `/v2/txid/init`
/// publishes it: derived under [`NATIVE_SCHEMA`], whatever history's schema.
pub fn setup_seed(geometry: &Geometry, kind: DisplayKind) -> u64 {
    setup_seed_in(NATIVE_SCHEMA, geometry.name, kind.as_str())
}

/// Binds a query to one revision and one table, buckets included, so a body
/// prepared for one bucket is refused by another bucket's runtime.
pub fn query_binding(manifest_digest: &str, table: DisplayTable) -> [u8; 8] {
    crate::shard::manifest::query_binding_for_schema(
        DISPLAY_SCHEMA,
        manifest_digest,
        &table.label(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Txid;

    #[test]
    fn labels_round_trip_and_are_canonical() {
        for table in [
            DisplayTable::Directory(0),
            DisplayTable::Directory(7),
            DisplayTable::Directory(MAX_BUCKETS - 1),
        ] {
            assert_eq!(DisplayTable::parse(&table.label()), Some(table));
        }
        for bad in [
            "directory-",
            "directory-01",
            "directory-+1",
            "directory-64",
            "directory--1",
            "txdirectory",
            "pages",
        ] {
            assert_eq!(DisplayTable::parse(bad), None, "{bad}");
        }
        assert_eq!(DisplayTable::Directory(3).file_name(1), "directory-3.1.bin");
    }

    /// Seeds are published by every running server; they must never move.
    #[test]
    fn setup_seeds_are_golden() {
        assert_eq!(
            setup_seed(&TXID_2K8, DisplayKind::TxDirectory),
            0x0571_b2f6_02b0_0dbd
        );
        assert_eq!(DisplayTable::Directory(5).kind(), DisplayKind::TxDirectory);
    }

    #[test]
    fn binding_separates_buckets_and_revisions() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let t0 = DisplayTable::Directory(0);
        let t1 = DisplayTable::Directory(1);
        assert_ne!(query_binding(&a, t0), query_binding(&a, t1));
        assert_ne!(query_binding(&a, t0), query_binding(&b, t0));
        // Distinct from the history binding of the same digest and label.
        assert_ne!(
            query_binding(&a, t0),
            crate::shard::manifest::query_binding(&a, "directory-0")
        );
    }

    #[test]
    fn buckets_are_balanced_and_shard_independent() {
        let n = 4;
        let mut counts = [0u32; 4];
        for i in 0u32..40_000 {
            let tag = Tag::of(&Txid(Sha256::digest(i.to_le_bytes()).into()));
            counts[bucket(&tag, n) as usize] += 1;
        }
        // Binomial(40,000, 1/4): sigma is about 87; five sigma either way.
        for count in counts {
            assert!((10_000 - 435..=10_000 + 435).contains(&count), "{counts:?}");
        }
        let tag = Tag::of(&Txid([9; 32]));
        assert_eq!(bucket(&tag, 1), 0);
    }

    /// The row moves with every input: seed, shard, bucket and tag.
    #[test]
    fn placement_depends_on_seed_shard_bucket_and_tag() {
        let tag = Tag::of(&Txid([9; 32]));
        let other = Tag::of(&Txid([10; 32]));
        let row = placement_row(&tag, 0, 3, 1, 2048);
        assert!(row < 2048);
        // Any one input changing moves most rows; count over many tags.
        let moved = |f: &dyn Fn(&Tag) -> (u64, u64)| {
            (0u32..256)
                .map(|i| Tag::of(&Txid(Sha256::digest(i.to_le_bytes()).into())))
                .filter(|t| {
                    let (a, b) = f(t);
                    a != b
                })
                .count()
        };
        let base = |t: &Tag| placement_row(t, 0, 3, 1, 2048);
        assert!(moved(&|t| (base(t), placement_row(t, 1, 3, 1, 2048))) > 250);
        assert!(moved(&|t| (base(t), placement_row(t, 0, 4, 1, 2048))) > 250);
        assert!(moved(&|t| (base(t), placement_row(t, 0, 3, 2, 2048))) > 250);
        assert_ne!(row, placement_row(&other, 0, 3, 1, 2048));
        // Golden: clients and publishers must agree on every row.
        assert_eq!(placement_row(&tag, 0, 3, 1, 2048), 54);
        // One SHA-256 block: at most 55 bytes before the padding.
        assert!(PLACEMENT_DOMAIN.len() + 4 + 8 + 4 + 16 <= 55);
    }
}
