//! JSON metadata shapes exchanged with the filter service.
//!
//! These live outside the `client` feature so the service can build its
//! responses from the same definitions a wallet parses, rather than the two
//! sides drifting apart in separate hand-written structs.
//!
//! Hashes appear here in display hex, because these are the human-facing
//! surfaces. Binary serialization uses internal order; see `envelope.rs`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Response shape of `GET /v1/filters/info`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FilterServiceInfo {
    /// Genesis block hash in display hex; the chain's identity.
    pub genesis_hash: String,
    pub network: String,
    pub profile: String,
    pub envelope_version: u16,
    /// First height this service publishes a filter for.
    pub start_height: u64,
    /// Highest height with durable coverage, if any.
    pub covered_through: Option<u64>,
    pub covered_block_hash: Option<String>,
    pub max_records_per_batch: u64,
    pub max_filter_bytes: usize,
}

/// Response shape of `GET /v1/health`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FilterServiceHealth {
    /// `syncing`, `serving` or `failed`.
    pub phase: String,
    pub detail: Option<String>,
    pub covered_through: Option<u64>,
    pub tip_height: Option<u64>,
    pub filters_stored: u64,
}

/// One entry of `GET /v1/filters/digests`.
///
/// The digest is derivable from filter bytes the caller already holds, so this
/// exists for the case where it does not hold them: comparing what different
/// operators publish for the same block without downloading both sets of
/// filters. Agreement across independent operators is evidence about
/// construction that a single operator's own digest cannot provide, since a
/// digest supplied alongside a false filter simply commits to the false filter.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FilterDigestEntry {
    pub height: u64,
    pub block_hash: String,
    /// Double-SHA-256 of the serialized filter bytes, in display hex.
    pub filter_hash: String,
}

/// One entry of `GET /v1/filters/chain`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChainEntry {
    pub height: u64,
    /// Display hex, as a human-facing JSON field.
    pub block_hash: String,
}

/// The seal thresholds a shard set was built under.
///
/// Part of the published map because they are schema, not tuning: a wallet that
/// cached shards built under different thresholds would be holding two
/// incompatible partitions of the same chain. Changing any of them re-shards.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SealParameters {
    /// Distinct scripts, which size the filter and the directory.
    pub max_scripts: u64,
    /// Page rows, which size the pages table. Not derivable from the event
    /// count: pages are per-script and padded, so many short histories cost far
    /// more rows than the same number of events in a few long ones.
    pub max_page_rows: u64,
    /// Distinct transaction ids, which size the transaction-detail table.
    pub max_txids: u64,
}

/// One entry of the published height-to-shard map.
///
/// Occupancy counts are published so a wallet — or an independent operator —
/// can check that a shard was sealed where the thresholds say it should have
/// been, rather than taking the boundary on trust.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ShardMapEntry {
    pub shard_id: u64,
    /// The table geometry this shard was built at, by registry name.
    ///
    /// In the map rather than only in the manifest because a wallet needs it
    /// *before* it fetches anything: the geometry decides which prepared
    /// parameter set to query with and the row count to split an index over, so
    /// a wallet that waited for the manifest would already have had to guess.
    pub geometry: String,
    pub start_height: u64,
    pub end_height: u64,
    /// The block before `start_height`, in display hex.
    pub parent_block_hash: String,
    /// The block at `end_height`, in display hex.
    pub terminal_block_hash: String,
    /// Double-SHA-256 of the shard's serialized filter bytes, in display hex.
    pub filter_hash: String,
    pub scripts: u64,
    pub page_rows: u64,
    pub txids: u64,
    /// Segments in the shard's directory table, and in its pages table.
    ///
    /// One apiece in the ordinary case. A shard whose content did not fit one
    /// segment of the pinned geometry holds more, and a wallet needs the counts
    /// before it can query: a row is addressed within the shard's whole logical
    /// row space, and every segment is asked, so the segment a script lands in
    /// is never named in a request.
    pub directory_segments: u32,
    pub page_segments: u32,
    /// Digest of the shard's manifest: the identity of *this revision* of it.
    ///
    /// A growing tail is republished as a new revision with its own digest, so
    /// this is what a wallet records alongside provisional coverage in order to
    /// notice that the range it covered has been superseded.
    pub manifest_digest: String,
    /// Which published revision of this shard the entry describes.
    ///
    /// Zero for a shard published once. A sealed shard's revision is final.
    pub revision: u32,
    /// False only for the tail, which is still growing toward a threshold.
    ///
    /// Coverage taken from an unsealed shard is provisional: it is recorded
    /// with `manifest_digest` and re-derived when a later revision, or the
    /// sealed shard, appears.
    pub sealed: bool,
}

/// Response shape of `GET /v2/filters/shards`.
///
/// This is protocol data, not a convenience index. Shard boundaries are derived
/// from chain content, so a wallet cannot recompute them arithmetically and an
/// operator must reproduce these boundaries rather than derive its own — which
/// is what keeps a disagreement about one event localized to one shard's
/// digests instead of shifting every later boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ShardMap {
    /// Genesis block hash in display hex; the chain's identity.
    pub genesis_hash: String,
    pub network: String,
    /// The range profile, distinct from the per-block profile.
    pub profile: String,
    pub range_envelope_version: u16,
    /// First height shard zero covers.
    pub start_height: u64,
    /// The seal thresholds each geometry in this set was built under, by
    /// geometry name.
    ///
    /// One entry per geometry the map uses, not one for the map: thresholds are
    /// derived from the row counts, so a set mixing archive and recent shards
    /// was sealed under two policies and publishing a single one would describe
    /// neither. A wallet checking that a shard sealed where it should have uses
    /// the entry its geometry names.
    pub seal: BTreeMap<String, SealParameters>,
    /// Ascending by `shard_id`, gapless, starting at zero.
    pub shards: Vec<ShardMapEntry>,
    /// Every re-cut this publication has made, oldest first.
    ///
    /// A re-cut rebuilds sealed history from some height up under other
    /// boundaries, typically merging sealed recent shards into a wider archive
    /// geometry. That renumbers every later shard and changes its digest, but
    /// not the chain, so a wallet that already covered those heights keeps
    /// what it holds. The declaration is what lets it tell an announced re-cut
    /// from a publisher silently rewriting sealed content. Declarations are
    /// never dropped, so a wallet offline across several re-cuts still
    /// recognizes the revisions it holds. Absent from a map that was never
    /// re-cut, which keeps such a map's bytes and digest unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recuts: Vec<Recut>,
}

/// One re-cut of a publication.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Recut {
    /// Strictly increasing across a map's re-cuts, from one.
    pub epoch: u32,
    /// First height whose shards changed. Below it the map is unchanged.
    pub from_height: u64,
    /// Every entry the map published at or above `from_height` before this
    /// re-cut, ascending, exactly as it was published: the re-cut shards, the
    /// sealed shards renumbered above them, and the tail.
    pub superseded: Vec<SupersededShard>,
}

/// A map entry a re-cut replaced, as the earlier map published it.
///
/// Only the fields a wallet holds about a revision it read: enough to match
/// its stored coverage, events and unfinished page work to the declaration
/// without trusting anything the current map says about them.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SupersededShard {
    /// The id it had. Manifests bind the id, so this only cross-checks the
    /// digest against what a wallet stored with it.
    pub shard_id: u64,
    pub geometry: String,
    pub start_height: u64,
    pub end_height: u64,
    pub terminal_block_hash: String,
    pub manifest_digest: String,
    pub revision: u32,
    /// False only for the tail the re-cut replaced.
    pub sealed: bool,
}

/// The most superseded entries a map may declare across all its re-cuts.
///
/// A declaration lists every entry a re-cut replaced and is kept forever, so
/// the list only grows. Sixty-five thousand entries is far more than any
/// publication will replace (the live sets hold well under a thousand
/// shards); the bound exists so a hostile map cannot make every wallet index,
/// store or scan an unbounded list.
pub const MAX_SUPERSEDED: usize = 65_536;

/// The highest block height a declaration may name. Zcash heights are 32-bit,
/// and wallets store them that way.
pub const MAX_DECLARED_HEIGHT: u64 = u32::MAX as u64;

impl ShardMap {
    /// Checks that this map is well formed and uses a supported range envelope
    /// and filter profile. Call before accepting publication identity, reporting
    /// coverage, or planning requests, including passes with no remaining work.
    /// Unknown versions and profiles are refused without interpreting their data.
    pub fn validate_supported(
        &self,
    ) -> Result<&'static crate::transparent::filter::profile::RangeProfile, String> {
        self.check_shape()?;
        self.check_supported_format()
    }

    /// Checks only the advertised envelope version and registered filter
    /// profile, independently of the number of shards or re-cut declarations.
    /// This is suitable for each batch after [`Self::validate_supported`] has
    /// admitted the whole map; it does not establish gapless map coverage.
    pub fn check_supported_format(
        &self,
    ) -> Result<&'static crate::transparent::filter::profile::RangeProfile, String> {
        if self.range_envelope_version
            != crate::transparent::filter::envelope::RANGE_ENVELOPE_VERSION
        {
            return Err(format!(
                "unsupported range envelope version {}",
                self.range_envelope_version
            ));
        }
        crate::transparent::filter::profile::range_profile(&self.profile)
            .ok_or_else(|| format!("unsupported shard filter profile {:?}", self.profile))
    }

    /// The revision a declared re-cut superseded under `digest`, if any.
    ///
    /// A scan of every declaration: for one lookup. Anything looking up many
    /// digests builds [`superseded_index`](Self::superseded_index) once.
    pub fn superseded(&self, digest: &str) -> Option<&SupersededShard> {
        self.recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .find(|shard| shard.manifest_digest == digest)
    }

    /// Every declared superseded revision, by manifest digest.
    ///
    /// `check_shape` refuses a digest declared twice, so on a checked map
    /// each digest names exactly one entry.
    pub fn superseded_index(&self) -> BTreeMap<&str, &SupersededShard> {
        self.recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .map(|shard| (shard.manifest_digest.as_str(), shard))
            .collect()
    }

    /// The newest re-cut's epoch; zero for a map never re-cut.
    pub fn recut_epoch(&self) -> u32 {
        self.recuts.last().map_or(0, |recut| recut.epoch)
    }

    /// The shard covering `height`, if the map covers it.
    ///
    /// Binary search rather than arithmetic: with content-sealed boundaries
    /// there is no width to divide by. This is how a wallet turns its birthday
    /// into the first shard it must sync.
    pub fn shard_for_height(&self, height: u64) -> Option<&ShardMapEntry> {
        let index = self
            .shards
            .binary_search_by(|shard| {
                if shard.end_height < height {
                    std::cmp::Ordering::Less
                } else if shard.start_height > height {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;
        self.shards.get(index)
    }

    /// Checks the map is internally well formed before anything is fetched.
    ///
    /// A wallet that skipped this could sync a map with a hole in it and treat
    /// the result as complete coverage. Height continuity is checked here;
    /// binding the hashes to the wallet's accepted chain needs wallet state and
    /// belongs to `check_range_batch`.
    pub fn check_shape(&self) -> Result<(), String> {
        if self.shards.is_empty() {
            return Err("shard map is empty".into());
        }
        if self.shards[0].start_height != self.start_height {
            return Err(format!(
                "shard 0 starts at {} but the map starts at {}",
                self.shards[0].start_height, self.start_height
            ));
        }
        for (index, shard) in self.shards.iter().enumerate() {
            if shard.shard_id != index as u64 {
                return Err(format!(
                    "shard at position {index} claims id {}",
                    shard.shard_id
                ));
            }
            if shard.end_height < shard.start_height {
                return Err(format!("shard {index} ends before it starts"));
            }
            // A shard with no segment has no table to query, and a wallet that
            // accepted one would advance coverage over a range it never read.
            if shard.directory_segments == 0 || shard.page_segments == 0 {
                return Err(format!("shard {index} declares no segments"));
            }
            // A geometry with no published thresholds is a shard whose
            // boundary cannot be checked, and one with no name is a shard whose
            // rows a wallet would have to guess at.
            if shard.geometry.is_empty() {
                return Err(format!("shard {index} names no geometry"));
            }
            if !self.seal.contains_key(&shard.geometry) {
                return Err(format!(
                    "shard {index} is {} but the map publishes no seal parameters for it",
                    shard.geometry
                ));
            }
            if !is_digest(&shard.manifest_digest) {
                return Err(format!(
                    "shard {index} has no manifest digest to identify its revision"
                ));
            }
            if let Some(previous) = index.checked_sub(1).and_then(|i| self.shards.get(i)) {
                if previous.end_height.checked_add(1) != Some(shard.start_height) {
                    return Err(format!(
                        "shard {index} starts at {} but shard {} ends at {}",
                        shard.start_height, previous.shard_id, previous.end_height
                    ));
                }
                // The hash chain is what makes a gap detectable at all. Heights
                // alone would accept a map whose shards were built over two
                // different branches, since both would still be contiguous.
                if shard.parent_block_hash != previous.terminal_block_hash {
                    return Err(format!(
                        "shard {} does not chain to shard {}",
                        shard.shard_id, previous.shard_id
                    ));
                }
                // A sealed shard after an unsealed one would mean the tail was
                // published out of order, and the wallet would have no way to
                // tell which of the two is current.
                if !previous.sealed {
                    return Err(format!(
                        "shard {} follows unsealed shard {}",
                        shard.shard_id, previous.shard_id
                    ));
                }
            }
        }
        self.check_recuts()
    }

    /// Checks the re-cut declarations against each other and against the map.
    ///
    /// What a wallet relies on when it keeps history across a re-cut: that the
    /// revisions it holds are named exactly once, that none of them is still
    /// published, and that every shard the re-cut renumbered took a revision
    /// above the one it replaced, so a revision only ever rises within a
    /// geometry and start height. Every field is also checked for the form a
    /// wallet stores it in, so a malformed declaration is refused here rather
    /// than wherever a wallet first tries to use it, and no arithmetic on a
    /// hostile value can overflow.
    fn check_recuts(&self) -> Result<(), String> {
        let total: usize = self.recuts.iter().map(|recut| recut.superseded.len()).sum();
        if total > MAX_SUPERSEDED {
            return Err(format!(
                "the map declares {total} superseded entries, more than {MAX_SUPERSEDED}"
            ));
        }
        let mut epoch = 0u32;
        let mut digests = std::collections::BTreeSet::new();
        let published: std::collections::BTreeSet<&str> = self
            .shards
            .iter()
            .map(|shard| shard.manifest_digest.as_str())
            .collect();
        // The revision each published geometry and start height carries.
        let current: BTreeMap<(&str, u64), u32> = self
            .shards
            .iter()
            .map(|entry| {
                (
                    (entry.geometry.as_str(), entry.start_height),
                    entry.revision,
                )
            })
            .collect();
        for recut in &self.recuts {
            if recut.epoch <= epoch {
                return Err(format!(
                    "re-cut epoch {} does not rise above {epoch}",
                    recut.epoch
                ));
            }
            epoch = recut.epoch;
            if recut.from_height > MAX_DECLARED_HEIGHT {
                return Err(format!(
                    "re-cut {} starts at {}, above any block height",
                    recut.epoch, recut.from_height
                ));
            }
            let Some(first) = recut.superseded.first() else {
                return Err(format!("re-cut {} supersedes nothing", recut.epoch));
            };
            if first.start_height != recut.from_height {
                return Err(format!(
                    "re-cut {} starts at {} but supersedes from {}",
                    recut.epoch, recut.from_height, first.start_height
                ));
            }
            let last = recut.superseded.len() - 1;
            for (index, shard) in recut.superseded.iter().enumerate() {
                if shard.end_height < shard.start_height || shard.end_height > MAX_DECLARED_HEIGHT {
                    return Err(format!(
                        "re-cut {} supersedes a shard whose range {}..={} is no block range",
                        recut.epoch, shard.start_height, shard.end_height
                    ));
                }
                if let Some(previous) = index.checked_sub(1).map(|i| &recut.superseded[i]) {
                    if previous.end_height.checked_add(1) != Some(shard.start_height)
                        || previous.shard_id.checked_add(1) != Some(shard.shard_id)
                    {
                        return Err(format!(
                            "re-cut {} supersedes shards that do not follow one another",
                            recut.epoch
                        ));
                    }
                }
                // Only the last entry of the earlier map can have been its tail.
                if !shard.sealed && index != last {
                    return Err(format!(
                        "re-cut {} supersedes unsealed shard {} before its last",
                        recut.epoch, shard.shard_id
                    ));
                }
                if !is_digest(&shard.manifest_digest) {
                    return Err(format!(
                        "re-cut {} supersedes shard {} without a manifest digest",
                        recut.epoch, shard.shard_id
                    ));
                }
                if !is_digest(&shard.terminal_block_hash) {
                    return Err(format!(
                        "re-cut {} supersedes shard {} without a terminal block hash",
                        recut.epoch, shard.shard_id
                    ));
                }
                if published.contains(shard.manifest_digest.as_str()) {
                    return Err(format!(
                        "re-cut {} supersedes {} but the map still publishes it",
                        recut.epoch, shard.manifest_digest
                    ));
                }
                if !digests.insert(shard.manifest_digest.as_str()) {
                    return Err(format!("{} is superseded twice", shard.manifest_digest));
                }
                if !self.seal.contains_key(&shard.geometry) {
                    return Err(format!(
                        "re-cut {} supersedes a {} shard but the map publishes no seal \
                         parameters for it",
                        recut.epoch, shard.geometry
                    ));
                }
                if current
                    .get(&(shard.geometry.as_str(), shard.start_height))
                    .is_some_and(|revision| *revision <= shard.revision)
                {
                    return Err(format!(
                        "shard at {} keeps its geometry across re-cut {} without a higher \
                         revision",
                        shard.start_height, recut.epoch
                    ));
                }
            }
        }
        // Only the newest re-cut is still a boundary of the current map; a later
        // re-cut may have merged across an older one's starting height.
        if let Some(recut) = self.recuts.last() {
            if self
                .shard_for_height(recut.from_height)
                .is_none_or(|shard| shard.start_height != recut.from_height)
            {
                return Err(format!(
                    "re-cut {} starts at {}, which is no shard boundary of this map",
                    recut.epoch, recut.from_height
                ));
            }
        }
        Ok(())
    }
}

/// Sixty-four lowercase hex digits, the form digests and block hashes are
/// published and stored in.
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(tag: u64) -> String {
        format!("{tag:064x}")
    }

    fn hash(height: u64) -> String {
        format!("{:064x}", height + 1)
    }

    fn entry(
        id: u64,
        geometry: &str,
        start: u64,
        end: u64,
        revision: u32,
        sealed: bool,
    ) -> ShardMapEntry {
        ShardMapEntry {
            shard_id: id,
            geometry: geometry.into(),
            start_height: start,
            end_height: end,
            parent_block_hash: hash(start - 1),
            terminal_block_hash: hash(end),
            filter_hash: digest(0),
            scripts: 1,
            page_rows: 1,
            txids: 1,
            directory_segments: 1,
            page_segments: 1,
            // Distinct for every field a revision differs in.
            manifest_digest: digest(
                (u64::from(geometry == "wide") << 60)
                    | (id << 40)
                    | (start << 24)
                    | (end << 8)
                    | u64::from(revision),
            ),
            revision,
            sealed,
        }
    }

    fn superseded(entry: &ShardMapEntry) -> SupersededShard {
        SupersededShard {
            shard_id: entry.shard_id,
            geometry: entry.geometry.clone(),
            start_height: entry.start_height,
            end_height: entry.end_height,
            terminal_block_hash: entry.terminal_block_hash.clone(),
            manifest_digest: entry.manifest_digest.clone(),
            revision: entry.revision,
            sealed: entry.sealed,
        }
    }

    fn map(shards: Vec<ShardMapEntry>, recuts: Vec<Recut>) -> ShardMap {
        let seal = SealParameters {
            max_scripts: 10,
            max_page_rows: 10,
            max_txids: 0,
        };
        ShardMap {
            genesis_hash: hash(0),
            network: "main".into(),
            profile: "zcash-transparent-range-v2".into(),
            range_envelope_version: 1,
            start_height: 1,
            seal: [("narrow".to_string(), seal), ("wide".to_string(), seal)].into(),
            shards,
            recuts,
        }
    }

    #[test]
    fn acceptance_requires_supported_versions_profiles_and_valid_shape() {
        let (_, valid) = before_and_after();
        for profile in [
            crate::transparent::filter::RANGE_PROFILE_V1,
            crate::transparent::filter::RANGE_PROFILE_V2,
        ] {
            let mut map = valid.clone();
            map.profile = profile.name.into();
            assert_eq!(map.validate_supported().unwrap(), &profile);
        }
        let mut unsupported = valid.clone();
        unsupported.range_envelope_version += 1;
        unsupported.check_shape().unwrap();
        assert!(
            unsupported
                .validate_supported()
                .unwrap_err()
                .contains("envelope version")
        );
        unsupported = valid.clone();
        unsupported.profile = "unknown-range-profile".into();
        unsupported.check_shape().unwrap();
        assert!(
            unsupported
                .validate_supported()
                .unwrap_err()
                .contains("filter profile")
        );
        unsupported = valid;
        unsupported.shards.clear();
        assert!(
            unsupported
                .validate_supported()
                .unwrap_err()
                .contains("empty")
        );
    }

    #[test]
    fn current_revision_digests_must_be_canonical_hex_before_admission() {
        let (_, valid) = before_and_after();
        for digest in [
            "A".repeat(64),
            "g".repeat(64),
            format!("../{}", "a".repeat(61)),
            format!("{}?x=1", "a".repeat(60)),
            format!("{}#tag", "a".repeat(60)),
            format!("{}%2f", "a".repeat(61)),
        ] {
            assert_eq!(digest.len(), 64);
            let mut map = valid.clone();
            map.shards[0].manifest_digest = digest;
            assert!(map.check_shape().unwrap_err().contains("manifest digest"));
            assert!(map.validate_supported().is_err());
        }
        valid.validate_supported().unwrap();
    }

    /// Before: 0 [1,10], 1 [11,20], 2 [21,30], 3 [31,40], tail 4 [41,45].
    /// After re-cutting 1–2 into one wide shard: 0, wide 1 [11,30], 2 [31,40]
    /// and tail 3 [41,46], each renumbered entry at a higher revision.
    fn before_and_after() -> (Vec<ShardMapEntry>, ShardMap) {
        let before = vec![
            entry(0, "narrow", 1, 10, 0, true),
            entry(1, "narrow", 11, 20, 0, true),
            entry(2, "narrow", 21, 30, 0, true),
            entry(3, "narrow", 31, 40, 0, true),
            entry(4, "narrow", 41, 45, 7, false),
        ];
        let recut = Recut {
            epoch: 1,
            from_height: 11,
            superseded: before[1..].iter().map(superseded).collect(),
        };
        let after = map(
            vec![
                before[0].clone(),
                entry(1, "wide", 11, 30, 0, true),
                entry(2, "narrow", 31, 40, 1, true),
                entry(3, "narrow", 41, 46, 8, false),
            ],
            vec![recut],
        );
        (before, after)
    }

    #[test]
    fn a_map_never_re_cut_keeps_its_bytes() {
        let (before, _) = before_and_after();
        let plain = map(before, Vec::new());
        let bytes = serde_json::to_string(&plain).unwrap();
        assert!(!bytes.contains("recuts"), "{bytes}");
        let parsed: ShardMap = serde_json::from_str(&bytes).unwrap();
        assert_eq!(parsed, plain);
        assert_eq!(parsed.recut_epoch(), 0);
    }

    #[test]
    fn a_declared_re_cut_is_well_formed() {
        let (before, after) = before_and_after();
        after.check_shape().unwrap();
        assert_eq!(after.recut_epoch(), 1);
        assert_eq!(
            after
                .superseded(&before[4].manifest_digest)
                .map(|s| s.sealed),
            Some(false)
        );
        assert!(after.superseded(&before[0].manifest_digest).is_none());
    }

    #[test]
    fn a_declaration_that_does_not_hold_is_refused() {
        let (before, after) = before_and_after();
        let refused = |change: &dyn Fn(&mut ShardMap), expect: &str| {
            let mut map = after.clone();
            change(&mut map);
            let error = map.check_shape().unwrap_err();
            assert!(error.contains(expect), "{expect}: {error}");
        };
        refused(&|m| m.recuts[0].epoch = 0, "does not rise");
        refused(&|m| m.recuts[0].from_height = 12, "supersedes from");
        refused(&|m| m.recuts[0].superseded.clear(), "supersedes nothing");
        refused(
            &|m| {
                m.recuts[0].superseded.remove(1);
            },
            "do not follow",
        );
        refused(
            &|m| m.recuts[0].superseded[0].sealed = false,
            "before its last",
        );
        refused(
            &|m| m.recuts[0].superseded[0].manifest_digest = m.shards[1].manifest_digest.clone(),
            "still publishes",
        );
        refused(
            &|m| m.recuts[0].superseded[2].geometry = "other".into(),
            "no seal",
        );
        refused(&|m| m.shards[2].revision = 0, "without a higher revision");
        refused(&|m| m.shards[3].revision = 7, "without a higher revision");
        refused(
            &|m| {
                let mut again = m.recuts[0].clone();
                again.epoch = 2;
                again.from_height = 12;
                again.superseded = vec![superseded(&before[1])];
                again.superseded[0].start_height = 12;
                m.recuts.push(again);
            },
            "superseded twice",
        );
        refused(
            &|m| {
                m.recuts.push(Recut {
                    epoch: 2,
                    from_height: 35,
                    superseded: vec![superseded(&entry(9, "narrow", 35, 40, 0, true))],
                });
            },
            "no shard boundary",
        );
    }

    /// Every declared field is checked for the form a wallet stores it in,
    /// and no hostile value can overflow the checks themselves.
    #[test]
    fn a_malformed_or_oversized_declaration_is_refused() {
        let (_, after) = before_and_after();
        let refused = |change: &dyn Fn(&mut ShardMap), expect: &str| {
            let mut map = after.clone();
            change(&mut map);
            let error = map.check_shape().unwrap_err();
            assert!(error.contains(expect), "{expect}: {error}");
        };
        refused(
            &|m| {
                m.recuts[0].superseded[1]
                    .manifest_digest
                    .make_ascii_uppercase()
            },
            "without a manifest digest",
        );
        refused(
            &|m| m.recuts[0].superseded[1].terminal_block_hash = "zz".repeat(32),
            "without a terminal block hash",
        );
        refused(
            &|m| m.recuts[0].superseded[1].terminal_block_hash = "ab".into(),
            "without a terminal block hash",
        );
        refused(
            &|m| m.recuts[0].superseded[3].end_height = MAX_DECLARED_HEIGHT + 1,
            "is no block range",
        );
        refused(
            &|m| {
                let last = m.recuts[0].superseded.len() - 1;
                m.recuts[0].superseded[last - 1].end_height = u64::MAX;
            },
            "is no block range",
        );
        refused(
            &|m| m.recuts[0].superseded[0].shard_id = u64::MAX,
            "do not follow",
        );
        refused(
            &|m| {
                m.recuts[0].from_height = u64::MAX;
                m.recuts[0].superseded[0].start_height = u64::MAX;
            },
            "above any block height",
        );
        refused(
            &|m| {
                let extra = m.recuts[0].superseded[0].clone();
                m.recuts[0]
                    .superseded
                    .extend(std::iter::repeat_n(extra, MAX_SUPERSEDED));
            },
            "more than 65536",
        );
        // Overflow in the published shards' own continuity is refused too.
        let mut overflowing = after.clone();
        overflowing.recuts.clear();
        overflowing.shards[0].end_height = u64::MAX;
        assert!(overflowing.check_shape().is_err());
    }

    #[test]
    fn the_index_finds_every_declared_revision_once() {
        let (before, after) = before_and_after();
        let index = after.superseded_index();
        assert_eq!(index.len(), 4);
        for entry in &before[1..] {
            assert_eq!(
                index
                    .get(entry.manifest_digest.as_str())
                    .map(|s| s.shard_id),
                Some(entry.shard_id)
            );
            assert_eq!(
                after.superseded(&entry.manifest_digest),
                index.get(entry.manifest_digest.as_str()).copied()
            );
        }
        assert!(!index.contains_key(before[0].manifest_digest.as_str()));
    }
}
