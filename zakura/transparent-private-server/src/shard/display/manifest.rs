//! A display shard's manifest as the publisher writes it from the tables it
//! built; the manifest itself is
//! [`zakura_transparent_private_shared::shard::display::manifest`].

use sha2::{Digest, Sha256};
use zakura_transparent_private_shared::shard::display::manifest::{
    DisplayBucket, DisplayLayout, DisplayManifest, ManifestHeader,
};
use zakura_transparent_private_shared::shard::display::DISPLAY_SCHEMA;
use zakura_transparent_private_shared::shard::layout::Geometry;
use zakura_transparent_private_shared::shard::manifest::TableGeometry;

use super::tables::BuiltDisplay;

/// Writing a [`DisplayManifest`] for a built shard.
pub trait DisplayManifestBuild {
    /// The manifest of the shard `built`, under `header`, at `geometry`.
    fn new(header: ManifestHeader, geometry: &Geometry, built: &BuiltDisplay) -> Self;
}

fn digest_tables(segments: &[Vec<u8>], geometry: &Geometry) -> Vec<TableGeometry> {
    segments
        .iter()
        .map(|segment| TableGeometry {
            rows: geometry.directory_rows,
            row_bytes: geometry.directory_row_bytes as u32,
            sha256: hex::encode(Sha256::digest(segment)),
        })
        .collect()
}

impl DisplayManifestBuild for DisplayManifest {
    fn new(header: ManifestHeader, geometry: &Geometry, built: &BuiltDisplay) -> Self {
        Self {
            schema: DISPLAY_SCHEMA.to_string(),
            network: header.network,
            genesis_hash: header.genesis_hash,
            shard_id: header.shard_id,
            start_height: header.start_height,
            end_height: header.end_height,
            parent_block_hash: header.parent_block_hash,
            terminal_block_hash: header.terminal_block_hash,
            parent_manifest_digest: header.parent_manifest_digest,
            sealed: header.sealed,
            revision: header.revision,
            supersedes: header.supersedes,
            geometry: geometry.name.to_string(),
            n_buckets: built.buckets.len() as u32,
            archive_target: header.archive_target,
            layout: DisplayLayout::of(geometry),
            blocks: header.end_height - header.start_height + 1,
            records: built.records,
            buckets: built
                .buckets
                .iter()
                .enumerate()
                .map(|(b, bucket)| DisplayBucket {
                    bucket: b as u32,
                    records: bucket.records,
                    placement_seed: bucket.placement_seed,
                    directory_segments: digest_tables(&bucket.directory, geometry),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::display::{build_shard, DisplayMapSplit as _};
    use crate::shard::txid::{DisplayFacts, DisplayOutput};
    use zakura_transparent_private_shared::events::Txid;
    use zakura_transparent_private_shared::shard::display::*;

    fn built() -> BuiltDisplay {
        let entries: Vec<_> = (0u8..20)
            .map(|i| {
                DisplayFacts {
                    txid: Txid([i; 32]),
                    coinbase: false,
                    fee: 1,
                    has_shielded_components: false,
                    spent: vec![DisplayOutput {
                        value: 2,
                        script: vec![0; 25],
                    }],
                    outputs: vec![DisplayOutput {
                        value: 1,
                        script: vec![0; 25],
                    }],
                }
                .entry()
                .unwrap()
            })
            .collect();
        build_shard(5, &TXID_2K8, 2, &entries).unwrap()
    }

    fn header(sealed: bool) -> ManifestHeader {
        ManifestHeader {
            network: "mainnet".into(),
            genesis_hash: "00".repeat(32),
            shard_id: 5,
            start_height: 100,
            end_height: 199,
            parent_block_hash: "11".repeat(32),
            terminal_block_hash: "22".repeat(32),
            parent_manifest_digest: "33".repeat(32),
            sealed,
            revision: 0,
            supersedes: String::new(),
            archive_target: 10,
        }
    }

    fn manifest() -> DisplayManifest {
        DisplayManifest::new(header(true), &TXID_2K8, &built())
    }

    fn map() -> DisplayMap {
        let seal = DisplaySealParams {
            n_archive: 2,
            n_recent: 2,
            archive_target: 5,
            recent_window: 5,
            reorg_margin: 100,
        };
        let mut shards = Vec::new();
        let mut parent = "11".repeat(32);
        for (i, sealed) in [true, true, false].into_iter().enumerate() {
            let mut h = header(sealed);
            h.shard_id = 7 + i as u64;
            h.start_height = 100 + i as u64 * 100;
            h.end_height = h.start_height + 99;
            h.parent_block_hash = parent.clone();
            h.terminal_block_hash = format!("{:064x}", i + 1);
            parent = h.terminal_block_hash.clone();
            let m = DisplayManifest::new(h, &TXID_2K8, &built());
            shards.push(DisplayMapEntry::from_manifest(&m, &m.digest()));
        }
        DisplayMap {
            schema: DISPLAY_SCHEMA.into(),
            network: "mainnet".into(),
            genesis_hash: "00".repeat(32),
            seal,
            start_height: 100,
            first_shard_id: 7,
            shards,
        }
    }

    /// The recent shard 9 over `[start, 399]`, chained to the block before
    /// `start`, beside archives 7 over `[100, 199]` and 8 over `[200, 299]`.
    fn overlapping(start: u64, parent: String) -> DisplayMap {
        let mut m = map();
        let recent = &mut m.shards[2];
        recent.start_height = start;
        recent.parent_block_hash = parent;
        m
    }

    #[test]
    fn manifest_validation_refuses_inconsistent_content() {
        let mut m = manifest();
        m.revision = 1;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[0].records += 1;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.geometry = "decoupled-32k-32k".into();
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[1].directory_segments[0].rows = 4096;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[1].directory_segments[0].row_bytes = 4096;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.buckets[0].placement_seed = MAX_PLACEMENT_SEEDS;
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.layout.row_bytes = 4096;
        assert!(m.validate().is_err());
        let mut m = DisplayManifest::new(header(false), &TXID_2K8, &built());
        m.revision = 3;
        m.supersedes = "44".repeat(32);
        m.validate().unwrap();
    }

    #[test]
    fn the_recent_shard_may_overlap_the_archives() {
        let terminal = |i: usize| format!("{i:064x}");
        // Inside the newest archive, at its start, inside an older one, at
        // the map's start, and right after the archives.
        for (start, parent) in [
            (250, "99".repeat(32)),
            (200, terminal(1)),
            (150, "99".repeat(32)),
            (100, "11".repeat(32)),
            (300, terminal(2)),
        ] {
            let m = overlapping(start, parent);
            m.check_shape().unwrap();
            // Heights the archives hold go to them, the rest to recent.
            assert_eq!(m.unsealed_start(), 300);
            assert_eq!(
                m.shard_for_height(start).unwrap().shard_id,
                7 + (start / 100 - 1)
            );
            assert_eq!(m.shard_for_height(299).unwrap().shard_id, 8);
            assert_eq!(m.shard_for_height(300).unwrap().shard_id, 9);
            assert!(m.shard_for_height(400).is_none());
            m.split().unwrap();
        }
        // A wrong parent where an archive names the block before the start.
        for (start, parent) in [(200, terminal(2)), (300, terminal(1)), (100, terminal(1))] {
            assert!(overlapping(start, parent).check_shape().is_err(), "{start}");
        }
        // Below the map, above the first unsealed height, or not above the
        // archives.
        assert!(overlapping(99, "99".repeat(32)).check_shape().is_err());
        assert!(overlapping(301, "99".repeat(32)).check_shape().is_err());
        let mut short = map();
        short.shards[2].end_height = 299;
        short.shards[2].start_height = 250;
        assert!(short.check_shape().is_err());
        // A recent shard below the window, unless it starts at the map's.
        let mut thin = overlapping(250, "99".repeat(32));
        thin.seal.recent_window = thin.shards[2].min_bucket_records + 1;
        assert!(thin.check_shape().is_err());
        let mut young = overlapping(100, "11".repeat(32));
        young.seal.recent_window = young.shards[2].min_bucket_records + 1;
        young.check_shape().unwrap();
    }

    #[test]
    fn manifest_block_count_rejects_overflow_and_keeps_representable_limits() {
        let mut m = manifest();
        m.start_height = 0;
        m.end_height = u64::MAX;
        m.blocks = 0; // The value unchecked arithmetic would wrap to.
        assert!(m.validate().is_err());
        m.start_height = u64::MAX;
        m.end_height = 0;
        m.blocks = 1;
        assert!(m.validate().is_err());
        for (start, end, blocks) in [(1, u64::MAX, u64::MAX), (u64::MAX, u64::MAX, 1), (0, 0, 1)] {
            m.start_height = start;
            m.end_height = end;
            m.blocks = blocks;
            m.validate().unwrap();
            m.blocks = blocks - 1;
            assert!(m.validate().is_err());
        }
    }

    #[test]
    fn manifest_record_total_rejects_overflow_and_keeps_representable_limits() {
        let mut m = manifest();
        assert_eq!(m.buckets.len(), 2);
        for (first, second, total) in [(u64::MAX, u64::MAX, u64::MAX - 1), (u64::MAX, 1, 0)] {
            m.buckets[0].records = first;
            m.buckets[1].records = second;
            m.records = total;
            assert!(m.validate().is_err());
        }
        for (first, second, total) in [
            (u64::MAX - 1, 1, u64::MAX),
            (u64::MAX, 0, u64::MAX),
            (0, 0, 0),
        ] {
            m.buckets[0].records = first;
            m.buckets[1].records = second;
            m.records = total;
            m.validate().unwrap();
            m.records = total ^ 1;
            assert!(m.validate().is_err());
        }
    }

    #[test]
    fn manifest_validates_and_every_field_reaches_the_digest() {
        let base = manifest();
        base.validate().unwrap();
        let digest = base.digest();
        type Mutation = Box<dyn Fn(&mut DisplayManifest)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|m| m.schema.push('x')),
            Box::new(|m| m.network.push('x')),
            Box::new(|m| m.genesis_hash = "99".repeat(32)),
            Box::new(|m| m.shard_id += 1),
            Box::new(|m| m.start_height += 1),
            Box::new(|m| m.end_height += 1),
            Box::new(|m| m.parent_block_hash = "99".repeat(32)),
            Box::new(|m| m.terminal_block_hash = "99".repeat(32)),
            Box::new(|m| m.parent_manifest_digest = "99".repeat(32)),
            Box::new(|m| m.sealed = false),
            Box::new(|m| m.revision += 1),
            Box::new(|m| m.supersedes = "99".repeat(32)),
            Box::new(|m| m.geometry = "txid-2k".into()),
            Box::new(|m| m.n_buckets += 1),
            Box::new(|m| m.archive_target += 1),
            Box::new(|m| m.layout.entry_bytes += 1),
            Box::new(|m| m.blocks += 1),
            Box::new(|m| m.records += 1),
            Box::new(|m| m.layout.directory_choices = 2),
            Box::new(|m| m.buckets[0].records += 1),
            Box::new(|m| m.buckets[1].placement_seed += 1),
            Box::new(|m| m.buckets[1].directory_segments[0].sha256 = "99".repeat(32)),
            Box::new(|m| {
                let extra = m.buckets[0].directory_segments[0].clone();
                m.buckets[0].directory_segments.push(extra);
            }),
        ];
        for mutate in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(changed.digest(), digest);
        }
    }

    #[test]
    fn full_map_rejects_overflowing_archive_heights_and_ids() {
        let original = map();
        for index in [0, 1] {
            let mut hostile = original.clone();
            hostile.shards[index].end_height = u64::MAX;
            assert!(hostile.check_shape().is_err());
            // The range must also be rejected when there is no recent shard.
            hostile.shards.pop();
            assert!(hostile.check_shape().is_err());
        }
        let mut hostile = original.clone();
        hostile.first_shard_id = u64::MAX;
        hostile.shards[0].shard_id = u64::MAX;
        hostile.shards[1].shard_id = 0;
        hostile.shards[2].shard_id = 1;
        assert!(hostile.check_shape().is_err());
        // The highest representable consecutive ids still describe a valid map.
        let mut valid = original;
        valid.first_shard_id = u64::MAX - 2;
        for (index, shard) in valid.shards.iter_mut().enumerate() {
            shard.shard_id = valid.first_shard_id + index as u64;
        }
        valid.check_shape().unwrap();
    }

    #[test]
    fn map_shape_and_lookup() {
        let m = map();
        m.check_shape().unwrap();
        assert_eq!(m.shard_for_height(250).unwrap().shard_id, 8);
        assert_eq!(m.shard(9).unwrap().tier(), "recent");
        assert!(m.shard(6).is_none() && m.shard_for_height(99).is_none());
        assert_eq!(m.covered_through(), Some(399));

        type Mutation = Box<dyn Fn(&mut DisplayMap)>;
        let broken: Vec<Mutation> = vec![
            Box::new(|m| m.first_shard_id = 0),
            Box::new(|m| m.shards[1].shard_id = 20),
            Box::new(|m| m.shards[1].start_height += 1),
            Box::new(|m| m.shards[1].parent_block_hash = "99".repeat(32)),
            Box::new(|m| m.shards[0].sealed = false),
            Box::new(|m| m.shards[0].min_bucket_records = 4),
            Box::new(|m| m.shards[0].revision = 1),
            Box::new(|m| m.shards[2].n_buckets = 1),
            Box::new(|m| m.shards[0].directory_segments[1] = 0),
            Box::new(|m| m.shards[0].placement_seeds.push(0)),
            Box::new(|m| m.shards[2].placement_seeds[0] = MAX_PLACEMENT_SEEDS),
            Box::new(|m| m.shards[0].geometry = "decoupled-2k-8k".into()),
            Box::new(|m| m.shards.clear()),
        ];
        for mutate in broken {
            let mut changed = map();
            mutate(&mut changed);
            assert!(changed.check_shape().is_err());
        }
        // A window that dropped its oldest shard is still well formed.
        let mut dropped = map();
        dropped.shards.remove(0);
        dropped.first_shard_id = 8;
        dropped.start_height = 200;
        dropped.check_shape().unwrap();
    }
}
