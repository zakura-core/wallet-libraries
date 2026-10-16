use super::manifest::check_continuation;
use super::shard::overload_backoff;
use super::walk::validate_page_boundary;
use super::*;
use crate::engine::adapters::StaticChain;
use crate::engine::store::RunCursor;
use transparent_filter::{SealParameters, ShardMapEntry};
use transparent_shard::manifest::{PageChild, ShardManifest};

fn entry(shard_id: u64, start: u64, end: u64, sealed: bool) -> ShardMapEntry {
    ShardMapEntry {
        shard_id,
        geometry: "decoupled-2k-8k".into(),
        start_height: start,
        end_height: end,
        parent_block_hash: format!("{:064x}", shard_id),
        terminal_block_hash: format!("{:064x}", shard_id + 100),
        filter_hash: format!("{:064x}", shard_id + 200),
        scripts: 1,
        page_rows: 1,
        txids: 1,
        directory_segments: 1,
        page_segments: 1,
        manifest_digest: format!("{:064x}", shard_id + 300),
        revision: 0,
        sealed,
    }
}

fn map(shards: Vec<ShardMapEntry>) -> ShardMap {
    let mut seal = std::collections::BTreeMap::new();
    seal.insert(
        "decoupled-2k-8k".to_string(),
        SealParameters {
            max_scripts: 98_304,
            max_page_rows: 7_936,
            max_txids: 0,
        },
    );
    ShardMap {
        genesis_hash: format!("{:064x}", 1),
        network: "main".into(),
        profile: "zcash-transparent-range-v1".into(),
        range_envelope_version: 1,
        start_height: 100,
        seal,
        shards,
        recuts: Vec::new(),
    }
}

/// The ordinary case the recovery exists for: the sealed prefix agrees and
/// the unsealed tail has been replaced by a longer revision.
#[test]
fn a_replaced_tail_over_an_agreeing_prefix_continues_the_set() {
    let before = map(vec![entry(0, 100, 199, true), entry(1, 200, 249, false)]);
    let mut after = before.clone();
    after.shards[1].end_height = 299;
    after.shards[1].revision = 1;
    after.shards[1].manifest_digest = "ff".repeat(32);
    assert_eq!(check_continuation(&before, &after, 199), Ok(()));
}

/// Shards appended past the tail is the same case, and is what a wallet
/// several revisions behind meets.
#[test]
fn appended_shards_continue_the_set() {
    let before = map(vec![entry(0, 100, 199, true), entry(1, 200, 249, false)]);
    let mut after = before.clone();
    after.shards[1].sealed = true;
    after.shards.push(entry(2, 250, 299, false));
    assert!(check_continuation(&before, &after, 199).is_ok());
}

#[test]
fn a_different_set_identity_is_not_a_continuation() {
    let before = map(vec![entry(0, 100, 199, true)]);
    for mutate in [
        (|m: &mut ShardMap| m.genesis_hash = "ff".repeat(32)) as fn(&mut ShardMap),
        |m: &mut ShardMap| m.network = "test".into(),
        |m: &mut ShardMap| m.profile = "other".into(),
        |m: &mut ShardMap| m.range_envelope_version = 2,
        |m: &mut ShardMap| m.start_height = 1,
    ] {
        let mut after = before.clone();
        mutate(&mut after);
        assert!(
            check_continuation(&before, &after, 199).is_err(),
            "a changed set identity must be refused"
        );
    }
}

/// Sealed content is immutable, so a shard whose covered range now reads
/// differently means a different set — not a longer one. This is the check
/// that makes the resume point provably equal to where coverage stopped.
///
/// A declared re-cut is no continuation either, even when it lies wholly above
/// what the sync has covered: it gives the ids the walk resumes by to
/// other ranges. That sync ends, and the next starts from the re-cut map.
#[test]
fn a_re_cut_covered_shard_is_not_a_continuation() {
    let before = map(vec![entry(0, 100, 199, true), entry(1, 200, 249, false)]);
    let mut after = before.clone();
    after.shards[0].end_height = 149;
    assert!(check_continuation(&before, &after, 199).is_err());

    // Shards 1 and 2 re-cut into one, the tail renumbered above it.
    let before = map(vec![
        entry(0, 100, 199, true),
        entry(1, 200, 249, true),
        entry(2, 250, 299, true),
        entry(3, 300, 320, false),
    ]);
    let mut wide = entry(1, 200, 299, true);
    wide.revision = 1;
    wide.manifest_digest = "aa".repeat(32);
    let mut tail = entry(2, 300, 321, false);
    tail.revision = 1;
    tail.manifest_digest = "bb".repeat(32);
    let undeclared = map(vec![before.shards[0].clone(), wide, tail]);
    let mut declared = undeclared.clone();
    declared.recuts.push(transparent_filter::Recut {
        epoch: 1,
        from_height: 200,
        superseded: before.shards[1..]
            .iter()
            .map(|entry| transparent_filter::SupersededShard {
                shard_id: entry.shard_id,
                geometry: entry.geometry.clone(),
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                manifest_digest: entry.manifest_digest.clone(),
                revision: entry.revision,
                sealed: entry.sealed,
            })
            .collect(),
    });
    for covered in [199, 249] {
        assert!(
            check_continuation(&before, &declared, covered).is_err(),
            "a declared re-cut ends the sync with {covered} covered"
        );
    }
    assert!(
        check_continuation(&before, &undeclared, 249).is_err(),
        "an undeclared re-cut of covered history"
    );
    // Wholly above coverage and undeclared, it is the walk's resume
    // point, not this check, that refuses a shard id moved elsewhere.
    assert!(check_continuation(&before, &undeclared, 199).is_ok());
    // The same map refreshed again continues itself.
    assert!(check_continuation(&declared, &declared, 321).is_ok());
}

/// Stored sealed coverage is found in the map by the height it starts at.
/// A re-cut that declares the revision it replaced keeps that coverage
/// good; the same re-cut undeclared, or a declaration that disagrees with
/// what the store holds, does not.
#[test]
fn sealed_coverage_is_vouched_for_by_height_or_by_declaration() {
    let before = map(vec![
        entry(0, 100, 199, true),
        entry(1, 200, 249, true),
        entry(2, 250, 299, true),
        entry(3, 300, 320, false),
    ]);
    let held = |shard: &ShardMapEntry| CoverageRange {
        script: vec![1],
        start_height: shard.start_height,
        end_height: shard.end_height,
        kind: CoverageKind::Settled,
        shard_id: shard.shard_id,
        revision_digest: shard.manifest_digest.clone(),
        terminal_block_hash: shard.terminal_block_hash.clone(),
        source_anchor: Some(Anchor {
            height: shard.end_height,
            hash: shard.terminal_block_hash.clone(),
        }),
    };
    let mut wide = entry(1, 200, 299, true);
    wide.revision = 1;
    wide.manifest_digest = "aa".repeat(32);
    let mut tail = entry(2, 300, 321, false);
    tail.revision = 1;
    tail.manifest_digest = "bb".repeat(32);
    let undeclared = map(vec![before.shards[0].clone(), wide, tail]);
    let mut declared = undeclared.clone();
    declared.recuts.push(transparent_filter::Recut {
        epoch: 1,
        from_height: 200,
        superseded: before.shards[1..]
            .iter()
            .map(|entry| transparent_filter::SupersededShard {
                shard_id: entry.shard_id,
                geometry: entry.geometry.clone(),
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal_block_hash: entry.terminal_block_hash.clone(),
                manifest_digest: entry.manifest_digest.clone(),
                revision: entry.revision,
                sealed: entry.sealed,
            })
            .collect(),
    });
    let vouches =
        |map: &ShardMap, range: &CoverageRange| vouches_for(map, &map.superseded_index(), range);
    for shard in &before.shards[..3] {
        assert!(vouches(&before, &held(shard)));
        assert!(vouches(&declared, &held(shard)), "{}", shard.shard_id);
    }
    assert!(vouches(&undeclared, &held(&before.shards[0])));
    assert!(!vouches(&undeclared, &held(&before.shards[1])));
    assert!(
        !vouches(&undeclared, &held(&before.shards[2])),
        "a sealed range whose start the map no longer cuts at"
    );
    // A declaration must name what the store holds.
    let mut moved = held(&before.shards[1]);
    moved.shard_id = 7;
    assert!(!vouches(&declared, &moved));
    let mut longer = held(&before.shards[1]);
    longer.end_height += 1;
    longer.source_anchor.as_mut().unwrap().height += 1;
    assert!(!vouches(&declared, &longer));
    // A range cut short of its shard is left to the chain checks.
    let mut clipped = held(&before.shards[1]);
    clipped.end_height -= 10;
    assert!(vouches(&undeclared, &clipped));
    // Without a source anchor, the covered endpoint must be the declared
    // one; the published revision itself is still matched by digest.
    let mut legacy = held(&before.shards[1]);
    legacy.source_anchor = None;
    assert!(vouches(&declared, &legacy));
    legacy.terminal_block_hash = "ee".repeat(32);
    assert!(
        !vouches(&declared, &legacy),
        "at the declared end, another block"
    );
    // Cut short by a target, it rests on a block inside the range.
    legacy.end_height -= 10;
    assert!(vouches(&declared, &legacy));
    legacy.end_height += 11;
    assert!(!vouches(&declared, &legacy), "past the declared end");
    let mut legacy_published = held(&before.shards[0]);
    legacy_published.source_anchor = None;
    legacy_published.terminal_block_hash = "ee".repeat(32);
    assert!(vouches(&declared, &legacy_published));
}

/// A sealed range the map no longer vouches for is a contradiction only
/// when the wallet's chain accepts both the block it rests on and the
/// block the replacement ends on, at or below the target. A publisher
/// that followed a shallow reorg through a just-sealed shard before the
/// wallet's chain did is unsettled, not refused, and becomes a reorg once
/// the chain moves.
#[test]
fn a_rewrite_is_refused_only_when_both_blocks_are_on_the_wallets_chain() {
    let stored = entry(1, 200, 249, true);
    let held = CoverageRange {
        script: vec![1],
        start_height: 200,
        end_height: 249,
        kind: CoverageKind::Settled,
        shard_id: 1,
        revision_digest: stored.manifest_digest.clone(),
        terminal_block_hash: stored.terminal_block_hash.clone(),
        source_anchor: Some(Anchor {
            height: 249,
            hash: stored.terminal_block_hash.clone(),
        }),
    };
    let mut replacement = stored.clone();
    replacement.manifest_digest = "aa".repeat(32);
    replacement.terminal_block_hash = "bb".repeat(32);
    let republished = map(vec![entry(0, 100, 199, true), replacement.clone()]);
    let target = Anchor {
        height: 260,
        hash: "cc".repeat(32),
    };
    let chain = |at_249: &str| StaticChain {
        hashes: [(249, at_249.to_string()), (260, target.hash.clone())].into(),
    };
    // The wallet's chain still holds the old block: the publisher is
    // ahead of it through a reorg, or wrong; either way, not yet.
    assert_eq!(
        judge_rewrite(
            &republished,
            &held,
            &target,
            &chain(&stored.terminal_block_hash)
        ),
        Rewrite::Unsettled(249)
    );
    // Once the chain moves to the publisher's branch, it is a reorg.
    assert_eq!(
        judge_rewrite(&republished, &held, &target, &chain(&"bb".repeat(32))),
        Rewrite::Reorg
    );
    assert_eq!(
        judge_rewrite(&republished, &held, &target, &StaticChain::default()),
        Rewrite::Unsettled(249)
    );
    // Both blocks on the wallet's chain, at different heights: an
    // undeclared re-cut or a rewrite, and the publisher's alone.
    let mut wider = replacement.clone();
    wider.end_height = 259;
    wider.terminal_block_hash = "dd".repeat(32);
    let recut = map(vec![entry(0, 100, 199, true), wider.clone()]);
    let both = StaticChain {
        hashes: [
            (249, stored.terminal_block_hash.clone()),
            (259, "dd".repeat(32)),
            (260, target.hash.clone()),
        ]
        .into(),
    };
    assert_eq!(
        judge_rewrite(&recut, &held, &target, &both),
        Rewrite::Contradiction
    );
    // Not when the replacement ends past the target or is unsealed.
    let early = Anchor {
        height: 255,
        hash: "ee".repeat(32),
    };
    assert_eq!(
        judge_rewrite(&recut, &held, &early, &both),
        Rewrite::Unsettled(259)
    );
    let mut unsealed = recut.clone();
    unsealed.shards[1].sealed = false;
    assert_eq!(
        judge_rewrite(&unsealed, &held, &target, &both),
        Rewrite::Unsettled(259)
    );
}

/// Unfinished pages under a revision the map no longer publishes keep
/// what they saved only for a declared sealed re-cut whose item's own
/// target the chain still accepts; nothing else the declaration says is
/// relied on.
#[test]
fn unfinished_work_keeps_its_events_only_over_an_accepted_target() {
    let target = Anchor {
        height: 260,
        hash: "aa".repeat(32),
    };
    let item = PendingPages {
        id: Some(1),
        shard_id: 2,
        revision_digest: "11".repeat(32),
        script: vec![1],
        cursor: RunCursor {
            child: 0,
            row: 0,
            older_runs: None,
        },
        fragments: Vec::new(),
        carried: Vec::new(),
        attempts: 0,
        target_anchor: Some(target.clone()),
    };
    let declaration = |shard_id: u64, sealed: bool| transparent_filter::SupersededShard {
        shard_id,
        geometry: "decoupled-2k-8k".into(),
        start_height: 250,
        end_height: 299,
        terminal_block_hash: "bb".repeat(32),
        manifest_digest: item.revision_digest.clone(),
        revision: 0,
        sealed,
    };
    let accepting = StaticChain {
        hashes: [(260, target.hash.clone()), (299, "bb".repeat(32))].into(),
    };
    // The target since reorganised away; the declared end still accepted.
    let reorganised = StaticChain {
        hashes: [(260, "cc".repeat(32)), (299, "bb".repeat(32))].into(),
    };
    let sealed = declaration(2, true);
    assert_eq!(
        unfinished(&item, Some(&sealed), Some(255), &accepting),
        Unfinished::Drop,
        "declared, sealed, target accepted: the saved events stay"
    );
    assert_eq!(
        unfinished(&item, Some(&sealed), Some(255), &reorganised),
        Unfinished::Rewind(250),
        "a declaration whose end the chain accepts cannot keep events read for a target \
         it no longer accepts"
    );
    let mut forged = sealed.clone();
    forged.start_height = 258;
    assert_eq!(
        unfinished(&item, Some(&forged), Some(255), &reorganised),
        Unfinished::Rewind(255),
        "never from the declared start alone"
    );
    assert_eq!(
        unfinished(&item, Some(&declaration(2, false)), Some(255), &accepting),
        Unfinished::Rewind(250),
        "a declared tail is rolled back"
    );
    assert_eq!(
        unfinished(&item, Some(&declaration(3, true)), Some(255), &accepting),
        Unfinished::Rewind(255),
        "a declaration under another id is no declaration of this item"
    );
    assert_eq!(
        unfinished(&item, None, Some(255), &accepting),
        Unfinished::Rewind(255),
        "undeclared: from the lowest saved height"
    );
    assert_eq!(unfinished(&item, None, None, &accepting), Unfinished::Drop);
    let unknown = StaticChain::default();
    assert_eq!(
        unfinished(&item, Some(&sealed), Some(255), &unknown),
        Unfinished::Rewind(250),
        "a target the chain cannot place is not held"
    );
    let mut untargeted = item.clone();
    untargeted.target_anchor = None;
    assert_eq!(
        unfinished(&untargeted, Some(&sealed), Some(255), &accepting),
        Unfinished::Rewind(250)
    );
}

/// The walk resumes after a refresh only at a shard starting where the
/// withdrawn one did; anything else would skip or repeat heights.
#[test]
fn the_walk_resumes_only_where_the_withdrawn_shard_started() {
    let withdrawn = entry(2, 250, 299, true);
    let mut republished = withdrawn.clone();
    republished.manifest_digest = "aa".repeat(32);
    republished.end_height = 320;
    assert_eq!(check_resume(&republished, &withdrawn), Ok(()));
    let moved = entry(2, 300, 349, true);
    let error = check_resume(&moved, &withdrawn).unwrap_err();
    assert!(
        error.contains("moves shard 2 from height 250 to 300"),
        "{error}"
    );
}

#[test]
fn withdrawing_a_covered_shard_is_not_a_continuation() {
    let before = map(vec![entry(0, 100, 199, true), entry(1, 200, 249, false)]);
    let after = map(vec![]);
    assert!(check_continuation(&before, &after, 199).is_err());
}

#[test]
fn coverage_ending_below_what_was_read_is_not_a_continuation() {
    let before = map(vec![entry(0, 100, 199, true), entry(1, 200, 249, false)]);
    let after = map(vec![entry(0, 100, 199, true)]);
    assert!(
        check_continuation(&before, &after, 249).is_err(),
        "a map ending below covered history withdraws what the wallet read"
    );
    assert!(
        check_continuation(&before, &after, 199).is_ok(),
        "the same map is fine when only the uncovered tail is gone"
    );
}

/// Seal parameters are what the boundaries were derived from, so a geometry
/// already in use may not be resealed — but a set growing into another tier
/// may declare a geometry the wallet had not seen.
#[test]
fn reseal_is_refused_but_a_new_geometry_is_not() {
    let before = map(vec![entry(0, 100, 199, true)]);
    let mut resealed = before.clone();
    resealed
        .seal
        .get_mut("decoupled-2k-8k")
        .unwrap()
        .max_page_rows = 1;
    assert!(check_continuation(&before, &resealed, 199).is_err());

    let mut widened = before.clone();
    widened.seal.insert(
        "decoupled-32k-32k".to_string(),
        SealParameters {
            max_scripts: 393_216,
            max_page_rows: 63_488,
            max_txids: 0,
        },
    );
    assert!(check_continuation(&before, &widened, 199).is_ok());
}

fn manifest_for(entry: &ShardMapEntry, parent: &str, map: &ShardMap) -> ShardManifest {
    use transparent_shard::manifest::{
        ManifestLayout, ManifestOccupancy, ManifestSeal, TableGeometry,
    };
    let geometry = transparent_shard::layout::by_name(&entry.geometry).unwrap();
    let seal = &map.seal[&entry.geometry];
    ShardManifest {
        schema: transparent_shard::SCHEMA.to_string(),
        profile: map.profile.clone(),
        geometry: entry.geometry.clone(),
        network: map.network.clone(),
        genesis_hash: map.genesis_hash.clone(),
        shard_id: entry.shard_id,
        start_height: entry.start_height,
        end_height: entry.end_height,
        parent_block_hash: entry.parent_block_hash.clone(),
        terminal_block_hash: entry.terminal_block_hash.clone(),
        tag_salt_counter: 0,
        parent_manifest_digest: parent.to_string(),
        sealed: entry.sealed,
        revision: entry.revision,
        supersedes: String::new(),
        seal: ManifestSeal {
            scripts_target: seal.max_scripts,
            scripts_capacity: seal.max_scripts * 2,
            directory_bytes_target: 1,
            directory_bytes_capacity: 2,
            page_rows_target: seal.max_page_rows,
            page_rows_capacity: geometry.page_rows,
            max_page_children: transparent_shard::MAX_PAGE_CHILDREN,
        },
        layout: ManifestLayout {
            max_script_bytes: transparent_shard::MAX_SCRIPT_BYTES as u32,
            inline_events: transparent_shard::INLINE_EVENTS,
            events_per_page: transparent_shard::EVENTS_PER_PAGE,
            page_row_header_bytes: transparent_shard::PAGE_ROW_HEADER_BYTES as u32,
            page_entry_header_bytes: transparent_shard::PAGE_ENTRY_HEADER_BYTES as u32,
            directory_choices: transparent_shard::build::DIRECTORY_CHOICES as u32,
        },
        filter_hash: entry.filter_hash.clone(),
        directory_segments: (0..entry.directory_segments)
            .map(|i| TableGeometry {
                rows: geometry.directory_rows,
                row_bytes: geometry.directory_row_bytes as u32,
                sha256: format!("{:064x}", 1000 + i),
            })
            .collect(),
        // One page shard per map-declared page shard: all but the last a
        // single block, the last the rest of the range.
        page_children: (0..u64::from(entry.page_segments))
            .map(|i| {
                let last = i + 1 == u64::from(entry.page_segments);
                PageChild {
                    index: i as u32,
                    start_height: entry.start_height + i,
                    end_height: if last {
                        entry.end_height
                    } else {
                        entry.start_height + i
                    },
                    terminal_block_hash: if last {
                        entry.terminal_block_hash.clone()
                    } else {
                        format!("{:064x}", 3000 + i)
                    },
                    tag_salt_counter: 0,
                    sealed: entry.sealed || !last,
                    page_segments: vec![TableGeometry {
                        rows: geometry.page_rows,
                        row_bytes: geometry.page_row_bytes as u32,
                        sha256: format!("{:064x}", 2000 + i),
                    }],
                    occupancy: transparent_shard::manifest::PageChildOccupancy {
                        page_rows: 1,
                        fragments: 1,
                        runs: 1,
                        events: 1,
                    },
                }
            })
            .collect(),
        occupancy: ManifestOccupancy {
            scripts: 1,
            page_rows: u64::from(entry.page_segments),
            fragments: u64::from(entry.page_segments),
            events: 1,
            blocks: 100,
            txids: 1,
            excluded_scripts: 0,
        },
        directory_choice: None,
    }
}

/// A published choice table is checked with the manifest: one that does
/// not decode, or indexes a different number of scripts than the shard
/// places, stops the sync rather than falling back to two queries.
#[test]
fn a_malformed_directory_choice_is_refused_with_the_manifest() {
    let script: &[u8] = &[0x51, 0x01];
    let valid = transparent_shard::manifest::encode_directory_choice(
        &transparent_shard::ChoiceTable::build(0, &[(script, 1)]).unwrap(),
    );
    let two = transparent_shard::manifest::encode_directory_choice(
        &transparent_shard::ChoiceTable::build(0, &[(script, 1), (&[0x51, 0x02], 0)]).unwrap(),
    );
    for (choice, accepted) in [
        (valid, true),
        (two, false),
        ("not base64!".to_string(), false),
        (String::new(), false),
    ] {
        let mut entry = entry(0, 100, 199, true);
        let map = map(vec![entry.clone()]);
        let mut manifest = manifest_for(&entry, "", &map);
        manifest.directory_choice = Some(choice.clone());
        entry.manifest_digest = manifest.digest();
        let map = self::map(vec![entry.clone()]);
        let verified = verify_manifest(&manifest.canonical_bytes(), &entry, "", &map);
        match (accepted, verified) {
            (true, Ok(verified)) => {
                assert!(directory_choice(&verified).unwrap().is_some())
            }
            (false, Err(SyncError::Invalid(_))) => {}
            (_, other) => panic!("{choice:?}: {other:?}"),
        }
    }
}

/// The manifest that digests to what the map names, and agrees with it in
/// every field, is accepted; every single-field departure is refused with
/// the field named, and a changed body without a changed digest is caught
/// by the digest first.
#[test]
fn a_manifest_is_accepted_only_when_it_agrees_with_the_map_in_every_field() {
    let mut first = entry(0, 100, 199, true);
    let mut second = entry(1, 200, 249, false);
    let map = map(vec![first.clone(), second.clone()]);
    let genuine_first = manifest_for(&first, "", &map);
    first.manifest_digest = genuine_first.digest();
    let genuine_second = manifest_for(&second, &first.manifest_digest, &map);
    second.manifest_digest = genuine_second.digest();
    let map = self::map(vec![first.clone(), second.clone()]);

    verify_manifest(&genuine_first.canonical_bytes(), &first, "", &map).expect("genuine");
    verify_manifest(
        &genuine_second.canonical_bytes(),
        &second,
        &first.manifest_digest,
        &map,
    )
    .expect("genuine, chained");
    let mut bad_layout = genuine_second.clone();
    bad_layout.layout.events_per_page = 46;
    let mut matching_entry = second.clone();
    matching_entry.manifest_digest = bad_layout.digest();
    assert!(matches!(
        verify_manifest(
            &bad_layout.canonical_bytes(),
            &matching_entry,
            &first.manifest_digest,
            &map
        ),
        Err(SyncError::ManifestMismatch {
            field: "layout",
            ..
        })
    ));

    // Any change to the bytes changes the digest, so the first refusal is
    // always the digest's.
    let mut altered = genuine_second.clone();
    altered.end_height += 1;
    let error = verify_manifest(
        &altered.canonical_bytes(),
        &second,
        &first.manifest_digest,
        &map,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            SyncError::ManifestMismatch {
                field: "digest",
                ..
            }
        ),
        "{error}"
    );

    // A map entry that disagrees with a genuine manifest names the field.
    type Mutation = Box<dyn Fn(&mut ShardMapEntry)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "geometry",
            Box::new(|e| e.geometry = "decoupled-32k-32k".into()),
        ),
        ("range", Box::new(|e| e.end_height = 250)),
        (
            "parent_block_hash",
            Box::new(|e| e.parent_block_hash = "ff".repeat(32)),
        ),
        (
            "terminal_block_hash",
            Box::new(|e| e.terminal_block_hash = "ee".repeat(32)),
        ),
        ("filter_hash", Box::new(|e| e.filter_hash = "dd".repeat(32))),
        ("sealed", Box::new(|e| e.sealed = true)),
        ("revision", Box::new(|e| e.revision = 1)),
        ("segment_count", Box::new(|e| e.page_segments = 2)),
    ];
    for (field, mutate) in cases {
        let mut disagreeing = second.clone();
        mutate(&mut disagreeing);
        // The digest still matches the bytes; only the map entry changed.
        disagreeing.manifest_digest = genuine_second.digest();
        let error = verify_manifest(
            &genuine_second.canonical_bytes(),
            &disagreeing,
            &first.manifest_digest,
            &map,
        )
        .unwrap_err();
        match error {
            SyncError::ManifestMismatch { field: found, .. } => assert_eq!(found, field),
            other => panic!("{field}: {other}"),
        }
    }
    // A broken chain is a different sequence of shards.
    let error = verify_manifest(&genuine_second.canonical_bytes(), &second, "", &map).unwrap_err();
    assert!(matches!(
        error,
        SyncError::ManifestMismatch {
            field: "parent_manifest_digest",
            ..
        }
    ));
    // A map naming another set is refused before any field comparison.
    let mut other_set = map.clone();
    other_set.genesis_hash = "cc".repeat(32);
    let error = verify_manifest(
        &genuine_second.canonical_bytes(),
        &second,
        &first.manifest_digest,
        &other_set,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SyncError::ManifestMismatch {
            field: "genesis_hash",
            ..
        }
    ));
}

#[test]
fn backoff_prefers_the_services_figure_and_caps_it() {
    // Each wait is its base jittered by up to half again, never less.
    let within = |wait: Duration, base: Duration| wait >= base && wait <= base * 3 / 2;
    assert!(within(overload_backoff(1, None), OVERLOAD_BACKOFF));
    assert!(within(overload_backoff(2, None), OVERLOAD_BACKOFF * 2));
    assert!(
        within(
            overload_backoff(1, Some(Duration::from_millis(10))),
            Duration::from_millis(10)
        ),
        "the service knows why it refused"
    );
    assert!(
        within(
            overload_backoff(1, Some(Duration::from_secs(3600))),
            OVERLOAD_BACKOFF_CAP
        ),
        "a delay a wallet cannot sanity-check must not park a sync"
    );
    assert!(
        within(overload_backoff(20, None), OVERLOAD_BACKOFF_CAP),
        "doubling is capped too"
    );
}
#[test]
fn compact_boundaries_reject_underfilled_reordered_and_cross_row_reference_shortcuts() {
    use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
    let receive = TransparentEvent::Receive(ReceiveEvent {
        metadata: None,
        height: 100,
        transaction_index: 0,
        txid: Txid([7; 32]),
        output_index: 3,
        value: 9,
        coinbase: false,
    });
    let spend = TransparentEvent::Spend(SpendEvent {
        metadata: None,
        height: 101,
        transaction_index: 0,
        spending_txid: Txid([8; 32]),
        input_index: 0,
        spent_txid: Txid([7; 32]),
        spent_output_index: 3,
    });
    let mut boundary = crate::engine::store::PageBoundary {
        event_bytes: 4000,
        last_event: receive,
    };
    // 58 spare bytes would hold the local 43-byte form. Treating this
    // spend as 79 bytes would incorrectly accept the premature boundary.
    assert!(validate_page_boundary(Some(&boundary), &[spend]).is_err());
    boundary.event_bytes = 4029;
    let next = validate_page_boundary(Some(&boundary), &[spend]).unwrap();
    assert_eq!(next.event_bytes, 79); // References reset at the new fragment.
    assert!(validate_page_boundary(Some(&next), &[receive]).is_err());
    assert!(validate_page_boundary(None, &[]).is_err());
}
