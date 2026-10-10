use super::*;

#[test]
fn a_page_under_a_source_the_map_no_longer_names_is_completed_once_covered() {
    let map = map();
    let (sealed, tail) = (&map.shards[0], &map.shards[1]);
    let resealed = resealing(&map, 1);
    let script = address_script(watch().addresses[0].address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = seeded(&dir, &script, map.start_height);
    // The sealed shard is covered; a budget-limited pass left a page on the tail.
    let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(
            sealed,
            &sealed.manifest_digest,
            end,
            &script,
            vec![],
        ))
        .unwrap();
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    let mut open = covered(tail, &tail.manifest_digest, end, &script, vec![]);
    open.covered_scripts.clear();
    open.pending_upsert = vec![store_page(tail, &script, 3)];
    adapter.store.commit_shard(open).unwrap();
    let first = pass(&mut adapter, &map);
    assert_eq!(first.state, BatchState::Ready);
    let opening = first.commits[1].clone();
    assert_eq!(opening.opened_pages.len(), 1);
    adapter.acknowledge_applied(&first).unwrap();
    // The wallet applied it and holds the page under the tail's revision.
    let mut holding = watch();
    holding.pending_pages = vec![PendingPage {
        request: opening.opened_pages[0].clone(),
        revision: opening.revision.clone(),
        target: opening.context.target,
    }];

    // Resealing the tail's geometry gives the tail a new source, so no
    // commit of the page's revision follows. While the retried retrieval
    // covers only the sealed shard, the page stays open.
    publication_change(&mut adapter, &resealed);
    adapter.store.bind_set(&SetIdentity::of(&resealed)).unwrap();
    adapter
        .store
        .add_scripts(&[ScriptEntry {
            script: script.clone(),
            origin: ScriptOrigin::Imported,
            required_from: map.start_height,
        }])
        .unwrap();
    let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(
            sealed,
            &sealed.manifest_digest,
            end,
            &script,
            vec![],
        ))
        .unwrap();
    let chain = StaticChain::from_map(&resealed);
    let partial = adapter
        .normalize(&holding, resealed.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(partial.state, BatchState::Ready);
    assert_eq!(revisions(&partial), vec![first.commits[0].revision.clone()]);
    adapter.acknowledge_applied(&partial).unwrap();

    // Once the batch covers the page's range under the new source, a
    // completion-only commit under the page's own revision follows the
    // commits that cover it, anchored at that revision's publication.
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(
            &resealed.shards[1],
            &tail.manifest_digest,
            end,
            &script,
            vec![],
        ))
        .unwrap();
    let batch = adapter
        .normalize(&holding, resealed.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(batch.commits.len(), 3);
    assert_ne!(batch.commits[1].revision.source, opening.revision.source);
    let completion = &batch.commits[2];
    assert_eq!(
        completion,
        &TransparentLedgerCommit {
            context: opening.context,
            revision: opening.revision.clone(),
            anchor: ChainPoint {
                height: block_height(tail.end_height).unwrap(),
                hash: block_hash_from_display(&tail.terminal_block_hash).unwrap(),
            },
            receives: vec![],
            spends: vec![],
            coverage: vec![],
            unsupported: vec![],
            opened_pages: vec![],
            completed_pages: vec![opening.opened_pages[0].page.clone()],
        }
    );
    // It is not recorded as exported, so later passes never settle it
    // against the map, which publishes its shard under another source.
    let old_exported: bool = adapter
        .catalog
        .query_row(
            "SELECT exported FROM pir_bridge_catalog WHERE source=?1",
            [&opening.revision.source],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!old_exported);
    adapter.acknowledge_applied(&batch).unwrap();
    let after = pass(&mut adapter, &resealed);
    assert_eq!(after.state, BatchState::Ready);
    assert_eq!(revisions(&after), revisions(&batch)[..2].to_vec());

    // A page whose revision's publication block the wallet's chain does
    // not hold waits.
    let mut elsewhere = holding.clone();
    elsewhere.pending_pages[0].revision.publication.hash = BlockHash([0x55; 32]);
    let waiting = adapter
        .normalize(&elsewhere, resealed.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(waiting.state, BatchState::Ready);
    assert_eq!(revisions(&waiting), revisions(&after));
}

#[test]
fn a_page_under_a_source_the_map_names_is_left_to_its_revisions() {
    let map = map();
    let tail = &map.shards[1];
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    // The wallet holds a page under the tail's first revision, and the
    // companion covers the tail's successor over the page's range.
    let mut holding = watch();
    holding.pending_pages = vec![PendingPage {
        request: PageRequest {
            page: vec![1],
            addresses: vec![holding.addresses[0].address],
            from: block_height(tail.start_height).unwrap(),
            through: block_height(tail.end_height).unwrap(),
        },
        revision: first.commits[1].revision.clone(),
        target: holding.target.unwrap(),
    }];
    let successor = republished(&map, 1, 1, "5a".repeat(32));
    retrieve_tail(&mut adapter, &successor);
    // Qualifying the successor withdraws that page in the wallet, which
    // would refuse a completion under the superseded revision.
    let batch = adapter
        .normalize(
            &holding,
            successor.clone(),
            MORE,
            &StaticChain::from_map(&successor),
        )
        .unwrap();
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(batch.commits.len(), 2);
    assert_eq!(batch.commits[1].revision.lineage, 2);
    assert!(
        batch
            .commits
            .iter()
            .all(|commit| commit.completed_pages.is_empty())
    );
}

#[test]
fn a_reset_store_that_stops_before_binding_is_pending() {
    let map = map();
    let t = map.shards.last().unwrap().end_height;
    let resealed = resealing(&map, 1);
    // The wallet's target is above the resealed map's end, and its chain
    // holds another block at that end, so the pass cannot clamp and the
    // reference client stops before binding the store.
    let mut watch = watch();
    let target = ChainPoint {
        height: block_height(t + 10).unwrap(),
        hash: BlockHash([9; 32]),
    };
    watch.target = Some(target);
    let mut chain = StaticChain::from_map(&resealed);
    chain.hashes.insert(t + 10, target.hash.to_string());
    chain.hashes.insert(t, "aa".repeat(32));
    let behind = |adapter: &mut ReferenceRecovery| {
        let mut filters = CountingFilters::serving(serde_json::to_vec(&resealed).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(&watch, &chain, &mut filters, &mut shards)
            .unwrap();
        assert_eq!((filters.filters, shards.calls()), (0, 1));
        assert_eq!(batch.progress.outcome, Outcome::Behind);
        assert!(batch.commits.is_empty());
        assert_eq!(adapter.store.set_identity().unwrap(), None);
        batch
    };

    // A fresh companion has exported nothing, so nothing can disagree.
    let dir = tempfile::tempdir().unwrap();
    let mut fresh = ReferenceRecovery::open(dir.path().join("fresh.sqlite"), config()).unwrap();
    assert_eq!(behind(&mut fresh).state, BatchState::Ready);

    // A reset companion still holds exported revisions the pass never
    // checked against the publication.
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    publication_change(&mut adapter, &resealed);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
    let batch = behind(&mut adapter);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(adapter.acknowledge_applied(&batch).is_err());
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
}

#[test]
fn a_revision_exported_before_a_reset_is_held_back_while_it_reopens_a_page() {
    let map = map();
    let (sealed, tail) = (&map.shards[0], &map.shards[1]);
    let resealed = resealing(&map, 1);
    let address = watch().addresses[0].address;
    let script = address_script(address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    let (sealed_revision, old_tail) = (&first.commits[0].revision, &first.commits[1].revision);

    // After the reset the store retrieves again. It covers the new tail,
    // but a budget-limited pass left page work on the sealed shard, whose
    // source is unchanged and which the wallet already covers.
    publication_change(&mut adapter, &resealed);
    adapter.store.bind_set(&SetIdentity::of(&resealed)).unwrap();
    adapter
        .store
        .add_scripts(&[ScriptEntry {
            script: script.clone(),
            origin: ScriptOrigin::Imported,
            required_from: map.start_height,
        }])
        .unwrap();
    let sealed_end = (sealed.end_height, sealed.terminal_block_hash.as_str());
    let mut open = covered(sealed, &sealed.manifest_digest, sealed_end, &script, vec![]);
    open.covered_scripts.clear();
    open.pending_upsert = vec![store_page(sealed, &script, 3)];
    adapter.store.commit_shard(open).unwrap();
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(
            &resealed.shards[1],
            &tail.manifest_digest,
            end,
            &script,
            vec![],
        ))
        .unwrap();
    let chain = StaticChain::from_map(&resealed);
    // The wallet would refuse that page over its own coverage, so the
    // sealed shard's revision is held back; the new tail is exported.
    let batch = pass(&mut adapter, &resealed);
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(batch.commits.len(), 1);
    let new_tail = &batch.commits[0].revision;
    assert!(new_tail.source != sealed_revision.source && new_tail.source != old_tail.source);
    assert!(batch.commits[0].opened_pages.is_empty());
    adapter.acknowledge_applied(&batch).unwrap();

    // A page the wallet holds for that revision is replayed instead.
    let mut holding = watch();
    holding.pending_pages = vec![PendingPage {
        request: PageRequest {
            page: page_continuation_id(sealed.shard_id, &sealed.manifest_digest, &script, 3),
            addresses: vec![address],
            from: block_height(sealed.start_height).unwrap(),
            through: block_height(sealed.end_height).unwrap(),
        },
        revision: sealed_revision.clone(),
        target: holding.target.unwrap(),
    }];
    let replayed = adapter
        .normalize(&holding, resealed.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(replayed.state, BatchState::Ready);
    assert_eq!(&replayed.commits[0].revision, sealed_revision);
    assert_eq!(
        replayed.commits[0].opened_pages,
        vec![holding.pending_pages[0].request.clone()]
    );

    // Once the page work is done, the revision is exported again with its
    // coverage.
    let pending = adapter.store.pending().unwrap();
    let mut done = covered(sealed, &sealed.manifest_digest, sealed_end, &script, vec![]);
    done.pending_complete = vec![pending[0].id.unwrap()];
    adapter.store.commit_shard(done).unwrap();
    let batch = pass(&mut adapter, &resealed);
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(&batch.commits[0].revision, sealed_revision);
    assert!(batch.commits[0].opened_pages.is_empty());
    assert_eq!(batch.commits[0].coverage, first.commits[0].coverage);
}

#[test]
fn a_map_under_the_previous_set_below_the_anchor_does_not_reset_the_store() {
    let map = map();
    let tail = &map.shards[1];
    let t = tail.end_height;
    let resealed = resealing(&map, 1);
    // A companion bound to the new set, synced through the tail's end.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &resealed);
    let anchor = Anchor {
        height: t,
        hash: tail.terminal_block_hash.clone(),
    };
    adapter.store.commit_anchor(&anchor, t, t).unwrap();
    let first = pass(&mut adapter, &resealed);
    adapter.acknowledge_applied(&first).unwrap();
    let held = store_rows(&adapter);
    let catalog = (cataloged(&adapter), exported(&adapter));

    // A replica that has not caught up still serves the previous set and
    // ends below the anchor: the pass waits, keeping store and catalog.
    let mut lagging = map.clone();
    lagging.shards.pop();
    let mut filters = CountingFilters::serving(serde_json::to_vec(&lagging).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(
            &watch(),
            &StaticChain::from_map(&resealed),
            &mut filters,
            &mut shards,
        )
        .unwrap();
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
    assert_eq!(batch.state, BatchState::Pending);
    assert_eq!(
        batch.progress,
        Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        }
    );
    assert!(batch.commits.is_empty());
    assert_eq!(
        adapter.store.set_identity().unwrap(),
        Some(SetIdentity::of_schema(&resealed, SCHEMA))
    );
    assert_eq!(store_rows(&adapter), held);
    assert_eq!((cataloged(&adapter), exported(&adapter)), catalog);

    // Once the wallet's chain no longer holds the anchor, as after a reorg,
    // the same map is a publication change.
    let mut watch = watch();
    let target = ChainPoint {
        height: block_height(t + 10).unwrap(),
        hash: BlockHash([9; 32]),
    };
    watch.target = Some(target);
    let mut reorged = StaticChain::from_map(&resealed);
    reorged.hashes.insert(t + 10, target.hash.to_string());
    reorged.hashes.insert(t, "aa".repeat(32));
    let mut filters = CountingFilters::serving(serde_json::to_vec(&lagging).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    assert!(matches!(
        adapter.recover(&watch, &reorged, &mut filters, &mut shards),
        Err(RecoveryError::PublicationChanged)
    ));
    assert_eq!(adapter.store.set_identity().unwrap(), None);

    // So is a map under the previous set that reaches the anchor.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &resealed);
    adapter.store.commit_anchor(&anchor, t, t).unwrap();
    publication_change(&mut adapter, &map);
}
