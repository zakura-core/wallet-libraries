use super::*;

#[test]
fn a_declared_re_cut_is_ready_and_keeps_the_exported_history() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, first) =
        recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
    let tail = first.commits[4].revision.clone();

    // The sealed history is exported again exactly as the wallet holds it,
    // anchors and coverage included. W and S3′ hold no stored facts, so
    // nothing is exported under them, and the renumbered tail replaces the
    // old one in its source.
    let batch = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(batch.commits.len(), 5);
    assert_eq!(batch.commits[..4], first.commits[..4]);
    let renumbered = &batch.commits[4].revision;
    assert_eq!(renumbered.source, tail.source);
    assert_eq!(renumbered.lineage, tail.lineage + 1);
    assert_eq!(batch.retired_revisions(), std::slice::from_ref(&tail));
    assert!(adapter.acknowledge_applied(&batch).is_err());
    adapter.acknowledge_reconciled(&batch).unwrap();
    let starts: Vec<u64> = before
        .shards
        .iter()
        .map(|entry| entry.start_height)
        .collect();
    assert_eq!(
        exported(&adapter),
        vec![
            (starts[0], 1),
            (starts[1], 1),
            (starts[2], 1),
            (starts[3], 1),
            (starts[4], 8)
        ]
    );
    // W and S3′ are cataloged, so a later regression is still caught.
    assert_eq!(cataloged(&adapter), 7);
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);

    // A replay is ready, changes nothing and resolves nothing.
    let replay = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(replay.state, BatchState::Ready);
    assert_eq!(replay.commits, batch.commits);
    assert!(replay.retired_revisions().is_empty());
    adapter.acknowledge_applied(&replay).unwrap();
}

#[test]
fn a_renumbered_tail_succeeds_in_its_source_once_retrieved() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &before);
    let first = recut_pass(&mut adapter, &watch, &before, &chain);
    adapter.acknowledge_applied(&first).unwrap();
    // Until the renumbered tail is retrieved, the old one has no successor.
    withdraw_tail(&mut adapter, &after);
    let pending = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(pending.state, BatchState::Pending);
    assert!(pending.commits.is_empty());
    retrieve_tail(&mut adapter, &after);
    let ready = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(ready.state, BatchState::Ready);
    assert_eq!(
        ready.retired_revisions(),
        std::slice::from_ref(&first.commits[4].revision)
    );
}

#[test]
fn an_undeclared_re_cut_is_still_withdrawn() {
    let (before, after) = recut_pair();
    let mut undeclared = after.clone();
    undeclared.recuts.clear();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, _) =
        recut_companion(&dir.path().join("companion.sqlite"), &before, &undeclared);
    // S3's source is published at another sealed revision.
    let batch = recut_pass(&mut adapter, &watch, &undeclared, &chain);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
    );
    assert!(batch.commits.is_empty());
    assert!(adapter.acknowledge_applied(&batch).is_err());

    // Merging the last sealed shards instead renumbers only the tail. Their
    // heights are published under another source.
    let s = &before.shards;
    let merged = recut_map(
        vec![
            s[0].clone(),
            s[1].clone(),
            recut_entry(
                2,
                WIDE,
                (s[2].start_height, s[3].end_height),
                (0, true),
                0x32,
            ),
            recut_entry(
                3,
                NARROW,
                (s[4].start_height, after.shards[3].end_height),
                (7, false),
                0x34,
            ),
        ],
        vec![],
    );
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, _) = recut_companion(&dir.path().join("companion.sqlite"), &before, &merged);
    let batch = recut_pass(
        &mut adapter,
        &watch,
        &merged,
        &accepting(&[&before, &merged]),
    );
    assert_eq!(batch.state, BatchState::Withdrawn(WithdrawnCause::Retired));
    assert!(batch.commits.is_empty());
}

#[test]
fn a_sealed_rewrite_the_sync_refuses_is_withdrawn_before_any_retrieval() {
    let (before, after) = recut_pair();
    let mut undeclared = after.clone();
    undeclared.recuts.clear();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &before);
    let first = recut_pass(&mut adapter, &watch, &before, &chain);
    adapter.acknowledge_applied(&first).unwrap();
    let held = (store_rows(&adapter), catalog_rows(&adapter));
    // The sync finds sealed coverage the map rewrites over blocks the
    // wallet's chain still accepts, and refuses it before reading.
    let mut filters = CountingFilters::serving(serde_json::to_vec(&undeclared).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(&watch, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
    );
    assert_eq!(
        batch.progress,
        Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        }
    );
    assert!(batch.commits.is_empty());
    assert!(adapter.acknowledge_applied(&batch).is_err());
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
    assert_eq!((store_rows(&adapter), catalog_rows(&adapter)), held);
}

#[test]
fn a_declaration_must_match_the_catalog() {
    let (before, mut after) = recut_pair();
    // S2 is declared at a revision number it was never published under.
    after.recuts[0].superseded[1].revision = 1;
    after.check_shape().unwrap();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, _) = recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
    let recorded = catalog_rows(&adapter);
    let batch = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
    assert!(batch.commits.is_empty());
    assert!(adapter.acknowledge_applied(&batch).is_err());
    // Only the published W, S3′ and T′ were recorded, not the revision the
    // declaration claimed for S2.
    let rows = catalog_rows(&adapter);
    assert_eq!(rows.len(), recorded.len() + 3);
    let s2 = before.shards[2].start_height;
    assert!(rows.iter().all(|row| row.1 != s2 || row.2 == 1));
}

#[test]
fn a_successor_must_rise_above_its_declared_revision() {
    let (_, after) = recut_pair();
    // The map's own shape check refuses a renumbered shard that does not
    // take a higher revision, before any catalog transaction.
    let mut level = after.clone();
    level.shards[2].revision = 0;
    assert!(level.check_shape().is_err());
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &after);
    assert!(matches!(
        adapter.normalize(
            &watching(&after),
            level.clone(),
            MORE,
            &accepting(&[&after])
        ),
        Err(RecoveryError::Failure(_))
    ));

    // The catalog checks the same rule by source and lineage, with no
    // history: a fresh companion's pass, given such revisions directly.
    let set = SetIdentity::of_schema(&after, SCHEMA);
    let published = |map: &ShardMap| -> Vec<Published> {
        map.shards
            .iter()
            .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
            .collect()
    };
    let declared = |map: &ShardMap| -> Vec<Published> {
        map.recuts
            .iter()
            .flat_map(|recut| &recut.superseded)
            .map(|shard| Published::declared(&adapter.binding, &set, shard).unwrap())
            .collect()
    };
    let mut lower = after.clone();
    lower.recuts[0].superseded[2].revision = 2;
    let mut conflicting = after.clone();
    let mut again = superseded(&after.shards[2]);
    again.revision = 0;
    again.manifest_digest = "ee".repeat(32);
    conflicting.recuts.push(Recut {
        epoch: 2,
        from_height: again.start_height,
        superseded: vec![again],
    });
    let fresh = tempfile::tempdir().unwrap();
    let mut fresh =
        TransparentHistoryRecovery::open(fresh.path().join("fresh.sqlite"), config()).unwrap();
    for (map, cause) in [
        (&level, WithdrawnCause::Equivocation),
        (&lower, WithdrawnCause::Regression),
        (&conflicting, WithdrawnCause::Equivocation),
    ] {
        let (published, declared) = (published(map), declared(map));
        let mut pass = catalog::CatalogPass::begin(&mut fresh.catalog, &published, &[]).unwrap();
        pass.check_declarations(&published, &declared);
        assert_eq!(pass.state(), BatchState::Withdrawn(cause));
    }
    // The well-formed declaration passes.
    let (published, declared) = (published(&after), declared(&after));
    let mut pass = catalog::CatalogPass::begin(&mut fresh.catalog, &published, &[]).unwrap();
    pass.check_declarations(&published, &declared);
    assert_eq!(pass.state(), BatchState::Ready);
}

#[test]
fn the_source_ignores_the_shard_id() {
    let (before, after) = recut_pair();
    let config = config();
    let binding = catalog::companion_binding([
        &config.source,
        &config.account_binding,
        config.origin.as_bytes(),
        SCHEMA.as_bytes(),
    ]);
    let set = SetIdentity::of_schema(&after, SCHEMA);
    let source = |entry: &ShardMapEntry| {
        catalog::source_identity(&binding, &set, &entry.geometry, entry.start_height).unwrap()
    };
    // Renumbered at the same heights: the same source.
    for (old, new) in [
        (&before.shards[3], &after.shards[2]),
        (&before.shards[4], &after.shards[3]),
    ] {
        assert_ne!(old.shard_id, new.shard_id);
        assert_eq!(source(old), source(new));
    }
    // Re-cut under another geometry from the same height: another source.
    assert_ne!(source(&before.shards[1]), source(&after.shards[1]));
    // A declared revision has the identity it had when published.
    let declared = Published::declared(&binding, &set, &after.recuts[0].superseded[2]).unwrap();
    let published = Published::of(
        &binding,
        &SetIdentity::of_schema(&before, SCHEMA),
        &before.shards[3],
    )
    .unwrap();
    assert_eq!(declared.revision, published.revision);
    // The formula, as documented.
    let entry = &after.shards[2];
    let seal = serde_json::to_vec(&set.seal[&entry.geometry]).unwrap();
    let lp = |hash: &mut Sha256, value: &[u8]| {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    };
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-source-v3");
    hash.update(binding);
    lp(&mut hash, SCHEMA.as_bytes());
    lp(&mut hash, set.network.as_bytes());
    lp(&mut hash, set.genesis_hash.as_bytes());
    lp(&mut hash, set.profile.as_bytes());
    hash.update(set.range_envelope_version.to_le_bytes());
    hash.update(set.start_height.to_le_bytes());
    lp(&mut hash, entry.geometry.as_bytes());
    lp(&mut hash, &seal);
    hash.update(entry.start_height.to_le_bytes());
    assert_eq!(<[u8; 32]>::from(hash.finalize()), source(entry));
}

#[test]
fn a_lagging_replica_behind_a_re_cut_is_pending() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, _) = recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
    let batch = recut_pass(&mut adapter, &watch, &after, &chain);
    adapter.acknowledge_reconciled(&batch).unwrap();
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);
    // The store has since read S3′ as well, as for a script added after
    // the re-cut: it holds sealed history only the re-cut map publishes.
    let script = address_script(watch.addresses[0].address);
    let s3 = &after.shards[2];
    let end = (s3.end_height, s3.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(s3, &s3.manifest_digest, end, &script, vec![]))
        .unwrap();
    let held = (store_rows(&adapter), catalog_rows(&adapter));

    // A replica still serving the map from before the re-cut. The sync
    // refuses it as a rewrite of that history before reading anything,
    // and the pass, seeing an epoch below the one it recorded, takes it
    // for a lagging replica: pending and behind, touching nothing.
    let mut filters = CountingFilters::serving(serde_json::to_vec(&before).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    let lagging = adapter
        .recover(&watch, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!(lagging.state, BatchState::Pending);
    assert_eq!(
        lagging.progress,
        Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        }
    );
    assert!(lagging.commits.is_empty());
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
    assert_eq!((store_rows(&adapter), catalog_rows(&adapter)), held);
    // A pass over the earlier map records no lower epoch.
    recut_pass(&mut adapter, &watch, &before, &chain);
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);

    // A publication change restarts the store, and with it the epoch.
    let resealed = resealing(&after, 1);
    let mut filters = CountingFilters::serving(serde_json::to_vec(&resealed).unwrap());
    assert!(matches!(
        adapter.recover(&watch, &accepting(&[&resealed]), &mut filters, &mut shards),
        Err(RecoveryError::PublicationChanged)
    ));
    assert_eq!(adapter.store.set_identity().unwrap(), None);
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 0);
}

#[test]
fn a_page_under_a_declared_revision_is_completed_once() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let script = address_script(watch.addresses[0].address);
    let s3 = &before.shards[3];
    // A companion that left page work on S3, which the wallet applied.
    let opened = |dir: &tempfile::TempDir| {
        let mut adapter = seeded(dir, &script, before.start_height);
        for entry in &before.shards {
            let end = (entry.end_height, entry.terminal_block_hash.as_str());
            let mut commit = covered(entry, &entry.manifest_digest, end, &script, vec![]);
            if entry.shard_id == s3.shard_id {
                commit.covered_scripts.clear();
                commit.pending_upsert = vec![store_page(entry, &script, 3)];
            }
            adapter.store.commit_shard(commit).unwrap();
        }
        let first = recut_pass(&mut adapter, &watch, &before, &chain);
        assert_eq!(first.state, BatchState::Ready);
        adapter.acknowledge_applied(&first).unwrap();
        let opening = first.commits[3].clone();
        assert_eq!(opening.opened_pages.len(), 1);
        let mut holding = watch.clone();
        holding.pending_pages = vec![PendingPage {
            request: opening.opened_pages[0].clone(),
            revision: opening.revision.clone(),
            target: opening.context.target,
        }];
        (adapter, holding, opening)
    };
    let completions = |batch: &RecoveryBatch<u32>, page: &[u8]| -> Vec<RecoveryRevision> {
        batch
            .commits
            .iter()
            .filter(|commit| commit.completed_pages.iter().any(|done| done == page))
            .map(|commit| commit.revision.clone())
            .collect()
    };

    // The sync dropped the store's page work under S3, which the map no
    // longer publishes, and retrieved S3′ in its place. No commit of S3
    // follows, so a completion under S3's own revision does, once S3′
    // covers the page.
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, holding, opening) = opened(&dir);
    adapter
        .store
        .rollback_above(
            &Anchor {
                height: s3.start_height - 1,
                hash: s3.parent_block_hash.clone(),
            },
            "superseded page work",
        )
        .unwrap();
    for entry in &after.shards[2..] {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
            .unwrap();
    }
    let batch = recut_pass(&mut adapter, &holding, &after, &chain);
    assert_eq!(batch.state, BatchState::Ready);
    let page = &opening.opened_pages[0].page;
    assert_eq!(completions(&batch, page), vec![opening.revision.clone()]);
    let completion = batch.commits.last().unwrap();
    assert_eq!(
        completion.anchor,
        ChainPoint {
            height: block_height(s3.end_height).unwrap(),
            hash: block_hash_from_display(&s3.terminal_block_hash).unwrap(),
        }
    );
    assert!(completion.coverage.is_empty());
    // S3′, in S3's source, carries the coverage.
    assert!(
        batch
            .commits
            .iter()
            .any(|commit| commit.revision.source == opening.revision.source
                && commit.revision.lineage == opening.revision.lineage + 1
                && !commit.coverage.is_empty())
    );

    // The store finished the page under S3 before the re-cut, so S3's own
    // commit covers and completes it, and nothing completes it again.
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, holding, opening) = opened(&dir);
    let pending = adapter.store.pending().unwrap();
    let end = (s3.end_height, s3.terminal_block_hash.as_str());
    let mut done = covered(s3, &s3.manifest_digest, end, &script, vec![]);
    done.pending_complete = vec![pending[0].id.unwrap()];
    adapter.store.commit_shard(done).unwrap();
    retrieve_tail(&mut adapter, &after);
    let batch = recut_pass(&mut adapter, &holding, &after, &chain);
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(completions(&batch, page), vec![opening.revision.clone()]);
    assert!(
        !batch
            .commits
            .iter()
            .find(|commit| commit.revision == opening.revision)
            .unwrap()
            .coverage
            .is_empty()
    );
}

#[test]
fn a_recreated_companion_after_a_re_cut_collides_with_nothing() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, first) =
        recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
    let kept = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(kept.state, BatchState::Ready);
    adapter.acknowledge_reconciled(&kept).unwrap();

    // The companion is lost after the re-cut. Its replacement retrieves the
    // re-cut publication from scratch.
    let mut recreated = covering(&dir.path().join("recreated.sqlite"), &after);
    let healed = recut_pass(&mut recreated, &watch, &after, &chain);
    assert_eq!(healed.state, BatchState::Ready);
    assert!(healed.retired_revisions().is_empty());
    assert_eq!(healed.commits.len(), after.shards.len());
    // S0 and T′ reproduce what the wallet holds; S3′ rises in S3's source;
    // W is a new source.
    assert_eq!(healed.commits[0], kept.commits[0]);
    assert_eq!(healed.commits[3].revision, kept.commits[4].revision);
    assert_eq!(
        healed.commits[2].revision.source,
        first.commits[3].revision.source
    );
    assert_eq!(
        healed.commits[2].revision.lineage,
        first.commits[3].revision.lineage + 1
    );
    // The wallet's integrity rule: within a source, a lineage names one
    // revision, and a revision one lineage.
    let mut lineages: BTreeMap<(Vec<u8>, u64), RecoveryRevision> = BTreeMap::new();
    let mut revisions: BTreeMap<(Vec<u8>, Vec<u8>), u64> = BTreeMap::new();
    for commit in first
        .commits
        .iter()
        .chain(&kept.commits)
        .chain(&healed.commits)
    {
        let revision = &commit.revision;
        let named = lineages
            .entry((revision.source.clone(), revision.lineage))
            .or_insert_with(|| revision.clone());
        assert_eq!(named, revision);
        let lineage = revisions
            .entry((revision.source.clone(), revision.revision.clone()))
            .or_insert(revision.lineage);
        assert_eq!(*lineage, revision.lineage);
    }
}

#[test]
fn a_version_two_companion_is_rebuilt_keeping_its_store() {
    let map = map();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let mut adapter = covering(&path, &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    let store = store_rows(&adapter);
    drop(adapter);
    // Back to the v2 layout: a catalog keyed by shard id, with a row.
    let v2 = Connection::open(&path).unwrap();
    v2.execute_batch(
        "DROP TABLE pir_bridge_catalog;
         CREATE TABLE pir_bridge_catalog (
            source BLOB NOT NULL CHECK(length(source)=32),
            shard_id INTEGER NOT NULL CHECK(shard_id>=0),
            digest TEXT NOT NULL,
            sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
            lineage INTEGER NOT NULL CHECK(lineage>0),
            revision BLOB NOT NULL CHECK(length(revision)=32),
            height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
            hash BLOB NOT NULL CHECK(length(hash)=32),
            exported INTEGER NOT NULL DEFAULT 0 CHECK(exported IN (0,1)),
            current INTEGER NOT NULL DEFAULT 0 CHECK(current IN (0,1)),
            PRIMARY KEY(source,digest,sealed), UNIQUE(source,lineage), UNIQUE(source,revision));
         INSERT INTO pir_bridge_catalog VALUES
            (zeroblob(32), 1, 'aa', 0, 1, zeroblob(32), 1, zeroblob(32), 1, 1);
         UPDATE pir_bridge_binding SET value='transparent-reference-companion-v2' WHERE key='format';
         DELETE FROM pir_bridge_binding WHERE key='recut-epoch';",
    )
    .unwrap();
    // Another account's companion is still refused, and changes nothing.
    let mut other = config();
    other.account_binding = vec![2];
    assert!(TransparentHistoryRecovery::open(&path, other).is_err());
    let format = |conn: &Connection| -> String {
        conn.query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='format'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(format(&v2), "transparent-reference-companion-v2");

    // Opening rebuilds the catalog in place, empty, and keeps the store.
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    assert_eq!(format(&v2), "transparent-reference-companion-v3");
    assert_eq!(cataloged(&adapter), 0);
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 0);
    assert_eq!(store_rows(&adapter), store);
    // The next pass exports the stored facts again, without retrieving.
    let again = pass(&mut adapter, &map);
    assert_eq!(again.state, BatchState::Ready);
    assert_eq!(again.commits, first.commits);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
}

#[test]
fn a_page_under_a_declared_revision_with_saved_events_completes_once() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let script = address_script(watch.addresses[0].address);
    let s3 = &before.shards[3];
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = seeded(&dir, &script, before.start_height);
    // A budget-limited pass saved a receive under S3 and left the rest of
    // its pages, and the wallet holds both.
    let saved =
        TransparentEvent::Receive(zakura_transparent_private_shared::events::ReceiveEvent {
            metadata: None,
            height: (s3.start_height + 10) as u32,
            txid: zakura_transparent_private_shared::events::Txid([7; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
    for entry in &before.shards {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        let mut commit = covered(entry, &entry.manifest_digest, end, &script, vec![]);
        if entry.shard_id == s3.shard_id {
            commit = covered(entry, &entry.manifest_digest, end, &script, vec![saved]);
            commit.covered_scripts.clear();
            commit.pending_upsert = vec![store_page(entry, &script, 3)];
        }
        adapter.store.commit_shard(commit).unwrap();
    }
    let first = recut_pass(&mut adapter, &watch, &before, &chain);
    assert_eq!(first.state, BatchState::Ready);
    adapter.acknowledge_applied(&first).unwrap();
    let opening = first.commits[3].clone();
    assert_eq!(opening.opened_pages.len(), 1);
    assert_eq!(opening.receives.len(), 1);
    let mut holding = watch.clone();
    holding.pending_pages = vec![PendingPage {
        request: opening.opened_pages[0].clone(),
        revision: opening.revision.clone(),
        target: opening.context.target,
    }];

    // Across the declared re-cut the sync drops the page work under S3,
    // whose last block the wallet's chain accepts, and keeps what it saved;
    // the tail is read again.
    let pending = adapter.store.pending().unwrap();
    adapter
        .store
        .commit_shard(crate::engine::ShardCommit {
            pending_complete: vec![pending[0].id.unwrap()],
            ..Default::default()
        })
        .unwrap();
    withdraw_tail(&mut adapter, &before);
    let read = |adapter: &mut TransparentHistoryRecovery, entry: &ShardMapEntry| {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
            .unwrap();
    };
    read(&mut adapter, &after.shards[3]);
    assert_eq!(adapter.store.events().unwrap().len(), 1);
    assert!(adapter.store.pending().unwrap().is_empty());
    let page = &opening.opened_pages[0].page;
    let completing = |batch: &RecoveryBatch<u32>| -> Vec<TransparentLedgerCommit<u32>> {
        batch
            .commits
            .iter()
            .filter(|commit| commit.completed_pages.contains(page))
            .cloned()
            .collect()
    };
    // Until the script's gap is read again, the page stays open.
    let batch = recut_pass(&mut adapter, &holding, &after, &chain);
    assert_eq!(batch.state, BatchState::Ready);
    assert!(completing(&batch).is_empty());
    adapter.acknowledge_reconciled(&batch).unwrap();

    // Once it is, under S3′, S3's own commit carries the saved receive and
    // S3′ the coverage. The page is completed once, under S3's revision,
    // in a completion-only commit after both, so the wallet applies the
    // coverage that completes it first.
    read(&mut adapter, &after.shards[2]);
    let batch = recut_pass(&mut adapter, &holding, &after, &chain);
    assert_eq!(batch.state, BatchState::Ready);
    let completing = completing(&batch);
    assert_eq!(completing.len(), 1);
    assert_eq!(completing[0].revision, opening.revision);
    assert_eq!(completing[0].completed_pages, vec![page.clone()]);
    assert!(completing[0].receives.is_empty() && completing[0].coverage.is_empty());
    assert_eq!(
        completing[0].anchor,
        ChainPoint {
            height: block_height(s3.end_height).unwrap(),
            hash: block_hash_from_display(&s3.terminal_block_hash).unwrap(),
        }
    );
    let position = |found: &dyn Fn(&TransparentLedgerCommit<u32>) -> bool| {
        batch.commits.iter().position(found).unwrap()
    };
    let saved_at = position(&|commit| {
        commit.revision == opening.revision && commit.receives == opening.receives
    });
    let covered_at = position(&|commit| {
        commit.revision.source == opening.revision.source
            && commit.revision.lineage == opening.revision.lineage + 1
            && !commit.coverage.is_empty()
    });
    let completed_at = position(&|commit| commit.completed_pages.contains(page));
    assert!(batch.commits[saved_at].completed_pages.is_empty());
    assert!(completed_at > saved_at && completed_at > covered_at);
}

#[test]
fn a_declared_revision_never_reuses_a_pruned_exported_lineage() {
    let base = map();
    let tail = base.shards[1].clone();
    let script = address_script(watch().addresses[0].address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    // The tail T, at lineage 1, is exported, then replaced and reconciled,
    // so the catalog prunes its row while the wallet keeps T for good.
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    let t = first.commits[1].revision.clone();
    let next = republished(&base, 1, 1, "5a".repeat(32));
    retrieve_tail(&mut adapter, &next);
    let replaced = pass(&mut adapter, &next);
    assert_eq!(replaced.retired_revisions(), std::slice::from_ref(&t));
    adapter.acknowledge_reconciled(&replaced).unwrap();
    assert_eq!(cataloged(&adapter), 2);
    assert!(
        catalog_rows(&adapter)
            .iter()
            .all(|row| row.1 != tail.start_height || row.2 != 1)
    );

    // A map declares a sealed revision at the tail's geometry and start, at
    // revision 0, so at T's source and lineage, under a digest the store
    // holds a fact under.
    let planted = "77".repeat(32);
    let end = tail.start_height + 50;
    let terminal = "ab".repeat(32);
    let mut forged = republished(&base, 1, 2, "5b".repeat(32));
    forged.recuts = vec![Recut {
        epoch: 1,
        from_height: tail.start_height,
        superseded: vec![SupersededShard {
            shard_id: tail.shard_id,
            geometry: tail.geometry.clone(),
            start_height: tail.start_height,
            end_height: end,
            terminal_block_hash: terminal.clone(),
            manifest_digest: planted.clone(),
            revision: 0,
            sealed: true,
        }],
    }];
    forged.check_shape().unwrap();
    retrieve_tail(&mut adapter, &forged);
    let receive =
        TransparentEvent::Receive(zakura_transparent_private_shared::events::ReceiveEvent {
            metadata: None,
            height: (tail.start_height + 10) as u32,
            txid: zakura_transparent_private_shared::events::Txid([9; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
    let mut planted_entry = tail.clone();
    planted_entry.end_height = end;
    planted_entry.sealed = true;
    let mut facts = covered(
        &planted_entry,
        &planted,
        (end, &terminal),
        &script,
        vec![receive],
    );
    facts.covered_scripts.clear();
    adapter.store.commit_shard(facts).unwrap();
    let mut chain = StaticChain::from_map(&forged);
    chain.hashes.insert(end, terminal);
    // The wallet would refuse it as an integrity failure and recovery suspension the
    // account, so the companion refuses it first.
    let batch = adapter
        .normalize(&watch(), forged.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
    assert!(batch.commits.is_empty());
    // A published revision at that lineage is refused the same way.
    let colliding = republished(&base, 1, 0, "c0".repeat(32));
    retrieve_tail(&mut adapter, &colliding);
    assert_eq!(
        pass(&mut adapter, &colliding).state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
}

#[test]
fn a_refused_declaration_does_not_raise_the_epoch() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    let dir = tempfile::tempdir().unwrap();
    let (mut adapter, _) = recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
    // A map misstating a declared revision at the highest epoch is refused,
    // and records no epoch.
    let mut forged = after.clone();
    forged.recuts[0].superseded[1].revision = 1;
    forged.recuts[0].epoch = u32::MAX;
    forged.check_shape().unwrap();
    let batch = recut_pass(&mut adapter, &watch, &forged, &chain);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 0);
    // Nor does a ready map whose re-cut starts above everything the store
    // read and supersedes nothing it holds: such a map rewrites nothing the
    // store holds, so a store that read only below it needs no guard.
    let other = tempfile::tempdir().unwrap();
    let script = address_script(watch.addresses[0].address);
    let mut plain = seeded(&other, &script, before.start_height);
    for entry in &before.shards[..3] {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        plain
            .store
            .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
            .unwrap();
    }
    let s3 = &before.shards[3];
    let mut ghost = superseded(&recut_entry(9, WIDE, (1, 2), (0, true), 0x99));
    ghost.start_height = s3.start_height;
    ghost.end_height = s3.end_height;
    let mut idle = before.clone();
    idle.recuts = vec![Recut {
        epoch: u32::MAX,
        from_height: s3.start_height,
        superseded: vec![ghost],
    }];
    idle.check_shape().unwrap();
    let ready = recut_pass(&mut plain, &watch, &idle, &chain);
    assert_eq!(ready.state, BatchState::Ready);
    assert_eq!(catalog::recut_epoch(&plain.catalog).unwrap(), 0);
    // The honest re-cut map is not held behind, and its ready pass, over
    // revisions the store holds, records its epoch.
    let honest = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(honest.state, BatchState::Ready);
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);
    let mut filters = CountingFilters::serving(serde_json::to_vec(&after).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    let synced = adapter
        .recover(&watch, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!(synced.state, BatchState::Ready);
    assert_eq!(filters.filters, 0);
}

#[test]
fn a_companion_that_read_the_re_cut_map_holds_older_maps_behind() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    // A companion recreated after the re-cut, or one born above it, holds
    // nothing the re-cut superseded, only what the re-cut map publishes.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &after);
    let first = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(first.state, BatchState::Ready);
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), 1);
    adapter.acknowledge_applied(&first).unwrap();
    let held = (store_rows(&adapter), catalog_rows(&adapter));

    // A replica still serving the map from before the re-cut would rewrite
    // what the store read. The pass waits for it before the sync, and
    // touches nothing.
    let mut filters = CountingFilters::serving(serde_json::to_vec(&before).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    let lagging = adapter
        .recover(&watch, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!(lagging.state, BatchState::Pending);
    assert_eq!(
        lagging.progress,
        Progress {
            covered_through: 0,
            outcome: Outcome::Behind,
        }
    );
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
    assert_eq!((store_rows(&adapter), catalog_rows(&adapter)), held);
}

#[test]
fn a_forged_epoch_never_holds_an_honest_map_back() {
    let base = map();
    let tail = base.shards[1].clone();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    assert_eq!(first.state, BatchState::Ready);
    adapter.acknowledge_applied(&first).unwrap();
    // The same shards, plus a re-cut at the tail's start at the highest
    // epoch, superseding a revision nobody published. It passes every
    // check, the store read the tail it starts at, and its epoch is
    // recorded.
    let mut forged = base.clone();
    forged.recuts = vec![Recut {
        epoch: u32::MAX,
        from_height: tail.start_height,
        superseded: vec![SupersededShard {
            shard_id: tail.shard_id,
            geometry: base.shards[0].geometry.clone(),
            start_height: tail.start_height,
            end_height: tail.end_height,
            terminal_block_hash: tail.terminal_block_hash.clone(),
            manifest_digest: "ee".repeat(32),
            revision: 0,
            sealed: false,
        }],
    }];
    forged.check_shape().unwrap();
    let batch = pass(&mut adapter, &forged);
    assert_eq!(batch.state, BatchState::Ready);
    adapter.acknowledge_applied(&batch).unwrap();
    assert_eq!(catalog::recut_epoch(&adapter.catalog).unwrap(), u32::MAX);

    // The honest map, served afterwards, rewrites nothing the store holds,
    // so it syncs and is ready.
    let recovered = |adapter: &mut TransparentHistoryRecovery, map: &ShardMap| {
        let mut filters = CountingFilters::serving(serde_json::to_vec(map).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(
                &watch(),
                &StaticChain::from_map(map),
                &mut filters,
                &mut shards,
            )
            .unwrap();
        assert_eq!(filters.filters, 0);
        batch
    };
    let honest = recovered(&mut adapter, &base);
    assert_eq!(honest.state, BatchState::Ready);
    assert_eq!(honest.progress.outcome, Outcome::Complete);

    // The forged epoch can only soften a real contradiction: a map that
    // rewrites the sealed shard the store holds is taken for a lagging
    // replica, pending instead of withdrawn.
    let rewritten = republished(&base, 0, 0, "e0".repeat(32));
    let softened = recovered(&mut adapter, &rewritten);
    assert_eq!(softened.state, BatchState::Pending);
    assert_eq!(softened.progress.outcome, Outcome::Behind);
    // Without a recorded epoch the same map is withdrawn.
    let fresh = tempfile::tempdir().unwrap();
    let mut plain = covering(&fresh.path().join("companion.sqlite"), &base);
    let first = pass(&mut plain, &base);
    plain.acknowledge_applied(&first).unwrap();
    assert_eq!(
        recovered(&mut plain, &rewritten).state,
        BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
    );
}

#[test]
fn a_digest_declared_under_another_geometry_or_start_is_an_equivocation() {
    let (before, after) = recut_pair();
    let (watch, chain) = (watching(&after), accepting(&[&before, &after]));
    // S2's digest declared under the wide geometry, which gives it another
    // source; or S2 declared from a height after its start, with S1 ending
    // there.
    let mut moved = after.clone();
    moved.recuts[0].superseded[1].geometry = WIDE.into();
    let mut shifted = after.clone();
    shifted.recuts[0].superseded[0].end_height += 1;
    shifted.recuts[0].superseded[0].terminal_block_hash =
        recut_hash(shifted.recuts[0].superseded[0].end_height);
    shifted.recuts[0].superseded[1].start_height += 1;
    let mut chain = chain;
    let shifted_end = shifted.recuts[0].superseded[0].end_height;
    chain.hashes.insert(shifted_end, recut_hash(shifted_end));
    for map in [moved, shifted] {
        map.check_shape().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (mut adapter, _) =
            recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        let batch = recut_pass(&mut adapter, &watch, &map, &chain);
        assert_eq!(
            batch.state,
            BatchState::Withdrawn(WithdrawnCause::Equivocation)
        );
        assert!(batch.commits.is_empty());
    }
}

#[test]
fn a_fact_under_a_declared_revision_must_fit_it() {
    let (before, after) = recut_pair();
    let watch = watching(&after);
    let script = address_script(watch.addresses[0].address);
    let (s1, s2) = (&before.shards[1], &before.shards[2]);
    let chain = accepting(&[&before, &after]);
    let fresh = |dir: &tempfile::TempDir| {
        let (adapter, _) = recut_companion(&dir.path().join("companion.sqlite"), &before, &after);
        adapter
    };
    // The wallet's chain holds another block where S1 ended, which no
    // published shard ends on: S1's facts rest on a branch the wallet
    // left, so the batch waits.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = fresh(&dir);
    let mut elsewhere = chain.clone();
    elsewhere.hashes.insert(s1.end_height, "e1".repeat(32));
    let batch = recut_pass(&mut adapter, &watch, &after, &elsewhere);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());

    // A fact outside S2's declared range does not fit it.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = fresh(&dir);
    let outside =
        TransparentEvent::Receive(zakura_transparent_private_shared::events::ReceiveEvent {
            metadata: None,
            height: (s2.end_height + 1) as u32,
            txid: zakura_transparent_private_shared::events::Txid([3; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
    let end = (s2.end_height, s2.terminal_block_hash.as_str());
    let mut stray = covered(s2, &s2.manifest_digest, end, &script, vec![outside]);
    stray.covered_scripts.clear();
    adapter.store.commit_shard(stray).unwrap();
    let batch = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());

    // Nor does coverage under S2's digest that names another shard id.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = fresh(&dir);
    let mut renamed = s2.clone();
    renamed.shard_id = 7;
    adapter
        .store
        .commit_shard(covered(&renamed, &s2.manifest_digest, end, &script, vec![]))
        .unwrap();
    let batch = recut_pass(&mut adapter, &watch, &after, &chain);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
}
