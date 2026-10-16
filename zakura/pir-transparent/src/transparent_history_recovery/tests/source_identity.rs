use super::*;

#[test]
fn source_identity_binds_account_origin_and_schema() {
    let map = map();
    let dir = tempfile::tempdir().unwrap();
    let sources = |name: &str, config: TransparentHistoryRecoveryConfig| -> Vec<Vec<u8>> {
        let mut adapter = covering_as(&dir.path().join(name), config, &map);
        let batch = pass(&mut adapter, &map);
        assert_eq!(batch.state, BatchState::Ready);
        batch
            .commits
            .iter()
            .map(|commit| commit.revision.source.clone())
            .collect()
    };
    let base = sources("base.sqlite", config());
    assert_eq!(base.len(), 2);
    assert_ne!(base[0], base[1]);
    // Reopening the companion derives the same sources.
    let mut reopened =
        TransparentHistoryRecovery::open(dir.path().join("base.sqlite"), config()).unwrap();
    let again: Vec<_> = revisions(&pass(&mut reopened, &map))
        .into_iter()
        .map(|revision| revision.source)
        .collect();
    assert_eq!(again, base);
    // Another account or origin derives other sources for every shard.
    let mut account = config();
    account.account_binding = vec![2];
    let mut origin = config();
    origin.origin = "https://another-origin.test".into();
    let account = sources("account.sqlite", account);
    let origin = sources("origin.sqlite", origin);
    for other in [&account, &origin] {
        for (theirs, ours) in other.iter().zip(&base) {
            assert_ne!(theirs, ours);
        }
    }
    assert_ne!(account, origin);
    // So does another schema under the same account and origin.
    let config = config();
    let set = SetIdentity::of_schema(&map, SCHEMA);
    let schema = |schema: &str| {
        let binding = catalog::companion_binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            schema.as_bytes(),
        ]);
        let entry = &map.shards[1];
        catalog::source_identity(&binding, &set, &entry.geometry, entry.start_height)
            .unwrap()
            .to_vec()
    };
    assert_eq!(schema(SCHEMA), base[1]);
    assert_ne!(schema("transparent-shard-v10"), base[1]);
}

#[test]
fn source_identity_survives_a_new_geometry_tier() {
    let map = map();
    let mut grown = map.clone();
    grown.seal.insert(
        "recent-1k-2k".into(),
        SealParameters {
            max_scripts: 1,
            max_page_rows: 2,
            max_txids: 3,
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let before = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&before).unwrap();
    // The bound companion continues into the grown set with the same sources.
    let after = pass(&mut adapter, &grown);
    assert_eq!(after.state, BatchState::Ready);
    assert_eq!(revisions(&after), revisions(&before));
    assert_eq!(cataloged(&adapter), 2);
    // A companion first bound after the tier appeared derives identical triples.
    let mut recreated = covering(&dir.path().join("recreated.sqlite"), &grown);
    assert_eq!(revisions(&pass(&mut recreated, &grown)), revisions(&before));
}

#[test]
fn a_changed_seal_changes_only_its_geometrys_sources() {
    let map = map();
    let (archive, recent) = (&map.shards[0], &map.shards[1]);
    assert_ne!(archive.geometry, recent.geometry);
    let mut resealed = map.clone();
    resealed.seal.get_mut(&recent.geometry).unwrap().max_scripts += 1;
    let config = config();
    let binding = catalog::companion_binding([
        &config.source,
        &config.account_binding,
        config.origin.as_bytes(),
        SCHEMA.as_bytes(),
    ]);
    let set = SetIdentity::of_schema(&map, SCHEMA);
    let reset = SetIdentity::of_schema(&resealed, SCHEMA);
    let source = |set: &SetIdentity, entry: &ShardMapEntry| {
        catalog::source_identity(&binding, set, &entry.geometry, entry.start_height).unwrap()
    };
    assert_eq!(source(&set, archive), source(&reset, &resealed.shards[0]));
    assert_ne!(source(&set, recent), source(&reset, &resealed.shards[1]));
    // A bound companion does not continue into the resealed set.
    assert!(!set.continues(&reset));
}

#[test]
fn a_recreated_companion_distinguishes_a_shifted_shard_boundary() {
    let original = map();
    let recent = &original.shards[1];
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("original.sqlite"), &original);
    let before = pass(&mut adapter, &original);
    assert_eq!(before.state, BatchState::Ready);
    let prior = revisions(&before)[1].clone();

    // Re-cutting the archive geometry can reuse a recent shard's id for a
    // different height range, without changing its geometry or revision
    // number. Both directions must give that range another source.
    for start in [recent.start_height - 1, recent.start_height + 1] {
        let mut recut = original.clone();
        recut
            .seal
            .get_mut(&original.shards[0].geometry)
            .unwrap()
            .max_scripts += 1;
        recut.shards[0].end_height = start - 1;
        recut.shards[1].start_height = start;
        recut.shards[1].manifest_digest = "77".repeat(32);
        recut.check_shape().unwrap();
        assert!(
            !SetIdentity::of_schema(&original, SCHEMA)
                .continues(&SetIdentity::of_schema(&recut, SCHEMA))
        );

        let path = dir.path().join(format!("recut-{start}.sqlite"));
        let mut recreated = covering(&path, &recut);
        let batch = pass(&mut recreated, &recut);
        assert_eq!(batch.state, BatchState::Ready);
        let next = revisions(&batch)[1].clone();
        assert_eq!(next.lineage, prior.lineage);
        assert_ne!(next.revision, prior.revision);
        assert_ne!(next.source, prior.source);

        // Reopening unchanged data still reproduces the same identity.
        drop(recreated);
        let mut reopened = TransparentHistoryRecovery::open(&path, config()).unwrap();
        assert_eq!(revisions(&pass(&mut reopened, &recut))[1], next);
    }
}

#[test]
fn lineage_follows_the_published_revision() {
    let map = republished(&map(), 1, 7, map().shards[1].manifest_digest.clone());
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let batch = pass(&mut adapter, &map);
    assert_eq!(batch.state, BatchState::Ready);
    let lineages: Vec<_> = revisions(&batch)
        .iter()
        .map(|revision| revision.lineage)
        .collect();
    assert_eq!(lineages, vec![1, 8]);
    for (revision, entry) in revisions(&batch).iter().zip(&map.shards) {
        let mut identity = Sha256::new();
        identity.update(b"transparent-reference-revision-v2");
        identity.update(entry.manifest_digest.as_bytes());
        identity.update([u8::from(entry.sealed)]);
        assert_eq!(revision.revision, identity.finalize().to_vec());
        assert_eq!(revision.sealed, entry.sealed);
        assert_eq!(
            revision.publication.height,
            block_height(entry.end_height).unwrap()
        );
        assert_eq!(
            revision.publication.hash,
            block_hash_from_display(&entry.terminal_block_hash).unwrap()
        );
    }
    // A recreated companion reproduces identical triples.
    let mut recreated = covering(&dir.path().join("recreated.sqlite"), &map);
    assert_eq!(revisions(&pass(&mut recreated, &map)), revisions(&batch));
}
