use super::*;

#[test]
fn exported_rows_are_classified_by_the_first_matching_rule() {
    let base = map();
    let mut sealed = republished(&base, 1, 1, "5e".repeat(32));
    sealed.shards[1].sealed = true;

    // A sealed shard published under another source is retired, not changed.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    let mut moved = base.clone();
    moved.shards[0].geometry = base.shards[1].geometry.clone();
    let batch = pass(&mut adapter, &moved);
    assert_eq!(batch.state, BatchState::Withdrawn(WithdrawnCause::Retired));

    // A sealed shard beyond the map's last shard is pending, not changed.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &sealed);
    let first = pass(&mut adapter, &sealed);
    adapter.acknowledge_applied(&first).unwrap();
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
    let mut behind = sealed.clone();
    behind.shards.pop();
    let batch = pass(&mut adapter, &behind);
    assert_eq!(batch.state, BatchState::Pending);

    // A changed sealed shard is withdrawn even when this batch commits its
    // source at a higher lineage, which would replace an unsealed one.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    let changed = republished(&base, 0, 1, "c1".repeat(32));
    adapter
        .store
        .rollback_above(
            &Anchor {
                height: base.start_height - 1,
                hash: base.shards[0].parent_block_hash.clone(),
            },
            "changed sealed shard",
        )
        .unwrap();
    cover(&mut adapter, &changed);
    let batch = pass(&mut adapter, &changed);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
    );
    assert!(batch.commits.is_empty());
    // The same row, settled against a commit of its source at a higher lineage.
    let set = SetIdentity::of_schema(&changed, SCHEMA);
    let published: Vec<_> = changed
        .shards
        .iter()
        .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
        .collect();
    assert_eq!(published[0].revision.source, revisions(&first)[0].source);
    let committed = BTreeMap::from([(published[0].revision.source.as_slice(), 2)]);
    let mut settling = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
    assert!(settling.settle(&published, &committed).unwrap().is_empty());
    assert_eq!(
        settling.state(),
        BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
    );
    drop(settling);

    // Rows whose source the map no longer publishes are matched by height.
    // The publisher sealed part of the tail and started a new one above
    // it, and the companion exported both.
    let tail = &base.shards[1];
    let cut_at = tail.start_height + 250;
    let mut cut = base.clone();
    cut.shards[1].sealed = true;
    cut.shards[1].revision = 1;
    cut.shards[1].end_height = cut_at - 1;
    cut.shards[1].terminal_block_hash = "c7".repeat(32);
    cut.shards[1].manifest_digest = "c1".repeat(32);
    cut.shards.push(ShardMapEntry {
        shard_id: 2,
        start_height: cut_at,
        parent_block_hash: "c7".repeat(32),
        manifest_digest: "c2".repeat(32),
        ..tail.clone()
    });
    cut.check_shape().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &cut);
    let first = pass(&mut adapter, &cut);
    assert_eq!(first.state, BatchState::Ready);
    adapter.acknowledge_applied(&first).unwrap();
    let settled = |adapter: &mut ReferenceRecovery, map: &ShardMap| {
        let set = SetIdentity::of_schema(map, SCHEMA);
        let published: Vec<_> = map
            .shards
            .iter()
            .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
            .collect();
        let mut settling = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
        settling.settle(&published, &BTreeMap::new()).unwrap();
        settling.state()
    };
    // A replica still serving the tail uncut is behind: below the cut its
    // source is published unsealed at a lower lineage, and above it the
    // new tail's start lies inside that unsealed tail.
    assert_eq!(settled(&mut adapter, &base), BatchState::Pending);
    // The same heights inside a sealed shard under another geometry, which
    // no re-cut declared, are retired.
    let mut merged = base.clone();
    merged.shards[1].geometry = base.shards[0].geometry.clone();
    merged.shards[1].sealed = true;
    merged.shards[1].manifest_digest = "d1".repeat(32);
    assert_eq!(
        settled(&mut adapter, &merged),
        BatchState::Withdrawn(WithdrawnCause::Retired)
    );
}

#[test]
fn retired_revisions_are_pruned_after_acknowledgment() {
    let mut map = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    for revision in 1..=50u32 {
        map = republished(&map, 1, revision, format!("{revision:064x}"));
        retrieve_tail(&mut adapter, &map);
        let batch = pass(&mut adapter, &map);
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(revisions(&batch)[1].lineage, u64::from(revision) + 1);
        assert_eq!(batch.retired_revisions().len(), 1);
        adapter.acknowledge_reconciled(&batch).unwrap();
        assert!(cataloged(&adapter) <= map.shards.len() as u64 + 2);
    }
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 51)]);
    assert_eq!(cataloged(&adapter), 2);
}

#[test]
fn store_caches_keep_only_named_revisions() {
    let map = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let retired = "0d".repeat(32);
    let setup = |digest: &str| SetupKey {
        set_digest: "set".into(),
        revision_digest: digest.into(),
        table: Table::Directory,
        segment: 0,
    };
    let named: Vec<&str> = map
        .shards
        .iter()
        .map(|entry| entry.manifest_digest.as_str())
        .collect();
    for digest in named.iter().copied().chain([retired.as_str()]) {
        adapter
            .store
            .put_filter(digest, "ff", false, b"filter")
            .unwrap();
        adapter
            .store
            .put_setup(
                &setup(digest),
                &SetupBlob {
                    public_params_base64: "AA==".into(),
                    public_params_sha256: "00".into(),
                },
            )
            .unwrap();
    }
    let last = adapter.store.last_commit().unwrap();
    assert!(last > 1);
    assert_eq!(pass(&mut adapter, &map).state, BatchState::Ready);
    // Only revisions the map names keep their cached filters and setup.
    for digest in named {
        assert!(adapter.store.filter(digest, "ff").unwrap().is_some());
        assert!(adapter.store.setup(&setup(digest)).unwrap().is_some());
    }
    assert!(adapter.store.filter(&retired, "ff").unwrap().is_none());
    assert!(adapter.store.setup(&setup(&retired)).unwrap().is_none());
    // The commit log keeps only its last entry, the one the store reads.
    let commits: u64 = adapter
        .catalog
        .query_row("SELECT COUNT(*) FROM commits", [], |r| r.get(0))
        .unwrap();
    assert_eq!(commits, 1);
    assert_eq!(adapter.store.last_commit().unwrap(), last);
}

#[test]
fn a_version_one_companion_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let config = config();
    // A v1 companion: a binding with no format, beside the per-companion
    // revision table.
    drop(SqliteStore::open(&path).unwrap());
    let v1 = Connection::open(&path).unwrap();
    v1.execute_batch(
        "CREATE TABLE pir_bridge_binding (key TEXT PRIMARY KEY, value BLOB NOT NULL);
         CREATE TABLE pir_bridge_revisions (source BLOB NOT NULL);",
    )
    .unwrap();
    v1.execute(
        "INSERT INTO pir_bridge_binding VALUES ('account-source', ?1)",
        [catalog::binding([
            &config.source,
            &config.account_binding,
            config.origin.as_bytes(),
            SCHEMA.as_bytes(),
        ])
        .to_vec()],
    )
    .unwrap();
    let refused = |path: &Path| {
        matches!(
            ReferenceRecovery::open(path, config.clone()),
            Err(RecoveryError::Invalid(message)) if message == "companion format v1; recreate"
        )
    };
    assert!(refused(&path));
    // Either mark alone identifies the old format.
    v1.execute_batch("DROP TABLE pir_bridge_revisions").unwrap();
    assert!(refused(&path));
    v1.execute_batch(
        "INSERT INTO pir_bridge_binding VALUES ('format', 'transparent-reference-companion-v2');
         CREATE TABLE pir_bridge_revisions (source BLOB NOT NULL);",
    )
    .unwrap();
    assert!(refused(&path));
    // A recreated companion opens, records its format, and reopens.
    let fresh = dir.path().join("recreated.sqlite");
    drop(ReferenceRecovery::open(&fresh, config.clone()).unwrap());
    let format: String = Connection::open(&fresh)
        .unwrap()
        .query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='format'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(format, "transparent-reference-companion-v3");
    ReferenceRecovery::open(&fresh, config).unwrap();
}
