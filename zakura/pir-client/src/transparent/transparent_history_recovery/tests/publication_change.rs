use super::*;

#[test]
fn a_publication_change_resets_the_store_and_keeps_the_catalog() {
    let map = map();
    let mut resealed = map.clone();
    resealed
        .seal
        .get_mut(&map.shards[1].geometry)
        .unwrap()
        .max_scripts += 1;
    let (sealed, tail) = (&map.shards[0], &map.shards[1]);
    let script = address_script(watch().addresses[0].address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    // Every store table holds something: a receive and its spend, a pending
    // page, a cached run, a content failure, cached filter and setup, and a
    // committed anchor.
    let receive =
        TransparentEvent::Receive(zakura_pir_protocol::transparent::events::ReceiveEvent {
            metadata: None,
            height: sealed.start_height as u32,
            txid: zakura_pir_protocol::transparent::events::Txid([1; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
    let spend = TransparentEvent::Spend(zakura_pir_protocol::transparent::events::SpendEvent {
        metadata: None,
        height: sealed.start_height as u32 + 1,
        spending_txid: zakura_pir_protocol::transparent::events::Txid([2; 32]),
        transaction_index: 2,
        input_index: 0,
        spent_txid: zakura_pir_protocol::transparent::events::Txid([1; 32]),
        spent_output_index: 0,
    });
    let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
    let mut events = covered(
        sealed,
        &sealed.manifest_digest,
        end,
        &script,
        vec![receive, spend],
    );
    events.covered_scripts.clear();
    events.cached_runs = vec![crate::transparent::engine::store::CachedRun {
        child_digest: "cd".repeat(32),
        script: script.clone(),
        shard_id: sealed.shard_id,
        older: None,
        events: vec![receive],
    }];
    adapter.store.commit_shard(events).unwrap();
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    let mut open = covered(tail, &tail.manifest_digest, end, &script, vec![]);
    open.covered_scripts.clear();
    open.pending_upsert = vec![store_page(tail, &script, 3)];
    open.failed_entries = vec![script.clone()];
    adapter.store.commit_shard(open).unwrap();
    adapter
        .store
        .put_filter(&sealed.manifest_digest, "ff", true, b"filter")
        .unwrap();
    adapter
        .store
        .put_setup(
            &SetupKey {
                set_digest: "set".into(),
                revision_digest: sealed.manifest_digest.clone(),
                table: Table::Directory,
                segment: 0,
            },
            &SetupBlob {
                public_params_base64: "AA==".into(),
                public_params_sha256: "00".into(),
            },
        )
        .unwrap();
    let anchor = Anchor {
        height: tail.end_height,
        hash: tail.terminal_block_hash.clone(),
    };
    adapter
        .store
        .commit_anchor(&anchor, tail.end_height, tail.end_height)
        .unwrap();
    let first = pass(&mut adapter, &map);
    assert_eq!(first.state, BatchState::Ready);
    assert_eq!(first.commits[0].receives.len(), 1);
    assert_eq!(first.commits[1].opened_pages.len(), 1);
    adapter.acknowledge_applied(&first).unwrap();
    let original = revisions(&first);
    // Facts read under the bound set are never exported under another one.
    let deferred = adapter
        .normalize(
            &watch(),
            resealed.clone(),
            MORE,
            &StaticChain::from_map(&resealed),
        )
        .unwrap();
    assert_eq!(deferred.state, BatchState::Pending);
    assert!(deferred.commits.is_empty());
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
    let held = store_rows(&adapter);
    assert_eq!(held.len(), 11);
    for (table, rows) in held {
        assert!(rows > 0, "{table}");
    }

    // A pass starting from the resealed map stops at the set check, having
    // emptied every store table but the schema version and the content failures:
    // a service changing its publication set earns a held entry no more attempts.
    publication_change(&mut adapter, &resealed);
    let reset = store_rows(&adapter);
    assert_eq!(reset.len(), 11);
    for (table, rows) in reset {
        let expected = match table.as_str() {
            "wallet_meta" => 3, // schema version and two shard revision bindings
            "failed_entries" => 1,
            _ => 0,
        };
        assert_eq!(rows, expected, "{table}");
    }
    assert_eq!(
        adapter
            .store
            .entry_failures(tail.shard_id, &tail.manifest_digest, &script)
            .unwrap(),
        1
    );
    let kept: BTreeMap<String, String> = adapter
        .catalog
        .prepare("SELECT key, value FROM wallet_meta ORDER BY key")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        kept,
        BTreeMap::from([
            ("schema_version".to_owned(), "7".to_owned()),
            (
                format!("failure_revision:{}", sealed.shard_id),
                sealed.manifest_digest.clone(),
            ),
            (
                format!("failure_revision:{}", tail.shard_id),
                tail.manifest_digest.clone(),
            ),
        ])
    );
    // The catalog keeps every row. Only the tail's revision, whose source the
    // resealed map no longer names, stops counting as exported.
    assert_eq!(cataloged(&adapter), 2);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
    drop(adapter);

    // The retried pass, on the same companion reopened, gets past the check
    // and binds the store to the resealed set.
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    let mut filters = CountingFilters::serving(serde_json::to_vec(&resealed).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    assert!(matches!(
        adapter.recover(
            &watch(),
            &StaticChain::from_map(&resealed),
            &mut filters,
            &mut shards
        ),
        Err(RecoveryError::Failure(_))
    ));
    assert!(filters.filters > 0);
    assert_eq!(
        adapter.store.set_identity().unwrap(),
        Some(SetIdentity::of_schema(&resealed, SCHEMA))
    );
    // Once the publication is retrieved again, the pass is ready. The
    // unchanged source reproduces its triple; the resealed geometry's shard
    // has a new source.
    cover(&mut adapter, &resealed);
    let retried = pass(&mut adapter, &resealed);
    assert_eq!(retried.state, BatchState::Ready);
    let retried_revisions = revisions(&retried);
    assert_eq!(retried_revisions[0], original[0]);
    assert_ne!(retried_revisions[1].source, original[1].source);
    adapter.acknowledge_applied(&retried).unwrap();
    // The changed source keeps its highest row, neither current nor exported.
    assert_eq!(cataloged(&adapter), 3);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
}

#[test]
fn an_unchanged_source_keeps_its_history_across_a_publication_change() {
    let base = map();
    let (archive, recent) = (&base.shards[0].geometry, &base.shards[1].geometry);
    // A publisher at sealed revision 4 and tail revision 6.
    let first = republished(&base, 0, 4, base.shards[0].manifest_digest.clone());
    let first = republished(&first, 1, 6, base.shards[1].manifest_digest.clone());
    let resealed = |geometry: &str| {
        let mut map = first.clone();
        map.seal.get_mut(geometry).unwrap().max_scripts += 1;
        map
    };
    let exporting = |dir: &tempfile::TempDir| {
        let mut adapter = covering(&dir.path().join("companion.sqlite"), &first);
        let batch = pass(&mut adapter, &first);
        adapter.acknowledge_applied(&batch).unwrap();
        assert_eq!(exported(&adapter), vec![(ARCHIVE, 5), (TAIL, 7)]);
        adapter
    };

    // A re-cut that reseals the tail's geometry and restarts revision
    // numbers. The sealed shard keeps its source, so its restarted revision
    // is a regression rather than a lineage that collides in the wallet.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = exporting(&dir);
    let recut = republished(&resealed(recent), 0, 0, "c0".repeat(32));
    publication_change(&mut adapter, &recut);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 5)]);
    cover(&mut adapter, &recut);
    let batch = pass(&mut adapter, &recut);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::Regression)
    );
    assert!(batch.commits.is_empty());

    // A re-cut that reseals the sealed shard's geometry. The tail keeps its
    // source, so its restarted revisions are pending below the old maximum,
    // equivocate at it, and replace the exported tail only above it.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = exporting(&dir);
    let recut = resealed(archive);
    let restarted = |revision: u32| republished(&recut, 1, revision, format!("{revision:064x}"));
    publication_change(&mut adapter, &restarted(2));
    assert_eq!(exported(&adapter), vec![(TAIL, 7)]);
    cover(&mut adapter, &restarted(2));
    let batch = pass(&mut adapter, &restarted(2));
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
    retrieve_tail(&mut adapter, &restarted(6));
    let batch = pass(&mut adapter, &restarted(6));
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
    assert!(batch.commits.is_empty());
    retrieve_tail(&mut adapter, &restarted(7));
    let batch = pass(&mut adapter, &restarted(7));
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(revisions(&batch)[1].lineage, 8);
    let retired: Vec<_> = batch
        .retired_revisions()
        .iter()
        .map(|revision| revision.lineage)
        .collect();
    assert_eq!(retired, vec![7]);
    assert!(adapter.acknowledge_applied(&batch).is_err());
    adapter.acknowledge_reconciled(&batch).unwrap();
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 5), (TAIL, 8)]);
}

#[test]
fn a_shard_id_reused_for_other_content_gets_a_new_source() {
    let before = map();
    // Resealing the archive geometry re-shards it: its shard ends later, and
    // shard id 1 names other content under the same geometry and seal.
    let mut after = before.clone();
    after
        .seal
        .get_mut(&before.shards[0].geometry)
        .unwrap()
        .max_scripts += 1;
    let moved = "3c".repeat(32);
    after.shards[0].end_height += 100;
    after.shards[0].terminal_block_hash = moved.clone();
    after.shards[0].manifest_digest = "a0".repeat(32);
    after.shards[1].start_height += 100;
    after.shards[1].parent_block_hash = moved;
    after.shards[1].manifest_digest = "a1".repeat(32);
    let config = config();
    let binding = catalog::companion_binding([
        &config.source,
        &config.account_binding,
        config.origin.as_bytes(),
        SCHEMA.as_bytes(),
    ]);
    let source = |map: &ShardMap, entry: &ShardMapEntry| {
        let set = SetIdentity::of_schema(map, SCHEMA);
        catalog::source_identity(&binding, &set, &entry.geometry, entry.start_height).unwrap()
    };
    assert_ne!(
        source(&before, &before.shards[1]),
        source(&after, &after.shards[1])
    );
    // The start height alone tells them apart.
    let mut unmoved = after.shards[1].clone();
    unmoved.start_height = before.shards[1].start_height;
    assert_eq!(source(&before, &before.shards[1]), source(&after, &unmoved));

    // So the new tail, at the revision number the companion exported for
    // the old one, is a new source after the publication change rather than
    // an equivocation.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &before);
    let first = pass(&mut adapter, &before);
    adapter.acknowledge_applied(&first).unwrap();
    publication_change(&mut adapter, &after);
    assert!(exported(&adapter).is_empty());
    cover(&mut adapter, &after);
    let batch = pass(&mut adapter, &after);
    assert_eq!(batch.state, BatchState::Ready);
    let (old, new) = (revisions(&first), revisions(&batch));
    assert_eq!(new[1].lineage, old[1].lineage);
    assert_ne!(new[1].revision, old[1].revision);
    assert_ne!(new[1].source, old[1].source);
}
