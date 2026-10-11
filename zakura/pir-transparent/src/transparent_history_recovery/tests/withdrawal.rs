use super::*;

#[test]
fn a_lagging_tail_is_pending_not_withdrawn() {
    let base = map();
    let ahead = republished(&base, 1, 5, "a5".repeat(32));
    let lagging = republished(&base, 1, 3, "a3".repeat(32));
    // A companion that covers only the sealed shard, so the lagging tail is the
    // only finding.
    let dir = tempfile::tempdir().unwrap();
    let script = address_script(watch().addresses[0].address);
    let mut adapter = seeded(&dir, &script, base.start_height);
    let sealed = &base.shards[0];
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
    let first = pass(&mut adapter, &ahead);
    assert_eq!(first.state, BatchState::Ready);
    adapter.acknowledge_applied(&first).unwrap();
    assert_eq!(cataloged(&adapter), 2);
    // An unseen tail revision below the one recorded: a lagging replica.
    let batch = pass(&mut adapter, &lagging);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
    assert_eq!(cataloged(&adapter), 2);
    assert!(adapter.acknowledge_applied(&batch).is_err());
    // Once the replica catches up the same companion is ready again.
    assert_eq!(pass(&mut adapter, &ahead).state, BatchState::Ready);

    // A map missing the newest shard, whose facts the companion exported.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    assert_eq!(first.commits.len(), 2);
    adapter.acknowledge_applied(&first).unwrap();
    let mut behind = base.clone();
    behind.shards.pop();
    let batch = pass(&mut adapter, &behind);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
    assert_eq!(cataloged(&adapter), 2);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);

    // A replica that has not caught up with the tail's seal: it still serves
    // the tail unsealed, below the sealed revision the companion exported.
    let mut sealed = republished(&base, 1, 1, "5e".repeat(32));
    sealed.shards[1].sealed = true;
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &sealed);
    let first = pass(&mut adapter, &sealed);
    assert_eq!(first.state, BatchState::Ready);
    adapter.acknowledge_applied(&first).unwrap();
    let batch = pass(&mut adapter, &base);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
    assert_eq!(cataloged(&adapter), 2);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
    assert_eq!(pass(&mut adapter, &sealed).state, BatchState::Ready);
}

#[test]
fn a_regressed_sealed_publication_is_withdrawn() {
    let mut sealed = map();
    sealed.shards[1].sealed = true;
    sealed.shards[1].revision = 4;
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &sealed);
    let first = pass(&mut adapter, &sealed);
    assert_eq!(revisions(&first)[1].lineage, 5);
    adapter.acknowledge_applied(&first).unwrap();
    let regressed = republished(&sealed, 1, 2, "b2".repeat(32));
    let batch = pass(&mut adapter, &regressed);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::Regression)
    );
    assert!(batch.commits.is_empty());
    assert_eq!(cataloged(&adapter), 2);
    assert!(adapter.acknowledge_applied(&batch).is_err());
}

#[test]
fn an_equivocating_revision_is_withdrawn() {
    let base = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    let equivocation = BatchState::Withdrawn(WithdrawnCause::Equivocation);
    // Other content under the same revision number.
    let other = republished(&base, 1, 0, "e0".repeat(32));
    // The same content sealed under the same revision number.
    let mut resealed = base.clone();
    resealed.shards[1].sealed = true;
    // The same content and revision number ending at another block.
    let mut moved = base.clone();
    moved.shards[1].terminal_block_hash = "77".repeat(32);
    for map in [other, resealed, moved] {
        let batch = pass(&mut adapter, &map);
        assert_eq!(batch.state, equivocation);
        assert!(batch.commits.is_empty());
    }
    // Nothing equivocating was recorded: the original publication is still ready.
    assert_eq!(cataloged(&adapter), 2);
    assert_eq!(pass(&mut adapter, &base).state, BatchState::Ready);
}

#[test]
fn a_changed_sealed_revision_is_withdrawn() {
    let base = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    // The exported sealed shard is published again with other content.
    let changed = republished(&base, 0, 1, "c1".repeat(32));
    let batch = pass(&mut adapter, &changed);
    assert_eq!(
        batch.state,
        BatchState::Withdrawn(WithdrawnCause::ChangedSealed)
    );
    assert!(batch.commits.is_empty());
    assert!(adapter.acknowledge_applied(&batch).is_err());
}

#[test]
fn an_exported_shard_under_another_geometry_is_retired() {
    let base = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    // The tail is republished under the archive geometry, so another source.
    let mut regeometried = republished(&base, 1, 1, "f1".repeat(32));
    regeometried.shards[1].geometry = base.shards[0].geometry.clone();
    retrieve_tail(&mut adapter, &regeometried);
    let batch = pass(&mut adapter, &regeometried);
    assert_eq!(batch.state, BatchState::Withdrawn(WithdrawnCause::Retired));
    assert!(batch.commits.is_empty());
}
