use super::*;

#[test]
fn a_replaced_tail_is_ready_when_its_successor_is_exported() {
    let map = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    let predecessor = revisions(&first)[1].clone();
    let successor = republished(&map, 1, 1, "5a".repeat(32));
    retrieve_tail(&mut adapter, &successor);
    let batch = pass(&mut adapter, &successor);
    assert_eq!(batch.state, BatchState::Ready);
    let replacing = &revisions(&batch)[1];
    assert_eq!(replacing.source, predecessor.source);
    assert_eq!(replacing.lineage, predecessor.lineage + 1);
    assert_eq!(
        batch.retired_revisions(),
        std::slice::from_ref(&predecessor)
    );
    // The predecessor stays recorded as exported until the wallet acknowledges
    // reconciling it, and is forgotten then, whatever the caller did to the
    // batch's commits.
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1), (TAIL, 2)]);
    let mut batch = batch;
    batch.commits.extend(first.commits.iter().cloned());
    assert!(adapter.acknowledge_applied(&batch).is_err());
    adapter.acknowledge_reconciled(&batch).unwrap();
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
    assert_eq!(cataloged(&adapter), 2);
}

#[test]
fn a_replaced_tail_without_a_retrieved_successor_is_pending() {
    let map = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    let successor = republished(&map, 1, 1, "5a".repeat(32));
    withdraw_tail(&mut adapter, &successor);
    let batch = pass(&mut adapter, &successor);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
    assert!(adapter.acknowledge_applied(&batch).is_err());
    // The successor is recorded, but the predecessor is still the export.
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
    assert_eq!(cataloged(&adapter), 3);
}

#[test]
fn a_ready_batch_lists_exactly_the_retirements_its_commits_resolve() {
    let base = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    assert_eq!(first.state, BatchState::Ready);
    assert!(first.retired_revisions().is_empty());
    adapter.acknowledge_applied(&first).unwrap();
    let original = first.commits[1].revision.clone();

    // The tail is republished, and the batch exporting it is never
    // acknowledged.
    let next = republished(&base, 1, 1, "b1".repeat(32));
    retrieve_tail(&mut adapter, &next);
    let unacknowledged = pass(&mut adapter, &next);
    assert_eq!(unacknowledged.state, BatchState::Ready);
    let intermediate = unacknowledged.commits[1].revision.clone();

    // It is republished again, skipping revision numbers. Until the
    // successor is retrieved, the batch lists and exports nothing.
    let last = republished(&base, 1, 4, "b4".repeat(32));
    withdraw_tail(&mut adapter, &last);
    let pending = pass(&mut adapter, &last);
    assert_eq!(pending.state, BatchState::Pending);
    assert!(pending.commits.is_empty());
    assert!(pending.retired_revisions().is_empty());

    // Retrieved, the successor resolves both earlier tails, listed exactly
    // as the wallet holds them; the still published sealed shard is not.
    retrieve_tail(&mut adapter, &last);
    let batch = pass(&mut adapter, &last);
    assert_eq!(batch.state, BatchState::Ready);
    let successor = &batch.commits[1].revision;
    assert_eq!(successor.source, original.source);
    assert_eq!(successor.lineage, 5);
    let mut listed = batch.retired_revisions().to_vec();
    listed.sort_by_key(|revision| revision.lineage);
    assert_eq!(listed, vec![original, intermediate]);
    assert!(
        !batch
            .retired_revisions()
            .contains(&first.commits[0].revision)
    );

    // Ordinary acknowledgment refuses it and records nothing; the reconciled
    // one forgets the earlier tails.
    let recorded = catalog_rows(&adapter);
    assert!(matches!(
        adapter.acknowledge_applied(&batch),
        Err(RecoveryError::Invalid(_))
    ));
    assert_eq!(catalog_rows(&adapter), recorded);
    adapter.acknowledge_reconciled(&batch).unwrap();
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 5)]);

    // The next batch resolves nothing, and ordinary acknowledgment applies.
    let after = pass(&mut adapter, &last);
    assert_eq!(after.state, BatchState::Ready);
    assert_eq!(after.commits, batch.commits);
    assert!(after.retired_revisions().is_empty());
    adapter.acknowledge_applied(&after).unwrap();
}

#[test]
fn pending_and_withdrawn_batches_list_nothing_and_refuse_both_acknowledgments() {
    let base = map();
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = covering(&dir.path().join("companion.sqlite"), &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    let refused = |adapter: &mut ReferenceRecovery, batch: &RecoveryBatch<u32>| {
        assert!(batch.commits.is_empty());
        assert!(batch.retired_revisions().is_empty());
        let recorded = catalog_rows(adapter);
        assert!(adapter.acknowledge_applied(batch).is_err());
        assert!(adapter.acknowledge_reconciled(batch).is_err());
        assert_eq!(catalog_rows(adapter), recorded);
    };

    // The tail is republished, and its successor is not retrieved yet.
    let replaced = republished(&base, 1, 1, "5a".repeat(32));
    withdraw_tail(&mut adapter, &replaced);
    let pending = pass(&mut adapter, &replaced);
    assert_eq!(pending.state, BatchState::Pending);
    refused(&mut adapter, &pending);

    // Retrieved, the successor would resolve the old tail, but the sealed
    // shard equivocates.
    retrieve_tail(&mut adapter, &replaced);
    let equivocating = republished(&replaced, 0, 0, "e0".repeat(32));
    let withdrawn = pass(&mut adapter, &equivocating);
    assert_eq!(
        withdrawn.state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
    refused(&mut adapter, &withdrawn);

    // Neither forgot the old tail: without the equivocation it is listed.
    let ready = pass(&mut adapter, &replaced);
    assert_eq!(ready.state, BatchState::Ready);
    assert_eq!(
        ready.retired_revisions(),
        std::slice::from_ref(&first.commits[1].revision)
    );
}

#[test]
fn retired_revisions_survive_until_reconciled_and_replay_identically() {
    let mut map = map();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let mut adapter = covering(&path, &map);
    let first = pass(&mut adapter, &map);
    adapter.acknowledge_applied(&first).unwrap();
    let original = first.commits[1].revision.clone();
    map = republished(&map, 1, 1, "5a".repeat(32));
    retrieve_tail(&mut adapter, &map);
    let ready = pass(&mut adapter, &map);
    assert_eq!(ready.retired_revisions(), std::slice::from_ref(&original));
    let recorded = catalog_rows(&adapter);

    // Replaying the pass, before or after a crash, returns the same batch,
    // notifications and receipt, and records nothing new.
    let replayed = pass(&mut adapter, &map);
    drop(adapter);
    let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
    let reopened = pass(&mut adapter, &map);
    for batch in [&replayed, &reopened] {
        assert_eq!(batch.state, BatchState::Ready);
        assert_eq!(batch.commits, ready.commits);
        assert_eq!(batch.retired_revisions(), ready.retired_revisions());
        assert_eq!(batch.token, ready.token);
    }
    assert_eq!(catalog_rows(&adapter), recorded);
    // Without trusted reconciliation the batch stays unacknowledged.
    assert!(adapter.acknowledge_applied(&reopened).is_err());
    assert_eq!(catalog_rows(&adapter), recorded);

    // The tail moves again before the wallet reconciled. The newer batch
    // lists both unacknowledged revisions, and the older receipt is stale.
    map = republished(&map, 1, 2, "5b".repeat(32));
    retrieve_tail(&mut adapter, &map);
    let newer = pass(&mut adapter, &map);
    assert_eq!(newer.state, BatchState::Ready);
    let mut lineages: Vec<_> = newer
        .retired_revisions()
        .iter()
        .map(|revision| revision.lineage)
        .collect();
    lineages.sort_unstable();
    assert_eq!(lineages, vec![1, 2]);
    assert!(newer.retired_revisions().contains(&original));
    assert!(adapter.acknowledge_reconciled(&reopened).is_err());
    adapter.acknowledge_reconciled(&newer).unwrap();
    // A receipt is acknowledged once.
    assert!(adapter.acknowledge_reconciled(&newer).is_err());
    assert!(adapter.acknowledge_applied(&newer).is_err());
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 3)]);

    // Once reconciled, replay lists nothing and is idempotent.
    let settled = pass(&mut adapter, &map);
    let recorded = catalog_rows(&adapter);
    let again = pass(&mut adapter, &map);
    assert_eq!(settled.commits, newer.commits);
    assert!(settled.retired_revisions().is_empty());
    assert!(again.retired_revisions().is_empty());
    assert_eq!(again.token, settled.token);
    assert_eq!(catalog_rows(&adapter), recorded);
    adapter.acknowledge_applied(&again).unwrap();
    // A batch without retirements may also be acknowledged as reconciled.
    let last = pass(&mut adapter, &map);
    adapter.acknowledge_reconciled(&last).unwrap();
}

#[test]
fn a_publication_change_forgets_retirements_of_sources_it_drops() {
    let base = map();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let mut adapter = covering(&path, &base);
    let first = pass(&mut adapter, &base);
    adapter.acknowledge_applied(&first).unwrap();
    let next = republished(&base, 1, 1, "5a".repeat(32));
    retrieve_tail(&mut adapter, &next);
    let listed = pass(&mut adapter, &next);
    assert_eq!(listed.state, BatchState::Ready);
    assert_eq!(
        listed.retired_revisions(),
        std::slice::from_ref(&first.commits[1].revision)
    );
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1), (TAIL, 2)]);

    // The wallet crashes before reconciling, and the tail's geometry is
    // resealed. The reset forgets the listed retirement unacknowledged: no
    // successor under the dropped source can resolve it.
    drop(adapter);
    let mut adapter = ReferenceRecovery::open(&path, config()).unwrap();
    let resealed = resealing(&next, 1);
    publication_change(&mut adapter, &resealed);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1)]);
    assert_eq!(cataloged(&adapter), 3);

    // No later batch lists it, and ordinary acknowledgment applies.
    cover(&mut adapter, &resealed);
    let retried = pass(&mut adapter, &resealed);
    assert_eq!(retried.state, BatchState::Ready);
    assert!(retried.retired_revisions().is_empty());
    assert_ne!(
        retried.commits[1].revision.source,
        listed.commits[1].revision.source
    );
    adapter.acknowledge_applied(&retried).unwrap();
    assert!(pass(&mut adapter, &resealed).retired_revisions().is_empty());
}
