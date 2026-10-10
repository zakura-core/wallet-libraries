use super::*;

/// A filter source that serves `maps` in turn and then repeats the last, and
/// answers every filter request with bytes no map names, which the client
/// reads as a revision withdrawn mid-sync.
struct Republishing {
    maps: Vec<Vec<u8>>,
    served: usize,
    filters: usize,
}

impl FilterSource for Republishing {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        let map = self.maps[self.served.min(self.maps.len() - 1)].clone();
        self.served += 1;
        let cost = map.len() as u64;
        Ok((map, cost))
    }
    fn filter(&mut self, _shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.filters += 1;
        Ok((b"withdrawn".to_vec(), 9))
    }
}

#[test]
fn a_publication_diverging_from_the_sync_is_pending_and_keeps_the_companion() {
    let first = map();
    let behind_by_divergence = Progress {
        covered_through: 0,
        outcome: Outcome::Behind,
    };
    let script = address_script(watch().addresses[0].address);
    // A companion that exported the sealed shard; the tail is still to retrieve.
    let companion = |dir: &tempfile::TempDir| {
        let mut adapter = seeded(dir, &script, first.start_height);
        let sealed = &first.shards[0];
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
        let batch = pass(&mut adapter, &first);
        assert_eq!(batch.commits.len(), 1);
        adapter.acknowledge_applied(&batch).unwrap();
        adapter
    };
    // Reading the tail's withdrawn revision makes the sync refresh to `then`.
    let refreshing = |adapter: &mut ReferenceRecovery, then: &ShardMap| {
        let mut filters = Republishing {
            maps: [&first, then]
                .map(|map| serde_json::to_vec(map).unwrap())
                .to_vec(),
            served: 0,
            filters: 0,
        };
        let mut shards = CountingShards::serving(SCHEMA);
        let batch = adapter
            .recover(
                &watch(),
                &StaticChain::from_map(&first),
                &mut filters,
                &mut shards,
            )
            .unwrap();
        assert_eq!((filters.served, filters.filters), (2, 1));
        batch
    };

    // The refreshed map republishes the covered sealed shard with other
    // content under the same revision. The kept catalog sees the
    // equivocation a recreated one could not, and recovers if the
    // publisher reverts.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = companion(&dir);
    let equivocating = republished(&first, 0, 0, "e0".repeat(32));
    let batch = refreshing(&mut adapter, &equivocating);
    assert_eq!(batch.state, BatchState::Pending);
    assert_eq!(batch.progress, behind_by_divergence);
    assert!(batch.commits.is_empty());
    assert!(adapter.acknowledge_applied(&batch).is_err());
    assert_eq!(
        pass(&mut adapter, &equivocating).state,
        BatchState::Withdrawn(WithdrawnCause::Equivocation)
    );
    assert_eq!(pass(&mut adapter, &first).state, BatchState::Ready);

    // A refreshed map under another set identity leaves the store bound to
    // the first; the next pass, starting from it, resets the store.
    let mut resealed = first.clone();
    resealed
        .seal
        .get_mut(&first.shards[1].geometry)
        .unwrap()
        .max_scripts += 1;
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = companion(&dir);
    let batch = refreshing(&mut adapter, &resealed);
    assert_eq!(batch.state, BatchState::Pending);
    assert_eq!(batch.progress, behind_by_divergence);
    assert_eq!(
        adapter.store.set_identity().unwrap(),
        Some(SetIdentity::of_schema(&first, SCHEMA))
    );
    publication_change(&mut adapter, &resealed);
    assert_eq!(cataloged(&adapter), 2);

    // A budget-limited pass left a pending page on the tail, and a lagging
    // replica's map no longer has it. The pass clamps to that map's end,
    // and the sync drops the page work, which saved nothing, rather than
    // diverging: a later map that publishes the tail reads it again. The
    // batch covers what that map publishes and keeps the catalog.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = companion(&dir);
    let tail = &first.shards[1];
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    let mut open = covered(tail, &tail.manifest_digest, end, &script, vec![]);
    open.covered_scripts.clear();
    open.pending_upsert = vec![PendingPages {
        id: None,
        shard_id: tail.shard_id,
        revision_digest: tail.manifest_digest.clone(),
        script: script.clone(),
        first_page: 0,
        page_count: 0,
        inline: vec![],
        next_ordinal: 0,
        attempts: 0,
        validated_events: 0,
        boundary: None,
        target_anchor: None,
    }];
    adapter.store.commit_shard(open).unwrap();
    let catalog = (cataloged(&adapter), exported(&adapter));
    let mut behind = first.clone();
    behind.shards.pop();
    let mut filters = CountingFilters::serving(serde_json::to_vec(&behind).unwrap());
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(
            &watch(),
            &StaticChain::from_map(&first),
            &mut filters,
            &mut shards,
        )
        .unwrap();
    assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 1));
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(
        batch.progress,
        Progress {
            covered_through: first.shards[0].end_height,
            outcome: Outcome::Behind,
        }
    );
    assert_eq!(revisions(&batch).len(), 1);
    assert!(batch.commits[0].opened_pages.is_empty());
    assert!(adapter.store.pending().unwrap().is_empty());
    assert_eq!(
        adapter.store.set_identity().unwrap(),
        Some(SetIdentity::of_schema(&first, SCHEMA))
    );
    assert_eq!((cataloged(&adapter), exported(&adapter)), catalog);
}

#[test]
fn normalization_uses_the_map_the_sync_finished_with() {
    let first = map();
    // The refreshed publication no longer advertises the tail; a later one
    // republishes it.
    let mut refreshed = first.clone();
    refreshed.shards.pop();
    let later = republished(&first, 1, 1, "5a".repeat(32));
    // The companion covers the sealed shard; the tail is still to retrieve.
    let script = address_script(watch().addresses[0].address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = seeded(&dir, &script, first.start_height);
    let sealed = &first.shards[0];
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
    let mut filters = Republishing {
        maps: [&first, &refreshed, &later]
            .map(|map| serde_json::to_vec(map).unwrap())
            .to_vec(),
        served: 0,
        filters: 0,
    };
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(
            &watch(),
            &StaticChain::from_map(&first),
            &mut filters,
            &mut shards,
        )
        .unwrap();
    // The tail's filter named a withdrawn revision, so the sync refreshed the
    // map once and stopped behind it. Nothing fetched another map.
    assert_eq!((filters.served, filters.filters), (2, 1));
    assert_eq!(batch.progress.outcome, Outcome::Behind);
    // The batch describes the refreshed map: the sealed shard only, with the
    // tail neither cataloged nor exported.
    assert_eq!(batch.state, BatchState::Ready);
    assert_eq!(batch.commits.len(), 1);
    assert_eq!(
        batch.commits[0].anchor.height,
        block_height(sealed.end_height).unwrap()
    );
    assert_eq!(cataloged(&adapter), 1);
}
