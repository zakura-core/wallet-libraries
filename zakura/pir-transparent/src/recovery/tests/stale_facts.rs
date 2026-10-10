use super::*;

#[test]
fn stale_store_facts_drop_their_shard_instead_of_failing() {
    let map = map();
    let (sealed, tail) = (&map.shards[0], &map.shards[1]);
    let script = address_script(watch().addresses[0].address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = seeded(&dir, &script, map.start_height);
    // Coverage and a receive on each shard, and an open page on the tail.
    let receive = |entry: &ShardMapEntry, txid| {
        TransparentEvent::Receive(transparent_events::ReceiveEvent {
            metadata: None,
            height: entry.start_height as u32,
            txid: transparent_events::Txid([txid; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        })
    };
    let end = (sealed.end_height, sealed.terminal_block_hash.as_str());
    adapter
        .store
        .commit_shard(covered(
            sealed,
            &sealed.manifest_digest,
            end,
            &script,
            vec![receive(sealed, 1)],
        ))
        .unwrap();
    let end = (tail.end_height, tail.terminal_block_hash.as_str());
    let mut open = covered(
        tail,
        &tail.manifest_digest,
        end,
        &script,
        vec![receive(tail, 2)],
    );
    open.pending_upsert = vec![PendingPages {
        id: None,
        shard_id: tail.shard_id,
        revision_digest: tail.manifest_digest.clone(),
        script: script.clone(),
        first_page: 3,
        page_count: 0,
        inline: vec![],
        next_ordinal: 0,
        attempts: 0,
        validated_events: 0,
        boundary: None,
        target_anchor: None,
    }];
    adapter.store.commit_shard(open).unwrap();
    let first = pass(&mut adapter, &map);
    assert_eq!(first.state, BatchState::Ready);
    assert_eq!(first.commits[1].opened_pages.len(), 1);
    adapter.acknowledge_applied(&first).unwrap();

    // The tail is replaced before the companion retrieves it again, and then
    // withdrawn from the map altogether: every tail fact is stale.
    let replaced = republished(&map, 1, 1, "5a".repeat(32));
    let mut behind = map.clone();
    behind.shards.pop();
    for map in [&replaced, &behind] {
        let batch = pass(&mut adapter, map);
        assert_eq!(batch.state, BatchState::Pending);
        assert!(batch.commits.is_empty());
        assert!(adapter.acknowledge_applied(&batch).is_err());
    }
    // Facts are placed by the revision they were read under: a published
    // one finds its commit, a stale one defers the batch, and so does a
    // published one naming another shard id.
    let set = SetIdentity::of_schema(&replaced, SCHEMA);
    let published: Vec<_> = replaced
        .shards
        .iter()
        .map(|entry| Published::of(&adapter.binding, &set, entry).unwrap())
        .collect();
    let chain = StaticChain::from_map(&replaced);
    let mut facts = Facts::new(&published, &[], None, watch().context().unwrap());
    facts.open(&published[0], first.commits[0].anchor);
    let mut stale = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
    let range = (sealed.start_height, sealed.end_height);
    let placed = facts
        .place(&mut stale, &chain, 0, &sealed.manifest_digest, range)
        .unwrap();
    assert_eq!(
        placed.map(|commit| &commit.revision),
        Some(&published[0].revision)
    );
    assert_eq!(stale.state(), BatchState::Ready);
    let range = (tail.start_height, tail.end_height);
    assert!(
        facts
            .place(&mut stale, &chain, 1, &tail.manifest_digest, range)
            .unwrap()
            .is_none()
    );
    assert_eq!(stale.state(), BatchState::Pending);
    drop(stale);
    let mut renamed = catalog::Pass::begin(&mut adapter.catalog, &published, &[]).unwrap();
    let range = (sealed.start_height, sealed.end_height);
    assert!(
        facts
            .place(&mut renamed, &chain, 1, &sealed.manifest_digest, range)
            .unwrap()
            .is_none()
    );
    assert_eq!(renamed.state(), BatchState::Pending);
    drop(renamed);

    // Retrieving the replacement repairs the companion.
    retrieve_tail(&mut adapter, &replaced);
    assert_eq!(pass(&mut adapter, &replaced).state, BatchState::Ready);
}
