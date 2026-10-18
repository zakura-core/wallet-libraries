use super::*;

#[test]
fn below_floor_view_is_lenient_only_below_the_floor() {
    let floor = 1_000;
    let held = "11".repeat(32);
    let other = "22".repeat(32);
    let chain = StaticChain {
        hashes: BTreeMap::from([(floor, held.clone())]),
    };
    let view = FloorAcceptingChain {
        chain: &chain,
        floor,
        genesis_hash: MAINNET_GENESIS_DISPLAY,
    };
    // Below the floor every block is accepted, and only block 0 has a hash.
    for height in [0, 1, floor - 1] {
        assert_eq!(view.is_accepted(height, &other), Acceptance::Accepted);
    }
    assert_eq!(view.hash_at(0).as_deref(), Some(MAINNET_GENESIS_DISPLAY));
    assert_eq!(view.hash_at(1), None);
    assert_eq!(view.hash_at(floor - 1), None);
    // From the floor up, the caller's chain alone answers.
    assert_eq!(view.is_accepted(floor, &held), Acceptance::Accepted);
    assert_eq!(view.is_accepted(floor, &other), Acceptance::Rejected);
    assert_eq!(view.is_accepted(floor + 1, &held), Acceptance::Unknown);
    assert_eq!(view.hash_at(floor), Some(held));
    assert_eq!(view.hash_at(floor + 1), None);
    assert_eq!(view.tip(), chain.tip());
    // A floor of 0, when nothing is watched, is never lenient.
    let strict = FloorAcceptingChain {
        chain: &chain,
        floor: 0,
        genesis_hash: MAINNET_GENESIS_DISPLAY,
    };
    assert_eq!(
        strict.is_accepted(0, MAINNET_GENESIS_DISPLAY),
        Acceptance::Unknown
    );
    assert_eq!(strict.hash_at(0), None);

    // The floor is the lowest required height, capped at the target.
    let mut watch = watch();
    let lowest = u64::from(u32::from(watch.addresses[0].required_from));
    watch.addresses.push(WatchedAddress {
        address: TransparentAddress::PublicKeyHash([8; 20]),
        required_from: block_height(lowest + 10).unwrap(),
        ..watch.addresses[0]
    });
    assert_eq!(watch_floor(&watch, u64::MAX), lowest);
    assert_eq!(watch_floor(&watch, lowest - 1), lowest - 1);
    watch.addresses.clear();
    assert_eq!(watch_floor(&watch, u64::MAX), 0);
}

#[test]
fn shards_ending_below_the_required_start_are_neither_exported_nor_cataloged() {
    let map = map();
    let (low, high) = (&map.shards[0], &map.shards[1]);
    let mut watch = watch();
    let address = watch.addresses[0].address;
    let script = address_script(address);
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = seeded(&dir, &script, map.start_height);
    // The companion also holds coverage and a receive in the shard below the floor.
    let receive =
        TransparentEvent::Receive(zakura_pir_protocol::transparent::events::ReceiveEvent {
            metadata: None,
            height: low.start_height as u32,
            txid: zakura_pir_protocol::transparent::events::Txid([1; 32]),
            transaction_index: 1,
            output_index: 0,
            value: 100,
            coinbase: false,
        });
    for (entry, events) in [(low, vec![receive]), (high, vec![])] {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(entry, &entry.manifest_digest, end, &script, events))
            .unwrap();
    }

    // The wallet's chain starts at the floor, so it has no hash for the low shard.
    watch.addresses[0].required_from = block_height(high.start_height).unwrap();
    let chain = StaticChain {
        hashes: BTreeMap::from([(high.end_height, high.terminal_block_hash.clone())]),
    };
    let batch = adapter
        .normalize(&watch, map.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(batch.commits.len(), 1);
    let commit = &batch.commits[0];
    assert_eq!(commit.anchor.height, block_height(high.end_height).unwrap());
    assert!(commit.receives.is_empty());
    assert_eq!(
        commit.coverage,
        vec![AddressRange {
            address,
            from: block_height(high.start_height).unwrap(),
            through: block_height(high.end_height).unwrap(),
        }]
    );
    assert_eq!(cataloged(&adapter), 1);

    // With the floor at the map's start, the same companion exports and
    // catalogs both shards, the receive included.
    watch.addresses[0].required_from = block_height(map.start_height).unwrap();
    let batch = adapter
        .normalize(&watch, map.clone(), MORE, &StaticChain::from_map(&map))
        .unwrap();
    assert_eq!(batch.commits.len(), 2);
    assert_eq!(batch.commits[0].receives.len(), 1);
    assert_eq!(cataloged(&adapter), 2);
}

#[test]
fn a_pass_watching_nothing_sends_no_request() {
    let map = map();
    let last = map.shards.last().unwrap();
    let mut watch = watch();
    watch.addresses.clear();
    let target = u64::from(u32::from(watch.target.unwrap().height));
    // The wallet holds only its target, far above block 0, the floor of an
    // empty watch set.
    assert_eq!(watch_floor(&watch, target), 0);
    let chain = StaticChain {
        hashes: BTreeMap::from([(last.end_height, last.terminal_block_hash.clone())]),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    let mut filters = CountingFilters::default();
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(&watch, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!(
        batch.progress,
        Progress {
            covered_through: target,
            outcome: Outcome::Complete,
        }
    );
    assert_eq!(batch.state, BatchState::Ready);
    assert!(batch.commits.is_empty());
    assert_eq!((filters.calls(), shards.calls()), (0, 0));
    assert!(adapter.store.set_identity().unwrap().is_none());
    assert_eq!(cataloged(&adapter), 0);
    adapter.acknowledge_applied(&batch).unwrap();
    // The target must still be accepted.
    assert!(matches!(
        adapter.recover(&watch, &StaticChain::default(), &mut filters, &mut shards),
        Err(RecoveryError::Invalid(_))
    ));
    assert_eq!((filters.calls(), shards.calls()), (0, 0));
}

#[test]
fn sync_target_clamps_only_to_an_accepted_end_at_or_above_the_floor_and_anchor() {
    let map = map();
    let last = map.shards.last().unwrap();
    let t = last.end_height;
    let end = Anchor {
        height: t,
        hash: last.terminal_block_hash.clone(),
    };
    let accepted = StaticChain::from_map(&map);
    let floor = map.start_height;
    let target = Anchor {
        height: t + 10,
        hash: "99".repeat(32),
    };
    let unclamped = SyncTarget {
        anchor: target.clone(),
        clamped: false,
    };

    // Behind, with every condition met: sync to the map's accepted end.
    assert_eq!(
        sync_target(&map, &target, floor, None, 0, &accepted),
        SyncTarget {
            anchor: end.clone(),
            clamped: true
        }
    );
    // A floor, companion anchor or retained event exactly at the end allows it.
    assert_eq!(
        sync_target(&map, &target, t, Some(&end), t, &accepted),
        SyncTarget {
            anchor: end.clone(),
            clamped: true
        }
    );
    // Ahead or level: the publication reaches the target.
    for reached in [t - 1, t] {
        let target = Anchor {
            height: reached,
            hash: "99".repeat(32),
        };
        assert_eq!(
            sync_target(&map, &target, floor, None, 0, &accepted),
            SyncTarget {
                anchor: target,
                clamped: false
            }
        );
    }
    // Below the floor: nothing the watch set requires is published yet.
    assert_eq!(
        sync_target(&map, &target, t + 1, None, 0, &accepted),
        unclamped
    );
    // An unaccepted terminal: the wallet's chain does not know the end.
    assert_eq!(
        sync_target(&map, &target, floor, None, 0, &StaticChain::default()),
        unclamped
    );
    // A map terminal on a stale branch: the wallet holds another block there.
    let mut stale = accepted.clone();
    stale.hashes.insert(t, "aa".repeat(32));
    assert_eq!(
        sync_target(&map, &target, floor, None, 0, &stale),
        unclamped
    );
    // A lagging replica: the companion already settled above the end, or
    // retains an event above it.
    let above = Anchor {
        height: t + 1,
        hash: "bb".repeat(32),
    };
    assert_eq!(
        sync_target(&map, &target, floor, Some(&above), 0, &accepted),
        unclamped
    );
    assert_eq!(
        sync_target(&map, &target, floor, None, t + 1, &accepted),
        unclamped
    );
}

#[test]
fn a_pass_behind_the_publication_syncs_to_its_accepted_end() {
    let map = map();
    let last = map.shards.last().unwrap();
    let t = last.end_height;
    let mut watch = watch();
    let wallet_target = ChainPoint {
        height: block_height(t + 10).unwrap(),
        hash: BlockHash([9; 32]),
    };
    watch.target = Some(wallet_target);
    let mut chain = StaticChain::from_map(&map);
    chain.hashes.insert(t + 10, wallet_target.hash.to_string());
    let address = watch.addresses[0].address;
    let script = address_script(address);

    // A wallet born above the publication's end has nothing to clamp to.
    let dir = tempfile::tempdir().unwrap();
    let mut young =
        TransparentHistoryRecovery::open(dir.path().join("companion.sqlite"), config()).unwrap();
    let mut born = watch.clone();
    born.addresses[0].required_from = block_height(t + 1).unwrap();
    let mut filters = CountingFilters::default();
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = young
        .recover(&born, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!(batch.progress.outcome, Outcome::Behind);
    assert!(batch.commits.is_empty());
    assert_eq!(young.store.anchor().unwrap(), None);
    assert_eq!((filters.filters, shards.calls()), (0, 1));

    // A companion already covering the script through the end needs no retrieval.
    let dir = tempfile::tempdir().unwrap();
    let mut adapter = seeded(&dir, &script, map.start_height);
    for entry in &map.shards {
        let end = (entry.end_height, entry.terminal_block_hash.as_str());
        adapter
            .store
            .commit_shard(covered(entry, &entry.manifest_digest, end, &script, vec![]))
            .unwrap();
    }
    let mut filters = CountingFilters::default();
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(&watch, &chain, &mut filters, &mut shards)
        .unwrap();
    assert_eq!((filters.filters, shards.calls()), (0, 1));
    // The client completed through the map's end, which is still behind the wallet.
    assert_eq!(
        batch.progress,
        Progress {
            covered_through: t,
            outcome: Outcome::Behind,
        }
    );
    assert_eq!(
        adapter.store.anchor().unwrap(),
        Some(Anchor {
            height: t,
            hash: last.terminal_block_hash.clone(),
        })
    );
    // Commits keep the wallet's target, and each anchor stays at its shard's end.
    assert_eq!(batch.commits.len(), map.shards.len());
    for (commit, entry) in batch.commits.iter().zip(&map.shards) {
        assert_eq!(commit.context.target, wallet_target);
        assert_eq!(
            commit.anchor,
            ChainPoint {
                height: block_height(entry.end_height).unwrap(),
                hash: block_hash_from_display(&entry.terminal_block_hash).unwrap(),
            }
        );
        assert_eq!(
            commit.coverage,
            vec![AddressRange {
                address,
                from: block_height(entry.start_height).unwrap(),
                through: block_height(entry.end_height).unwrap(),
            }]
        );
    }

    // After a reorg the wallet holds another block at the map's end. The pass
    // cannot clamp to it and is behind, and the tail's facts, which rest on
    // the old branch, wait for the publication to follow.
    let mut reorged = chain.clone();
    reorged.hashes.insert(t, "aa".repeat(32));
    let mut filters = CountingFilters::default();
    let mut shards = CountingShards::serving(SCHEMA);
    let batch = adapter
        .recover(&watch, &reorged, &mut filters, &mut shards)
        .unwrap();
    assert_eq!((filters.filters, shards.calls()), (0, 1));
    assert_eq!(batch.progress.outcome, Outcome::Behind);
    assert_eq!(batch.state, BatchState::Pending);
    assert!(batch.commits.is_empty());
}

#[test]
fn a_replaced_tail_rolls_back_below_the_floor_without_a_wallet_hash() {
    let map = map();
    let tail = map.shards.last().unwrap();
    // The companion covered an older tail revision, ending at a block the wallet accepts.
    let old_end = (tail.end_height - 38, "ef".repeat(32));
    // The wallet holds no block below the tail's start, where the rollback lands.
    let chain = StaticChain {
        hashes: BTreeMap::from([
            old_end.clone(),
            (tail.end_height, tail.terminal_block_hash.clone()),
        ]),
    };
    for (required_from, lenient) in [(tail.start_height, true), (map.start_height, false)] {
        let mut watch = watch();
        watch.addresses[0].required_from = block_height(required_from).unwrap();
        let script = address_script(watch.addresses[0].address);
        let dir = tempfile::tempdir().unwrap();
        let mut adapter = seeded(&dir, &script, required_from);
        let old = (old_end.0, old_end.1.as_str());
        adapter
            .store
            .commit_shard(covered(tail, &"cd".repeat(32), old, &script, vec![]))
            .unwrap();
        let mut filters = CountingFilters::default();
        let mut shards = CountingShards::serving(SCHEMA);
        // Below the floor the rollback is accepted and the pass goes on to the
        // tail's filter, which the counting source refuses. At or above it the
        // wallet's missing hash stops the pass before any filter request.
        let Err(RecoveryError::Failure(stopped)) =
            adapter.recover(&watch, &chain, &mut filters, &mut shards)
        else {
            panic!("the pass must fail at the filter or at the rollback");
        };
        let cause = if lenient {
            "transport:"
        } else {
            "no accepted rollback hash"
        };
        assert!(stopped.contains(cause), "{stopped}");
        assert_eq!(adapter.store.provisional().unwrap().is_empty(), lenient);
        assert_eq!(filters.filters, usize::from(lenient));
    }
}

#[test]
fn a_map_for_another_network_or_genesis_is_refused_before_retrieval() {
    let fixture: serde_json::Value = serde_json::from_slice(MAP).unwrap();
    let mut testnet = fixture.clone();
    testnet["network"] = "test".into();
    let mut forked = fixture;
    forked["genesis_hash"] = "11".repeat(32).into();
    for served in [testnet, forked] {
        let dir = tempfile::tempdir().unwrap();
        let mut adapter =
            TransparentHistoryRecovery::open(dir.path().join("companion.sqlite"), config())
                .unwrap();
        let mut filters = CountingFilters::serving(serde_json::to_vec(&served).unwrap());
        let mut shards = CountingShards::serving(SCHEMA);
        assert!(matches!(
            adapter.recover(
                &watch(),
                &StaticChain::from_map(&map()),
                &mut filters,
                &mut shards
            ),
            Err(RecoveryError::Invalid(_))
        ));
        assert_eq!((filters.maps, filters.filters, shards.calls()), (1, 0, 0));
        assert!(adapter.store.set_identity().unwrap().is_none());
    }
}
