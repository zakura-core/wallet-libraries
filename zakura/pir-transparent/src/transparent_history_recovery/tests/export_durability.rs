use super::*;

#[test]
fn normalized_events_preserve_attribution_and_local_shard_anchor_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let map = map();
    let entry = &map.shards[0];
    let watch = watch();
    let script = address_script(watch.addresses[0].address);
    adapter.store.bind_set(&SetIdentity::of(&map)).unwrap();
    adapter
        .store
        .add_scripts(&[ScriptEntry {
            script: script.clone(),
            origin: ScriptOrigin::Imported,
            required_from: map.start_height,
        }])
        .unwrap();
    let parent_meta = transparent_events::TransactionMetadata {
        fee: FeeState::Exact(0),
        transparent_input_count: 3,
        has_shielded_components: true,
    };
    let spend_meta = transparent_events::TransactionMetadata {
        fee: FeeState::Exact(10),
        transparent_input_count: 1,
        has_shielded_components: false,
    };
    let receive = TransparentEvent::Receive(transparent_events::ReceiveEvent {
        metadata: Some(parent_meta),
        height: entry.start_height as u32,
        txid: transparent_events::Txid([1; 32]),
        transaction_index: 1,
        output_index: 0,
        value: 100,
        coinbase: false,
    });
    let spend = TransparentEvent::Spend(transparent_events::SpendEvent {
        metadata: Some(spend_meta),
        height: entry.start_height as u32 + 1,
        spending_txid: transparent_events::Txid([2; 32]),
        transaction_index: 2,
        input_index: 0,
        spent_txid: transparent_events::Txid([1; 32]),
        spent_output_index: 0,
    });
    adapter
        .store
        .commit_shard(crate::engine::ShardCommit {
            source_anchor: None,
            shard_id: entry.shard_id,
            revision_digest: entry.manifest_digest.clone(),
            sealed: entry.sealed,
            start_height: entry.start_height,
            end_height: entry.end_height,
            terminal_block_hash: entry.terminal_block_hash.clone(),
            events: [receive, spend]
                .into_iter()
                .map(|event| StoredEvent {
                    script: script.clone(),
                    event,
                    shard_id: entry.shard_id,
                    revision_digest: entry.manifest_digest.clone(),
                })
                .collect(),
            covered_scripts: vec![script],
            pending_upsert: vec![],
            pending_complete: vec![],
            cached_runs: vec![],
            failed_entries: vec![],
        })
        .unwrap();
    let first = adapter
        .normalize(&watch, map.clone(), MORE, &StaticChain::from_map(&map))
        .unwrap();
    assert_eq!(first.state, BatchState::Ready);
    assert_eq!(first.commits.len(), 1);
    let commit = &first.commits[0];
    assert_eq!(
        commit.anchor.height,
        block_height(entry.end_height).unwrap()
    );
    assert!(commit.anchor.height < commit.context.target.height);
    assert_eq!(
        commit.receives[0].metadata.unwrap().fee,
        WholeTransactionFee::Exact(Zatoshis::ZERO)
    );
    assert!(commit.receives[0].metadata.unwrap().has_shielded_components);
    assert_eq!(
        commit.spends[0].metadata.unwrap().fee,
        WholeTransactionFee::Exact(Zatoshis::const_from_u64(10))
    );
    assert_eq!(
        commit.spends[0].metadata.unwrap().transparent_input_count,
        1
    );
    adapter.acknowledge_applied(&first).unwrap();
    assert!(adapter.acknowledge_applied(&first).is_err());
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let again = adapter
        .normalize(&watch, map.clone(), MORE, &StaticChain::from_map(&map))
        .unwrap();
    assert_eq!(again.commits, first.commits);
    adapter
        .store
        .rollback_above(
            &Anchor {
                height: map.start_height - 1,
                hash: map.shards[0].parent_block_hash.clone(),
            },
            "controlled fixture reorg",
        )
        .unwrap();
    // Other sealed content under the same revision number is withdrawn, and
    // stays withdrawn after a restart.
    let mut replacement = map.clone();
    replacement.shards[0].manifest_digest = "ab".repeat(32);
    let changed = adapter
        .normalize(
            &watch,
            replacement.clone(),
            MORE,
            &StaticChain::from_map(&replacement),
        )
        .unwrap();
    let withdrawn = BatchState::Withdrawn(WithdrawnCause::Equivocation);
    assert_eq!(changed.state, withdrawn);
    assert!(changed.commits.is_empty());
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let after_restart = adapter
        .normalize(
            &watch,
            replacement.clone(),
            MORE,
            &StaticChain::from_map(&replacement),
        )
        .unwrap();
    assert_eq!(after_restart.state, withdrawn);
    assert!(adapter.acknowledge_applied(&after_restart).is_err());
}

#[test]
fn possible_wallet_export_survives_crash_before_ack_and_withdrawal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let mut map = map();
    let mut adapter = covering(&path, &map);
    let batch = pass(&mut adapter, &map);
    assert_eq!(batch.state, BatchState::Ready);
    let possibly_applied = batch.commits[1].revision.clone();
    // The application may have applied this batch, then died before acknowledging it.
    drop(adapter);

    // The tail is republished. The companion withdrew its old coverage but has
    // not retrieved the successor, so nothing replaces what may be in the wallet.
    map.shards[1].revision = 1;
    map.shards[1].manifest_digest = "5a".repeat(32);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    withdraw_tail(&mut adapter, &map);
    let pending = pass(&mut adapter, &map);
    assert_eq!(pending.state, BatchState::Pending);
    assert!(pending.commits.is_empty());
    assert!(adapter.acknowledge_applied(&pending).is_err());
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1)]);
    // The export intent survives a restart.
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    assert_eq!(pass(&mut adapter, &map).state, BatchState::Pending);

    // Once the successor is retrieved it replaces the possibly applied tail.
    retrieve_tail(&mut adapter, &map);
    let ready = pass(&mut adapter, &map);
    assert_eq!(ready.state, BatchState::Ready);
    let successor = &ready.commits[1].revision;
    assert_eq!(successor.source, possibly_applied.source);
    assert_eq!(successor.lineage, possibly_applied.lineage + 1);
    // A crash before this acknowledgment replays the same batch.
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let replayed = pass(&mut adapter, &map);
    assert_eq!(replayed.state, BatchState::Ready);
    assert_eq!(replayed.commits, ready.commits);
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 1), (TAIL, 2)]);
    // The possibly applied tail is a notification the wallet must reconcile.
    assert_eq!(
        replayed.retired_revisions(),
        std::slice::from_ref(&possibly_applied)
    );
    assert!(matches!(
        adapter.acknowledge_applied(&replayed),
        Err(RecoveryError::Invalid(_))
    ));
    // Rejection must preserve the notification even across another crash.
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let replayed = pass(&mut adapter, &map);
    assert_eq!(replayed.retired_revisions(), &[possibly_applied]);
    assert!(adapter.acknowledge_reconciled(&batch).is_err());
    adapter.acknowledge_reconciled(&replayed).unwrap();
    assert!(adapter.acknowledge_reconciled(&replayed).is_err());
    assert_eq!(exported(&adapter), vec![(ARCHIVE, 1), (TAIL, 2)]);
    assert_eq!(cataloged(&adapter), 2);
    let acknowledged = pass(&mut adapter, &map);
    assert_eq!(acknowledged.state, BatchState::Ready);
    assert!(acknowledged.retired_revisions().is_empty());
    adapter.acknowledge_applied(&acknowledged).unwrap();
}

#[test]
fn empty_replacement_retains_notice_until_wallet_reconciliation_commits() {
    use zcash_client_backend::data_api::{
        Account as _,
        chain::ChainState,
        testing::{InitialChainState, TestBuilder, TestRng},
        transparent_ledger::{
            TransparentLedgerMode::PrivateRequired, TransparentLedgerRead as _,
            TransparentLedgerWrite as _,
        },
    };
    use zcash_client_sqlite::{
        WalletDb,
        testing::{BlockCache, db::TestDbFactory},
        util::SystemClock,
    };

    let mut publication = map();
    publication.shards.truncate(1);
    publication.shards[0].sealed = false;
    let start = publication.start_height;
    let parent = block_hash_from_display(&publication.shards[0].parent_block_hash).unwrap();
    let mut wallet = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(BlockCache::new())
        .with_initial_chain_state(|_, _| InitialChainState {
            chain_state: ChainState::empty(block_height(start - 1).unwrap(), parent),
            prior_sapling_roots: vec![],
            prior_orchard_roots: vec![],
        })
        .with_account_having_current_birthday()
        .build();
    wallet.generate_and_scan_empty_blocks(2);
    let account = wallet.test_account().unwrap().id();
    wallet
        .wallet_mut()
        .db_mut()
        .apply_transparent_policy(PrivateRequired)
        .unwrap();
    wallet
        .wallet_mut()
        .db_mut()
        .set_transparent_ledger_mode(PrivateRequired);
    let watch = wallet.wallet().db().transparent_watch_set(account).unwrap();
    let target = watch.target.unwrap();
    publication.shards[0].end_height = u64::from(u32::from(target.height));
    publication.shards[0].terminal_block_hash = target.hash.to_string();
    let chain = StaticChain::from_map(&publication);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("companion.sqlite");
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    adapter
        .store
        .bind_set(&SetIdentity::of(&publication))
        .unwrap();
    let scripts: Vec<_> = watch
        .addresses
        .iter()
        .map(|a| address_script(a.address))
        .collect();
    adapter
        .store
        .add_scripts(
            &scripts
                .iter()
                .map(|script| ScriptEntry {
                    script: script.clone(),
                    origin: ScriptOrigin::Imported,
                    required_from: start,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let entry = &publication.shards[0];
    adapter
        .store
        .commit_shard(crate::engine::ShardCommit {
            source_anchor: None,
            shard_id: entry.shard_id,
            revision_digest: entry.manifest_digest.clone(),
            sealed: false,
            start_height: start,
            end_height: entry.end_height,
            terminal_block_hash: entry.terminal_block_hash.clone(),
            events: vec![],
            covered_scripts: scripts.clone(),
            pending_upsert: vec![],
            pending_complete: vec![],
            cached_runs: vec![],
            failed_entries: vec![],
        })
        .unwrap();
    let first = adapter
        .normalize(&watch, publication.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(first.state, BatchState::Ready);
    let retired = first.commits[0].revision.clone();
    for commit in &first.commits {
        wallet
            .wallet_mut()
            .db_mut()
            .apply_transparent_ledger_commit(commit.clone())
            .unwrap();
    }
    wallet
        .wallet_mut()
        .db_mut()
        .qualify_transparent_revision(&retired)
        .unwrap();
    let wallet_path = wallet.wallet().conn().path().unwrap().to_owned();
    // Coverage rows the wallet durably holds under `revision`.
    let coverage_of = |revision: &RecoveryRevision| -> u64 {
        Connection::open(&wallet_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM tpir_coverage c JOIN tpir_revisions r ON r.id = c.revision_id
                 WHERE r.source = ?1 AND r.revision = ?2",
                rusqlite::params![revision.source, revision.revision],
                |row| row.get(0),
            )
            .unwrap()
    };
    let before = wallet
        .wallet()
        .db()
        .transparent_candidate_recovery(account)
        .unwrap();
    assert_eq!(before.covered_through, Some(target.height));
    // Crash after the wallet commits but before the companion acknowledges.
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    adapter
        .store
        .rollback_above(
            &Anchor {
                height: start - 1,
                hash: publication.shards[0].parent_block_hash.clone(),
            },
            "fixture withdrawal",
        )
        .unwrap();
    publication.shards[0].revision += 1;
    publication.shards[0].manifest_digest = "ab".repeat(32);
    // Until the companion retrieves a successor, the empty replacement keeps
    // the possibly applied revision's notice and hands the wallet nothing.
    let replacement = adapter
        .normalize(&watch, publication.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(replacement.state, BatchState::Pending);
    assert!(replacement.commits.is_empty());
    assert!(replacement.retired_revisions().is_empty());
    assert!(adapter.acknowledge_applied(&replacement).is_err());
    assert!(adapter.acknowledge_reconciled(&replacement).is_err());
    assert_eq!(
        wallet
            .wallet()
            .db()
            .transparent_candidate_recovery(account)
            .unwrap(),
        before
    );

    // Once retrieved, the successor resolves the retired revision.
    let entry = &publication.shards[0];
    adapter
        .store
        .commit_shard(crate::engine::ShardCommit {
            source_anchor: None,
            shard_id: entry.shard_id,
            revision_digest: entry.manifest_digest.clone(),
            sealed: false,
            start_height: start,
            end_height: entry.end_height,
            terminal_block_hash: entry.terminal_block_hash.clone(),
            events: vec![],
            covered_scripts: scripts,
            pending_upsert: vec![],
            pending_complete: vec![],
            cached_runs: vec![],
            failed_entries: vec![],
        })
        .unwrap();
    let replacement = adapter
        .normalize(&watch, publication.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(replacement.state, BatchState::Ready);
    assert_eq!(
        replacement.retired_revisions(),
        std::slice::from_ref(&retired)
    );
    let successor = replacement.commits[0].clone();
    assert_eq!(successor.revision.source, retired.source);
    assert_eq!(successor.revision.lineage, retired.lineage + 1);
    assert!(adapter.acknowledge_applied(&replacement).is_err());

    // A trusted reconciliation that fails changes nothing, and the notice
    // survives a crash.
    wallet.wallet().conn().execute_batch("CREATE TEMP TRIGGER fail_reconciliation BEFORE DELETE ON tpir_coverage BEGIN SELECT RAISE(ABORT, 'fixture reconciliation failure'); END;").unwrap();
    assert!(
        wallet
            .wallet_mut()
            .db_mut()
            .qualify_transparent_revision(&successor.revision)
            .is_err()
    );
    assert_eq!(
        wallet
            .wallet()
            .db()
            .transparent_candidate_recovery(account)
            .unwrap(),
        before
    );
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let replacement = adapter
        .normalize(&watch, publication.clone(), MORE, &chain)
        .unwrap();
    assert_eq!(
        replacement.retired_revisions(),
        std::slice::from_ref(&retired)
    );
    assert!(adapter.acknowledge_applied(&replacement).is_err());

    wallet
        .wallet()
        .conn()
        .execute_batch("DROP TRIGGER fail_reconciliation")
        .unwrap();
    // This controlled fixture trusts the successor, standing in for the
    // wallet's trusted operation, which qualifies and applies it in one
    // transaction. A publication change alone is never authorization in an
    // application.
    wallet
        .wallet_mut()
        .db_mut()
        .qualify_transparent_revision(&successor.revision)
        .unwrap();
    wallet
        .wallet_mut()
        .db_mut()
        .apply_transparent_ledger_commit(successor.clone())
        .unwrap();
    // A reopened wallet must observe the committed reconciliation before
    // acknowledgement: the retired evidence is withdrawn, and the successor
    // covers the target.
    let reopened = WalletDb::from_connection(
        Connection::open(&wallet_path).unwrap(),
        *wallet.network(),
        SystemClock,
        TestRng::seed_from_u64(0),
    )
    .with_transparent_ledger_mode(PrivateRequired);
    assert_eq!(coverage_of(&retired), 0);
    assert!(coverage_of(&successor.revision) > 0);
    assert_eq!(
        reopened
            .transparent_candidate_recovery(account)
            .unwrap()
            .covered_through,
        Some(target.height)
    );
    adapter.acknowledge_reconciled(&replacement).unwrap();
    drop(adapter);
    let mut adapter = TransparentHistoryRecovery::open(&path, config()).unwrap();
    let final_batch = adapter
        .normalize(&watch, publication, MORE, &chain)
        .unwrap();
    assert_eq!(final_batch.state, BatchState::Ready);
    assert!(final_batch.retired_revisions().is_empty());
    adapter.acknowledge_applied(&final_batch).unwrap();
}
