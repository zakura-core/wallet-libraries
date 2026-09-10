//! Forks and reorgs on controlled infrastructure: the same height with two
//! hashes, a fork that reaches into the sealed archive tier, one that lands
//! just above the tier boundary, one that reconverges, and one inside the
//! provisional tail. Every case ends exact against the reducer over the
//! winning branch, with nothing from the losing branch left behind.
//!
//! A sealed shard cannot be republished in place, so a fork in a sealed shard
//! is a new publication in a new directory, and the library's rule for it is
//! stated where the tests assert it: coverage rests on shard terminals, so a
//! fork inside a sealed shard rolls back to the highest accepted terminal
//! below the shard, not to the block before the fork.

mod common;

use std::collections::BTreeMap;

use common::blocks::*;
use common::catalogue::*;
use common::*;
use transparent_events::Txid;
use transparent_wallet::WorkLimits;
use zakura_wallet_sync::TransparentCompletion;

/// A receive to `script` at `height` on a forked branch, with its own txid.
fn add_receive(
    blocks: &mut BTreeMap<u64, Block>,
    height: u64,
    script: &transparent_filter::ScriptBytes,
    value: u64,
    tag: u8,
) {
    let block = blocks.get_mut(&height).unwrap();
    block.txs.push(Tx {
        txid: Txid([tag; 32]),
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: Txid([0xee; 32]),
                n: 0,
            },
            prev: None,
        }],
        vout: vec![TxOut {
            script: script.clone(),
            value,
        }],
    });
}

/// Drops every spending transaction at or above `from`.
fn drop_spends(
    blocks: &mut BTreeMap<u64, Block>,
    from: u64,
    of: &transparent_filter::ScriptBytes,
    chain: &Chain,
) {
    let outs: Vec<Txid> = chain
        .transactions()
        .flat_map(|(_, _, tx)| {
            tx.vout
                .iter()
                .filter(|o| o.script == *of)
                .map(move |_| tx.txid)
        })
        .collect();
    for (height, block) in blocks.iter_mut() {
        if *height < from {
            continue;
        }
        block
            .txs
            .retain(|tx| !tx.vin.iter().any(|i| outs.contains(&i.prevout.txid)));
    }
}

/// Publishes chain B (the winning branch) into a fresh directory and serves it.
async fn republished(
    chain_b: &Chain,
    dir: &std::path::Path,
    tail_revision: u32,
    supersedes: &str,
) -> (
    transparent_filter::ShardMap,
    String,
    std::sync::Arc<std::sync::Mutex<Faults>>,
) {
    let map = publish_layout(
        dir,
        &extract(chain_b),
        DEFAULT_LAYOUT,
        tiers,
        tail_revision,
        supersedes,
        chain_b.hash_fn(),
    );
    let (base, faults) = serve_traced(dir).await;
    (map, base, faults)
}

/// A wallet that has recovered the catalogue on chain A.
async fn recovered_a() -> (
    zakura_wallet_store::WalletDb,
    zakura_wallet_core::AccountId,
    Chain,
    Cast,
    transparent_filter::ShardMap,
    tempfile::TempDir,
) {
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, _) = served(&chain, dir.path()).await;
    let (db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    (db, account, chain, cast, map, dir)
}

fn losing_spend_txid(chain: &Chain, cast: &Cast) -> Txid {
    // The spend of ext[0], at shard 2 start + 10.
    chain
        .transactions()
        .find(|(_, _, tx)| {
            tx.vin.iter().any(|i| {
                chain
                    .find_output(&i.prevout)
                    .is_some_and(|(_, o)| o.script == cast.ext[0])
            })
        })
        .unwrap()
        .2
        .txid
}

#[tokio::test(flavor = "multi_thread")]
async fn a_same_height_fork_inside_a_sealed_shard_is_rolled_back_to_the_last_accepted_terminal() {
    let (db, account, chain, cast, map_a, _dir_a) = recovered_a().await;
    let (start, end_of_shard_1) = (shard_bounds(2).0, shard_bounds(1).1);
    let fork = start + 5;
    // Branch B: the spend of ext[0] never happens; ext[0] is paid again.
    let losing = losing_spend_txid(&chain, &cast);
    let chain_b = chain.fork_at(fork, |blocks| {
        drop_spends(blocks, fork, &cast.ext[0], &chain);
        add_receive(blocks, fork + 50, &cast.ext[0], 900, 0xf1);
    });
    assert_ne!(
        chain.hash(fork),
        chain_b.hash(fork),
        "the same height, another hash"
    );
    assert_eq!(chain.hash(fork - 1), chain_b.hash(fork - 1));
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 0, "").await;
    assert_eq!(
        map_b.shards[1].manifest_digest,
        map_a.shards[1].manifest_digest
    );
    assert_ne!(
        map_b.shards[2].manifest_digest,
        map_a.shards[2].manifest_digest
    );

    // The wallet learns of the fork from its own chain, without a rewind.
    let before = Snapshot::of(&db);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(
        progress.rolled_back_to,
        Some(h(end_of_shard_1)),
        "coverage rests on shard terminals: the rollback lands at the last accepted one below the fork"
    );
    assert!(
        !transport.opened.contains(&0) && !transport.opened.contains(&1),
        "the shards below the fork are still covered"
    );
    assert!(transport.queried.contains(&2) && transport.queried.contains(&3));
    let events = stored_events(&db);
    assert!(
        !events.iter().any(|(_, e)| e.txid() == losing),
        "the losing branch's spend is gone"
    );
    for terminal in db.transparent_coverage_terminals().unwrap() {
        if u64::from(terminal.0) <= end_of_shard_1 {
            assert_eq!(
                terminal.1,
                chain.hash(u64::from(terminal.0)).to_display_hex(),
                "coverage below the fork keeps its hash"
            );
        }
    }
    assert!(before.events.len() > 0);
    let expected = reduce(&chain_b, &cast.all, FIRST, chain_b.last());
    assert!(expected.utxos.values().any(|(_, v, _, _)| *v == 900));
    compare_blocks(&mut db, account, &expected);
    assert_eq!(state(&db, account).unresolved_spends, 0);
    check_requests(&db, account, &chain_b, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_same_height_fork_the_wallet_rewound_first_is_re_read_whole() {
    let (mut db, account, chain, cast, _map_a, _dir_a) = recovered_a().await;
    let fork = shard_bounds(2).0 + 5;
    let chain_b = chain.fork_at(fork, |blocks| {
        drop_spends(blocks, fork, &cast.ext[0], &chain);
        add_receive(blocks, fork + 50, &cast.ext[0], 900, 0xf2);
    });
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 0, "").await;

    // The wallet rewinds to the common ancestor and rescans, as the engine
    // would; the ledger's own coverage above the cut goes with the blocks.
    db.truncate_to(h(fork - 1)).unwrap();
    assert_eq!(
        state(&db, account).covered_through,
        Some(h(shard_bounds(1).1))
    );
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(
        progress.rolled_back_to, None,
        "the rewind already removed everything above the cut"
    );
    assert!(!transport.queried.contains(&0) && !transport.queried.contains(&1));
    assert!(
        transport.queried.contains(&2),
        "the forked shard is read again whole"
    );
    compare_blocks(
        &mut db,
        account,
        &reduce(&chain_b, &cast.all, FIRST, chain_b.last()),
    );
    check_requests(&db, account, &chain_b, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reconverging_fork_reappears_at_new_heights_and_hashes() {
    // Every transaction from the fork on is mined one block later on the
    // winning branch. Same outpoints, same values, other heights: nothing may
    // be reported as a conflict, and the balance is unchanged.
    let (db, account, chain, cast, _map_a, _dir_a) = recovered_a().await;
    let fork = shard_bounds(2).0 + 20;
    let last = chain.last();
    let chain_b = chain.fork_at(fork, |blocks| {
        let mut carried: Vec<Tx> = Vec::new();
        for height in fork..=last {
            let block = blocks.get_mut(&height).unwrap();
            let own = std::mem::take(&mut block.txs);
            block.txs = std::mem::replace(&mut carried, own);
        }
        // The last block keeps what was shifted into it and its own.
        blocks.get_mut(&last).unwrap().txs.extend(carried);
    });
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 0, "").await;
    let balance_before = db.transparent_balance(account).unwrap().total().into_u64();
    let heights_before: BTreeMap<Txid, u32> = stored_events(&db)
        .iter()
        .map(|(_, e)| (e.txid(), e.height()))
        .collect();

    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, _, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress =
        progress.expect("a reconverging fork is a rollback and a re-read, not a contradiction");
    complete(&progress);
    assert_eq!(progress.rolled_back_to, Some(h(shard_bounds(1).1)));
    let expected = reduce(&chain_b, &cast.all, FIRST, chain_b.last());
    assert_eq!(
        expected.balance, balance_before,
        "the same money, mined a block later"
    );
    compare_blocks(&mut db, account, &expected);
    let mut moved = 0;
    for (_, e) in stored_events(&db) {
        let before = heights_before[&e.txid()];
        if u64::from(before) >= fork && u64::from(before) < last {
            assert_eq!(e.height(), before + 1, "shifted by one block");
            moved += 1;
        } else {
            assert_eq!(e.height(), before);
        }
    }
    assert!(moved > 0, "some of the wallet's events lay above the fork");
    check_requests(&db, account, &chain_b, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cross_tier_reorg_just_above_the_archive_boundary() {
    // The fork is the first block of the recent tier. The archive tier is
    // untouched, and is neither re-read nor re-verified.
    let (db, account, chain, cast, map_a, _dir_a) = recovered_a().await;
    let fork = shard_bounds(2).0;
    let chain_b = chain.fork_at(fork, |blocks| {
        drop_spends(blocks, fork, &cast.ext[5], &chain);
    });
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 0, "").await;
    assert_eq!(
        map_b.shards[0].manifest_digest,
        map_a.shards[0].manifest_digest
    );
    assert_eq!(
        map_b.shards[1].manifest_digest,
        map_a.shards[1].manifest_digest
    );
    assert_ne!(
        map_b.shards[0].geometry, map_b.shards[3].geometry,
        "two tiers"
    );

    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.rolled_back_to, Some(h(fork - 1)));
    assert!(!transport.opened.contains(&0) && !transport.opened.contains(&1));
    assert!(transport.manifests > 0);
    let expected = reduce(&chain_b, &cast.all, FIRST, chain_b.last());
    assert!(
        expected
            .utxos
            .values()
            .any(|(s, v, _, _)| s == cast.ext[5].as_slice() && *v == 9_000),
        "the old receive is unspent on the winning branch"
    );
    compare_blocks(&mut db, account, &expected);
    check_requests(&db, account, &chain_b, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cross_tier_reorg_that_reaches_into_the_archive_tier() {
    // The fork lies inside the last archive shard: that sealed shard is
    // another publication on the winning branch, and everything from the
    // shard before it on is read again.
    let (db, account, chain, cast, map_a, _dir_a) = recovered_a().await;
    let fork = shard_bounds(1).1 - 5;
    let chain_b = chain.fork_at(fork, |blocks| {
        add_receive(blocks, fork + 2, &cast.ext[8], 5_555, 0xf3);
    });
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 0, "").await;
    assert_eq!(
        map_b.shards[0].manifest_digest,
        map_a.shards[0].manifest_digest
    );
    assert_ne!(
        map_b.shards[1].manifest_digest,
        map_a.shards[1].manifest_digest
    );
    assert_eq!(
        map_b.shards[1].geometry, map_a.shards[1].geometry,
        "still the archive geometry"
    );

    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.rolled_back_to, Some(h(shard_bounds(0).1)));
    assert!(
        !transport.opened.contains(&0),
        "the shard below the fork is kept"
    );
    for shard in 1..SHARDS {
        assert!(
            transport.queried.contains(&shard),
            "shard {shard} is read again"
        );
    }
    let expected = reduce(&chain_b, &cast.all, FIRST, chain_b.last());
    assert!(expected.utxos.values().any(|(_, v, _, _)| *v == 5_555));
    compare_blocks(&mut db, account, &expected);
    check_requests(&db, account, &chain_b, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_inside_the_provisional_tail_is_a_replaced_revision() {
    let (db, account, chain, cast, map_a, _dir_a) = recovered_a().await;
    let tail_start = shard_bounds(3).0;
    let fork = tail_start + 100;
    let tail_digest = map_a.shards[3].manifest_digest.clone();
    let chain_b = chain.fork_at(fork, |blocks| {
        drop_spends(blocks, fork, &cast.ext[5], &chain);
        add_receive(blocks, fork + 10, &cast.ext[6], 777, 0xf4);
    });
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 1, &tail_digest).await;
    assert_ne!(map_b.shards[3].manifest_digest, tail_digest);
    assert_eq!(map_b.shards[3].revision, 1);

    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.rolled_back_to, Some(h(tail_start - 1)));
    assert!(!transport.opened.contains(&2), "the sealed shards are kept");
    let provisional = db.transparent_provisional_coverage().unwrap();
    assert!(!provisional.is_empty());
    assert!(
        provisional
            .iter()
            .all(|r| r.revision_digest == map_b.shards[3].manifest_digest)
    );
    compare_blocks(
        &mut db,
        account,
        &reduce(&chain_b, &cast.all, FIRST, chain_b.last()),
    );
    check_requests(&db, account, &chain_b, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_work_orphaned_by_a_reorg_is_removed_with_the_range() {
    // A run stops on its budget with pages owed in the tail; then the tail
    // is reorganised. The owed pages belonged to a revision that no longer
    // exists on the wallet's chain, and go with it.
    let (mut db, account) = wallet();
    let (mut chain, cast) = catalogue(&mut db, account);
    // A paged history in the tail, so the tail owes pages.
    let tail_start = shard_bounds(3).0;
    for i in 0..long_history() {
        chain.pay(tail_start + 60 + i % 100, cast.ext[8].clone(), 13);
    }
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir_a = tempfile::tempdir().unwrap();
    let (map_a, base_a, _) = served(&chain, dir_a.path()).await;

    // Find a budget that leaves pages owed in the tail.
    let mut db = db;
    let mut found = false;
    for budget in [12u64, 16, 20, 24, 28, 32, 40, 48, 64] {
        let (next, _, progress) = recover(
            db,
            base_a.clone(),
            dir_a.path(),
            &map_a,
            WorkLimits {
                max_queries: Some(budget),
                max_private_bytes: None,
            },
        )
        .await;
        db = next;
        let progress = progress.unwrap();
        if db
            .transparent_pending()
            .unwrap()
            .iter()
            .any(|p| p.shard_id == 3)
        {
            assert_eq!(
                progress.completion,
                TransparentCompletion::Incomplete("query-budget".into())
            );
            found = true;
            break;
        }
        if progress.completion == TransparentCompletion::Complete {
            break;
        }
    }
    assert!(found, "a budget left pages owed in the tail");
    let owed: Vec<_> = db.transparent_pending().unwrap();
    let old_digest = map_a.shards[3].manifest_digest.clone();
    assert!(owed.iter().any(|p| p.revision_digest == old_digest));
    assert!(state(&db, account).anchor.is_none());

    let fork = tail_start;
    let chain_b = chain.fork_at(fork, |blocks| {
        drop_spends(blocks, fork, &cast.ext[5], &chain);
    });
    let dir_b = tempfile::tempdir().unwrap();
    let (map_b, base_b, faults) = republished(&chain_b, dir_b.path(), 0, "").await;
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain_b.hash_fn());
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.rolled_back_to, Some(h(fork - 1)));
    assert!(
        db.transparent_pending().unwrap().is_empty(),
        "nothing is owed for a revision the chain left behind"
    );
    assert!(
        !transport.revisions.iter().any(|r| *r == old_digest),
        "no query names the orphaned revision"
    );
    for terminal in db.transparent_coverage_terminals().unwrap() {
        assert_eq!(
            terminal.1,
            chain_b.hash(u64::from(terminal.0)).to_display_hex()
        );
    }
    compare_blocks(
        &mut db,
        account,
        &reduce(&chain_b, &cast.all, FIRST, chain_b.last()),
    );
    check_requests(&db, account, &chain_b, &faults);
}
