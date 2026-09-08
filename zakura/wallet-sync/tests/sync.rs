//! Engine tests.
//!
//! Each drives the real scanner and the real store over an in-memory chain of
//! real encrypted notes, so the only thing simulated is the network.

use assert_matches::assert_matches;
use zakura_wallet_core::{
    BlockAnchor, CompactBlock, pool::PoolId, retrieval::ActionRecord, scanning::ScanPriority,
};
use zakura_wallet_scan::{
    AccountId, KeyScope, ScanKeys, TransparentWatch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, fvk_from_seed, test_params},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_sync::{
    ByteBudget, CancellationToken, ChainSource, Direction, PublicRetrieval, Request, Retrieval,
    Retrieved, Step, SyncConfig, SyncEngine, SyncPhase,
    testing::{FailingChain, InMemoryChain, IncoherentChain, MapRetrieval, UnservedTransactions},
};
use zcash_protocol::consensus::BlockHeight;

const ALICE: AccountId = AccountId(1);
const START: u32 = IRONWOOD_ACTIVATION + 10;

type Params = zcash_protocol::local_consensus::LocalNetwork;

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

fn alice() -> orchard::keys::FullViewingKey {
    fvk_from_seed(1)
}

fn keys() -> ScanKeys {
    ScanKeys::from_accounts([(ALICE, alice())])
}

/// Builds an engine over a fresh wallet and the given chain.
fn engine(chain: InMemoryChain) -> SyncEngine<InMemoryChain, Params> {
    engine_with(chain, SyncConfig::default())
}

fn engine_with(chain: InMemoryChain, config: SyncConfig) -> SyncEngine<InMemoryChain, Params> {
    engine_over(chain, config)
}

/// Builds an engine over any source, for the doubles that wrap `InMemoryChain`.
fn engine_over<S: ChainSource + Send + Sync + 'static>(
    chain: S,
    config: SyncConfig,
) -> SyncEngine<S, Params> {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    SyncEngine::new(
        chain,
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        config,
    )
}

/// A chain of `count` blocks, each paying Alice `value`.
fn paying_chain(count: usize, value: u64) -> (BlockAnchor, Vec<CompactBlock>) {
    let mut chain = ChainBuilder::new(START);
    for i in 0..count {
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &alice(), KeyScope::External, value + i as u64);
            });
        });
    }
    (chain.anchor(), chain.into_blocks())
}

/// Total value of the notes the wallet holds.
fn balance(db: &WalletDb) -> i64 {
    db.connection()
        .query_row(
            "SELECT COALESCE(SUM(value), 0) FROM cache.received_notes",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn note_count(db: &WalletDb) -> u32 {
    db.connection()
        .query_row("SELECT COUNT(*) FROM cache.received_notes", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// A fingerprint of everything the wallet believes, for comparing two runs.
fn fingerprint(db: &WalletDb) -> Vec<String> {
    let mut out = Vec::new();
    for table in [
        "blocks",
        "transactions",
        "received_notes",
        "received_note_spends",
        "nullifier_map",
        "scan_queue",
        "tree_shards",
        "tree_checkpoints",
        "tree_cap",
        "enhance_candidates",
    ] {
        let mut stmt = db
            .connection()
            .prepare(&format!("SELECT * FROM cache.{table}"))
            .unwrap_or_else(|e| panic!("{table}: {e}"));
        let columns = stmt.column_count();
        let mut rows: Vec<String> = stmt
            .query_map([], |r| {
                let mut cells = Vec::with_capacity(columns);
                for i in 0..columns {
                    cells.push(format!("{:?}", r.get::<_, rusqlite::types::Value>(i)?));
                }
                Ok(cells.join(","))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        // Sorted, because row order is not part of what the wallet believes.
        rows.sort();
        out.push(format!("{table}: {}", rows.join("|")));
    }
    out
}

// ------------------------------------------------------------ syncing

#[tokio::test]
async fn an_engine_syncs_to_the_tip_with_the_right_balance() {
    let (anchor, blocks) = paying_chain(5, 1_000);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain);

    let summary = engine.run(&CancellationToken::new()).await.unwrap();

    assert_eq!(summary.notes, 5);
    assert!(!summary.cancelled);
    assert_eq!(summary.rewinds, 0);

    let db = engine.into_db();
    assert_eq!(note_count(&db), 5);
    assert_eq!(balance(&db), 1_000 + 1_001 + 1_002 + 1_003 + 1_004);
    assert_eq!(
        db.block_height_extrema().unwrap(),
        Some((h(START), h(START + 4)))
    );
}

#[tokio::test]
async fn a_second_run_finds_nothing_left_to_do() {
    let (anchor, blocks) = paying_chain(4, 500);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain);
    let cancel = CancellationToken::new();

    engine.run(&cancel).await.unwrap();
    let served = engine.db().block_height_extrema().unwrap();

    let second = engine.run(&cancel).await.unwrap();
    assert_eq!(second.batches, 0, "everything was already scanned");
    assert_eq!(engine.db().block_height_extrema().unwrap(), served);
}

#[tokio::test]
async fn an_empty_chain_leaves_an_empty_wallet() {
    let chain = InMemoryChain::new(
        ChainBuilder::new(START).anchor(),
        Vec::new(),
    );
    let mut engine = engine(chain);

    let summary = engine.run(&CancellationToken::new()).await.unwrap();
    assert_eq!(summary.batches, 0);
    assert_eq!(engine.db().block_height_extrema().unwrap(), None);
}

#[tokio::test]
async fn a_step_reports_exactly_what_it_did() {
    let (anchor, blocks) = paying_chain(3, 10);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain);
    let cancel = CancellationToken::new();

    engine.update_tip().await.unwrap();

    assert_matches!(
        engine.step(&cancel).await.unwrap(),
        Step::Scanned { range, notes } if range == (h(START)..h(START + 3)) && notes == 3
    );
    // With nothing left to scan, the engine asks about the transactions it
    // found, to recover the memos and outgoing data compact blocks omit. This
    // chain has no full transactions to give, so it answers that it does not
    // have them and the requests retire.
    assert_matches!(
        engine.step(&cancel).await.unwrap(),
        Step::Enhanced { fetched, applied, failed }
            if fetched == 3 && applied == 0 && failed == 0
    );
    assert_matches!(engine.step(&cancel).await.unwrap(), Step::Idle);
}

// ------------------------------------------------------------- budget

#[tokio::test]
async fn the_byte_budget_bounds_how_much_is_held_at_once() {
    // A block count would not do this: mainnet compact blocks vary in size by
    // four orders of magnitude, so a fixed count is either pointlessly small or
    // an out-of-memory kill.
    let mut chain = ChainBuilder::new(START);
    for _ in 0..8 {
        chain.block(|b| {
            b.tx(|t| {
                // Twenty actions a block, so each block is a few kilobytes.
                for _ in 0..20 {
                    t.decoy(PoolId::Ironwood, 1);
                }
                t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 1);
            });
        });
    }
    let anchor = chain.anchor();
    let blocks = chain.into_blocks();
    let per_block = zakura_wallet_sync::estimated_size(&blocks[0]);

    // A budget of two-and-a-bit blocks.
    let budget = ByteBudget::new(per_block * 2 + per_block / 2);
    let source = InMemoryChain::new(anchor, blocks);
    let mut engine = engine_with(
        source,
        SyncConfig {
            budget,
            ..SyncConfig::default()
        },
    );

    engine.update_tip().await.unwrap();
    let cancel = CancellationToken::new();

    // Every batch must fit the budget, so the eight blocks take several steps.
    let mut steps = 0;
    loop {
        match engine.step(&cancel).await.unwrap() {
            Step::Scanned { range, .. } => {
                steps += 1;
                let count = u32::from(range.end) - u32::from(range.start);
                assert!(
                    count <= 2,
                    "a batch of {count} blocks exceeds the budget of two"
                );
            }
            Step::Idle => break,
            // Not what these tests are about, but a real step the engine takes.
            Step::Enhanced { .. } => continue,
            other => panic!("unexpected {other:?}"),
        }
    }

    assert!(steps >= 4, "eight blocks at two a batch is at least four steps");
    assert_eq!(note_count(engine.db()), 8);
}

#[tokio::test]
async fn a_block_larger_than_the_whole_budget_is_still_scanned() {
    // Otherwise the wallet would stall permanently on one busy block.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            for _ in 0..50 {
                t.decoy(PoolId::Ironwood, 1);
            }
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 42);
        });
    });
    let anchor = chain.anchor();
    let blocks = chain.into_blocks();

    let mut engine = engine_with(
        InMemoryChain::new(anchor, blocks),
        SyncConfig {
            budget: ByteBudget::new(1),
            ..SyncConfig::default()
        },
    );

    engine.run(&CancellationToken::new()).await.unwrap();
    assert_eq!(note_count(engine.db()), 1);
    assert_eq!(balance(engine.db()), 42);
}

// -------------------------------------------------------------- reorgs

/// Builds a chain, syncs it, then reorgs from `depth` blocks below the tip.
async fn reorg_scenario(total: usize, depth: usize) -> (SyncEngine<InMemoryChain, Params>, u32) {
    let (anchor, blocks) = paying_chain(total, 1_000);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain.clone());
    let cancel = CancellationToken::new();

    engine.run(&cancel).await.unwrap();
    assert_eq!(note_count(engine.db()), total as u32);

    // Rebuild the chain's tail differently, and longer: a competing chain wins
    // by being longer, and it is the *new* blocks arriving above the wallet's
    // scanned tip that make it check continuity and discover the reorg. A
    // replacement of equal length delivers nothing new to check.
    let fork_at = START + (total - depth) as u32;
    let mut fork = ChainBuilder::with_anchor(
        fork_at,
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: (total - depth) as u32,
        },
    );
    for _ in 0..(depth + 2) {
        fork.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 7_777);
            });
        });
    }

    // Splice the fork onto the retained prefix so `prev_hash` is right there.
    let mut replacement = fork.into_blocks();
    let retained_hash = chain
        .blocks()
        .iter()
        .find(|b| b.height == h(fork_at - 1))
        .expect("the retained prefix has a tip")
        .hash;
    replacement[0].prev_hash = retained_hash;

    chain.reorg(h(fork_at), replacement);
    (engine, fork_at)
}

/// Drives an engine until it reports nothing left to do, returning how many
/// rewinds it took.
async fn converge(engine: &mut SyncEngine<InMemoryChain, Params>, rounds: usize) -> usize {
    let cancel = CancellationToken::new();
    let mut rewinds = 0;
    for _ in 0..rounds {
        engine.update_tip().await.unwrap();
        match engine.step(&cancel).await.unwrap() {
            Step::Idle => return rewinds,
            Step::Rewound { .. } => rewinds += 1,
            _ => {}
        }
    }
    panic!("the engine did not converge within {rounds} rounds");
}

/// Asserts the wallet matches the chain the source is now serving.
fn assert_matches_chain(engine: &SyncEngine<InMemoryChain, Params>, replaced: usize) {
    let db = engine.db();
    let reorged: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.received_notes WHERE value = 7777",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        reorged, replaced as i64,
        "the replaced blocks' notes should be the new chain's"
    );

    // Nothing from the abandoned chain survives above the fork point.
    let stale: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.blocks b
             WHERE NOT EXISTS (SELECT 1 FROM cache.received_notes n
                               WHERE n.transaction_id IN (
                                   SELECT id FROM cache.transactions WHERE block_height = b.height))
               AND b.height > 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stale, 0, "every stored block should still carry its note");
}

#[tokio::test]
async fn a_shallow_reorg_converges() {
    let (mut engine, _) = reorg_scenario(20, 5).await;
    let rewinds = converge(&mut engine, 60).await;
    assert!(rewinds > 0, "converging without rewinding proves nothing");
    assert_matches_chain(&engine, 7);
    assert_eq!(note_count(engine.db()), 22);
}

#[tokio::test]
async fn a_deep_reorg_converges() {
    let (mut engine, _) = reorg_scenario(80, 50).await;
    let rewinds = converge(&mut engine, 300).await;
    assert!(rewinds > 0, "converging without rewinding proves nothing");
    assert_matches_chain(&engine, 52);
    assert_eq!(note_count(engine.db()), 82);
}

#[tokio::test]
async fn a_reorg_leaves_the_wallet_matching_a_fresh_scan() {
    // The strongest statement available: after converging, the wallet must hold
    // exactly what scanning the final chain from scratch would produce.
    let (mut engine, _) = reorg_scenario(20, 5).await;
    converge(&mut engine, 60).await;

    let chain = engine.source().clone();
    let mut fresh = engine_with(chain, SyncConfig::default());
    fresh.run(&CancellationToken::new()).await.unwrap();

    assert_eq!(note_count(engine.db()), note_count(fresh.db()));
    assert_eq!(balance(engine.db()), balance(fresh.db()));
    assert_eq!(
        engine.db().block_height_extrema().unwrap(),
        fresh.db().block_height_extrema().unwrap()
    );
}

#[tokio::test]
async fn a_rewind_is_reported_and_deepens_on_repeated_failure() {
    // The rewind depth is engine policy, not the caller's: choosing it needs to
    // know how checkpoints are retained, which the caller does not.
    let (anchor, blocks) = paying_chain(60, 100);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain.clone());
    let cancel = CancellationToken::new();
    engine.run(&cancel).await.unwrap();

    // Rewrite the whole tail so every retry still finds a mismatch.
    let mut fork = ChainBuilder::with_anchor(
        h(START + 30).into(),
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 30,
        },
    );
    for _ in 0..40 {
        fork.block(|b| {
            b.tx(|t| {
                t.decoy(PoolId::Ironwood, 1);
            });
        });
    }
    chain.reorg(h(START + 30), fork.into_blocks());

    let mut depths = Vec::new();
    for _ in 0..4 {
        engine.update_tip().await.unwrap();
        match engine.step(&cancel).await.unwrap() {
            Step::Rewound { to, .. } => depths.push(u32::from(to)),
            _ => break,
        }
    }

    assert!(!depths.is_empty(), "expected at least one rewind");
    // Each rewind goes at least as far back as the last.
    for pair in depths.windows(2) {
        assert!(pair[1] <= pair[0], "rewinds should deepen: {depths:?}");
    }
}

#[tokio::test]
async fn a_rewind_never_goes_below_the_birthday() {
    // Below the birthday the wallet has no tree information, so there is
    // nothing there to rewind to.
    let (anchor, blocks) = paying_chain(3, 100);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain.clone());
    let cancel = CancellationToken::new();
    engine.run(&cancel).await.unwrap();

    let mut fork = ChainBuilder::with_anchor(
        h(START + 1).into(),
        zakura_wallet_core::pool::TreeSizes {
            orchard: 0,
            ironwood: 1,
        },
    );
    fork.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    chain.reorg(h(START + 1), fork.into_blocks());

    engine.update_tip().await.unwrap();
    if let Step::Rewound { to, .. } = engine.step(&cancel).await.unwrap() {
        assert!(
            to >= h(START - 1),
            "rewound to {to}, which is below the birthday's anchor"
        );
    }
}

// -------------------------------------------------- cancel and resume

#[tokio::test]
async fn cancelling_and_resuming_produces_an_identical_wallet() {
    // The invariant under test: a batch and the queue entry recording it land
    // together, so stopping between batches loses nothing and duplicates
    // nothing.
    let (anchor, blocks) = paying_chain(12, 300);

    // One uninterrupted run.
    let mut whole = engine_with(
        InMemoryChain::new(anchor.clone(), blocks.clone()),
        SyncConfig {
            budget: ByteBudget::new(400),
            ..SyncConfig::default()
        },
    );
    whole.run(&CancellationToken::new()).await.unwrap();
    let expected = fingerprint(whole.db());

    // The same work, cancelled after two batches and resumed.
    let mut interrupted = engine_with(
        InMemoryChain::new(anchor, blocks),
        SyncConfig {
            budget: ByteBudget::new(400),
            ..SyncConfig::default()
        },
    );
    interrupted.update_tip().await.unwrap();

    let cancel = CancellationToken::new();
    for _ in 0..2 {
        assert_matches!(
            interrupted.step(&cancel).await.unwrap(),
            Step::Scanned { .. }
        );
    }
    cancel.cancel();
    assert_matches!(interrupted.step(&cancel).await.unwrap(), Step::Cancelled);

    // Resume with a fresh token, exactly as a restarted process would.
    let resumed = interrupted.run(&CancellationToken::new()).await.unwrap();
    assert!(!resumed.cancelled);

    assert_eq!(
        fingerprint(interrupted.db()),
        expected,
        "resuming must reproduce the uninterrupted wallet exactly"
    );
}

#[tokio::test]
async fn cancelling_before_the_first_batch_does_nothing() {
    let (anchor, blocks) = paying_chain(4, 100);
    let mut engine = engine(InMemoryChain::new(anchor, blocks));

    let cancel = CancellationToken::new();
    cancel.cancel();

    let summary = engine.run(&cancel).await.unwrap();
    assert!(summary.cancelled);
    assert_eq!(summary.batches, 0);
    assert_eq!(engine.db().block_height_extrema().unwrap(), None);
}

// ------------------------------------------------------------ progress

#[tokio::test]
async fn progress_is_published_as_it_goes() {
    let (anchor, blocks) = paying_chain(6, 100);
    let mut engine = engine_with(
        InMemoryChain::new(anchor, blocks),
        SyncConfig {
            budget: ByteBudget::new(400),
            ..SyncConfig::default()
        },
    );
    let status = engine.status();

    assert_eq!(status.borrow().phase, SyncPhase::Bootstrapping);
    assert_eq!(status.borrow().scanned_to, None);

    engine.run(&CancellationToken::new()).await.unwrap();

    let final_status = status.borrow().clone();
    assert_eq!(final_status.phase, SyncPhase::Idle);
    assert_eq!(final_status.scanned_to, Some(h(START + 5)));
    assert_eq!(final_status.tip, Some(h(START + 5)));
    assert_eq!(final_status.blocks_remaining, 0);
    // Coverage is reported per pool, in commitments rather than blocks.
    assert_eq!(final_status.per_pool[0].0, PoolId::Orchard);
    assert_eq!(final_status.per_pool[1].0, PoolId::Ironwood);
}

#[tokio::test]
async fn progress_survives_having_no_listeners() {
    // Progress is advisory: the engine must not stop because nobody is reading.
    let (anchor, blocks) = paying_chain(3, 100);
    let mut engine = engine(InMemoryChain::new(anchor, blocks));
    drop(engine.status());

    let summary = engine.run(&CancellationToken::new()).await.unwrap();
    assert_eq!(summary.notes, 3);
}

// ------------------------------------------------------------- errors

#[tokio::test]
async fn a_source_failure_is_reported_not_swallowed() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    let mut engine = SyncEngine::new(
        FailingChain,
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        SyncConfig::default(),
    );

    let err = engine.run(&CancellationToken::new()).await.unwrap_err();
    assert_matches!(err, zakura_wallet_sync::Error::Source(_));
    assert!(err.to_string().contains("unavailable"), "{err}");
}

#[tokio::test]
async fn a_queued_range_the_source_cannot_serve_is_reported_not_hidden() {
    // A range the source has nothing for must not become an infinite loop —
    // and must not be reported as having caught up either. The range is still
    // queued, so the wallet has a hole in it; calling that `Idle` would make a
    // transient server failure look exactly like a completed sync.
    let chain = InMemoryChain::new(ChainBuilder::new(START).anchor(), Vec::new());
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    db.connection()
        .execute(
            &format!("INSERT INTO cache.scan_queue VALUES ({START}, {}, 20)", START + 100),
            [],
        )
        .unwrap();

    let mut engine = SyncEngine::new(
        chain,
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        SyncConfig::default(),
    );

    let cancel = CancellationToken::new();
    assert_matches!(
        engine.step(&cancel).await.unwrap(),
        Step::Stalled { range } if range == (h(START)..h(START + 100))
    );

    // And a whole run says the same thing, rather than returning a summary
    // indistinguishable from a successful one.
    let summary = engine.run(&cancel).await.unwrap();
    assert!(!summary.is_complete(), "the queued range was never scanned");
    assert_eq!(summary.stalled, Some(h(START)..h(START + 100)));
}

#[tokio::test]
async fn the_minimum_priority_bounds_what_is_scanned() {
    // Asking only for chain-tip work is how a caller says "just catch up",
    // rather than starting a full recovery.
    let (anchor, blocks) = paying_chain(5, 100);
    let mut engine = engine_with(
        InMemoryChain::new(anchor, blocks),
        SyncConfig {
            min_priority: ScanPriority::ChainTip,
            ..SyncConfig::default()
        },
    );

    engine.update_tip().await.unwrap();
    // With no shard metadata the queue holds only a `Historic` range, which
    // ranks below the floor, so there is nothing to do.
    assert_matches!(
        engine.step(&CancellationToken::new()).await.unwrap(),
        Step::Idle
    );
    assert_eq!(note_count(engine.db()), 0);
}

#[tokio::test]
async fn an_incoherent_source_is_eventually_given_up_on() {
    // A reorg converges once the wallet rewinds below the fork point. A source
    // that is simply broken never does, and past the checkpoint window there is
    // nothing left to rewind to: recovery becomes a rescan from the birthday,
    // which has a visible cost and so is the caller's decision.
    // The chain must be long enough that the doubling rewind exceeds the
    // checkpoint window before it runs out of history to rewind through;
    // otherwise the engine simply runs out of queued work first.
    let (anchor, blocks) = paying_chain(250, 100);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain.clone());
    let cancel = CancellationToken::new();
    engine.run(&cancel).await.unwrap();

    let broken = IncoherentChain::new(chain);
    let db = engine.into_db();
    let mut engine = SyncEngine::new(
        broken,
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        SyncConfig::default(),
    );

    // Force a range the source does hold to be re-verified, so every attempt
    // fetches real blocks and fails their continuity check.
    engine
        .db_mut()
        .truncate_to(h(START + 200))
        .unwrap();

    let mut rewinds = 0;
    for _ in 0..12 {
        match engine.step(&cancel).await {
            Ok(Step::Rewound { .. }) => rewinds += 1,
            Ok(Step::Idle) => break,
            Ok(_) => {}
            Err(zakura_wallet_sync::Error::Unrecoverable { rewound_by, .. }) => {
                assert!(
                    rewound_by > zakura_wallet_store::PRUNING_DEPTH as u32,
                    "gave up at depth {rewound_by}, still inside the checkpoint window"
                );
                assert!(rewinds > 0, "it should have tried rewinding first");
                return;
            }
            Err(other) => panic!("unexpected {other}"),
        }
    }
    panic!("the engine kept rewinding instead of giving up");
}

#[tokio::test]
async fn a_malformed_block_is_not_treated_as_a_reorg() {
    // A block claiming actions for a pool that has not activated is a faulty or
    // hostile source, not a chain that moved. Rewinding would not fix it, and
    // retrying the same data would loop.
    let mut chain = ChainBuilder::new(zakura_wallet_scan::testing::IRONWOOD_ACTIVATION - 5);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice(), KeyScope::External, 1);
        });
    });
    let anchor = chain.anchor();
    let blocks = chain.into_blocks();

    let mut db = test_db().unwrap();
    db.set_birthday(h(zakura_wallet_scan::testing::IRONWOOD_ACTIVATION - 5))
        .unwrap();
    let mut engine = SyncEngine::new(
        InMemoryChain::new(anchor, blocks),
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        SyncConfig::default(),
    );

    let err = engine.run(&CancellationToken::new()).await.unwrap_err();
    assert_matches!(
        err,
        zakura_wallet_sync::Error::Unrecoverable { rewound_by: 0, .. }
    );
    assert!(err.to_string().contains("without rewinding") || err.to_string().contains("0"));
}

#[tokio::test]
async fn a_range_starting_at_genesis_has_no_anchor() {
    // Every range must be anchored on the block below it, and there is no block
    // below the genesis block.
    let mut chain = ChainBuilder::new(0);
    chain.empty_blocks(3);
    let source = InMemoryChain::new(chain.anchor(), chain.into_blocks());
    let chain = source;
    let mut db = test_db().unwrap();
    db.set_birthday(h(0)).unwrap();
    db.connection()
        .execute("INSERT INTO cache.scan_queue VALUES (0, 3, 20)", [])
        .unwrap();

    let mut engine = SyncEngine::new(
        chain,
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        SyncConfig::default(),
    );

    let err = engine
        .step(&CancellationToken::new())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        zakura_wallet_sync::Error::MissingAnchor { height } if height == h(0)
    );
    assert!(err.to_string().contains("anchor"), "{err}");
}

#[tokio::test]
async fn the_engine_does_not_refetch_what_it_already_scanned() {
    let (anchor, blocks) = paying_chain(10, 100);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain.clone());
    let cancel = CancellationToken::new();

    engine.run(&cancel).await.unwrap();
    let after_first = chain.blocks_served();
    assert_eq!(after_first, 10);

    engine.run(&cancel).await.unwrap();
    assert_eq!(
        chain.blocks_served(),
        after_first,
        "a second run should fetch nothing"
    );
}

#[tokio::test]
async fn an_anchor_comes_from_the_source_when_the_wallet_has_not_scanned_it() {
    // Under descending recovery most ranges do not continue from anything the
    // wallet has scanned, so the source has to supply the chain state below
    // them.
    let (_, blocks) = paying_chain(10, 100);
    let anchor = BlockAnchor {
        height: h(START - 1),
        hash: blocks[0].prev_hash,
        tree_sizes: zakura_wallet_core::pool::TreeSizes::default(),
    };
    let chain = InMemoryChain::new(anchor, blocks.clone());

    // Ask for an anchor at a height the chain does hold, and one it does not.
    let from_block = chain.anchor(h(START + 3)).await.unwrap();
    assert_eq!(from_block.hash, blocks[3].hash);
    assert_eq!(from_block.tree_sizes, blocks[3].tree_sizes);

    let below = chain.anchor(h(START - 1)).await.unwrap();
    assert_eq!(below.height, h(START - 1));
}

// --------------------------------------------------------- reporting

#[test]
fn a_ratio_reports_a_fraction_only_when_there_is_something_to_measure() {
    use zakura_wallet_sync::Ratio;

    assert_eq!(
        Ratio {
            numerator: 1,
            denominator: 4
        }
        .fraction(),
        Some(0.25)
    );
    assert_eq!(
        Ratio {
            numerator: 0,
            denominator: 0
        }
        .fraction(),
        None,
        "an unmeasured pool must not report zero progress"
    );
}

#[test]
fn every_error_renders_and_exposes_its_cause() {
    use std::error::Error as _;
    use zakura_wallet_sync::{Error, SourceError};

    let source = Error::Source(SourceError::new(
        zakura_wallet_sync::testing::Unavailable,
    ));
    assert!(source.to_string().contains("chain source"), "{source}");
    assert!(source.source().is_some());

    let store = Error::Store(zakura_wallet_store::TreeError::Store(
        zakura_wallet_store::Error::CheckpointConflict {
            checkpoint_id: h(9),
        },
    ));
    assert!(store.to_string().contains('9'), "{store}");
    assert!(store.source().is_some());

    let unrecoverable = Error::Unrecoverable {
        cause: zakura_wallet_scan::ScanError::PrevHashMismatch {
            at_height: h(1_234),
        },
        rewound_by: 160,
    };
    assert!(unrecoverable.to_string().contains("160"), "{unrecoverable}");
    assert!(unrecoverable.source().is_some());

    let missing = Error::MissingAnchor { height: h(77) };
    assert!(missing.to_string().contains("77"), "{missing}");
    assert!(missing.source().is_none());
}

#[test]
#[should_panic(expected = "at least one block")]
fn a_zero_byte_budget_is_rejected() {
    // A zero budget can never make progress; failing at construction beats
    // looping forever.
    let _ = ByteBudget::new(0);
}

#[test]
fn the_standard_budgets_are_ordered_as_named() {
    assert!(ByteBudget::MOBILE.bytes() < ByteBudget::DESKTOP.bytes());
    assert_eq!(ByteBudget::new(1_234).bytes(), 1_234);
}

#[tokio::test]
async fn a_run_counts_the_rewinds_it_performed() {
    let (mut engine, _) = reorg_scenario(20, 5).await;

    let summary = engine.run(&CancellationToken::new()).await.unwrap();
    assert!(
        summary.rewinds > 0,
        "the run should have discovered the reorg: {summary:?}"
    );
    assert!(summary.batches > 0);
}

#[tokio::test]
async fn every_source_operation_can_fail() {
    // The engine boxes transport errors so its own error type does not have to
    // be generic over every transport; each entry point must carry that
    // through.
    use zakura_wallet_sync::testing::Unavailable;

    let chain = FailingChain;
    assert_eq!(chain.tip().await.unwrap_err(), Unavailable);
    assert_eq!(chain.anchor(h(1)).await.unwrap_err(), Unavailable);
    assert_eq!(
        chain
            .fetch(h(1)..h(2), ByteBudget::MOBILE, Direction::Ascending)
            .await
            .unwrap_err(),
        Unavailable
    );
    assert_eq!(Unavailable.to_string(), "the chain source is unavailable");
}

#[test]
fn a_boxed_source_error_keeps_its_cause() {
    use std::error::Error as _;
    use zakura_wallet_sync::{SourceError, testing::Unavailable};

    let err = SourceError::new(Unavailable);
    assert!(err.to_string().contains("unavailable"), "{err}");
    let cause = err.source().expect("the transport error is preserved");
    assert!(cause.to_string().contains("unavailable"));
}

#[test]
fn storage_errors_convert_into_engine_errors() {
    use zakura_wallet_sync::Error;

    let from_tree: Error = zakura_wallet_store::TreeError::Store(
        zakura_wallet_store::Error::CheckpointConflict {
            checkpoint_id: h(1),
        },
    )
    .into();
    assert_matches!(from_tree, Error::Store(_));

    let from_store: Error = zakura_wallet_store::Error::CheckpointConflict {
        checkpoint_id: h(1),
    }
    .into();
    assert_matches!(from_store, Error::Store(_));
}

/// The root of an empty shard, which is a valid root for a shard that contains
/// nothing yet.
fn empty_shard_root() -> orchard::tree::MerkleHashOrchard {
    use incrementalmerkletree::{Hashable, Level};
    <orchard::tree::MerkleHashOrchard as Hashable>::empty_root(Level::from(
        zakura_wallet_store::SHARD_HEIGHT,
    ))
}

// ------------------------------------------------------ descending recovery

#[tokio::test]
async fn recovery_scans_the_newest_blocks_first() {
    // The claim the whole design rests on: a restoring wallet sees its current
    // balance long before the history below it has been downloaded. Scanning
    // forwards from the birthday would show nothing until the very end.
    let (anchor, blocks) = paying_chain(12, 1_000);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine_with(
        chain,
        SyncConfig {
            // Small enough that recovery takes several batches, so the order
            // they are taken in is observable.
            budget: ByteBudget::new(400),
            ..SyncConfig::default()
        },
    );

    engine.update_tip().await.unwrap();
    let cancel = CancellationToken::new();

    let first = engine.step(&cancel).await.unwrap();
    let Step::Scanned { range, .. } = first else {
        panic!("expected a scan, got {first:?}");
    };

    assert_eq!(
        range.end,
        h(START + 12),
        "the first batch must cover the newest blocks, not the oldest"
    );
    assert!(
        range.start > h(START),
        "and it must not have started at the birthday: {range:?}"
    );

    // Each subsequent batch works further back.
    let mut previous = range.start;
    loop {
        match engine.step(&cancel).await.unwrap() {
            Step::Scanned { range, .. } => {
                assert!(
                    range.end <= previous,
                    "recovery moved forwards: {range:?} after {previous}"
                );
                previous = range.start;
            }
            Step::Idle => break,
            // Not what these tests are about, but a real step the engine takes.
            Step::Enhanced { .. } => continue,
            other => panic!("unexpected {other:?}"),
        }
    }

    assert_eq!(previous, h(START), "recovery should reach the birthday");
    assert_eq!(note_count(engine.db()), 12);
}

#[tokio::test]
async fn tip_following_still_scans_forwards() {
    // Backwards is for recovery. At the tip the next block is the one that
    // matters and there is nothing below it left to find, so the direction
    // depends on what the range is for.
    use zakura_wallet_core::scanning::ScanPriority;
    use zakura_wallet_sync::Direction;

    // The engine's own rule, checked directly: the mapping is small enough that
    // a test of it is worth more than a test through the engine.
    for (priority, expected) in [
        (ScanPriority::ChainTip, Direction::Ascending),
        (ScanPriority::Verify, Direction::Ascending),
        (ScanPriority::Historic, Direction::Descending),
        (ScanPriority::FoundNote, Direction::Descending),
        (ScanPriority::OpenAdjacent, Direction::Descending),
    ] {
        assert_eq!(
            zakura_wallet_sync::direction_for(priority),
            expected,
            "{priority:?}"
        );
    }
}

#[tokio::test]
async fn a_descending_fetch_returns_blocks_in_chain_order() {
    // Which end of the range is covered changes; the order they arrive in does
    // not, because everything above expects chain order.
    use zakura_wallet_sync::Direction;

    let (anchor, blocks) = paying_chain(10, 1);
    let chain = InMemoryChain::new(anchor, blocks);

    let descending = chain
        .fetch(h(START)..h(START + 10), ByteBudget::new(400), Direction::Descending)
        .await
        .unwrap();
    let ascending = chain
        .fetch(h(START)..h(START + 10), ByteBudget::new(400), Direction::Ascending)
        .await
        .unwrap();

    assert!(descending.windows(2).all(|w| w[1].height == w[0].height + 1));
    assert!(ascending.windows(2).all(|w| w[1].height == w[0].height + 1));
    assert_eq!(
        descending.last().unwrap().height,
        h(START + 9),
        "descending covers the top of the range"
    );
    assert_eq!(
        ascending.first().unwrap().height,
        h(START),
        "ascending covers the bottom"
    );
}

// ----------------------------------------------------------- subtree roots

#[tokio::test]
async fn subtree_roots_are_downloaded_before_scanning() {
    // Without them a note found near the tip cannot be witnessed until every
    // shard beneath it has been scanned, which would make descending recovery
    // pointless: the balance appears and stays unspendable.
    use zakura_wallet_sync::SubtreeRoot;

    let (anchor, blocks) = paying_chain(4, 1_000);
    let chain = InMemoryChain::new(anchor, blocks);
    chain.with_subtree_roots(
        PoolId::Ironwood,
        vec![SubtreeRoot {
            index: 0,
            end_height: h(START + 3),
            root: empty_shard_root(),
        }],
    );

    let mut engine = engine(chain);
    let downloaded = engine.update_subtree_roots().await.unwrap();
    assert_eq!(downloaded, 1);

    // The wallet now knows where that shard ends, which is what lets a found
    // note's scan range be widened to cover it.
    let end: Option<u32> = engine
        .db()
        .connection()
        .query_row(
            "SELECT subtree_end_height FROM cache.tree_shards WHERE pool = ? AND shard_index = 0",
            [PoolId::Ironwood.code()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(end, Some(START + 3));

    // And it does not ask for the same root twice.
    assert_eq!(engine.db().next_subtree_index(PoolId::Ironwood).unwrap(), 1);
    assert_eq!(engine.update_subtree_roots().await.unwrap(), 0);
}

#[tokio::test]
async fn roots_that_would_leave_a_hole_are_not_inserted() {
    // A shard the tree cannot be walked across is worse than a missing one: it
    // makes every witness beyond it unbuildable, and nothing would say so.
    use zakura_wallet_sync::SubtreeRoot;

    let (anchor, blocks) = paying_chain(2, 1_000);
    let chain = InMemoryChain::new(anchor, blocks);
    let root = empty_shard_root();
    chain.with_subtree_roots(
        PoolId::Ironwood,
        vec![
            SubtreeRoot { index: 0, end_height: h(START), root },
            // Index 1 is missing.
            SubtreeRoot { index: 2, end_height: h(START + 1), root },
        ],
    );

    let mut engine = engine(chain);
    let downloaded = engine.update_subtree_roots().await.unwrap();
    assert_eq!(downloaded, 1, "only the contiguous prefix should be taken");
    assert_eq!(engine.db().next_subtree_index(PoolId::Ironwood).unwrap(), 1);
}

#[tokio::test]
async fn a_run_downloads_roots_before_it_scans() {
    let (anchor, blocks) = paying_chain(3, 1_000);
    let chain = InMemoryChain::new(anchor, blocks);
    chain.with_subtree_roots(
        PoolId::Ironwood,
        vec![zakura_wallet_sync::SubtreeRoot {
            index: 0,
            end_height: h(START + 2),
            root: empty_shard_root(),
        }],
    );

    let mut engine = engine(chain);
    engine.run(&CancellationToken::new()).await.unwrap();

    assert_eq!(note_count(engine.db()), 3);
    assert_eq!(
        engine.db().next_subtree_index(PoolId::Ironwood).unwrap(),
        1,
        "the run should have taken the root without being asked"
    );
}

#[tokio::test]
async fn an_unrelated_batch_does_not_reset_the_rewind_escalation() {
    // The doubling rewind exists so that a fork the wallet cannot see the
    // bottom of is eventually given up on. Under descending recovery the queue
    // interleaves the failing range with historic ranges far below it, so a
    // counter that reset on *any* successful batch would be reset by an
    // unrelated one between two attempts at the same fork — and the depth would
    // never grow past its first step.
    let (anchor, blocks) = paying_chain(250, 100);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain.clone());
    let cancel = CancellationToken::new();
    engine.run(&cancel).await.unwrap();

    let broken = IncoherentChain::new(chain);
    let db = engine.into_db();
    let mut engine = SyncEngine::new(
        broken,
        test_params(),
        db,
        keys(),
        TransparentWatch::default(),
        SyncConfig::default(),
    );
    engine.db_mut().truncate_to(h(START + 200)).unwrap();

    // Every attempt fails at a *different* height, because the previous rewind
    // moved the range. Depth must still escalate: the height moving is a
    // consequence of the retry, not evidence of a new problem.
    let mut depths = Vec::new();
    for _ in 0..12 {
        match engine.step(&cancel).await {
            Ok(Step::Rewound { to, .. }) => depths.push(to),
            Ok(_) => break,
            Err(zakura_wallet_sync::Error::Unrecoverable { rewound_by, .. }) => {
                assert!(
                    rewound_by > zakura_wallet_store::PRUNING_DEPTH as u32,
                    "gave up at {rewound_by}, which is still inside the checkpoint window"
                );
                assert!(
                    depths.len() > 1,
                    "it should have escalated through several rewinds first"
                );
                return;
            }
            Err(other) => panic!("unexpected {other}"),
        }
    }
    panic!("the escalation never reached the give-up point");
}

// ------------------------------------------------------- enhancement

#[tokio::test]
async fn a_transaction_the_source_will_not_serve_is_counted_not_fatal() {
    // One unreachable transaction must not stop a wallet synchronising. It
    // stays queued, and the wallet keeps working with what it has.
    let (anchor, blocks) = paying_chain(3, 10);
    let chain = UnservedTransactions::new(InMemoryChain::new(anchor, blocks));
    let mut engine = engine_over(chain, SyncConfig::default());
    let cancel = CancellationToken::new();

    engine.update_tip().await.unwrap();
    // Scanning works; only the transaction lookups fail.
    engine.step(&cancel).await.unwrap();

    let step = engine.step(&cancel).await.unwrap();
    assert_matches!(
        step,
        Step::Enhanced { applied, failed, .. } if applied == 0 && failed > 0
    );

    // Crucially, the requests are still there: a source that could not be
    // reached has said nothing about these transactions, so the wallet must not
    // conclude they are gone.
    let tip = engine.db().chain_tip().unwrap().unwrap();
    let outstanding = engine
        .db()
        .pending_requests(
            zakura_wallet_store::retrieval::RequestScope::All,
            zakura_wallet_core::retrieval::LocatorKinds {
                status: true,
                transaction: true,
                action: true,
                block: true,
            },
            tip + 1,
            100,
        )
        .unwrap();
    assert!(
        !outstanding.is_empty(),
        "a transport failure must not retire a request; that would lose the \
         memo and outgoing data for good"
    );
}

#[tokio::test]
async fn the_same_question_is_not_asked_twice_at_one_tip() {
    // The engine's step loop runs hot. Without a backoff it would re-ask the
    // server about every pending transaction on every step, which learns
    // nothing and tells the server how eager the wallet is.
    let (anchor, blocks) = paying_chain(3, 10);
    let chain = InMemoryChain::new(anchor, blocks);
    let mut engine = engine(chain);
    let cancel = CancellationToken::new();

    engine.update_tip().await.unwrap();
    while !matches!(engine.step(&cancel).await.unwrap(), Step::Idle) {}

    let asked = engine.source().transactions_served();
    assert!(asked > 0, "the engine should have asked about something");

    // Another step at the same tip asks nothing further.
    assert_matches!(engine.step(&cancel).await.unwrap(), Step::Idle);
    assert_eq!(
        engine.source().transactions_served(),
        asked,
        "a second step at the same tip must not re-ask"
    );
}

// ------------------------------------------------------- the retrieval seam

/// A record that reproduces what a compact block already said about an action.
fn faithful_record(guard: &zakura_wallet_core::retrieval::Guard) -> ActionRecord {
    let mut enc = vec![0u8; 580];
    enc[..52].copy_from_slice(&guard.compact_ciphertext);
    ActionRecord {
        ephemeral_key: guard.ephemeral_key,
        enc_ciphertext: enc,
        cv_net: [0u8; 32],
        out_ciphertext: vec![0u8; 80],
        transparent_inputs: false,
        transparent_outputs: false,
    }
}

fn a_guard() -> zakura_wallet_core::retrieval::Guard {
    zakura_wallet_core::retrieval::Guard {
        subject: zcash_protocol::TxId::from_bytes([5u8; 32]),
        action_index: 2,
        nullifier: [1u8; 32],
        cmx: [2u8; 32],
        ephemeral_key: [3u8; 32],
        compact_ciphertext: [4u8; 52],
    }
}

#[tokio::test]
async fn a_private_backend_serves_only_what_a_public_one_cannot() {
    // The two backends are complements, and that is the point of the seam. A
    // public server cannot answer a position without being told the
    // transaction, which is the disclosure the position exists to avoid; a
    // private one answers nothing else.
    let public = PublicRetrieval::new(std::sync::Arc::new(InMemoryChain::default()));
    let private = MapRetrieval::new();

    assert!(public.serves().transaction && !public.serves().action);
    assert!(private.serves().action && !private.serves().transaction);
}

#[tokio::test]
async fn a_record_is_accepted_only_if_it_reproduces_what_the_block_said() {
    // The identity recheck. A service chooses what to return; it cannot make a
    // fabricated record reproduce an ephemeral key and ciphertext prefix the
    // wallet read out of a block itself. Everything else in the record is
    // unauthenticated, which is why failing to recover from it is never treated
    // as proof of anything.
    let guard = a_guard();
    let private = MapRetrieval::new();
    private.serve(PoolId::Ironwood, 7, faithful_record(&guard));

    let request = Request {
        locator: zakura_wallet_core::retrieval::Locator::Action {
            pool: PoolId::Ironwood,
            position: incrementalmerkletree::Position::from(7),
        },
        guard: Some(guard),
    };

    let answers = private.retrieve(std::slice::from_ref(&request)).await;
    let record = match answers.into_iter().next().unwrap().unwrap().unwrap() {
        Retrieved::Action(record) => record,
        other => panic!("a private backend answers with an action, not {other:?}"),
    };
    assert!(record.matches(&guard));

    // The same record against a different action's identity: refused. Without
    // this a reorg would let a stale answer be written onto whatever now
    // occupies the position.
    let mut elsewhere = a_guard();
    elsewhere.ephemeral_key = [9u8; 32];
    assert!(!record.matches(&elsewhere));

    // And a record whose ciphertext does not begin with what the block carried.
    let mut forged = faithful_record(&guard);
    forged.enc_ciphertext[10] = 0xff;
    assert!(!forged.matches(&guard));
}

#[tokio::test]
async fn a_transparent_flag_bars_a_transaction_from_private_retrieval_for_good() {
    // The one piece of the fork's routing machine that survives. A record
    // saying the transaction touches transparent means it can never be
    // completed privately — its transparent half is in no shielded record — so
    // the whole transaction has to be fetched publicly. That decision must
    // outlive rescans and reorgs: the identifier has been disclosed, and a
    // later response claiming otherwise cannot take that back.
    let guard = a_guard();
    let mut record = faithful_record(&guard);
    record.transparent_inputs = true;
    assert!(record.touches_transparent());

    let mut db = zakura_wallet_store::testing::test_db().unwrap();
    assert!(!db.is_fallback_barred(guard.subject).unwrap());

    zakura_wallet_store::WalletDb::bar_fallback(&mut db, guard.subject).unwrap();
    assert!(
        db.is_fallback_barred(guard.subject).unwrap(),
        "the decision must be recorded against the transaction, not the position"
    );
}

// ------------------------------------------------------ the transparent step

/// A stand-in for the private ledger, counting how often the engine ran it.
struct CountingTransparent {
    runs: std::sync::atomic::AtomicUsize,
    outcome: Result<zakura_wallet_sync::TransparentProgress, String>,
}

impl zakura_wallet_sync::TransparentSource for CountingTransparent {
    fn recover(
        &self,
        _db: &mut zakura_wallet_store::WalletDb,
    ) -> Result<
        zakura_wallet_sync::TransparentProgress,
        zakura_wallet_sync::transparent::BoxError,
    > {
        self.runs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.outcome.clone().map_err(Into::into)
    }
}

#[tokio::test]
async fn the_transparent_ledger_runs_once_a_pass_and_reports_where_it_reached() {
    // Once, not once per step: a run that reported a step every time would
    // never let `run` reach `Idle`, and one that never reported would leave the
    // caller unable to tell coverage had moved.
    let (anchor, blocks) = paying_chain(4, 10_000);
    let source = std::sync::Arc::new(CountingTransparent {
        runs: std::sync::atomic::AtomicUsize::new(0),
        outcome: Ok(zakura_wallet_sync::TransparentProgress {
            outputs: 2,
            spends: 1,
            unresolved: 0,
            settled_through: Some(h(START + 3)),
            covered_through: Some(h(START + 3)),
        }),
    });

    let mut engine = engine(InMemoryChain::new(anchor, blocks)).with_transparent(source.clone());
    let summary = engine.run(&CancellationToken::new()).await.unwrap();

    assert_eq!(source.runs.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(summary.transparent_outputs, 2);
    assert_eq!(summary.transparent_spends, 1);
    assert_eq!(summary.transparent_covered_through, Some(h(START + 3)));

    // And again on the next pass, because the published shard set grows even
    // when the wallet's own scan queue does not.
    engine.run(&CancellationToken::new()).await.unwrap();
    assert_eq!(source.runs.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_engine_with_no_transparent_source_still_syncs() {
    // The honest state of a wallet with no transparent service configured:
    // everything else works, and transparent coverage does not move. It is
    // reported as nothing read, never as a balance of zero.
    let (anchor, blocks) = paying_chain(4, 10_000);
    let mut engine = engine(InMemoryChain::new(anchor, blocks));

    let summary = engine.run(&CancellationToken::new()).await.unwrap();
    assert_eq!(summary.transparent_covered_through, None);
    assert_eq!(summary.transparent_outputs, 0);
    assert!(summary.batches > 0, "the rest of the sync is unaffected");
}

#[tokio::test]
async fn a_failing_transparent_ledger_fails_the_run_rather_than_reporting_success() {
    // Not swallowed. A wallet that carried on would report itself synced while
    // its transparent balance was silently stale, which is the exact failure
    // the coverage numbers exist to make visible.
    let (anchor, blocks) = paying_chain(2, 10_000);
    let source = std::sync::Arc::new(CountingTransparent {
        runs: std::sync::atomic::AtomicUsize::new(0),
        outcome: Err("the shard service is unreachable".to_owned()),
    });

    let mut engine = engine(InMemoryChain::new(anchor, blocks)).with_transparent(source);
    let err = engine.run(&CancellationToken::new()).await.unwrap_err();
    assert_matches!(err, zakura_wallet_sync::Error::Transparent(_));
    assert!(err.to_string().contains("unreachable"), "{err}");
}
