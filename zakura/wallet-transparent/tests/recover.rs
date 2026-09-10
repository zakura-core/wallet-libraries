//! Recovery against the real shard service, run in process.
//!
//! Every case that reads events ends by comparing the ledger the wallet keeps
//! with an independent traversal of the same events, and every recovery path —
//! a budget, a restart, the wallet's own rewind, a replaced tail, a reorg —
//! has to reach that equality. The cases that read nothing assert the other
//! half of the design: that a wallet whose filters matched nothing spends no
//! private query, and that a wallet which could not check an answer reports
//! itself unread rather than empty.

mod common;

use common::*;
use transparent_events::{ReceiveEvent, TransparentEvent};
use transparent_filter::{BlockHash, ScriptBytes, filter_hash};
use transparent_shard::layout::{RECENT_4K, RECENT_8K};
use transparent_wallet::WorkLimits;
use zakura_wallet_core::KeyScope;
use zakura_wallet_store::GapLimits;
use zakura_wallet_store::transparent_keys::TransparentKeys;
use zakura_wallet_sync::TransparentCompletion;

fn complete(progress: &zakura_wallet_sync::TransparentProgress) {
    assert_eq!(
        progress.completion,
        TransparentCompletion::Complete,
        "{progress:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_that_matches_nothing_advances_coverage_without_a_private_query() {
    // The case the whole design is meant to make cheap, so it must not cost a
    // query — or, worse, fail and leave the wallet re-reading the same range.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;

    let (db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("a run with no matches succeeds");
    complete(&progress);
    assert_eq!(
        transport.queries, 0,
        "nothing matched, so nothing was asked"
    );
    assert!(transport.opened.is_empty());
    assert_eq!(progress.outputs, 0);
    assert_eq!(progress.unresolved, 0);
    assert_eq!(progress.pending, 0);

    let (_, last) = shard_bounds(SHARDS - 1);
    let (_, last_sealed) = shard_bounds(SHARDS - 2);
    assert_eq!(progress.covered_through, Some(h(last)));
    assert_eq!(
        progress.settled_through,
        Some(h(last_sealed)),
        "the last shard is a growing tail, and coverage from it is provisional"
    );
    let state = state(&db, account);
    assert_eq!(state.covered_through, Some(h(last)));
    assert_eq!(state.provisional_shards, 1);
    assert_eq!(state.completion.as_deref(), Some("complete"));
    assert_eq!(state.anchor.map(|a| a.height), Some(h(last)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_with_history_recovers_it_exactly() {
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;

    let (mut db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("recovery completes");
    complete(&progress);
    assert!(
        transport.queries > 0,
        "the wallet's scripts matched, so it retrieved"
    );
    assert!(
        transport.manifests > 0,
        "every matched shard's manifest is verified before it is read"
    );
    assert_eq!(progress.unresolved, 0);
    assert_eq!(progress.spends, 1);

    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance(),
        "the balance is the projection of the same events"
    );
    let state = state(&db, account);
    assert_eq!(state.unresolved_spends, 0);
    assert_eq!(state.covered_through, Some(h(shard_bounds(SHARDS - 1).1)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spend_synced_later_resolves_against_a_receive_persisted_earlier() {
    // The case a one-shot sync cannot handle and the store exists for.
    let (db, account) = wallet();
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir_a = tempfile::tempdir().unwrap();
    let map_a = publish(dir_a.path(), &all[..2]);
    let dir_b = tempfile::tempdir().unwrap();
    let map_b = publish(dir_b.path(), &all);
    assert_eq!(
        map_a.shards[1].manifest_digest, map_b.shards[1].manifest_digest,
        "the sealed prefix is the same publication"
    );

    accept_through(&db, 2);
    let base_a = serve(dir_a.path()).await;
    let (db, _, progress) = recover(db, base_a, dir_a.path(), &map_a, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        50_000 + 7_000 + 11 * long_history(),
        "the receive is held, and nothing has spent it yet"
    );

    // The chain grows, the wallet scans it, the set is republished.
    accept_through(&db, SHARDS);
    let base_b = serve(dir_b.path()).await;
    let (mut db, _, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.spends, 1);
    assert_eq!(
        progress.unresolved, 0,
        "the old receive resolves the new spend"
    );
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_budget_stops_between_pages_and_resumes_exactly() {
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;

    // Enough for the directory rows and a page or two, not the whole history.
    let budget = WorkLimits {
        max_queries: Some(6),
        max_private_bytes: None,
    };
    let (db, first, progress) = recover(db, base.clone(), dir.path(), &map, budget).await;
    let progress = progress.unwrap();
    assert_eq!(
        progress.completion,
        TransparentCompletion::Incomplete("query-budget".into())
    );
    assert!(
        progress.pending > 0,
        "the pages not yet fetched are owed, durably"
    );
    assert!(first.queries <= 6);
    let state_after_budget = state(&db, account);
    assert_eq!(
        state_after_budget.completion.as_deref(),
        Some("query-budget")
    );
    assert_eq!(
        state_after_budget.anchor, None,
        "no anchor for a sync that stopped short"
    );
    let owed_before = db.transparent_pending().unwrap();

    let (mut db, second, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.pending, 0);
    assert!(db.transparent_pending().unwrap().is_empty());
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );

    // Resumption fetched what was owed and no more: a fresh wallet doing it
    // all at once asks at least as much as the two runs together minus the
    // directory rows the resumed run had to re-read.
    let (fresh, fresh_account) = wallet();
    accept_through(&fresh, SHARDS);
    assert_eq!(
        my_scripts(&fresh, fresh_account),
        mine,
        "same seed, same scripts"
    );
    let base = serve(dir.path()).await;
    let (_, whole, progress) = recover(fresh, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let owed_pages: u64 = owed_before
        .iter()
        .map(|p| u64::from(p.page_count - p.next_ordinal))
        .sum();
    assert!(
        second.queries <= whole.queries,
        "resuming ({}) cost no more than starting over ({})",
        second.queries,
        whole.queries
    );
    assert!(
        second.queries >= owed_pages,
        "every owed page ({owed_pages}) was fetched, in {} queries",
        second.queries
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_wallet_continues_from_its_commits_without_refetching() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = dir.path().join("wallet.db");
    let cache_path = dir.path().join("cache.db");
    let mut db = zakura_wallet_store::WalletDb::open(&wallet_path, &cache_path).unwrap();
    let account = db
        .create_account(
            &params(),
            &[7u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(FIRST),
        )
        .unwrap();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let set = tempfile::tempdir().unwrap();
    let map = publish(set.path(), &all);
    let base = serve(set.path()).await;

    let (db, first, progress) =
        recover(db, base.clone(), set.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let commits = db.transparent_last_commit().unwrap();
    let events = db.transparent_events().unwrap();
    drop(db);

    // The process forgets everything; the file does not.
    let db = zakura_wallet_store::WalletDb::open(&wallet_path, &cache_path).unwrap();
    assert_eq!(db.transparent_events().unwrap(), events);
    let (mut db, second, progress) =
        recover(db, base, set.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(
        second.queries, 0,
        "everything was already held; nothing was asked again"
    );
    assert_eq!(second.opened.len(), 0);
    assert!(first.queries > 0);
    assert_eq!(
        db.transparent_last_commit().unwrap(),
        commits + 1,
        "only the anchor is committed again"
    );
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wallets_own_rewind_rolls_the_ledger_back_and_the_next_sync_rereads_it() {
    // A rewind is the wallet saying the blocks above a height are gone. The
    // ledger follows: coverage above the cut is dropped along with the events
    // under it, and the next sync reads that range again, because coverage that
    // outlived its blocks would name a range nothing re-reads.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;
    let (mut db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );

    let (_, end_of_first) = shard_bounds(0);
    db.truncate_to(h(end_of_first)).unwrap();
    let cut = state(&db, account);
    assert_eq!(
        cut.covered_through,
        Some(h(end_of_first)),
        "coverage ends where the chain now ends"
    );
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        50_000,
        "only the receive in shard 0 survives; the spend in shard 2 is gone with its block"
    );

    // The wallet scans the same chain again and the ledger reads it again.
    accept_through(&db, SHARDS);
    let (mut db, again, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert!(
        again.queries > 0,
        "the discarded range is read again, not remembered"
    );
    assert!(
        !again.opened.contains(&0),
        "shard 0 survived the cut and is not re-read"
    );
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_provisional_tail_is_truncated_and_re_derived_then_settled() {
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let before = chain(&mine);
    let dir_a = tempfile::tempdir().unwrap();
    let map_a = publish(dir_a.path(), &before);
    let base_a = serve(dir_a.path()).await;
    let (db, _, progress) = recover(db, base_a, dir_a.path(), &map_a, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(state(&db, account).provisional_shards, 1);
    let tail_digest = map_a.shards[SHARDS as usize - 1].manifest_digest.clone();

    // The tail grows: a new receive lands in it, and it is republished as
    // revision 1 superseding revision 0.
    let mut after = before.clone();
    let late = FIRST + 3 * SPAN + 150;
    after[3].push((
        mine[1].clone(),
        TransparentEvent::Receive(ReceiveEvent {
            height: late as u32,
            txid: txid(999),
            transaction_index: 0,
            output_index: 0,
            value: 600,
            coinbase: false,
        }),
    ));
    let dir_b = tempfile::tempdir().unwrap();
    let map_b = publish_with(
        dir_b.path(),
        &after,
        |_| &RECENT_8K,
        1,
        &tail_digest,
        hash_at,
    );
    assert_ne!(map_b.shards[3].manifest_digest, tail_digest);
    let base_b = serve(dir_b.path()).await;
    let (mut db, _, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    let (tail_start, _) = shard_bounds(SHARDS - 1);
    assert_eq!(
        progress.rolled_back_to,
        Some(h(tail_start - 1)),
        "coverage from the replaced revision is truncated, not appended to"
    );
    compare(&store_ledger(&mut db), &traverse(&after, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance() + 600
    );
    let provisional = db.transparent_provisional_coverage().unwrap();
    assert!(
        provisional
            .iter()
            .all(|r| r.revision_digest == map_b.shards[3].manifest_digest),
        "what remains provisional rests on the new revision only"
    );

    // Then the set grows past it: the tail is sealed and a new one opens.
    let mut sealed = after.clone();
    sealed.push(Vec::new());
    let dir_c = tempfile::tempdir().unwrap();
    let map_c = publish(dir_c.path(), &sealed);
    assert!(map_c.shards[3].sealed);
    let (_, end) = shard_bounds(SHARDS);
    accept(&db, end, hash_at(end));
    let base_c = serve(dir_c.path()).await;
    let (mut db, _, progress) =
        recover(db, base_c, dir_c.path(), &map_c, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    compare(&store_ledger(&mut db), &traverse(&sealed, &mine));
    let state = state(&db, account);
    assert_eq!(state.settled_through, Some(h(shard_bounds(SHARDS - 1).1)));
    assert_eq!(state.covered_through, Some(h(end)));
    assert_eq!(
        state.provisional_shards, 1,
        "only the new empty tail is provisional"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reorg_in_the_wallets_chain_rolls_back_to_the_accepted_ancestor() {
    // The service did not tell the wallet about this; the wallet's own chain
    // did. Every block the coverage rests on is asked of it, newest first, and
    // the first one it rejects rolls back to the highest one it still accepts.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir_a = tempfile::tempdir().unwrap();
    let map_a = publish(dir_a.path(), &all);
    let base_a = serve(dir_a.path()).await;
    let (mut db, _, progress) =
        recover(db, base_a, dir_a.path(), &map_a, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());

    // The chain forks at the start of shard 2. The spend of the first script
    // is on the losing branch; the winning one carries a different receive.
    let (fork, _) = shard_bounds(2);
    let mut forked: Events = all.clone();
    forked[2].retain(|(_, event)| !matches!(event, TransparentEvent::Spend(_)));
    forked[2].push((
        mine[0].clone(),
        TransparentEvent::Receive(ReceiveEvent {
            height: (fork + 50) as u32,
            txid: txid(4_242),
            transaction_index: 0,
            output_index: 1,
            value: 900,
            coinbase: false,
        }),
    ));
    let forked_hash = hash_forked(fork);
    let dir_b = tempfile::tempdir().unwrap();
    let map_b = publish_with(dir_b.path(), &forked, |_| &RECENT_8K, 0, "", &forked_hash);
    assert_eq!(
        map_b.shards[1].manifest_digest,
        map_a.shards[1].manifest_digest
    );
    assert_ne!(
        map_b.shards[2].manifest_digest,
        map_a.shards[2].manifest_digest
    );

    // The wallet rewinds and rescans the winning branch, as the engine would.
    db.truncate_to(h(fork - 1)).unwrap();
    accept_through_with(&db, SHARDS, &forked_hash);
    let base_b = serve(dir_b.path()).await;
    let (mut db, transport, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert!(
        !transport.opened.contains(&0) && !transport.opened.contains(&1),
        "the shards below the fork are still covered and are not re-read"
    );
    compare(&store_ledger(&mut db), &traverse(&forked, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        50_000 + 900 + 7_000 + 7_001 + 11 * long_history(),
        "the spend on the losing branch is gone and the receive on the winning one is held"
    );
    assert_eq!(state(&db, account).unresolved_spends, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reorg_the_wallet_learns_of_between_syncs_is_found_by_the_ledger_itself() {
    // Without a rewind: the wallet's chain view changed under the ledger, and
    // the ledger notices because the block its coverage rests on is one the
    // wallet now rejects.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir_a = tempfile::tempdir().unwrap();
    let map_a = publish(dir_a.path(), &all);
    let base_a = serve(dir_a.path()).await;
    let (db, _, progress) = recover(db, base_a, dir_a.path(), &map_a, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());

    let (fork, _) = shard_bounds(3);
    let forked_hash = hash_forked(fork);
    let dir_b = tempfile::tempdir().unwrap();
    let map_b = publish_with(dir_b.path(), &all, |_| &RECENT_8K, 0, "", &forked_hash);
    accept_through_with(&db, SHARDS, &forked_hash);
    let base_b = serve(dir_b.path()).await;
    let (mut db, _, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.rolled_back_to, Some(h(fork - 1)));
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_accounts_and_a_gap_advance_are_read_in_one_run() {
    // Regression for the wholesale delete the old code made per script group:
    // the second account's run must not erase what the first one found, and a
    // payment at the edge of the address window must widen it and read the new
    // scripts in the same run.
    let (mut db, first) = wallet();
    let second = db
        .create_account(
            &params(),
            &[8u8; 32],
            zip32::AccountId::try_from(1).unwrap(),
            h(FIRST),
        )
        .unwrap();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, first);
    let theirs = my_scripts(&db, second);
    let window = GapLimits::default().external as usize;
    let edge = mine[window - 1].clone();

    let mut all = chain(&mine);
    all[0].push((
        theirs[0].clone(),
        TransparentEvent::Receive(ReceiveEvent {
            height: (FIRST + 9) as u32,
            txid: txid(77),
            transaction_index: 0,
            output_index: 0,
            value: 4_000,
            coinbase: false,
        }),
    ));
    all[1].push((
        edge.clone(),
        TransparentEvent::Receive(ReceiveEvent {
            height: (FIRST + SPAN + 90) as u32,
            txid: txid(78),
            transaction_index: 0,
            output_index: 0,
            value: 300,
            coinbase: false,
        }),
    ));
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;
    let watched_before = db.transparent_watch().unwrap().addresses.len();

    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    let watched_after = db.transparent_watch().unwrap().addresses.len();
    assert!(
        watched_after > watched_before,
        "a payment at the window's edge widened it ({watched_before} -> {watched_after})"
    );

    let mut everyone = mine.clone();
    everyone.extend(theirs.iter().cloned());
    compare(&store_ledger(&mut db), &traverse(&all, &everyone));
    assert_eq!(
        db.transparent_balance(first).unwrap().total().into_u64(),
        full_balance() + 300
    );
    assert_eq!(
        db.transparent_balance(second).unwrap().total().into_u64(),
        4_000
    );

    let last = shard_bounds(SHARDS - 1).1;
    for account in [first, second] {
        let state = state(&db, account);
        assert_eq!(
            state.covered_through,
            Some(h(last)),
            "every script of account {account:?}, the newly derived ones included, is covered"
        );
        assert_eq!(state.unresolved_spends, 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_matching_script_opens_exactly_the_shard_it_matched_and_no_other() {
    // The leak this design accepts, stated as a test: the service learns which
    // ranges had probable activity, and it must learn no more than that.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let mut all = decoys();
    all[1].push((
        mine[0].clone(),
        TransparentEvent::Receive(ReceiveEvent {
            height: (FIRST + SPAN + 1) as u32,
            txid: txid(5),
            transaction_index: 0,
            output_index: 0,
            value: 1_234,
            coinbase: false,
        }),
    ));
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;
    let (db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(
        transport.opened,
        vec![1],
        "only the shard whose filter matched is opened"
    );
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        1_234
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_that_has_scanned_nothing_reads_nothing_and_says_so() {
    let (db, account) = wallet();
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let (db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("nothing to check against is not a failure");
    assert_eq!(progress.covered_through, None);
    assert_eq!(
        progress.completion,
        TransparentCompletion::Incomplete(format!("chain-unknown:{}", shard_bounds(0).1))
    );
    assert_eq!(transport.queries, 0);
    let state = state(&db, account);
    assert_eq!(
        state.covered_through, None,
        "no coverage at all, never an empty balance and never a height"
    );
    assert_eq!(
        state.completion.as_deref(),
        Some(format!("chain-unknown:{}", shard_bounds(0).1).as_str())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_stops_where_the_wallet_stopped_scanning() {
    let (db, account) = wallet();
    accept_through(&db, 1);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let (db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("a truncated map is not an error");
    complete(&progress);
    assert_eq!(progress.covered_through, Some(h(shard_bounds(0).1)));
    assert_eq!(
        state(&db, account).covered_through,
        Some(h(shard_bounds(0).1))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_map_on_a_different_chain_is_refused_rather_than_truncated() {
    let (db, _) = wallet();
    accept_through(&db, SHARDS);
    accept(
        &db,
        shard_bounds(0).1,
        BlockHash::from_internal_bytes([0xab; 32]),
    );
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let (_, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let err = progress.expect_err("a map on another chain must be refused");
    assert!(
        format!("{err}").contains("rejected by wallet chain"),
        "got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_serving_another_schema_is_refused_before_anything_is_decoded() {
    let (db, _) = wallet();
    accept_through(&db, SHARDS);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let filters = Filters::load(dir.path(), &map);
    let (_, transport, progress) = recover_with(
        db,
        base.clone(),
        filters,
        WorkLimits::UNLIMITED,
        move |mut t| {
            let (raw, _) = transparent_wallet::ShardTransport::init(&mut t).unwrap();
            let mut init: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            init["schema"] = serde_json::json!("transparent-shard-v99");
            t.init_override = Some(serde_json::to_vec(&init).unwrap());
            t
        },
    )
    .await;
    let err = progress.expect_err("a schema this build does not read must be refused");
    assert!(
        format!("{err}").contains("transparent-shard-v99"),
        "got: {err}"
    );
    assert_eq!(transport.queries, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_filter_that_does_not_match_its_published_digest_is_refused() {
    let (db, _) = wallet();
    accept_through(&db, SHARDS);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let mut filters = Filters::load(dir.path(), &map);
    let swapped = filters.filters[&0].clone();
    assert_ne!(
        filter_hash(&swapped).to_display_hex(),
        map.shards[1].filter_hash
    );
    filters.filters.insert(1, swapped);
    let (_, _, progress) = recover_with(db, base, filters, WorkLimits::UNLIMITED, |t| t).await;
    let err = progress.expect_err("bytes the map does not commit to must be refused");
    assert!(
        format!("{err}").to_lowercase().contains("digest")
            || format!("{err}").contains("filter")
            || format!("{err}").contains("without offering a live revision"),
        "got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_script_the_private_tables_cannot_index_is_reported_not_hidden() {
    let (mut db, account) = wallet();
    accept_through(&db, SHARDS);
    let long = vec![0x51; transparent_shard::MAX_SCRIPT_BYTES + 1];
    db.record_transparent_address(
        account,
        zakura_wallet_core::KeyScope::External,
        900,
        "t1longscript",
        &long,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let (db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.outside_coverage, 1);
    let mine = db
        .transparent_coverage(account, h(FIRST))
        .unwrap()
        .into_iter()
        .find(|c| c.script == long)
        .unwrap();
    assert_eq!(
        mine.covered_through,
        h(FIRST - 1),
        "never read, and reported as never read rather than as empty"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reference_filter_reader_serves_a_published_set() {
    // The file-backed source this crate ships, over what the publisher wrote.
    let (db, _) = wallet();
    accept_through(&db, SHARDS);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let base = serve(dir.path()).await;
    let published =
        zakura_wallet_transparent::files::PublishedFilters::load(dir.path(), &map).unwrap();
    let (db, progress) = tokio::task::spawn_blocking(move || {
        let mut db = db;
        let mut published = published;
        let mut transport = Counting::new(&base);
        let progress = pir().recover_with(&mut db, &mut published, &mut transport);
        (db, progress)
    })
    .await
    .unwrap();
    complete(&progress.unwrap());
    drop(db);
    let _ = ScriptBytes::new(vec![]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_tail_with_fewer_events_is_a_rollback_not_a_panic() {
    // The events a run holds can go down as well as up: a republished tail
    // that lost a receive is truncated and re-read, and the run reports that
    // as zero recovered rather than failing on the way out.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let before = chain(&mine);
    let dir_a = tempfile::tempdir().unwrap();
    let map_a = publish(dir_a.path(), &before);
    let base_a = serve(dir_a.path()).await;
    let (db, _, progress) = recover(db, base_a, dir_a.path(), &map_a, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let tail_digest = map_a.shards[SHARDS as usize - 1].manifest_digest.clone();

    // Revision 1 of the tail no longer carries the second receive of mine[1].
    let mut after = before.clone();
    after[3].retain(|(s, _)| s.as_slice() != mine[1].as_slice());
    let dir_b = tempfile::tempdir().unwrap();
    let map_b = publish_with(
        dir_b.path(),
        &after,
        |_| &RECENT_8K,
        1,
        &tail_digest,
        hash_at,
    );
    let base_b = serve(dir_b.path()).await;
    let (mut db, _, progress) =
        recover(db, base_b, dir_b.path(), &map_b, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("fewer events than before is not a failure");
    complete(&progress);
    assert_eq!(progress.outputs, 0, "nothing new was recovered");
    assert_eq!(
        progress.rolled_back_to,
        Some(h(shard_bounds(SHARDS - 1).0 - 1))
    );
    compare(&store_ledger(&mut db), &traverse(&after, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance() - 7_001
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_window_that_keeps_moving_is_reported_unbounded_and_finished_by_the_next_run() {
    // Someone pays every fresh address in turn, so each pass widens the window
    // and the next pass has more to read. One run stops after its bound and
    // says so rather than calling a balance with unread scripts synchronized;
    // the run after it picks the work up where it stopped.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let ufvk = db.accounts(&params()).unwrap()[0].ufvk.clone();
    let keys = TransparentKeys::derive(&ufvk).unwrap();
    let gap = GapLimits::default().external;
    let mut all = decoys();
    // The address at the edge of each successive window: paying it moves the
    // window by one gap, seventeen times over.
    let mut paid = Vec::new();
    for k in 1..=17u32 {
        let index = k * gap - 1;
        let script = keys
            .address(&params(), KeyScope::External, index)
            .unwrap()
            .unwrap()
            .script;
        paid.push(ScriptBytes::new(script.clone()));
        all[0].push((
            ScriptBytes::new(script),
            TransparentEvent::Receive(ReceiveEvent {
                height: (FIRST + u64::from(k)) as u32,
                txid: txid(9_000 + u64::from(k)),
                transaction_index: 0,
                output_index: 0,
                value: 100,
                coinbase: false,
            }),
        ));
    }
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;

    let (db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    assert_eq!(
        progress.completion,
        TransparentCompletion::Incomplete("discovery-unbounded".into())
    );
    assert_eq!(
        state(&db, account).completion.as_deref(),
        Some("discovery-unbounded")
    );
    assert!(
        db.transparent_balance(account).unwrap().total().into_u64() < 1_700,
        "the last addresses paid were not yet read"
    );

    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    compare(&store_ledger(&mut db), &traverse(&all, &paid));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        1_700
    );
    assert_eq!(
        state(&db, account).covered_through,
        Some(h(shard_bounds(SHARDS - 1).1))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rewind_inside_a_shard_re_reads_that_shard_whole() {
    // An unscanned cut has no hash to bind clipped coverage. Drop the crossing
    // range and re-read it; never attach the old endpoint hash to the new height.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;
    let (mut db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());

    let (start_of_second, _) = shard_bounds(1);
    let cut = start_of_second + 50;
    db.truncate_to(h(cut)).unwrap();
    assert_eq!(
        state(&db, account).covered_through,
        Some(h(start_of_second - 1))
    );

    accept_through(&db, SHARDS);
    let (mut db, again, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(
        progress.rolled_back_to, None,
        "the wallet rewind already removed unverifiable coverage"
    );
    assert!(!again.queried.contains(&0), "shard 0 is still covered");
    assert!(
        again.queried.contains(&1),
        "the cut shard is read again whole"
    );
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_set_of_mixed_geometries_is_read_shard_by_shard() {
    // The deployed set is two tiers with different table shapes. Each shard's
    // geometry comes from its verified manifest, and the library re-derives
    // the scheme per shard rather than assuming one for the set.
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish_with(
        dir.path(),
        &all,
        |shard| if shard < 2 { &RECENT_4K } else { &RECENT_8K },
        0,
        "",
        hash_at,
    );
    assert_ne!(map.shards[0].geometry, map.shards[3].geometry);
    let base = serve(dir.path()).await;
    let (mut db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert!(transport.queried.contains(&0) && transport.queried.contains(&2));
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_born_inside_the_set_reads_from_its_birthday_without_the_blocks_below() {
    // An archive begins far below any wallet of this generation. The shards
    // below the birthday cannot be checked against blocks the wallet never
    // scanned and are not needed; the one straddling it is bound by its
    // terminal, and reading starts at the birthday.
    let mut db = zakura_wallet_store::testing::test_db().unwrap();
    let birthday = FIRST + SPAN + 50;
    let account = db
        .create_account(
            &params(),
            &[7u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(birthday),
        )
        .unwrap();
    // Nothing below the birthday: only the boundaries a real wallet would hold.
    for id in 1..SHARDS {
        let (start, end) = shard_bounds(id);
        if start >= birthday {
            accept(&db, start - 1, hash_at(start - 1));
        }
        accept(&db, end, hash_at(end));
    }
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;
    let (mut db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    assert_eq!(
        progress.completion,
        TransparentCompletion::Incomplete("unresolved-spends".into())
    );
    assert!(
        !transport.queried.contains(&0),
        "the shard below the birthday is not read"
    );
    assert!(transport.queried.contains(&1), "the shard straddling it is");
    // A shard is read whole: what it holds for a script from before the
    // birthday is history the wallet has, not history it filters out.
    compare(&store_ledger(&mut db), &traverse(&all[1..], &mine));
    let state = state(&db, account);
    assert_eq!(state.covered_through, Some(h(shard_bounds(SHARDS - 1).1)));
    assert_eq!(
        state.unresolved_spends, 1,
        "the spend of a receive from before the birthday is unresolved, and says so"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn publication_behind_the_wallet_target_never_reports_an_empty_complete_balance() {
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let old = tempfile::tempdir().unwrap();
    let old_map = publish(old.path(), &all[..3]);
    let old_base = serve(old.path()).await;
    let (db, transport, progress) =
        recover(db, old_base, old.path(), &old_map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    assert_eq!(
        progress.completion,
        TransparentCompletion::Incomplete(format!("publication-behind:{}", shard_bounds(3).1))
    );
    assert_eq!(transport.queries, 0);
    assert!(db.transparent_anchor().unwrap().is_none());
    let current = tempfile::tempdir().unwrap();
    let map = publish(current.path(), &all);
    let base = serve(current.path()).await;
    let (mut db, _, progress) =
        recover(db, base, current.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publication_ahead_of_the_wallet_commits_only_the_accepted_prefix() {
    let (db, account) = wallet();
    accept_through(&db, 3);
    let target = shard_bounds(3).0 + 5; // The tail payment is two blocks later.
    accept(&db, target, hash_at(target));
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;
    let (db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    complete(&progress);
    assert_eq!(progress.covered_through, Some(h(target)));
    assert!(
        db.transparent_events()
            .unwrap()
            .iter()
            .all(|e| u64::from(u32::from(e.height)) <= target)
    );
    assert_eq!(
        db.transparent_anchor().unwrap().unwrap().hash,
        hash_at(target).to_display_hex()
    );
    accept_through(&db, SHARDS);
    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
}

/// Closing the wallet in the middle of a recovery ends the run at the next
/// request, keeps every shard committed before it, records `stopped` rather
/// than a budget reason, and the next run finishes the job exactly.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_run_keeps_its_commits_and_the_next_run_finishes() {
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let mine = my_scripts(&db, account);
    let all = chain(&mine);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &all);
    let base = serve(dir.path()).await;

    let signal = zakura_wallet_transparent::StopSignal::new();
    let stopper = signal.clone();
    let filters = Filters::load(dir.path(), &map);
    let base_for_run = base.clone();
    let (db, stopped, result) = tokio::task::spawn_blocking(move || {
        let mut db = db;
        let mut filters = filters;
        let mut transport = StopAfter {
            inner: Counting::new(&base_for_run),
            signal: stopper,
            after: 3,
        };
        let result = pir()
            .with_stop(signal)
            .recover_with(&mut db, &mut filters, &mut transport);
        (db, transport.inner, result)
    })
    .await
    .unwrap();

    let error = result.expect_err("a stopped run does not report a completion");
    assert!(error.is_stopped(), "{error}");
    assert!(
        stopped.queries >= 3 && stopped.queries < 20,
        "the stop landed at the next request, after {} queries",
        stopped.queries
    );
    let state = state(&db, account);
    assert_eq!(
        state.completion.as_deref(),
        Some("stopped"),
        "the wallet says why it is incomplete"
    );
    assert_eq!(state.anchor, None, "nothing was accepted as complete");
    let kept = db.transparent_last_commit().unwrap();
    assert!(kept > 0, "shards committed before the stop are kept");

    let (mut db, second, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert!(second.queries > 0);
    assert!(
        db.transparent_last_commit().unwrap() > kept,
        "the second run continued rather than starting over"
    );
    compare(&store_ledger(&mut db), &traverse(&all, &mine));
    assert_eq!(
        db.transparent_balance(account).unwrap().total().into_u64(),
        full_balance()
    );
}

/// A run that fails for any other reason leaves `failed` beside the balance,
/// never `sync-in-progress`.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_run_does_not_leave_the_wallet_looking_busy() {
    let (db, account) = wallet();
    accept_through(&db, SHARDS);
    let dir = tempfile::tempdir().unwrap();
    let map = publish(dir.path(), &decoys());
    let (db, _, result) = recover_with(
        db,
        "http://127.0.0.1:1".to_owned(),
        Filters::load(dir.path(), &map),
        WorkLimits::UNLIMITED,
        |t| t,
    )
    .await;
    let error = result.unwrap_err();
    assert!(!error.is_stopped());
    assert_eq!(state(&db, account).completion.as_deref(), Some("failed"));
}
