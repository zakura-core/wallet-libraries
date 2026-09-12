//! The wallet histories M3 requires, recovered privately and held to an
//! independent reading of the blocks that made them.
//!
//! One chain carries every case at once — a receive, a spend, a coinbase, a
//! self-transfer, a script with a paged history, an old receive spent across
//! the tier boundary, a receive and spend that both land while the wallet is
//! away, a history that ends at zero, scripts nobody ever paid, an imported
//! script with history below the birthday, and a payment at the edge of the
//! address window that forces discovery — so that the cases cannot pass one
//! at a time and fail together. Every test ends in `compare_blocks`, which
//! checks the events, the ledger and what the wallet shows against a reducer
//! that never saw an event, and every test checks that nothing the service
//! saw named the wallet.

mod common;

use common::blocks::*;
use common::catalogue::*;
use common::*;
use transparent_filter::ScriptBytes;
use transparent_wallet::WorkLimits;
use zakura_wallet_core::KeyScope;
use zakura_wallet_store::{GapLimits, transparent::TransparentAnchor};
use zakura_wallet_sync::TransparentCompletion;

#[tokio::test(flavor = "multi_thread")]
async fn the_catalogue_is_recovered_exactly_at_the_accepted_anchor() {
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, faults) = served(&chain, dir.path()).await;

    let (mut db, transport, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.expect("recovery completes");
    complete(&progress);
    assert_eq!(progress.unresolved, 0);
    assert_eq!(progress.pending, 0);
    assert!(transport.queried.contains(&0) && transport.queried.contains(&3));

    let expected = reduce(&chain, &cast.all, FIRST, chain.last());
    assert!(expected.balance > 312_500_000, "the coinbase is counted");
    compare_blocks(&mut db, account, &expected);
    let state = state(&db, account);
    assert_eq!(state.anchor.map(|a| a.height), Some(h(chain.last())));
    assert_eq!(state.completion.as_deref(), Some("complete"));
    assert_eq!(state.outside_coverage, 0);
    assert_projection_matches_ledger(&mut db, account);
    check_requests(&db, account, &chain, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_catalogue_recovered_in_two_runs_equals_one_run() {
    // The wallet reads through the third shard, goes away while the tail is
    // written — a receive and its spend both land — and comes back.
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, 3, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, faults) = served(&chain, dir.path()).await;
    let (_, mid) = shard_bounds(2);

    let (mut db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let at_mid = reduce(&chain, &cast.all, FIRST, mid);
    compare_blocks(&mut db, account, &at_mid);
    assert_eq!(state(&db, account).anchor.map(|a| a.height), Some(h(mid)));
    let commits = db.transparent_last_commit().unwrap();

    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let (mut db, second, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert!(
        !second.opened.contains(&0) && !second.opened.contains(&1),
        "read shards stay read"
    );
    assert!(db.transparent_last_commit().unwrap() > commits);
    compare_blocks(
        &mut db,
        account,
        &reduce(&chain, &cast.all, FIRST, chain.last()),
    );
    check_requests(&db, account, &chain, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn coinbase_receives_keep_their_flag_through_the_store() {
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, _) = served(&chain, dir.path()).await;
    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());

    let coinbase: Vec<_> = stored_events(&db)
        .into_iter()
        .filter(|(script, _)| script == cast.ext[1].as_slice())
        .collect();
    assert_eq!(coinbase.len(), 1);
    assert!(matches!(
        coinbase[0].1,
        transparent_events::TransparentEvent::Receive(r) if r.coinbase && r.value == 312_500_000
    ));
    let ledger = store_ledger(&mut db);
    let utxo = ledger
        .utxos()
        .find(|u| u.script == cast.ext[1].as_slice())
        .unwrap();
    assert!(utxo.coinbase, "the ledger keeps the flag");
    assert!(
        db.transparent_utxos(account)
            .unwrap()
            .iter()
            .any(|(_, v, _)| *v == 312_500_000),
        "the output is shown"
    );
    db.update_chain_tip(&params(), h(chain.last() + 100))
        .unwrap();
    let spendable = db
        .spendable_utxos(
            account,
            zakura_wallet_store::TransparentSpendPolicy::AnyAddress,
        )
        .unwrap();
    assert!(
        spendable
            .iter()
            .all(|u| u.txout.value().into_u64() != 312_500_000),
        "recovering a coinbase output does not make it spendable"
    );
    assert!(!spendable.is_empty(), "ordinary outputs are offered");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_zero_balance_history_is_retained_not_erased() {
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, _) = served(&chain, dir.path()).await;
    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());

    let expected = reduce(&chain, &[cast.ext[7].clone()], FIRST, chain.last());
    assert_eq!(expected.balance, 0);
    assert!(expected.utxos.is_empty());
    assert_eq!(expected.history.len(), 2);
    let ledger = store_ledger(&mut db);
    assert!(ledger.utxos().all(|u| u.script != cast.ext[7].as_slice()));
    let history = ledger.history();
    for (txid, (height, received, spent)) in &expected.history {
        let entry = history
            .iter()
            .find(|t| t.txid == *txid)
            .expect("the transaction is in history");
        assert_eq!(
            (u64::from(entry.height), entry.received, entry.spent),
            (*height, *received, *spent)
        );
    }
    let shown = db.history(account, 100_000).unwrap();
    for txid in expected.history.keys() {
        assert!(
            shown.iter().any(|e| e.txid.as_ref() == &txid.0),
            "shown history keeps it"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_imported_script_is_read_from_the_set_start_without_raising_a_derived_birthday() {
    // A wallet born inside the set, holding one imported script whose history
    // begins before that birthday. The derived scripts are read from the
    // shard straddling the birthday; the imported one from the set's start.
    // Nothing raises the derived scripts' required height to cover the
    // imported one, and nothing lowers it either.
    let birthday = FIRST + SPAN + 50;
    let (mut db, account) = wallet_born_at(birthday);
    let (chain, cast) = catalogue(&mut db, account);
    // The wallet holds headers for the whole set, as a wallet importing a
    // script with history below its birthday would have to.
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, faults) = served(&chain, dir.path()).await;

    let (mut db, transport, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    let progress = progress.unwrap();
    assert_eq!(
        progress.completion,
        TransparentCompletion::Incomplete("unresolved-spends".into()),
        "two derived receives lie below the birthday and their spends cannot resolve"
    );
    assert!(
        transport.queries_to(0) > 0,
        "shard 0 is read for the imported script"
    );

    let scripts = db.transparent_scripts().unwrap();
    let imported = scripts
        .iter()
        .find(|s| s.script == cast.imported.as_slice())
        .unwrap();
    assert!(imported.imported);
    assert_eq!(
        imported.required_from,
        h(FIRST),
        "an imported script is required from the set's start"
    );
    for s in scripts.iter().filter(|s| !s.imported) {
        assert_eq!(
            s.required_from,
            h(birthday),
            "a derived script is required from the birthday"
        );
    }
    let imported_coverage = db
        .transparent_coverage_of(cast.imported.as_slice())
        .unwrap();
    assert_eq!(imported_coverage[0].start_height, h(FIRST));
    let derived_coverage = db.transparent_coverage_of(cast.ext[0].as_slice()).unwrap();
    assert_eq!(
        derived_coverage[0].start_height,
        h(FIRST + SPAN),
        "read from the straddling shard, not below"
    );

    let derived: Vec<ScriptBytes> = cast
        .all
        .iter()
        .filter(|s| **s != cast.imported)
        .cloned()
        .collect();
    let expected = reduce(&chain, &derived, FIRST + SPAN, chain.last()).merge(reduce(
        &chain,
        std::slice::from_ref(&cast.imported),
        FIRST,
        chain.last(),
    ));
    assert_eq!(expected.unresolved, 2);
    compare_blocks(&mut db, account, &expected);
    check_requests(&db, account, &chain, &faults);

    // A second run changes nothing about what is required.
    let (db, _, _) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    for s in db.transparent_scripts().unwrap() {
        let want = if s.imported { h(FIRST) } else { h(birthday) };
        assert_eq!(s.required_from, want, "required heights never move");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_between_shards_replays_nothing_and_changes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let (mut db, account) = wallet_on_disk(home.path());
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, faults) = served(&chain, dir.path()).await;

    let budget = WorkLimits {
        max_queries: Some(4),
        max_private_bytes: None,
    };
    let (db, _, progress) = recover(db, base.clone(), dir.path(), &map, budget).await;
    assert_eq!(
        progress.unwrap().completion,
        TransparentCompletion::Incomplete("query-budget".into())
    );
    let before = Snapshot::of(&db);
    drop(db);

    let db = reopen(home.path());
    assert_eq!(
        Snapshot::of(&db),
        before,
        "nothing changes on disk between close and open"
    );
    let (mut db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let expected = reduce(&chain, &cast.all, FIRST, chain.last());
    compare_blocks(&mut db, account, &expected);
    let settled = Snapshot::of(&db);
    drop(db);

    let db = reopen(home.path());
    let (mut db, again, progress) =
        recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(again.queries, 0, "nothing is asked again");
    let after = Snapshot::of(&db);
    assert_eq!(after.events, settled.events);
    assert_eq!(
        after.last_commit,
        settled.last_commit + 1,
        "only the anchor is committed again"
    );
    compare_blocks(&mut db, account, &expected);
    check_requests(&db, account, &chain, &faults);
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_reads_a_newly_derived_script_over_its_whole_required_range() {
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, faults) = served(&chain, dir.path()).await;
    let limits = GapLimits::default();
    let before = db.transparent_watch().unwrap().addresses.len();
    let required_before: Vec<_> = db.transparent_scripts().unwrap();
    assert!(
        required_before.is_empty(),
        "nothing is required before the first run"
    );

    let (mut db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let after = db.transparent_watch().unwrap().addresses.len();
    // The rule: the window reaches `limit` past the highest used index in
    // each scope. Externally the highest used index is 12 (paid once the
    // payment at 9 had widened the window), so the window ends at 22;
    // internally the self-transfer paid index 0, so it ends at 5.
    let highest = |scope: KeyScope| -> u32 {
        db.connection()
            .query_row(
                "SELECT MAX(transparent_child_index) FROM cache.addresses
                 WHERE account_id = ?1 AND key_scope = ?2",
                rusqlite::params![account.0, scope as u8],
                |row| row.get(0),
            )
            .unwrap()
    };
    assert_eq!(highest(KeyScope::External), 12 + limits.external);
    assert_eq!(highest(KeyScope::Internal), limits.internal);
    assert_eq!(
        after - before,
        (12 + limits.external - 9) as usize + 1,
        "exactly the indices the rule requires were derived, in both scopes"
    );
    assert!(
        db.addresses_to_generate(account, KeyScope::External, &limits)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.addresses_to_generate(account, KeyScope::Internal, &limits)
            .unwrap()
            .is_empty()
    );

    // The script at index 12 was derived by the widening and read over the
    // whole set, from the first height, so the payment to it in a shard the
    // older scripts had already read is held.
    let coverage = db.transparent_coverage_of(cast.ext[12].as_slice()).unwrap();
    assert_eq!(coverage.len(), SHARDS as usize);
    assert_eq!(coverage[0].start_height, h(FIRST));
    assert_eq!(coverage.last().unwrap().end_height, h(chain.last()));
    let expected = reduce(&chain, &cast.all, FIRST, chain.last());
    assert!(
        expected
            .utxos
            .values()
            .any(|(s, v, _, _)| s == cast.ext[12].as_slice() && *v == 400)
    );
    compare_blocks(&mut db, account, &expected);

    // Three runs later, every required height is where the first run put it.
    let required_after_first: Vec<_> = db.transparent_scripts().unwrap();
    assert_eq!(
        required_after_first.len(),
        after,
        "every watched script is required"
    );
    for s in &required_after_first {
        assert_eq!(
            s.required_from,
            h(FIRST),
            "the birthday, or the set's start, whichever is later"
        );
    }
    let mut db = db;
    for _ in 0..2 {
        let (next, again, progress) =
            recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
        complete(&progress.unwrap());
        assert_eq!(again.queries, 0);
        db = next;
    }
    assert_eq!(
        db.transparent_scripts().unwrap(),
        required_after_first,
        "nothing was raised or re-derived"
    );
    assert_eq!(
        db.transparent_watch().unwrap().addresses.len(),
        after,
        "no window moved without a payment"
    );
    check_requests(&db, account, &chain, &faults);
}

// ------------------------------------------------- lower targets

#[tokio::test(flavor = "multi_thread")]
async fn a_lower_target_below_the_accepted_anchor_is_refused_until_the_wallet_rolls_back() {
    // The wallet's scan tip goes down without a rewind: its chain still
    // accepts the anchor the ledger committed, so a lower target is not a
    // reorg and is refused. An explicit rollback to an accepted ancestor is
    // what lowers it, and the ledger then holds exactly that prefix.
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, _) = served(&chain, dir.path()).await;
    let (db, _, progress) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    let held = Snapshot::of(&db);

    let (_, lower) = shard_bounds(2);
    db.connection()
        .execute("DELETE FROM cache.blocks WHERE height > ?1", [lower as u32])
        .unwrap();
    let (mut db, transport, result) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    let error = result.expect_err("a lower target is refused");
    assert!(format!("{error}").contains("anchor"), "got: {error}");
    assert_eq!(transport.queries, 0, "nothing is read before the refusal");
    let after = Snapshot::of(&db);
    assert_eq!(after.events, held.events, "the refusal changes nothing");
    assert_eq!(after.anchor, held.anchor);
    assert_eq!(after.last_commit, held.last_commit);
    assert_eq!(after.completion.as_deref(), Some("failed"));

    db.rollback_transparent_to(
        &TransparentAnchor {
            height: h(lower),
            hash: chain.hash(lower).to_display_hex(),
        },
        "accepted-anchor rollback",
    )
    .unwrap();
    assert_eq!(state(&db, account).anchor.map(|a| a.height), Some(h(lower)));
    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    assert_eq!(state(&db, account).anchor.map(|a| a.height), Some(h(lower)));
    compare_blocks(&mut db, account, &reduce(&chain, &cast.all, FIRST, lower));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lower_target_below_retained_events_is_refused_without_an_anchor_too() {
    // No anchor was ever committed — the first run stopped on its budget —
    // but events above the new target were. They are not silently dropped.
    let (mut db, account) = wallet();
    let (chain, cast) = catalogue(&mut db, account);
    accept_layout(&db, DEFAULT_LAYOUT, SHARDS, chain.hash_fn());
    let dir = tempfile::tempdir().unwrap();
    let (map, base, _) = served(&chain, dir.path()).await;
    // Enough to read the first two shards' directories, not their pages.
    let budget = WorkLimits {
        max_queries: Some(8),
        max_private_bytes: None,
    };
    let (db, _, progress) = recover(db, base.clone(), dir.path(), &map, budget).await;
    assert_ne!(
        progress.unwrap().completion,
        TransparentCompletion::Complete
    );
    assert!(state(&db, account).anchor.is_none());
    let highest = stored_events(&db)
        .iter()
        .map(|(_, e)| u64::from(e.height()))
        .max()
        .unwrap();
    let (_, lower) = shard_bounds(0);
    assert!(
        highest > lower,
        "events above the first shard were committed"
    );

    db.connection()
        .execute("DELETE FROM cache.blocks WHERE height > ?1", [lower as u32])
        .unwrap();
    let held = Snapshot::of(&db);
    let (mut db, _, result) =
        recover(db, base.clone(), dir.path(), &map, WorkLimits::UNLIMITED).await;
    let error = result.expect_err("a target below retained events is refused");
    assert!(format!("{error}").contains("roll back"), "got: {error}");
    let after = Snapshot::of(&db);
    assert_eq!(after.events, held.events);
    assert_eq!(after.last_commit, held.last_commit);

    db.rollback_transparent_to(
        &TransparentAnchor {
            height: h(lower),
            hash: chain.hash(lower).to_display_hex(),
        },
        "accepted-anchor rollback",
    )
    .unwrap();
    assert!(
        stored_events(&db)
            .iter()
            .all(|(_, e)| u64::from(e.height()) <= lower)
    );
    let (mut db, _, progress) = recover(db, base, dir.path(), &map, WorkLimits::UNLIMITED).await;
    complete(&progress.unwrap());
    compare_blocks(&mut db, account, &reduce(&chain, &cast.all, FIRST, lower));
}
