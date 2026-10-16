//! The store contract, runnable against any [`WalletStore`].
//!
//! Every rule the sync relies on is exercised here without a network: a
//! refused commit writes nothing, a repeated commit changes nothing, a repeat
//! that differs is a contradiction, a rollback removes exactly the suffix,
//! setup reuse is keyed by set and revision, the pending bound refuses a whole
//! commit, and an empty store says so. The reference stores run it, and so
//! should any wallet that brings its own storage: a store that passes cannot
//! drift from the two the sync is tested over.
//!
//! Behind the `testing` feature so a wallet's own test suite can call
//! [`suite`] with a constructor for its store.

use crate::engine::client::Table;
use crate::engine::ledger::LedgerError;
use crate::engine::store::{
    Anchor, CachedRun, CoverageKind, PendingPages, RunCursor, ScriptEntry, ScriptOrigin,
    SetIdentity, SetupBlob, SetupKey, ShardCommit, StoreError, StoredEvent, WalletStore,
};
use std::collections::BTreeMap;
use transparent_events::{ReceiveEvent, SpendEvent, TransparentEvent, Txid};
use transparent_filter::SealParameters;

pub fn txid(tag: u8) -> Txid {
    Txid([tag; 32])
}

pub fn script(tag: u8) -> Vec<u8> {
    vec![0x76, 0xa9, 0x14, tag]
}

pub fn receive(tag: u8, index: u32, value: u64, height: u32) -> StoredEvent {
    StoredEvent {
        script: script(tag),
        event: TransparentEvent::Receive(ReceiveEvent {
            metadata: None,
            height,
            txid: txid(tag),
            transaction_index: 0,
            output_index: index,
            value,
            coinbase: false,
        }),
        shard_id: 0,
        revision_digest: "r0".into(),
    }
}

pub fn spend(script_tag: u8, spent: u8, spent_index: u32, spender: u8, height: u32) -> StoredEvent {
    StoredEvent {
        script: script(script_tag),
        event: TransparentEvent::Spend(SpendEvent {
            metadata: None,
            height,
            spending_txid: txid(spender),
            transaction_index: 1,
            input_index: 0,
            spent_txid: txid(spent),
            spent_output_index: spent_index,
        }),
        shard_id: 0,
        revision_digest: "r0".into(),
    }
}

pub fn identity() -> SetIdentity {
    SetIdentity {
        shard_schema: transparent_shard::SCHEMA.to_string(),
        network: "main".into(),
        genesis_hash: "00".repeat(32),
        profile: "zcash-transparent-range-v1".into(),
        range_envelope_version: 1,
        start_height: 0,
        seal: BTreeMap::from([(
            "decoupled-2k-8k".to_string(),
            SealParameters {
                max_scripts: 1,
                max_page_rows: 1,
                max_txids: 0,
            },
        )]),
    }
}

pub fn commit(
    shard_id: u64,
    revision: &str,
    sealed: bool,
    range: (u64, u64),
    events: Vec<StoredEvent>,
    covered: Vec<Vec<u8>>,
) -> ShardCommit {
    ShardCommit {
        source_anchor: None,
        shard_id,
        revision_digest: revision.into(),
        sealed,
        start_height: range.0,
        end_height: range.1,
        terminal_block_hash: format!("{:064x}", range.1),
        events: events
            .into_iter()
            .map(|mut stored| {
                stored.shard_id = shard_id;
                stored.revision_digest = revision.into();
                stored
            })
            .collect(),
        covered_scripts: covered,
        pending_upsert: Vec::new(),
        pending_complete: Vec::new(),
        cached_runs: Vec::new(),
        failed_entries: Vec::new(),
    }
}

pub fn pending(script_tag: u8, revision: &str) -> PendingPages {
    PendingPages {
        id: None,
        shard_id: 1,
        revision_digest: revision.into(),
        script: script(script_tag),
        cursor: RunCursor {
            child: 3,
            row: 4,
            older_runs: None,
        },
        fragments: Vec::new(),
        carried: vec![
            receive(script_tag, 7, 1, 60).event,
            spend(script_tag, script_tag, 7, 9, 70).event,
        ],
        attempts: 0,
        target_anchor: None,
    }
}

/// A cached run of shard 0 with no run below it.
pub fn cached_run(child: &str, script_tag: u8, heights: &[u32]) -> CachedRun {
    CachedRun {
        child_digest: child.into(),
        script: script(script_tag),
        shard_id: 0,
        older: None,
        events: heights
            .iter()
            .enumerate()
            .map(|(index, height)| receive(script_tag, index as u32, 1, *height).event)
            .collect(),
    }
}

/// The contract, over any store.
/// The contract, over any store. `make` returns a fresh, empty store each
/// time; its pending limit should be small (the reference tests use 8) so the
/// bound is exercised cheaply.
pub fn suite<S: WalletStore>(make: impl Fn() -> S) {
    an_empty_store_reports_nothing(&make);
    a_commit_is_idempotent_and_a_differing_repeat_is_refused_whole(&make);
    coverage_merges_settled_ranges_and_keeps_provisional_ones_apart(&make);
    rollback_removes_only_the_suffix(&make);
    a_retried_spend_cannot_change_its_script(&make);
    setup_is_keyed_by_set_revision_table_and_segment(&make);
    a_commit_past_the_pending_bound_is_refused_whole(&make);
    required_from_is_never_raised_and_the_set_is_bound_once(&make);
    promotion_settles_a_provisional_revision_in_place(&make);
    a_range_replaces_the_ranges_it_contains_whatever_their_shard(&make);
    a_range_inside_one_already_held_changes_nothing(&make);
    a_walk_cursor_and_its_carried_events_round_trip(&make);
    the_run_cache_is_written_with_its_commit_and_never_rewritten(&make);
    entry_failures_are_scoped_to_the_committed_revision(&make);
}

fn an_empty_store_reports_nothing<S: WalletStore>(make: &impl Fn() -> S) {
    let store = make();
    assert!(store.set_identity().unwrap().is_none());
    assert!(store.anchor().unwrap().is_none());
    assert!(store.scripts().unwrap().is_empty());
    assert!(store.events().unwrap().is_empty());
    assert!(store.pending().unwrap().is_empty());
    assert_eq!(store.last_commit().unwrap(), 0);
    let ledger = store.ledger().unwrap();
    assert_eq!(ledger.confirmed_balance(), 0);
    assert!(ledger.history().is_empty());
}

fn a_commit_is_idempotent_and_a_differing_repeat_is_refused_whole<S: WalletStore>(
    make: &impl Fn() -> S,
) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    let first = commit(
        0,
        "r0",
        true,
        (0, 99),
        vec![receive(1, 0, 5_000, 10), spend(1, 1, 0, 2, 50)],
        vec![script(1)],
    );
    let id = store.commit_shard(first.clone()).unwrap();
    assert_eq!(id, 1);
    let events_after = store.events().unwrap();
    assert_eq!(events_after.len(), 2);

    // The identical commit again: a new commit id, no new rows.
    let again = store.commit_shard(first).unwrap();
    assert_eq!(again, 2);
    assert_eq!(store.events().unwrap(), events_after);
    assert_eq!(store.coverage(&script(1)).unwrap().len(), 1);

    // A repeat whose receive differs in value is a contradiction, and the
    // whole commit — including an otherwise fine new receive — is refused.
    let differing = commit(
        0,
        "r0",
        true,
        (0, 99),
        vec![receive(1, 0, 9_999, 10), receive(3, 0, 1, 20)],
        vec![script(3)],
    );
    match store.commit_shard(differing) {
        Err(StoreError::Contradiction(LedgerError::ConflictingReceive(_, 0))) => {}
        other => panic!("expected a conflicting receive, got {other:?}"),
    }
    assert_eq!(store.events().unwrap(), events_after, "nothing was written");
    assert!(store.coverage(&script(3)).unwrap().is_empty());

    // The same outpoint spent by another transaction is a double spend.
    let double = commit(
        1,
        "r1",
        true,
        (100, 199),
        vec![spend(1, 1, 0, 7, 150)],
        vec![script(1)],
    );
    match store.commit_shard(double) {
        Err(StoreError::Contradiction(LedgerError::DoubleSpend(_, 0))) => {}
        other => panic!("expected a double spend, got {other:?}"),
    }
    assert_eq!(store.events().unwrap(), events_after);
    assert_eq!(store.last_commit().unwrap(), 2);
}

fn coverage_merges_settled_ranges_and_keeps_provisional_ones_apart<S: WalletStore>(
    make: &impl Fn() -> S,
) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(1, "r1", true, (100, 199), vec![], vec![script(1)]))
        .unwrap();
    store
        .commit_shard(commit(0, "r0", true, (0, 99), vec![], vec![script(1)]))
        .unwrap();
    store
        .commit_shard(commit(2, "r2", false, (200, 249), vec![], vec![script(1)]))
        .unwrap();
    let ranges = store.coverage(&script(1)).unwrap();
    assert_eq!(ranges.len(), 3, "one range per shard, in height order");
    assert_eq!((ranges[0].start_height, ranges[0].end_height), (0, 99));
    assert_eq!((ranges[1].start_height, ranges[1].end_height), (100, 199));
    assert_eq!(ranges[0].kind, CoverageKind::Settled);
    assert_eq!(ranges[2].kind, CoverageKind::Provisional);
    assert_eq!(ranges[2].revision_digest, "r2");
    let provisional = store.provisional().unwrap();
    assert_eq!(provisional.len(), 1);
}

fn rollback_removes_only_the_suffix<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(
            0,
            "r0",
            true,
            (0, 199),
            vec![receive(1, 0, 5_000, 10), receive(2, 0, 3_000, 150)],
            vec![script(1), script(2)],
        ))
        .unwrap();
    let mut tail = commit(
        1,
        "r1",
        false,
        (200, 249),
        vec![spend(1, 1, 0, 3, 220)],
        vec![script(1), script(2)],
    );
    tail.pending_upsert.push(pending(2, "r1"));
    store.commit_shard(tail).unwrap();
    store
        .commit_anchor(
            &Anchor {
                height: 249,
                hash: "tail".into(),
            },
            199,
            249,
        )
        .unwrap();
    assert_eq!(store.pending().unwrap().len(), 1);
    assert_eq!(store.ledger().unwrap().confirmed_balance(), 3_000);

    store
        .rollback_above(
            &Anchor {
                height: 199,
                hash: "h199".into(),
            },
            "tail replaced",
        )
        .unwrap();
    let events = store.events().unwrap();
    assert_eq!(events.len(), 2, "the spend above the cut is gone");
    assert_eq!(store.ledger().unwrap().confirmed_balance(), 8_000);
    for tag in [1u8, 2] {
        let ranges = store.coverage(&script(tag)).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].end_height, 199);
        assert_eq!(ranges[0].kind, CoverageKind::Settled);
    }
    assert!(store.provisional().unwrap().is_empty());
    assert!(
        store.pending().unwrap().is_empty(),
        "pending work of the replaced revision is gone with it"
    );
    let anchor = store.anchor().unwrap().unwrap();
    assert_eq!(anchor.height, 199);
}

fn setup_is_keyed_by_set_revision_table_and_segment<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    let key = SetupKey {
        set_digest: "set-a".into(),
        revision_digest: "rev-a".into(),
        table: Table::Directory,
        segment: 0,
    };
    let blob = SetupBlob {
        public_params_base64: "AAAA".into(),
        public_params_sha256: "ab".repeat(32),
    };
    store.put_setup(&key, &blob).unwrap();
    assert_eq!(store.setup(&key).unwrap(), Some(blob.clone()));
    // Every page shard's table publishes its own setup.
    let page = |child| SetupKey {
        table: Table::Pages(child),
        ..key.clone()
    };
    store.put_setup(&page(1), &blob).unwrap();
    assert_eq!(store.setup(&page(1)).unwrap(), Some(blob.clone()));
    assert_eq!(store.setup(&page(2)).unwrap(), None);
    for other in [
        SetupKey {
            set_digest: "set-b".into(),
            ..key.clone()
        },
        SetupKey {
            revision_digest: "rev-b".into(),
            ..key.clone()
        },
        SetupKey {
            table: Table::Pages(0),
            ..key.clone()
        },
        SetupKey {
            segment: 1,
            ..key.clone()
        },
    ] {
        assert_eq!(store.setup(&other).unwrap(), None, "{other:?}");
    }
    // Dropping a stale setup forgets that one alone, and dropping one not
    // held is no error.
    store.drop_setup(&page(1)).unwrap();
    assert_eq!(store.setup(&page(1)).unwrap(), None);
    assert_eq!(store.setup(&key).unwrap(), Some(blob.clone()));
    store.drop_setup(&page(2)).unwrap();
    store
        .put_filter("rev-a", "hash-a", true, b"filter bytes")
        .unwrap();
    assert_eq!(
        store.filter("rev-a", "hash-a").unwrap(),
        Some(b"filter bytes".to_vec())
    );
    assert_eq!(store.filter("rev-a", "hash-b").unwrap(), None);
    assert_eq!(store.filter("rev-b", "hash-a").unwrap(), None);
}

fn a_commit_past_the_pending_bound_is_refused_whole<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    let limit = store.pending_limit();
    let mut over = commit(1, "r1", false, (0, 99), vec![receive(1, 0, 1, 5)], vec![]);
    for tag in 0..=limit {
        over.pending_upsert.push(pending((tag % 250) as u8, "r1"));
    }
    match store.commit_shard(over) {
        Err(StoreError::PendingLimit { limit: reported }) => assert_eq!(reported, limit),
        other => panic!("expected the pending bound, got {other:?}"),
    }
    assert!(store.events().unwrap().is_empty(), "nothing was written");
    assert!(store.pending().unwrap().is_empty());
    let mut within = commit(1, "r1", false, (0, 99), vec![], vec![]);
    within.pending_upsert.push(pending(1, "r1"));
    store.commit_shard(within).unwrap();
    let held = store.pending().unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].id.is_some());
    // Advancing it keeps its id; finishing it removes it.
    let mut progressed = held[0].clone();
    progressed.cursor = RunCursor {
        child: 1,
        row: 9,
        older_runs: Some(1),
    };
    let mut advance = commit(1, "r1", false, (0, 99), vec![], vec![]);
    advance.pending_upsert.push(progressed.clone());
    store.commit_shard(advance).unwrap();
    let held = store.pending().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].cursor, progressed.cursor);
    let mut finish = commit(1, "r1", false, (0, 99), vec![], vec![script(1)]);
    finish.pending_complete.push(held[0].id.unwrap());
    store.commit_shard(finish).unwrap();
    assert!(store.pending().unwrap().is_empty());
}

fn required_from_is_never_raised_and_the_set_is_bound_once<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    let added = store
        .add_scripts(&[ScriptEntry {
            script: script(1),
            origin: ScriptOrigin::Derived,
            required_from: 100,
        }])
        .unwrap();
    assert_eq!(added, 1);
    let added = store
        .add_scripts(&[
            ScriptEntry {
                script: script(1),
                origin: ScriptOrigin::Derived,
                required_from: 500,
            },
            ScriptEntry {
                script: script(2),
                origin: ScriptOrigin::Imported,
                required_from: 0,
            },
        ])
        .unwrap();
    assert_eq!(added, 1, "only the new script counts");
    let scripts = store.scripts().unwrap();
    let one = scripts.iter().find(|e| e.script == script(1)).unwrap();
    assert_eq!(one.required_from, 100, "never raised");
    let two = scripts.iter().find(|e| e.script == script(2)).unwrap();
    assert_eq!(two.origin, ScriptOrigin::Imported);

    // The same lineage with a new geometry continues; another chain does not.
    let mut widened = identity();
    widened.seal.insert(
        "decoupled-32k-32k".into(),
        SealParameters {
            max_scripts: 2,
            max_page_rows: 2,
            max_txids: 0,
        },
    );
    store.bind_set(&widened).unwrap();
    let mut other = identity();
    other.genesis_hash = "ff".repeat(32);
    match store.bind_set(&other) {
        Err(StoreError::SetMismatch { .. }) => {}
        other => panic!("expected a set mismatch, got {other:?}"),
    }
}

fn promotion_settles_a_provisional_revision_in_place<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(0, "r0", true, (0, 99), vec![], vec![script(1)]))
        .unwrap();
    store
        .commit_shard(commit(1, "r1", false, (100, 149), vec![], vec![script(1)]))
        .unwrap();
    assert_eq!(store.coverage(&script(1)).unwrap().len(), 2);
    store.promote_provisional(1, "r1").unwrap();
    let ranges = store.coverage(&script(1)).unwrap();
    assert_eq!(ranges.len(), 2, "the range keeps its shard identity");
    assert!(
        ranges
            .iter()
            .all(|range| range.kind == CoverageKind::Settled)
    );
    assert!(store.provisional().unwrap().is_empty());
}

/// A re-cut merges narrower shards into one under another shard id, so a
/// script holding part of that range is covered again by a range starting
/// where one it holds does. The new range replaces every range of the script
/// it contains, whichever shard they came from, and leaves the rest, and the
/// script's other coverage, as they were.
fn a_range_replaces_the_ranges_it_contains_whatever_their_shard<S: WalletStore>(
    make: &impl Fn() -> S,
) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    for (shard, revision, range) in [
        (0, "r0", (0, 99)),
        (1, "r1", (100, 149)),
        (2, "r2", (150, 199)),
        (3, "r3", (200, 249)),
    ] {
        store
            .commit_shard(commit(
                shard,
                revision,
                true,
                range,
                vec![],
                vec![script(1)],
            ))
            .unwrap();
    }
    store
        .commit_shard(commit(1, "r1", true, (100, 149), vec![], vec![script(2)]))
        .unwrap();
    // Shards 1 and 2 re-cut into shard 1, covering both ranges; 3 renumbered.
    store
        .commit_shard(commit(1, "wide", true, (100, 199), vec![], vec![script(1)]))
        .unwrap();
    let ranges = store.coverage(&script(1)).unwrap();
    let held: Vec<_> = ranges
        .iter()
        .map(|range| {
            (
                range.start_height,
                range.end_height,
                range.revision_digest.as_str(),
            )
        })
        .collect();
    assert_eq!(held, [(0, 99, "r0"), (100, 199, "wide"), (200, 249, "r3")]);
    assert_eq!(
        store.coverage(&script(2)).unwrap()[0].revision_digest,
        "r1",
        "another script's coverage is its own"
    );
    // At an existing start under another shard id: the primary key of a
    // store keyed by script and start height must not refuse it.
    store
        .commit_shard(commit(
            2,
            "renumbered",
            true,
            (200, 249),
            vec![],
            vec![script(1)],
        ))
        .unwrap();
    let ranges = store.coverage(&script(1)).unwrap();
    assert_eq!(ranges.len(), 3);
    assert_eq!(ranges[2].shard_id, 2);
    assert_eq!(ranges[2].revision_digest, "renumbered");
    // The same commit again changes nothing.
    store
        .commit_shard(commit(
            2,
            "renumbered",
            true,
            (200, 249),
            vec![],
            vec![script(1)],
        ))
        .unwrap();
    assert_eq!(store.coverage(&script(1)).unwrap(), ranges);
}

/// A range strictly inside one the script already holds is covered already:
/// committing it changes no coverage, whatever shard it names, so a store
/// keyed by script and start height and one that is not give one answer.
fn a_range_inside_one_already_held_changes_nothing<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(1, "wide", true, (100, 199), vec![], vec![script(1)]))
        .unwrap();
    let held = store.coverage(&script(1)).unwrap();
    for (shard, revision, range) in [(5, "head", (100, 149)), (6, "rest", (150, 199))] {
        store
            .commit_shard(commit(
                shard,
                revision,
                true,
                range,
                vec![],
                vec![script(1)],
            ))
            .unwrap();
        assert_eq!(store.coverage(&script(1)).unwrap(), held, "{revision}");
    }
    // Reaching past it is not inside it: the longer range replaces it.
    store
        .commit_shard(commit(
            7,
            "longer",
            true,
            (100, 249),
            vec![],
            vec![script(1)],
        ))
        .unwrap();
    let ranges = store.coverage(&script(1)).unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].revision_digest, "longer");
}

fn a_retried_spend_cannot_change_its_script<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    store
        .commit_shard(commit(
            0,
            "r0",
            true,
            (0, 99),
            vec![receive(1, 0, 123, 10), spend(1, 1, 0, 3, 20)],
            vec![script(1)],
        ))
        .unwrap();
    let before = store.events().unwrap();
    let id = store.last_commit().unwrap();
    assert!(
        store
            .commit_shard(commit(
                0,
                "r0",
                true,
                (0, 99),
                vec![spend(2, 1, 0, 3, 20)],
                vec![script(2)]
            ))
            .is_err()
    );
    assert_eq!(store.events().unwrap(), before);
    assert_eq!(store.last_commit().unwrap(), id);
}

/// A walk's cursor, with the older-run count it expects or without one, and
/// the events it carries come back exactly, through an advance too.
fn a_walk_cursor_and_its_carried_events_round_trip<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    let item = pending(4, "r1");
    let mut first = commit(1, "r1", false, (0, 99), vec![], vec![]);
    first.pending_upsert.push(item.clone());
    store.commit_shard(first).unwrap();
    let held = store.pending().unwrap();
    assert_eq!(held.len(), 1);
    let id = held[0].id.expect("an assigned id");
    assert_eq!(
        PendingPages {
            id: Some(id),
            ..item.clone()
        },
        held[0]
    );
    let mut advanced = held[0].clone();
    advanced.cursor = RunCursor {
        child: 0,
        row: 0,
        older_runs: Some(0),
    };
    advanced.carried = vec![receive(4, 1, 2, 30).event, receive(4, 2, 2, 40).event];
    advanced.attempts = 2;
    let mut step = commit(1, "r1", false, (0, 99), vec![], vec![]);
    step.pending_upsert.push(advanced.clone());
    store.commit_shard(step).unwrap();
    assert_eq!(store.pending().unwrap(), vec![advanced]);
}

/// A cached run is written with the commit that carries it, read back by page
/// shard identity and script, never changed by a differing repeat — which
/// refuses the whole commit — and kept through a rollback. A commit covering a
/// script over its whole sealed shard drops that script's runs in the shard.
fn the_run_cache_is_written_with_its_commit_and_never_rewritten<S: WalletStore>(
    make: &impl Fn() -> S,
) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    assert_eq!(store.cached_run("child-a", &script(1)).unwrap(), None);
    let low = cached_run("child-a", 1, &[10, 20, 30]);
    let high = CachedRun {
        older: Some("child-a".into()),
        ..cached_run("child-b", 1, &[150])
    };
    let other = cached_run("child-a", 2, &[40]);
    let elsewhere = CachedRun {
        shard_id: 1,
        ..cached_run("child-x", 1, &[250])
    };
    // A walk still under way: the shard is open and nothing is covered.
    let mut first = commit(0, "r0", false, (0, 199), vec![], vec![]);
    first.cached_runs = vec![low.clone(), high.clone(), other.clone(), elsewhere.clone()];
    store.commit_shard(first.clone()).unwrap();
    assert_eq!(
        store.cached_run("child-a", &script(1)).unwrap(),
        Some(low.clone())
    );
    assert_eq!(store.cached_run("child-a", &script(3)).unwrap(), None);
    assert_eq!(store.cached_run("child-c", &script(1)).unwrap(), None);
    // The identical commit again changes nothing.
    store.commit_shard(first).unwrap();
    assert_eq!(
        store.cached_run("child-b", &script(1)).unwrap(),
        Some(high.clone())
    );

    // A different run, or a different run below it, under the same key is
    // refused, and nothing else the commit carried is written.
    for differing_run in [
        cached_run("child-a", 1, &[10, 20]),
        CachedRun {
            older: Some("child-z".into()),
            ..low.clone()
        },
    ] {
        let mut differing = commit(
            0,
            "r0",
            false,
            (0, 199),
            vec![receive(5, 0, 1, 50)],
            vec![script(5)],
        );
        differing.cached_runs = vec![differing_run];
        assert!(store.commit_shard(differing).is_err());
    }
    assert_eq!(
        store.cached_run("child-a", &script(1)).unwrap(),
        Some(low.clone())
    );
    assert!(store.events().unwrap().is_empty());
    assert!(store.coverage(&script(5)).unwrap().is_empty());

    store
        .rollback_above(
            &Anchor {
                height: 100,
                hash: "h100".into(),
            },
            "reorg",
        )
        .unwrap();
    assert_eq!(
        store.cached_run("child-b", &script(1)).unwrap(),
        Some(high),
        "a run keyed by its page shard's identity survives a rollback: the \
         identity only recurs on the chain it was published on"
    );

    // Coverage clipped to an anchor inside the sealed shard leaves the runs:
    // the next sync carries on through the shard.
    let mut clipped = commit(0, "r1", true, (0, 150), vec![], vec![script(1)]);
    clipped.source_anchor = Some(Anchor {
        height: 199,
        hash: format!("{:064x}", 199),
    });
    store.commit_shard(clipped).unwrap();
    assert_eq!(
        store.cached_run("child-a", &script(1)).unwrap(),
        Some(low.clone())
    );

    // Covering script 1 over the whole sealed shard 0 drops its runs there,
    // and only those.
    store
        .commit_shard(commit(0, "r1", true, (0, 199), vec![], vec![script(1)]))
        .unwrap();
    assert_eq!(store.cached_run("child-a", &script(1)).unwrap(), None);
    assert_eq!(store.cached_run("child-b", &script(1)).unwrap(), None);
    assert_eq!(
        store.cached_run("child-a", &script(2)).unwrap(),
        Some(other)
    );
    assert_eq!(
        store.cached_run("child-x", &script(1)).unwrap(),
        Some(elsewhere)
    );
}

/// Each commit naming an entry in `failed_entries` adds one to that entry's
/// count, keyed by shard revision and script. A refused commit adds nothing;
/// success and rollback preserve it, and a reused numeric id starts afresh.
fn entry_failures_are_scoped_to_the_committed_revision<S: WalletStore>(make: &impl Fn() -> S) {
    let mut store = make();
    store.bind_set(&identity()).unwrap();
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 0);
    let mut failed = commit(1, "r1", true, (0, 99), vec![], vec![script(2)]);
    failed.failed_entries = vec![script(1)];
    store.commit_shard(failed.clone()).unwrap();
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 1);
    assert_eq!(store.entry_failures(1, "r1", &script(2)).unwrap(), 0);
    assert_eq!(store.entry_failures(0, "r1", &script(1)).unwrap(), 0);
    assert_eq!(store.coverage(&script(1)).unwrap(), vec![]);
    assert_eq!(store.coverage(&script(2)).unwrap().len(), 1);

    // A second failed attempt under the same revision keeps counting.
    let mut again = commit(1, "r1", false, (0, 120), vec![], vec![]);
    again.failed_entries = vec![script(1), script(3)];
    store.commit_shard(again).unwrap();
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 2);
    assert_eq!(store.entry_failures(1, "r1", &script(3)).unwrap(), 1);

    // A refused commit records no failure.
    store
        .commit_shard(commit(
            2,
            "r3",
            true,
            (100, 199),
            vec![receive(5, 0, 1, 150)],
            vec![],
        ))
        .unwrap();
    let mut refused = commit(
        2,
        "r3",
        true,
        (100, 199),
        vec![receive(5, 0, 2, 150)],
        vec![],
    );
    refused.failed_entries = vec![script(1)];
    assert!(store.commit_shard(refused).is_err());
    assert_eq!(store.entry_failures(2, "r3", &script(1)).unwrap(), 0);

    // Success and rollback leave the count.
    store
        .commit_shard(commit(1, "r1", true, (0, 99), vec![], vec![script(1)]))
        .unwrap();
    store
        .rollback_above(
            &Anchor {
                height: 0,
                hash: "h0".into(),
            },
            "reorg",
        )
        .unwrap();
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 2);
    // A re-cut can assign this numeric id to a wholly different shard.
    assert_eq!(store.entry_failures(1, "recut", &script(1)).unwrap(), 0);
    let mut recut = commit(1, "recut", true, (200, 299), vec![], vec![]);
    recut.failed_entries = vec![script(1)];
    store.commit_shard(recut).unwrap();
    assert_eq!(store.entry_failures(1, "recut", &script(1)).unwrap(), 1);
    assert_eq!(store.entry_failures(1, "r1", &script(1)).unwrap(), 0);
}
