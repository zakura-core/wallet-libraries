//! Tests of directory coverage, on the shared one-time IVK fixtures.

use zcash_client_backend::data_api::one_time_ivk::coverage::{
    CoverageOutcome, CoverageState, CoverageStep, CoverageTarget, DirectoryHistory, Obligation,
    ObligationReceivers, OneTimeIvkCoverageRead as _, OneTimeIvkCoverageWrite as _, Snapshot,
    Window,
};

use super::WINDOW_FLOOR;
use crate::wallet::one_time_ivk::restore::tests::discovery::publication_at;
use crate::wallet::one_time_ivk::tests::*;
use crate::wallet::one_time_rewind;

/// The directory history the fixtures follow.
const HISTORY: DirectoryHistory = DirectoryHistory {
    catalog: [1; 32],
    epoch: 1,
};

/// The stored block at `height`.
fn point(st: &State, height: BlockHeight) -> ChainPoint {
    let sql = "SELECT hash FROM blocks WHERE height = ?1";
    let hash: [u8; 32] = value(st.wallet().conn(), sql, [u32::from(height)]);
    ChainPoint {
        height,
        hash: BlockHash(hash),
    }
}

/// A restored wallet scanned through ten blocks, with its windows derived.
fn prepared() -> (State, AccountUuid) {
    let mut st = restored_wallet();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(9);
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    assert!(
        db.prepare_one_time_coverage(account, 1_000, clock_now())
            .unwrap()
    );
    (st, account)
}

/// The bucket of [`HISTORY`] after stored block `start` through stored block `end`.
fn bucket(st: &State, start: BlockHeight, end: BlockHeight) -> CoverageStep {
    CoverageStep {
        start: Some(point(st, start)),
        end: point(st, end),
        digest: [2; 32],
        history: HISTORY,
    }
}

/// The cumulative snapshot through stored block `cutoff`.
fn snapshot(st: &State, cutoff: BlockHeight) -> Snapshot {
    Snapshot {
        cutoff: point(st, cutoff),
        digest: [3; 32],
    }
}

/// `snapshot` as a step of [`HISTORY`].
fn cumulative(snapshot: Snapshot) -> CoverageStep {
    CoverageStep {
        start: None,
        end: snapshot.cutoff,
        digest: snapshot.digest,
        history: HISTORY,
    }
}

/// The frontier target for `account`'s current receiver set.
fn frontier(st: &State, account: AccountUuid) -> CoverageTarget {
    let set = st.wallet().db().one_time_receiver_set(account).unwrap();
    CoverageTarget::Frontier {
        generation: set.generation,
    }
}

/// The target of `account`'s obligation `id` at its current receiver-set generation.
fn obligation(st: &State, account: AccountUuid, id: u64) -> CoverageTarget {
    let CoverageTarget::Frontier { generation } = frontier(st, account) else {
        unreachable!()
    };
    CoverageTarget::Obligation { id, generation }
}

/// Records `step` against `target` with `hits`, at the test clock's time.
fn record(
    st: &mut State,
    account: AccountUuid,
    target: CoverageTarget,
    step: CoverageStep,
    hits: &[KeyId],
) -> Result<CoverageOutcome, SqliteClientError> {
    let db = st.wallet_mut().db_mut();
    db.record_one_time_coverage(account, target, step, hits, clock_now())
}

/// Establishes `account`'s frontier at stored block `cutoff`, whose snapshot matched `hits`.
fn bootstrap(st: &mut State, account: AccountUuid, cutoff: BlockHeight, hits: &[KeyId]) {
    let (target, pinned) = (frontier(st, account), snapshot(st, cutoff));
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.pin_one_time_snapshot(account, target, pinned).unwrap(),
        Some(pinned)
    );
    let recorded = record(st, account, target, cumulative(pinned), hits);
    assert_eq!(recorded.unwrap(), CoverageOutcome::Recorded);
}

/// `account`'s coverage.
fn coverage(st: &State, account: AccountUuid) -> CoverageState {
    let db = st.wallet().db();
    db.one_time_coverage(account).unwrap().unwrap()
}

/// `(due cutoff, done height, applied, generation)` of `key`'s lookup, if it has one.
fn lookup(st: &State, key: KeyId) -> Option<(Option<u32>, Option<u32>, u32, u64)> {
    let sql = "SELECT l.cutoff_height, l.done_height, l.applied, l.generation
               FROM ironwood_one_time_lookups l
               JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
               WHERE k.purpose = ?1 AND k.key_index = ?2";
    let purpose = purpose_code(key.purpose()).unwrap();
    let params = rusqlite::params![purpose, key.index().to_be_bytes()];
    let found: Vec<_> = rows(st.wallet().conn(), sql, params);
    found.into_iter().next()
}

/// `(authenticated, issuance_blocked, advances_allocation)` of `key`.
fn facts(st: &State, key: KeyId) -> (bool, bool, bool) {
    let sql = "SELECT authenticated, issuance_blocked, advances_allocation
               FROM ironwood_one_time_keys WHERE purpose = ?1 AND key_index = ?2";
    let purpose = purpose_code(key.purpose()).unwrap();
    row(
        st.wallet().conn(),
        sql,
        rusqlite::params![purpose, key.index().to_be_bytes()],
    )
}

/// Registers `key` as an unauthenticated funding memo's key is, without allocating it, and
/// waiting for no lookup.
fn register_sparse(
    st: &mut State,
    account: AccountUuid,
    key: KeyId,
) -> Result<(), SqliteClientError> {
    let now = clock_now();
    tx(st.wallet_mut().db_mut(), |c, p| {
        register(c, p, account, key, start(), false, Discovery::Funding, now).map(|_| ())
    })
}

/// Makes every insert into `table` fail, as a crash would stop the write.
fn fail_inserts(st: &State, table: &str) {
    let sql = format!(
        "CREATE TEMP TRIGGER fail_{table} BEFORE INSERT ON {table}
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    );
    st.wallet().conn().execute_batch(&sql).unwrap();
}

/// Undoes [`fail_inserts`].
fn allow_inserts(st: &State, table: &str) {
    let sql = format!("DROP TRIGGER fail_{table}");
    st.wallet().conn().execute_batch(&sql).unwrap();
}

/// Each window covers its floor from index zero and grows past keys that advance
/// allocation. Its receivers are derived within each call's budget, resuming where the last
/// call stopped, and a registered index takes its receiver from the registry.
#[test]
fn windows_derive_within_a_budget_and_resume() {
    let mut st = restored_wallet();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    recover(db, account, KeyId::new(Purpose::Receive, 5), start());
    let window = |purpose, end, derived| Window {
        purpose,
        end,
        derived,
    };
    let now = clock_now();
    assert!(!db.prepare_one_time_coverage(account, 30, now).unwrap());
    assert_eq!(
        coverage(&st, account).windows,
        [
            window(Purpose::Receive, WINDOW_FLOOR, 30),
            window(Purpose::Refund, WINDOW_FLOOR, 0)
        ]
    );
    let db = st.wallet_mut().db_mut();
    assert!(!db.prepare_one_time_coverage(account, 150, now).unwrap());
    assert_eq!(coverage(&st, account).windows[1].derived, 80);
    let db = st.wallet_mut().db_mut();
    assert!(db.prepare_one_time_coverage(account, 1_000, now).unwrap());

    let set = st.wallet().db().one_time_receiver_set(account).unwrap();
    assert!(set.complete);
    assert_eq!(set.receivers.len(), 200);
    for work in &set.receivers {
        let receiver = derive(&st, work.key).address_at(0u32, Scope::External);
        assert_eq!(work.receiver, receiver.to_raw_address_bytes());
    }
    let sql = "SELECT COUNT(*) FROM ironwood_one_time_receiver_cache";
    assert_eq!(value::<u32>(st.wallet().conn(), sql, []), 199);

    // A key that advances allocation past the floor widens its window, which is incomplete
    // until the new indices are derived.
    let db = st.wallet_mut().db_mut();
    recover(db, account, KeyId::new(Purpose::Receive, 90), start());
    let state = coverage(&st, account);
    assert_eq!(state.windows[0], window(Purpose::Receive, 121, 100));
    assert!(
        !st.wallet()
            .db()
            .one_time_receiver_set(account)
            .unwrap()
            .complete
    );
}

/// A frontier starts from the cumulative snapshot pinned for it, which a newer publication
/// does not move, then follows buckets that continue it on the wallet's chain, tested
/// against the current receiver set. Each hit's lookup becomes due through the step's end
/// without allocating the hit's index.
#[test]
fn a_frontier_starts_from_its_pinned_snapshot_and_follows_buckets() {
    use CoverageOutcome::*;
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let (h0, h1) = (top - 6, top - 3);
    let (pinned, later) = (snapshot(&st, h0), snapshot(&st, h1));
    let target = frontier(&st, account);
    let refused = record(&mut st, account, target, cumulative(pinned), &[]);
    assert_eq!(refused.unwrap(), Discontinuous);
    let db = st.wallet_mut().db_mut();
    for snapshot in [pinned, later] {
        let pin = db.pin_one_time_snapshot(account, target, snapshot).unwrap();
        assert_eq!(pin, Some(pinned));
    }
    let moved = record(&mut st, account, target, cumulative(later), &[]);
    assert_eq!(moved.unwrap(), Discontinuous);
    let mut forged = cumulative(pinned);
    forged.end.hash = BlockHash([9; 32]);
    assert_eq!(
        record(&mut st, account, target, forged, &[]).unwrap(),
        OffChain
    );
    let CoverageTarget::Frontier { generation } = target else {
        unreachable!()
    };
    let older = CoverageTarget::Frontier {
        generation: generation - 1,
    };
    let stale = record(&mut st, account, older, cumulative(pinned), &[]);
    assert_eq!(stale.unwrap(), Stale);

    let hit = KeyId::new(Purpose::Receive, 3);
    let taken = record(&mut st, account, target, cumulative(pinned), &[hit]);
    assert_eq!(taken.unwrap(), Recorded);
    let state = coverage(&st, account);
    assert_eq!(state.frontier, Some((pinned.cutoff, generation)));
    assert_eq!(state.history, Some(HISTORY));
    assert_eq!(state.bootstrap, None);
    assert_eq!(lookup(&st, hit), Some((Some(u32::from(h0)), None, 0, 0)));
    assert_eq!(facts(&st, hit), (false, false, false));

    let gap = bucket(&st, h0 + 1, h1);
    assert_eq!(
        record(&mut st, account, target, gap, &[]).unwrap(),
        Discontinuous
    );
    let mut other = bucket(&st, h0, h1);
    other.history.epoch += 1;
    let changed = record(&mut st, account, target, other, &[]);
    assert_eq!(changed.unwrap(), HistoryChanged);
    let mut ahead = bucket(&st, h0, h1);
    ahead.end.height = top + 5;
    assert_eq!(
        record(&mut st, account, target, ahead, &[]).unwrap(),
        Pending
    );
    // A bucket may start below the frontier, as the one holding a snapshot's cutoff does.
    let overlapping = bucket(&st, h0 - 2, h1);
    let taken = record(&mut st, account, target, overlapping, &[hit]);
    assert_eq!(taken.unwrap(), Recorded);
    assert_eq!(
        coverage(&st, account).frontier,
        Some((point(&st, h1), generation))
    );
    assert_eq!(lookup(&st, hit), Some((Some(u32::from(h1)), None, 0, 0)));
}

/// A coverage write that fails partway, or names a hit outside its receivers, leaves the
/// frontier, the registry and every lookup as they were.
#[test]
fn a_failed_coverage_write_changes_nothing() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    bootstrap(&mut st, account, top - 6, &[]);
    let before = coverage(&st, account);
    let target = frontier(&st, account);
    let step = bucket(&st, top - 6, top - 3);
    let hit = KeyId::new(Purpose::Receive, 3);
    fail_inserts(&st, "ironwood_one_time_lookups");
    assert!(record(&mut st, account, target, step, &[hit]).is_err());
    allow_inserts(&st, "ironwood_one_time_lookups");
    assert_eq!(coverage(&st, account), before);
    assert!(get_key(st.wallet().db(), account, hit).unwrap().is_none());

    let outside = KeyId::new(Purpose::Receive, WINDOW_FLOOR);
    assert!(matches!(
        record(&mut st, account, target, step, &[hit, outside]),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    assert_eq!(coverage(&st, account), before);
    assert_eq!(lookup(&st, hit), None);
}

/// A key or window range joining the receiver set after the frontier passed its history
/// owes that history, in the same transaction, and fences out frontier steps tested
/// without it. An unauthenticated key far past the window joins alone, and stays in the
/// set once closed.
#[test]
fn receivers_joining_behind_the_frontier_owe_its_history_atomically() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let h0 = top - 6;
    let birthday = st.test_account().unwrap().birthday().height();
    bootstrap(&mut st, account, h0, &[]);
    let before = frontier(&st, account);
    let sparse = KeyId::new(Purpose::Refund, 1_000_000);
    register_sparse(&mut st, account, sparse).unwrap();
    let state = coverage(&st, account);
    assert_eq!(state.windows[1].end, WINDOW_FLOOR);
    let owed = |receivers| Obligation {
        id: 0,
        receivers,
        lower: birthday,
        through: h0,
        snapshot: None,
        bridged: None,
    };
    let ids: Vec<_> = state.obligations.iter().map(|o| o.id).collect();
    let anonymous: Vec<_> = state
        .obligations
        .into_iter()
        .map(|o| Obligation { id: 0, ..o })
        .collect();
    assert_eq!(anonymous, [owed(ObligationReceivers::Key(sparse))]);
    // Closing a key keeps it in the set.
    let sql = "UPDATE ironwood_one_time_keys SET closed_at = 1";
    exec(st.wallet().conn(), sql, []);
    let set = st.wallet().db().one_time_receiver_set(account).unwrap();
    assert!(set.receivers.iter().any(|w| w.key == sparse));
    let step = bucket(&st, h0, top - 3);
    let stale = record(&mut st, account, before, step, &[]);
    assert_eq!(stale.unwrap(), CoverageOutcome::Stale);

    let db = st.wallet_mut().db_mut();
    recover(db, account, KeyId::new(Purpose::Receive, 90), start());
    let grown = coverage(&st, account).obligations;
    assert_eq!(grown.len(), 2);
    assert_eq!(grown[0].id, ids[0]);
    assert_eq!(
        grown[1].receivers,
        ObligationReceivers::Window {
            purpose: Purpose::Receive,
            start: WINDOW_FLOOR,
            end: 121,
        }
    );
    // The window's new receivers are not derived, so nothing can vouch for them yet.
    let current = frontier(&st, account);
    let incomplete = record(&mut st, account, current, step, &[]);
    assert_eq!(incomplete.unwrap(), CoverageOutcome::Stale);

    let before = coverage(&st, account);
    let (late, advancing) = (
        KeyId::new(Purpose::Refund, 2_000_000),
        KeyId::new(Purpose::Receive, 200),
    );
    fail_inserts(&st, "ironwood_one_time_obligations");
    assert!(register_sparse(&mut st, account, late).is_err());
    let now = clock_now();
    let grown = tx(st.wallet_mut().db_mut(), |c, p| {
        register(
            c,
            p,
            account,
            advancing,
            start(),
            true,
            Discovery::Scan,
            now,
        )
    });
    assert!(grown.is_err());
    allow_inserts(&st, "ironwood_one_time_obligations");
    for key in [late, advancing] {
        assert!(get_key(st.wallet().db(), account, key).unwrap().is_none());
    }
    assert_eq!(coverage(&st, account), before);
}

/// An obligation tests the snapshot it pinned, which it keeps, then bridges with buckets
/// that continue it, and disappears once it reaches the frontier it owes. Its hits are
/// only its own receivers.
#[test]
fn an_obligation_bridges_from_its_pinned_snapshot_to_its_frontier() {
    use CoverageOutcome::*;
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let h0 = top - 4;
    bootstrap(&mut st, account, h0, &[]);
    let sparse = KeyId::new(Purpose::Refund, 1_000_000);
    register_sparse(&mut st, account, sparse).unwrap();
    let id = coverage(&st, account).obligations[0].id;
    let target = obligation(&st, account, id);
    let early = bucket(&st, h0 - 5, h0);
    assert_eq!(
        record(&mut st, account, target, early, &[]).unwrap(),
        Discontinuous
    );
    let (pinned, newer) = (snapshot(&st, h0 - 4), snapshot(&st, h0 - 1));
    let db = st.wallet_mut().db_mut();
    for snapshot in [pinned, newer] {
        let pin = db.pin_one_time_snapshot(account, target, snapshot).unwrap();
        assert_eq!(pin, Some(pinned));
    }
    let foreign = KeyId::new(Purpose::Refund, 5);
    assert!(matches!(
        record(&mut st, account, target, cumulative(pinned), &[foreign]),
        Err(SqliteClientError::InvalidOneTimeIvkInput(_))
    ));
    let tested = record(&mut st, account, target, cumulative(pinned), &[sparse]);
    assert_eq!(tested.unwrap(), Recorded);
    let state = coverage(&st, account);
    assert_eq!(state.obligations[0].bridged, Some(h0 - 4));
    assert_eq!(state.obligations[0].snapshot, Some(pinned));
    assert_eq!(
        lookup(&st, sparse),
        Some((Some(u32::from(h0 - 4)), None, 0, 0))
    );
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.pin_one_time_snapshot(account, target, newer).unwrap(),
        None
    );

    let partial = bucket(&st, h0 - 5, h0 - 2);
    assert_eq!(
        record(&mut st, account, target, partial, &[]).unwrap(),
        Recorded
    );
    assert_eq!(coverage(&st, account).obligations[0].bridged, Some(h0 - 2));
    let last = bucket(&st, h0 - 2, h0 + 1);
    assert_eq!(
        record(&mut st, account, target, last, &[]).unwrap(),
        Recorded
    );
    assert!(coverage(&st, account).obligations.is_empty());
    assert_eq!(record(&mut st, account, target, last, &[]).unwrap(), Stale);
}

/// A lookup walk completes only the target it was dispatched with: a target widened
/// meanwhile stays due, and a restart fences the walk out.
#[test]
fn a_lookup_walk_completes_only_its_dispatched_target() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let (h0, h1) = (top - 6, top - 3);
    let hit = KeyId::new(Purpose::Receive, 3);
    bootstrap(&mut st, account, h0, &[hit]);
    let now = clock_now();
    let db = st.wallet_mut().db_mut();
    let tickets = db.dispatch_one_time_lookups(account, now).unwrap();
    assert_eq!(tickets.len(), 1);
    let ticket = tickets[0].clone();
    assert_eq!((ticket.work.work.key, ticket.work.cutoff), (hit, h0));

    let target = frontier(&st, account);
    let step = bucket(&st, h0, h1);
    let widened = record(&mut st, account, target, step, &[hit]);
    assert_eq!(widened.unwrap(), CoverageOutcome::Recorded);
    let revision = publication_at(&st, h1);
    let db = st.wallet_mut().db_mut();
    assert!(
        db.record_one_time_lookup_page(account, &ticket, revision, 0, &[], true, now)
            .unwrap()
    );
    let (h0, h1) = (u32::from(h0), u32::from(h1));
    assert_eq!(lookup(&st, hit), Some((Some(h1), Some(h0), 0, 0)));

    let db = st.wallet_mut().db_mut();
    let ticket = db.dispatch_one_time_lookups(account, now).unwrap()[0].clone();
    assert_eq!(u32::from(ticket.work.cutoff), h1);
    let id = key_ref(&db.conn, account, hit).unwrap();
    tx(db, |c, _| one_time_rewind::restart_cursor(c, "?1", id)).unwrap();
    assert!(
        !db.record_one_time_lookup_page(account, &ticket, revision, 0, &[], true, now)
            .unwrap()
    );
    assert_eq!(lookup(&st, hit), Some((Some(h1), None, 0, 1)));
    let db = st.wallet_mut().db_mut();
    let ticket = &db.dispatch_one_time_lookups(account, now).unwrap()[0];
    assert_eq!(ticket.generation, 1);
    assert!(
        db.record_one_time_lookup_page(account, ticket, revision, 0, &[], true, now)
            .unwrap()
    );
    assert_eq!(lookup(&st, hit), Some((None, Some(h1), 0, 1)));
}

/// A rewind keeps the coverage the chain below its floor still supports: the frontier moves
/// down to the floor, obligations owe and bridge no further, a snapshot pinned above it is
/// unpinned, and a lookup done above it is due again. Walks in flight above it and frontier
/// steps tested before are fenced out. Keys and windows stay.
#[test]
fn a_rewind_keeps_the_coverage_its_floor_supports() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let (h0, floor) = (top - 6, top - 3);
    let (kept, unpinned) = (
        KeyId::new(Purpose::Refund, 1_000_000),
        KeyId::new(Purpose::Refund, 2_000_000),
    );
    let (done, walking) = (
        KeyId::new(Purpose::Receive, 3),
        KeyId::new(Purpose::Receive, 4),
    );
    bootstrap(&mut st, account, h0, &[]);
    let target = frontier(&st, account);
    let step = bucket(&st, h0, top - 1);
    let recorded = record(&mut st, account, target, step, &[done, walking]);
    assert_eq!(recorded.unwrap(), CoverageOutcome::Recorded);
    for key in [kept, unpinned] {
        register_sparse(&mut st, account, key).unwrap();
    }
    let obligations = coverage(&st, account).obligations;
    let (first, second) = (
        obligation(&st, account, obligations[0].id),
        obligation(&st, account, obligations[1].id),
    );
    let (below, above) = (snapshot(&st, h0), snapshot(&st, top - 2));
    let db = st.wallet_mut().db_mut();
    db.pin_one_time_snapshot(account, first, below).unwrap();
    db.pin_one_time_snapshot(account, second, above).unwrap();
    let tested = record(&mut st, account, first, cumulative(below), &[]);
    assert_eq!(tested.unwrap(), CoverageOutcome::Recorded);
    let now = clock_now();
    let revision = publication_at(&st, top - 1);
    let db = st.wallet_mut().db_mut();
    let tickets = db.dispatch_one_time_lookups(account, now).unwrap();
    let ticket = |key| tickets.iter().find(|t| t.work.work.key == key).unwrap();
    assert!(
        db.record_one_time_lookup_page(account, ticket(done), revision, 0, &[], true, now)
            .unwrap()
    );
    let before = coverage(&st, account);
    let keys = all_keys(st.wallet().db(), account).unwrap().len();

    let db = st.wallet_mut().db_mut();
    tx(db, |c, _| one_time_rewind::truncate(c, floor)).unwrap();
    let after = coverage(&st, account);
    assert_eq!(after.frontier.map(|f| f.0), Some(point(&st, floor)));
    assert!(after.generation > before.generation);
    assert_eq!(after.windows, before.windows);
    let floor_height = floor;
    let expected = [
        (Some(below), Some(h0), floor_height),
        (None, None, floor_height),
    ];
    let found: Vec<_> = after
        .obligations
        .iter()
        .map(|o| (o.snapshot, o.bridged, o.through))
        .collect();
    assert_eq!(found, expected);
    let floor = u32::from(floor);
    let at = u32::from(top - 1);
    assert_eq!(lookup(&st, done), Some((Some(at), None, 0, 0)));
    let db = st.wallet_mut().db_mut();
    let stale = ticket(walking);
    assert!(
        !db.record_one_time_lookup_page(account, stale, revision, 0, &[], true, now)
            .unwrap()
    );
    assert_eq!(lookup(&st, walking).unwrap().3, 1);
    assert_eq!(all_keys(st.wallet().db(), account).unwrap().len(), keys);
    let step = bucket(&st, BlockHeight::from(floor), top);
    let fenced = record(&mut st, account, target, step, &[]);
    assert_eq!(fenced.unwrap(), CoverageOutcome::Stale);

    // A floor without a stored block leaves no frontier to keep, nor obligations.
    let birthday = st.test_account().unwrap().birthday().height();
    let db = st.wallet_mut().db_mut();
    tx(db, |c, _| one_time_rewind::truncate(c, birthday - 10)).unwrap();
    let dropped = coverage(&st, account);
    assert_eq!(dropped.frontier, None);
    assert!(dropped.obligations.is_empty());
}

/// Following another history, or a newer epoch of the same catalog, drops the frontier and
/// every obligation so the whole set is bootstrapped again, and restarts every lookup from
/// page zero. An older epoch changes nothing.
#[test]
fn a_new_history_bootstraps_every_receiver_again() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let h0 = top - 6;
    let hit = KeyId::new(Purpose::Receive, 3);
    bootstrap(&mut st, account, h0, &[hit]);
    register_sparse(&mut st, account, KeyId::new(Purpose::Refund, 1_000_000)).unwrap();
    let now = clock_now();
    let revision = publication_at(&st, h0);
    let db = st.wallet_mut().db_mut();
    let ticket = &db.dispatch_one_time_lookups(account, now).unwrap()[0];
    assert!(
        db.record_one_time_lookup_page(account, ticket, revision, 0, &[], true, now)
            .unwrap()
    );
    let before = coverage(&st, account);
    let db = st.wallet_mut().db_mut();
    for epoch in [0, 1] {
        let older = DirectoryHistory { epoch, ..HISTORY };
        assert!(!db.reset_one_time_history(account, older).unwrap());
    }
    assert_eq!(coverage(&st, account), before);

    let newer = DirectoryHistory {
        epoch: 2,
        ..HISTORY
    };
    let db = st.wallet_mut().db_mut();
    assert!(db.reset_one_time_history(account, newer).unwrap());
    let after = coverage(&st, account);
    assert_eq!(after.history, Some(newer));
    assert_eq!((after.frontier, after.bootstrap), (None, None));
    assert!(after.obligations.is_empty());
    assert!(after.generation > before.generation);
    assert_eq!(lookup(&st, hit), Some((Some(u32::from(h0)), None, 0, 1)));
    let target = frontier(&st, account);
    let step = cumulative(snapshot(&st, h0));
    let refused = record(&mut st, account, target, step, &[]);
    assert_eq!(refused.unwrap(), CoverageOutcome::HistoryChanged);
}

/// Lowering an account's birthday owes its whole receiver set the history from the new
/// birthday through the frontier.
#[test]
fn lowering_the_birthday_owes_every_receiver_its_history() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    bootstrap(&mut st, account, top - 6, &[]);
    let sparse = KeyId::new(Purpose::Refund, 1_000_000);
    register_sparse(&mut st, account, sparse).unwrap();
    let lowered = st.test_account().unwrap().birthday().height() - 50;
    let db = st.wallet_mut().db_mut();
    let sql = "UPDATE accounts SET birthday_height = ?1";
    exec(&db.conn, sql, [u32::from(lowered)]);
    tx(db, |c, _| one_time_rewind::reopen_discovery(c, account)).unwrap();
    let owed: Vec<_> = coverage(&st, account)
        .obligations
        .into_iter()
        .filter(|o| o.lower == lowered)
        .map(|o| (o.receivers, o.through))
        .collect();
    let window = |purpose| ObligationReceivers::Window {
        purpose,
        start: 0,
        end: WINDOW_FLOOR,
    };
    assert_eq!(
        owed,
        [
            (window(Purpose::Refund), top - 6),
            (ObligationReceivers::Key(sparse), top - 6),
            (window(Purpose::Receive), top - 6),
        ]
    );
}

/// A finished obligation's ID is never given to another, so a late answer for it is stale
/// even when a newer obligation pinned the same snapshot.
#[test]
fn a_late_answer_for_a_finished_obligation_is_stale() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let h0 = top - 4;
    bootstrap(&mut st, account, h0, &[]);
    let pinned = snapshot(&st, h0 - 2);
    let first = KeyId::new(Purpose::Refund, 1_000_000);
    register_sparse(&mut st, account, first).unwrap();
    let id = coverage(&st, account).obligations[0].id;
    let target = obligation(&st, account, id);
    let db = st.wallet_mut().db_mut();
    db.pin_one_time_snapshot(account, target, pinned).unwrap();
    let tested = record(&mut st, account, target, cumulative(pinned), &[]);
    assert_eq!(tested.unwrap(), CoverageOutcome::Recorded);
    let last = bucket(&st, h0 - 3, h0);
    assert_eq!(
        record(&mut st, account, target, last, &[]).unwrap(),
        CoverageOutcome::Recorded
    );
    assert!(coverage(&st, account).obligations.is_empty());

    register_sparse(&mut st, account, KeyId::new(Purpose::Refund, 2_000_000)).unwrap();
    let newer = coverage(&st, account).obligations[0].id;
    assert_ne!(newer, id);
    let current = obligation(&st, account, newer);
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.pin_one_time_snapshot(account, current, pinned).unwrap(),
        Some(pinned)
    );
    let late = obligation(&st, account, id);
    let answer = record(&mut st, account, late, cumulative(pinned), &[first]);
    assert_eq!(answer.unwrap(), CoverageOutcome::Stale);
    assert_eq!(coverage(&st, account).obligations[0].bridged, None);
}

/// A hit on a key scanned from before the step is still looked up: the scan may still owe
/// a rescan with the key, and the key may close before that rescan runs.
#[test]
fn a_hit_on_a_scanned_key_is_looked_up_even_if_it_closes() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let key = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Receive, start());
    let sql = "SELECT EXISTS(SELECT 1 FROM scan_queue WHERE priority != ?1)";
    let scanned = crate::wallet::scanning::priority_code(
        &zcash_client_backend::data_api::scanning::ScanPriority::Scanned,
    );
    assert!(value::<bool>(st.wallet().conn(), sql, [scanned]));
    bootstrap(&mut st, account, top - 6, &[key.key_id()]);
    let due = Some((Some(u32::from(top - 6)), None, 0, 0));
    assert_eq!(lookup(&st, key.key_id()), due);
    let sql = "UPDATE ironwood_one_time_keys SET closed_at = 1";
    exec(st.wallet().conn(), sql, []);
    assert_eq!(lookup(&st, key.key_id()), due);
}

/// A snapshot fetched before a rewind or a history change pins nothing afterwards, for the
/// frontier or an obligation, so it cannot wedge recovery on a stale snapshot.
#[test]
fn a_delayed_pin_is_fenced_out() {
    let (mut st, account) = prepared();
    let top = tip(&st).height;
    let early = frontier(&st, account);
    let db = st.wallet_mut().db_mut();
    tx(db, |c, _| one_time_rewind::truncate(c, top - 1)).unwrap();
    let delayed = snapshot(&st, top - 3);
    let db = st.wallet_mut().db_mut();
    assert_eq!(
        db.pin_one_time_snapshot(account, early, delayed).unwrap(),
        None
    );
    assert_eq!(coverage(&st, account).bootstrap, None);

    bootstrap(&mut st, account, top - 6, &[]);
    register_sparse(&mut st, account, KeyId::new(Purpose::Refund, 1_000_000)).unwrap();
    let id = coverage(&st, account).obligations[0].id;
    let before_rewind = obligation(&st, account, id);
    let db = st.wallet_mut().db_mut();
    tx(db, |c, _| one_time_rewind::truncate(c, top - 1)).unwrap();
    let pinned = db.pin_one_time_snapshot(account, before_rewind, delayed);
    assert_eq!(pinned.unwrap(), None);
    assert_eq!(coverage(&st, account).obligations[0].snapshot, None);

    let before_reset = frontier(&st, account);
    let newer = DirectoryHistory {
        epoch: 2,
        ..HISTORY
    };
    let db = st.wallet_mut().db_mut();
    assert!(db.reset_one_time_history(account, newer).unwrap());
    let pinned = db.pin_one_time_snapshot(account, before_reset, delayed);
    assert_eq!(pinned.unwrap(), None);
    assert_eq!(coverage(&st, account).bootstrap, None);
}
