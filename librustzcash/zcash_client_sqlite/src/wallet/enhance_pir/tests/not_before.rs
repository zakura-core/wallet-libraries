//! The first private query of a newly queued position waits a random time drawn from the
//! wallet's random source (`docs/pir-remaining-leaks-plan.md`, change D).
use std::time::{Duration, SystemTime};

use zcash_client_backend::data_api::testing::{FakeCompactOutput, TestRng};

use super::*;
use crate::util::Clock;

const MAX_DELAY: Duration = Duration::from_secs(120);

/// A wallet with the production delay bound, private Enhance and a random source seeded `seed`.
fn delayed_state(seed: u64) -> State {
    let mut st = state_with_factory(TestDbFactory::default());
    let db = st.wallet_mut().db_mut();
    db.set_enhance_pir_max_delay(MAX_DELAY);
    db.set_enhancement_mode(EnhancementMode::PrivateIronwood);
    db.rng = TestRng::seed_from_u64(seed);
    st
}

/// Scans a block paying `outputs` notes to the wallet and returns its height.
fn scan_notes(st: &mut State, outputs: usize) -> BlockHeight {
    let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(st));
    let outputs = (0..outputs)
        .map(|i| {
            FakeCompactOutput::new(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(10_000 + i as u64),
            )
        })
        .collect::<Vec<_>>();
    let (height, _, _) = st.generate_next_block_multi(&outputs);
    st.scan_cached_blocks(height, 1);
    height
}

fn now(st: &State) -> SystemTime {
    st.wallet().db().clock.now()
}

fn private_work(st: &State) -> Vec<EnhancePirWork> {
    st.wallet()
        .db()
        .transaction_enhancement_work()
        .unwrap()
        .into_iter()
        .filter_map(|work| match work {
            TransactionEnhancementWork::Private(work) => Some(work),
            TransactionEnhancementWork::Public(_) => None,
        })
        .collect()
}

fn waiting(st: &State) -> Vec<(EnhancePirRequest, SystemTime)> {
    private_work(st)
        .into_iter()
        .filter_map(|work| match work {
            EnhancePirWork::Waiting {
                request,
                not_before,
            } => Some((request, not_before)),
            _ => None,
        })
        .collect()
}

fn queries(st: &State) -> Vec<EnhancePirRequest> {
    private_work(st)
        .into_iter()
        .filter_map(|work| match work {
            EnhancePirWork::Query(request) => Some(request),
            _ => None,
        })
        .collect()
}

fn single_wait(st: &State) -> (EnhancePirRequest, SystemTime) {
    let waiting = waiting(st);
    assert_eq!(waiting.len(), 1, "one newly queued position waits");
    waiting[0]
}

#[test]
fn a_newly_queued_position_is_not_queried_before_its_time() {
    let mut st = delayed_state(0);
    let queued_at = now(&st);
    scan_notes(&mut st, 1);
    let (request, not_before) = single_wait(&st);
    assert!(queries(&st).is_empty(), "nothing is due at the queue time");
    assert!(not_before > queued_at && not_before <= queued_at + MAX_DELAY);

    st.wallet().db().clock.tick(
        not_before
            .duration_since(queued_at)
            .unwrap()
            .saturating_sub(Duration::from_secs(1)),
    );
    assert_eq!(single_wait(&st), (request, not_before), "a second early");
    st.wallet().db().clock.tick(Duration::from_secs(1));
    assert!(waiting(&st).is_empty());
    assert_eq!(queries(&st), vec![request], "due at its time");
}

#[test]
fn the_delay_comes_from_the_wallet_random_source() {
    let draw = |seed| {
        let mut st = delayed_state(seed);
        let queued_at = now(&st);
        scan_notes(&mut st, 1);
        single_wait(&st).1.duration_since(queued_at).unwrap()
    };
    assert_eq!(draw(1), draw(1), "the same seed gives the same delay");
    assert_ne!(draw(1), draw(2), "another seed gives another delay");

    // Positions found in one scan get independent times.
    let mut st = delayed_state(3);
    scan_notes(&mut st, 2);
    let waiting = waiting(&st);
    assert_eq!(waiting.len(), 2);
    assert_ne!(waiting[0].0.position(), waiting[1].0.position());
    assert_ne!(waiting[0].1, waiting[1].1);
}

#[test]
fn a_rescan_keeps_the_time_and_a_rewind_draws_a_new_one() {
    let mut st = delayed_state(4);
    let height = scan_notes(&mut st, 1);
    let (request, not_before) = single_wait(&st);

    st.wallet().db().clock.tick(Duration::from_secs(30));
    st.scan_cached_blocks(height, 1);
    assert_eq!(single_wait(&st), (request, not_before), "a rescan keeps it");

    st.wallet_mut()
        .db_mut()
        .truncate_to_height(height - 1)
        .unwrap();
    assert!(private_work(&st).is_empty());
    st.wallet().db().clock.tick(MAX_DELAY * 2);
    let requeued_at = now(&st);
    st.scan_cached_blocks(height, 1);
    let (again, later) = single_wait(&st);
    assert_eq!(again, request);
    assert!(later > requeued_at, "the rewind deleted the old time");
}

#[test]
fn completing_a_position_deletes_its_time() {
    let mut st = delayed_state(5);
    scan_notes(&mut st, 1);
    let (request, not_before) = single_wait(&st);
    st.wallet().db().clock.tick(
        not_before
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .saturating_sub(now(&st).duration_since(SystemTime::UNIX_EPOCH).unwrap()),
    );
    assert_eq!(queries(&st), vec![request]);
    finish_incoming(&mut st, request);
    let rows: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM ironwood_enhance_not_before",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

/// A restart is the application's doing, not a reply's. A fresh session draws a new wait for a
/// position whose earlier one has passed, at its first wallet write, and keeps it across
/// rescans within the session.
#[test]
fn a_fresh_session_draws_the_wait_again_and_keeps_it_within_the_session() {
    let mut st = delayed_state(6);
    let height = scan_notes(&mut st, 1);
    let (request, _) = single_wait(&st);
    st.wallet().db().clock.tick(MAX_DELAY * 2);
    assert_eq!(queries(&st), vec![request], "the first wait has passed");

    // The application restarts: a new session over the same database.
    st.wallet_mut().db_mut().enhance_pir_session = Default::default();
    let restarted_at = now(&st);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    st.wallet_mut().update_chain_tip(tip).unwrap();
    let (again, not_before) = single_wait(&st);
    assert_eq!(again, request);
    assert!(not_before > restarted_at && not_before <= restarted_at + MAX_DELAY);
    assert!(queries(&st).is_empty(), "not due before the new wait");

    st.wallet().db().clock.tick(Duration::from_secs(1));
    st.scan_cached_blocks(height, 1);
    assert_eq!(
        single_wait(&st),
        (request, not_before),
        "the session keeps it across a rescan"
    );
}
