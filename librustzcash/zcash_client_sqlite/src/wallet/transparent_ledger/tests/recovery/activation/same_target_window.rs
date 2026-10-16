//! Window growth a reply causes is watched from the next target.
//!
//! A receive near the end of an account's window grows it. Watching the grown addresses in a
//! second pass at the same target would let a forging service test addresses as often as it
//! can trigger a catch-up pass; the watch set at that target keeps the window its first read
//! saw, and the growth is watched from the next target.

use super::*;

const EXTERNAL: TransparentKeyScope = TransparentKeyScope::EXTERNAL;
const INTERNAL: TransparentKeyScope = TransparentKeyScope::INTERNAL;

/// The watched addresses, in the watch set's order.
fn addresses(ws: &TransparentAddressWatchSet<AccountUuid>) -> Vec<TransparentAddress> {
    ws.addresses.iter().map(|w| w.address).collect()
}

/// The watched derived indices of `scope`, ascending.
fn indices(ws: &TransparentAddressWatchSet<AccountUuid>, scope: TransparentKeyScope) -> Vec<u32> {
    let mut indices: Vec<_> = ws
        .addresses
        .iter()
        .filter_map(|w| match w.origin {
            WatchOrigin::Derived { scope: s, index }
            | WatchOrigin::CandidateWindow { scope: s, index }
                if s == scope =>
            {
                Some(index.index())
            }
            _ => None,
        })
        .collect();
    indices.sort_unstable();
    indices
}

/// A candidate account that read its watch set and committed a receive at the window's last
/// external address, `depth` blocks below the target, which grows the window.
fn grown_candidate(depth: u32) -> (State, AccountUuid, TransparentAddressWatchSet<AccountUuid>) {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let ws = watch(&st, account);
    let (last, _) = last_external(&ws);
    let mut c = commit(&ws);
    c.receives = vec![receive(1, last, 1_000, below_target(&ws, depth))];
    c.coverage = full_coverage(&ws);
    assert!(apply(&mut st, c).unwrap().window_grew);
    (st, account, ws)
}

#[test]
fn a_same_target_catch_up_watches_what_the_first_pass_watched() {
    let (mut st, account, first) = grown_candidate(1);
    // The growth is stored: the account is incomplete until the grown addresses are covered.
    assert!(
        recovery(&st, account)
            .blockers
            .contains(&CandidateBlocker::IncompleteCoverage)
    );
    // A catch-up pass at the same target watches the first pass's addresses.
    let again = watch(&st, account);
    assert_eq!(again.target, first.target);
    assert_eq!(addresses(&again), addresses(&first));
    // Still incomplete: completion is not capped.
    let mut c = commit(&again);
    c.coverage = full_coverage(&again);
    apply(&mut st, c).unwrap();
    assert!(
        recovery(&st, account)
            .blockers
            .contains(&CandidateBlocker::IncompleteCoverage)
    );
    // The next target watches the grown window, and a pass over it completes the account.
    scan_new_blocks(&mut st, 1);
    let next = watch(&st, account);
    assert_ne!(next.target, first.target);
    assert!(indices(&next, EXTERNAL).len() > indices(&first, EXTERNAL).len());
    assert!(
        addresses(&first)
            .iter()
            .all(|a| addresses(&next).contains(a))
    );
    let mut c = commit(&next);
    c.coverage = full_coverage(&next);
    assert!(!apply(&mut st, c).unwrap().window_grew);
    assert_eq!(recovery(&st, account).blockers, vec![]);
}

#[test]
fn a_fresh_session_watches_the_grown_window() {
    let (mut st, account, first) = grown_candidate(1);
    assert_eq!(addresses(&watch(&st, account)), addresses(&first));
    // A restart forgets what the first read watched.
    st.wallet_mut().db_mut().transparent_pir_session = Default::default();
    let fresh = watch(&st, account);
    assert_eq!(fresh.target, first.target);
    assert!(indices(&fresh, EXTERNAL).len() > indices(&first, EXTERNAL).len());
}

#[test]
fn a_reorg_to_a_lower_target_releases_the_window() {
    let (mut st, account, first) = grown_candidate(2);
    assert_eq!(addresses(&watch(&st, account)), addresses(&first));
    let target = first.target.unwrap().height;
    st.truncate_to_height(target - 1);
    let lower = watch(&st, account);
    assert_eq!(lower.target.unwrap().height, target - 1);
    assert!(indices(&lower, EXTERNAL).len() > indices(&first, EXTERNAL).len());
}

#[test]
fn a_candidates_restore_window_is_watched_whole() {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let ws = watch(&st, account);
    assert_eq!(indices(&ws, EXTERNAL), (0..50).collect::<Vec<_>>());
    assert_eq!(indices(&ws, INTERNAL), (0..25).collect::<Vec<_>>());
    // A receive inside the restore window does not grow it.
    let early = ws
        .addresses
        .iter()
        .find(|w| {
            matches!(w.origin,
                WatchOrigin::Derived { scope, index } | WatchOrigin::CandidateWindow { scope, index }
                    if scope == EXTERNAL && index.index() == 3)
        })
        .unwrap()
        .address;
    let mut c = commit(&ws);
    c.receives = vec![receive(1, early, 1_000, below_target(&ws, 1))];
    c.coverage = full_coverage(&ws);
    assert!(!apply(&mut st, c).unwrap().window_grew);
    let again = watch(&st, account);
    assert_eq!(addresses(&again), addresses(&ws));
    assert_eq!(recovery(&st, account).blockers, vec![]);
}

#[test]
fn an_active_accounts_gap_generation_is_watched_from_the_next_target() {
    let (mut st, account, _) = active_wallet();
    let first = watch(&st, account);
    assert_eq!(first.lifecycle, AccountLifecycle::Active);
    let (last, index) = last_external(&first);
    let addresses_before = count(&st, "addresses");
    let mut c = commit(&first);
    c.receives = vec![receive(5, last, 60_000, below_target(&first, 0))];
    c.coverage = full_coverage(&first);
    assert!(apply(&mut st, c).unwrap().window_grew);
    // A catch-up pass at the same target watches the first pass's addresses, even after it
    // makes the grown window the wallet's own.
    let again = watch(&st, account);
    assert_eq!(addresses(&again), addresses(&first));
    let mut c = commit(&again);
    c.coverage = full_coverage(&again);
    apply(&mut st, c).unwrap();
    assert!(count(&st, "addresses") > addresses_before);
    assert_eq!(addresses(&watch(&st, account)), addresses(&first));
    // The next target watches the wallet's new addresses.
    scan_new_blocks(&mut st, 1);
    assert!(last_external(&watch(&st, account)).1 > index);
}
