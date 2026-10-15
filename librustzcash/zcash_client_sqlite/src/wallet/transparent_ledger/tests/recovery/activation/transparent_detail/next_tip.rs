//! Lookups a reply queues wait for the next chain tip.
//!
//! A recovery reply or an Enhance reply can queue a txid lookup. Listing it at the tip the reply
//! arrived would let the display service see another service's reply turn into a query within
//! one sync, so the listing holds such work back until the tip changes.

use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerWrite as _;

use super::*;
use crate::testing::db::{test_clock, test_rng};

/// The txids listed when `prefer` is preferred.
fn preferred_listing(st: &State, prefer: TxId) -> Vec<TxId> {
    st.wallet()
        .db()
        .transparent_detail_work(now(), 100, &[prefer], None)
        .unwrap()
        .requests
        .into_iter()
        .map(|r| r.txid)
        .collect()
}

/// An [`active_wallet`] and a commit recovering a new receive at the watch set's target,
/// `depth` blocks below it.
fn recovered_receive(depth: u32) -> (State, TransparentLedgerCommit<AccountUuid>, TxId) {
    let (st, account, _) = active_wallet();
    let ws = watch(&st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, depth));
    let mut c = commit(&ws);
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    (st, c, txid_of(&fresh))
}

#[test]
fn a_recovered_receive_is_listed_from_the_next_tip() {
    let (mut st, c, txid) = recovered_receive(0);
    apply(&mut st, c).unwrap();
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
    // Neither listed nor, when the user opens the receipt, preferred at the reply's tip.
    assert!(!listing(&st).contains(&txid));
    assert!(!preferred_listing(&st, txid).contains(&txid));
    scan_new_blocks(&mut st, 1);
    assert!(listing(&st).contains(&txid));
    assert!(preferred_listing(&st, txid).contains(&txid));
}

#[test]
fn work_queued_before_the_tip_stays_listed() {
    let (mut st, account, unspent) = active_wallet();
    // Activation queued these lookups before the two scanned blocks.
    let queued = listing(&st);
    assert!(queued.contains(&txid_of(&unspent)));
    let ws = watch(&st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, 0));
    let mut c = commit(&ws);
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    // A reply at this tip holds back only the work it queued.
    assert_eq!(listing(&st), queued);
}

#[test]
fn a_reorg_to_a_lower_tip_releases_held_work() {
    let (mut st, c, txid) = recovered_receive(2);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    apply(&mut st, c).unwrap();
    assert!(!listing(&st).contains(&txid));
    st.truncate_to_height(tip - 1);
    assert_eq!(st.wallet().chain_height().unwrap(), Some(tip - 1));
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
    assert!(listing(&st).contains(&txid));
}

#[test]
fn handles_sharing_a_session_hold_the_same_work_and_a_fresh_session_lists_it() {
    let (mut st, c, txid) = recovered_receive(0);
    let handle = |st: &State| {
        crate::WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            test_clock(),
            test_rng(),
        )
        .unwrap()
        .with_transparent_ledger_mode(PrivateRequired)
    };
    let list = |db: &crate::WalletDb<_, _, _, _>| -> Vec<TxId> {
        db.transparent_detail_work(now(), 100, &[], None)
            .unwrap()
            .requests
            .into_iter()
            .map(|r| r.txid)
            .collect()
    };
    // The reply is applied through another handle of the wallet sharing its session.
    let mut other =
        handle(&st).with_transparent_pir_session(st.wallet().db().transparent_pir_session());
    other.apply_transparent_ledger_commit(c).unwrap();
    assert_eq!(reasons(&st, txid), Some(RECEIVE));
    assert!(!list(&other).contains(&txid));
    assert!(!listing(&st).contains(&txid));
    // A handle with a session of its own, as after a restart, lists it.
    assert!(list(&handle(&st)).contains(&txid));
    // So does the wallet's handle once the tip changes.
    scan_new_blocks(&mut st, 1);
    assert!(listing(&st).contains(&txid));
    assert!(list(&other).contains(&txid));
}
