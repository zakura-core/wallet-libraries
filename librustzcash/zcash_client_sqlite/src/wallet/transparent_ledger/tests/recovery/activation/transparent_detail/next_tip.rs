//! Lookups a reply queues wait for the next chain tip.
//!
//! A recovery reply or an Enhance reply can queue a txid lookup. Listing it at the tip the reply
//! arrived would let the display service see another service's reply turn into a query within
//! one sync, so the listing holds such work back until the tip changes.

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

#[test]
fn a_caller_owned_transaction_cannot_release_an_existing_hold() {
    use zcash_client_backend::data_api::WalletWrite as _;

    let (mut st, c, held) = recovered_receive(0);
    apply(&mut st, c).unwrap();
    assert!(!listing(&st).contains(&held));
    let account = st.test_account().unwrap().id();
    let ws = watch(&st, account);
    let fresh = receive(6, external(&ws), 70_000, below_target(&ws, 0));
    let mut c = commit(&ws);
    c.receives = vec![fresh.clone()];
    c.coverage = full_coverage(&ws);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    let network = *st.network();
    let session = st.wallet().db().transparent_pir_session();
    let result = {
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        let mut db = crate::WalletDb::from_connection(
            crate::SqlTransaction::new(&tx),
            network,
            test_clock(),
            test_rng(),
        )
        .with_transparent_ledger_mode(PrivateRequired)
        .with_transparent_pir_session(session);
        db.update_chain_tip(tip + 1).unwrap();
        assert!(matches!(
            db.apply_transparent_policy(PrivateRequired),
            Err(SqliteClientError::TransparentSessionTransactionRequired)
        ));
        assert!(matches!(
            db.activate_transparent_ledger(account),
            Err(SqliteClientError::TransparentSessionTransactionRequired)
        ));
        assert!(matches!(
            db.set_transaction_status(
                held,
                zcash_client_backend::data_api::TransactionStatus::Mined(tip)
            ),
            Err(SqliteClientError::TransparentSessionTransactionRequired)
        ));
        let result = db.apply_transparent_ledger_commit(c);
        drop(db);
        tx.rollback().unwrap();
        result
    };
    assert!(matches!(
        result,
        Err(SqliteClientError::TransparentSessionTransactionRequired)
    ));
    assert_eq!(st.wallet().chain_height().unwrap(), Some(tip));
    assert_eq!(reasons(&st, txid_of(&fresh)), None);
    assert!(!listing(&st).contains(&held));
}

#[test]
fn wallet_owned_transactions_publish_holds_only_after_commit() {
    use zcash_client_backend::data_api::WalletWrite as _;

    for fail_commit in [false, true] {
        let (mut st, first, held) = recovered_receive(0);
        apply(&mut st, first).unwrap();
        let account = st.test_account().unwrap().id();
        let ws = watch(&st, account);
        let fresh = receive(6, external(&ws), 70_000, below_target(&ws, 0));
        let txid = txid_of(&fresh);
        let mut c = commit(&ws);
        c.receives = vec![fresh];
        c.coverage = full_coverage(&ws);
        let tip = st.wallet().chain_height().unwrap().unwrap();
        if fail_commit {
            conn(&st).commit_hook(Some(|| true));
        }
        let result: Result<(), SqliteClientError> =
            st.wallet_mut().db_mut().transactionally(|db| {
                db.update_chain_tip(tip + 1)?;
                db.apply_transparent_ledger_commit(c.clone())?;
                assert!(
                    !db.transparent_detail_work(now(), 100, &[txid], None)?
                        .requests
                        .iter()
                        .any(|r| r.txid == txid)
                );
                if fail_commit {
                    Ok(())
                } else {
                    Err(SqliteClientError::CorruptedData(
                        "abort the test transaction".into(),
                    ))
                }
            });
        conn(&st).commit_hook(None::<fn() -> bool>);
        if fail_commit {
            assert!(matches!(result, Err(SqliteClientError::DbError(_))));
        } else {
            assert!(
                matches!(result, Err(SqliteClientError::CorruptedData(ref message)) if message == "abort the test transaction")
            );
        }
        assert_eq!(st.wallet().chain_height().unwrap(), Some(tip));
        assert_eq!(reasons(&st, txid), None);
        assert!(!listing(&st).contains(&held));
        assert!(
            !st.wallet()
                .db()
                .transparent_pir_session
                .held(tip + 1)
                .contains(&txid)
        );
        st.wallet_mut()
            .db_mut()
            .transactionally_with_extension(|db, _| {
                db.apply_transparent_ledger_commit(c)?;
                Ok::<_, SqliteClientError>(())
            })
            .unwrap();
        assert_eq!(reasons(&st, txid), Some(RECEIVE));
        assert!(!listing(&st).contains(&txid));
        scan_new_blocks(&mut st, 1);
        assert!(listing(&st).contains(&txid));
    }
}
