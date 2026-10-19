//! Storage transitions use real migrated wallets; scanner/network integration stays in their suites.
use super::*;
use crate::wallet::one_time_ivk::{
    self, Discovery,
    tests::{State, scanned_wallet},
};
use zcash_client_backend::data_api::{Account, WalletRead};

/// An enabled wallet with both minimum windows fully derived and an anchored test history.
fn ready() -> (State, AccountUuid, FilterWork<AccountUuid>) {
    let mut st = scanned_wallet();
    let account = st.test_account().unwrap().id();
    let db = st.wallet_mut().db_mut();
    db.set_one_time_recovery_enabled(account, true).unwrap();
    assert!(db.prepare_one_time_recovery(account, 200, 1).unwrap());
    assert!(
        db.accept_one_time_history(
            account,
            History {
                genesis: [1; 32],
                archive: [2; 32],
                epoch: 0
            }
        )
        .unwrap()
    );
    let work = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    assert_eq!(work.receivers.len(), 200);
    (st, account, work)
}

/// One complete filter at the captured cursor, optionally matching the first receiver.
fn judgment(work: &FilterWork<AccountUuid>, hit: bool) -> FilterJudgment {
    FilterJudgment {
        block: ChainPoint {
            height: work.next_height,
            hash: BlockHash([3; 32]),
        },
        hits: if hit {
            vec![work.receivers[0].key]
        } else {
            vec![]
        },
    }
}

/// Derivation does not reserve an address, and malformed ranges commit neither progress nor matches.
#[test]
fn block_recovery_derivation_and_atomic_filter_acceptance() {
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    let count: u64 = db
        .conn
        .query_row("SELECT COUNT(*) FROM ironwood_one_time_keys", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    let first = judgment(&work, true);
    assert!(
        db.record_one_time_filters(account, &work, &[first.clone(), first.clone()])
            .is_err()
    );
    assert!(
        db.one_time_pending_matches(account, 100)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.one_time_filter_work(account, 1024).unwrap().unwrap(),
        work
    );
    assert!(
        db.record_one_time_filters(account, &work, &[first])
            .unwrap()
    );
    let pending = db.one_time_pending_matches(account, 100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].receiver, work.receivers[0]);
    assert_eq!(
        db.one_time_filter_work(account, 1024)
            .unwrap()
            .unwrap()
            .next_height,
        work.next_height + 1
    );
    assert!(
        !db.record_one_time_filters(account, &work, &[judgment(&work, true)])
            .unwrap()
    );
}

/// Disabling preserves work but rejects old callbacks, and re-enabling cannot revive their generation.
#[test]
fn block_recovery_toggle_fences_without_erasing_obligations() {
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    assert!(
        db.record_one_time_filters(account, &work, &[judgment(&work, true)])
            .unwrap()
    );
    let next = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    db.set_one_time_recovery_enabled(account, false).unwrap();
    assert!(db.one_time_filter_work(account, 1024).unwrap().is_none());
    assert!(
        db.one_time_pending_matches(account, 1024)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.one_time_recovery_state(account)
            .unwrap()
            .unwrap()
            .pending_matches,
        1
    );
    assert!(
        !db.record_one_time_filters(account, &next, &[judgment(&next, false)])
            .unwrap()
    );
    db.set_one_time_recovery_enabled(account, true).unwrap();
    db.prepare_one_time_recovery(account, 200, 1).unwrap();
    assert!(
        !db.record_one_time_filters(account, &next, &[judgment(&next, false)])
            .unwrap()
    );
    let resumed = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    assert_eq!(resumed.next_height, next.next_height);
    assert_eq!(db.one_time_pending_matches(account, 1024).unwrap().len(), 1);
}

/// Corrections replay negatives and invalidate callbacks; neither epoch nor retired identity can roll back.
#[test]
fn block_recovery_history_reset_and_rollback() {
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    assert!(
        db.record_one_time_filters(account, &work, &[judgment(&work, false)])
            .unwrap()
    );
    let next = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    let newer = History {
        epoch: 1,
        ..work.fence.history
    };
    assert!(db.accept_one_time_history(account, newer).unwrap());
    assert!(
        !db.record_one_time_filters(account, &next, &[judgment(&next, false)])
            .unwrap()
    );
    assert_eq!(
        db.one_time_filter_work(account, 1024)
            .unwrap()
            .unwrap()
            .next_height,
        work.next_height
    );
    assert!(
        !db.accept_one_time_history(account, work.fence.history)
            .unwrap()
    );
    assert!(
        db.accept_one_time_history(
            account,
            History {
                archive: [4; 32],
                ..newer
            }
        )
        .unwrap()
    );
    assert!(!db.accept_one_time_history(account, newer).unwrap());
}

/// Actual per-key/block scan evidence settles only that block, and is reusable after opening the DB again.
#[test]
fn block_recovery_exact_scan_keeps_older_match_and_survives_restart() {
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    let key = work.receivers[0].key;
    db.transactionally(|db| {
        one_time_ivk::register(
            db.conn.0,
            &db.params,
            account,
            key,
            work.next_height,
            false,
            Discovery::Funding,
            1,
        )
    })
    .unwrap();
    let first = judgment(&work, true);
    let second = FilterJudgment {
        block: ChainPoint {
            height: work.next_height + 1,
            hash: BlockHash([4; 32]),
        },
        hits: vec![key],
    };
    assert!(
        db.record_one_time_filters(account, &work, &[first.clone(), second.clone()])
            .unwrap()
    );
    db.transactionally(|db| {
        scanned(
            db.conn.0,
            &[(account, key)],
            &[(second.block.height, second.block.hash)],
        )
    })
    .unwrap();
    let matches = db.one_time_pending_matches(account, 10).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].block, first.block);
    // Use a second physical connection, so this cannot accidentally rely on handle-local state.
    let path = db.conn.path().unwrap().to_owned();
    let conn = Connection::open(path).unwrap();
    let owner = account_key(&conn, &db.params, account).unwrap().0.0;
    let n:u64=conn.query_row("SELECT COUNT(*) FROM ironwood_key_scans s JOIN ironwood_one_time_keys k ON k.id=s.one_time_key_id WHERE k.account_id=?1",[owner],|r|r.get(0)).unwrap();
    assert_eq!(n, 1);
    assert_eq!(pending(&conn, &db.params, account, 10).unwrap(), matches);
    db.accept_one_time_history(
        account,
        History {
            epoch: 1,
            ..work.fence.history
        },
    )
    .unwrap();
    let replay = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    assert!(
        db.record_one_time_filters(account, &replay, &[first, second])
            .unwrap()
    );
    assert_eq!(db.one_time_pending_matches(account, 10).unwrap().len(), 1);
}

/// New sparse keys owe old history, do not widen the derived window without supported evidence,
/// and stale work from before they joined cannot claim coverage for them.
#[test]
fn block_recovery_late_sparse_key_and_rewind() {
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    assert!(
        db.record_one_time_filters(account, &work, &[judgment(&work, false)])
            .unwrap()
    );
    let before = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    let key = KeyId::new(Purpose::Refund, u64::MAX);
    db.transactionally(|db| {
        one_time_ivk::register(
            db.conn.0,
            &db.params,
            account,
            key,
            work.next_height,
            false,
            Discovery::Funding,
            1,
        )
    })
    .unwrap();
    assert!(
        !db.record_one_time_filters(account, &before, &[judgment(&before, false)])
            .unwrap()
    );
    let late = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    assert_eq!(late.receivers.len(), 1);
    assert_eq!(late.receivers[0].key, key);
    assert_eq!(late.next_height, work.next_height);
    assert!(
        db.one_time_recovery_state(account)
            .unwrap()
            .unwrap()
            .windows
            .iter()
            .all(|w| w.end == 100)
    );
    db.transactionally(|db| {
        crate::wallet::one_time_rewind::truncate(db.conn.0, work.next_height - 1)
    })
    .unwrap();
    assert!(
        !db.record_one_time_filters(account, &late, &[judgment(&late, false)])
            .unwrap()
    );
    assert_eq!(
        db.one_time_filter_work(account, 1024)
            .unwrap()
            .unwrap()
            .next_height,
        work.next_height
    );
}

/// Stored keys and old operations alone never create local watches. A locally recorded bound
/// survives toggles, and an empty successful operation stays watched until that original limit.
#[test]
fn block_recovery_local_watch_provenance_and_hard_limit() {
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    let key = work.receivers[0].key;
    let (id, _) = db
        .transactionally(|db| {
            one_time_ivk::register(
                db.conn.0,
                &db.params,
                account,
                key,
                work.next_height,
                false,
                Discovery::Funding,
                1,
            )
        })
        .unwrap();
    db.conn.execute("INSERT INTO ironwood_one_time_operations(one_time_key_id,reference,deadline,begun_at,expectation) VALUES (?1,'old',100,1,1)",[id]).unwrap();
    let range = work.next_height..work.next_height + 1;
    assert!(
        db.one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .is_empty()
    );
    db.conn.execute("INSERT INTO ironwood_one_time_operations(one_time_key_id,reference,deadline,begun_at,expectation,local_watch_deadline,local_watch_accepted) VALUES (?1,'local',100,1,1,100,1)",[id]).unwrap();
    assert_eq!(
        db.one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    db.transactionally(|db| {
        scanned(
            db.conn.0,
            &[(account, key)],
            &[(work.next_height, BlockHash([3; 32]))],
        )?;
        close_local_watches(db.conn.0, (work.next_height, BlockHash([3; 32])))
    })
    .unwrap();
    assert_eq!(
        db.one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    db.set_one_time_recovery_enabled(account, false).unwrap();
    assert!(
        db.one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .is_empty()
    );
    db.set_one_time_recovery_enabled(account, true).unwrap();
    assert_eq!(
        db.one_time_local_watch_keys(range.clone(), 86499)
            .unwrap()
            .len(),
        1
    );
    assert!(
        db.one_time_local_watch_keys(range, 86500)
            .unwrap()
            .is_empty()
    );
    assert!(db.conn.execute("UPDATE ironwood_one_time_operations SET local_watch_deadline=200 WHERE reference='local'",[]).is_err());
}

/// Same-seed accounts own independent windows and cursors, and work cannot cross their boundary.
#[test]
fn block_recovery_accounts_are_isolated() {
    use secrecy::{ExposeSecret, SecretVec};
    use zcash_client_backend::data_api::WalletWrite;
    let (mut st, account, first) = ready();
    let seed = SecretVec::new(st.test_seed().unwrap().expose_secret().clone());
    let birthday = st.test_account().unwrap().birthday().clone();
    let db = st.wallet_mut().db_mut();
    let (other, _) = db.create_account("other", &seed, &birthday, None).unwrap();
    db.set_one_time_recovery_enabled(other, true).unwrap();
    db.prepare_one_time_recovery(other, 200, 1).unwrap();
    db.accept_one_time_history(other, first.fence.history)
        .unwrap();
    let second = db.one_time_filter_work(other, 1024).unwrap().unwrap();
    db.prepare_one_time_recovery(account, 200, 1).unwrap();
    let first = db.one_time_filter_work(account, 1024).unwrap().unwrap();
    assert_eq!(first.receivers[0].key, second.receivers[0].key);
    assert_ne!(first.receivers[0].receiver, second.receivers[0].receiver);
    assert!(
        !db.record_one_time_filters(other, &first, &[judgment(&first, true)])
            .unwrap()
    );
    assert!(
        db.record_one_time_filters(account, &first, &[judgment(&first, true)])
            .unwrap()
    );
    db.set_one_time_recovery_enabled(account, false).unwrap();
    assert!(
        db.record_one_time_filters(other, &second, &[judgment(&second, false)])
            .unwrap()
    );
    assert_eq!(
        db.one_time_recovery_state(account)
            .unwrap()
            .unwrap()
            .pending_matches,
        1
    );
    assert_eq!(
        db.one_time_recovery_state(other)
            .unwrap()
            .unwrap()
            .pending_matches,
        0
    );
}

/// Real scanned receipts keep a watch through partial payment and confirmation, then a reorg
/// reopens it without changing its deadline. Corrected status can also reopen it within that bound.
#[test]
fn block_recovery_watch_receipts_confirmations_and_repair() {
    use crate::wallet::one_time_ivk::tests::{p2pkh, pay};
    use zakura_one_time_ivk::swap::{Observation, OperationStatus, ReceiptExpectation};
    use zcash_protocol::value::Zatoshis;
    let (mut st, account, work) = ready();
    let key = work.receivers[0].key;
    let from = st.wallet().chain_height().unwrap().unwrap() + 1;
    let db = st.wallet_mut().db_mut();
    let (_, registered) = db
        .transactionally(|db| {
            one_time_ivk::register(
                db.conn.0,
                &db.params,
                account,
                key,
                from,
                true,
                Discovery::Scan,
                1,
            )
        })
        .unwrap();
    let deposit = p2pkh(5).encode(&db.params);
    db.record_refund_operation(account, key.index(), &deposit, 100, 1)
        .unwrap();
    let status = Observation {
        status: OperationStatus::Terminal(ReceiptExpectation::Positive(Some(
            Zatoshis::const_from_u64(15000),
        ))),
        funded: true,
    };
    db.record_operation_status(account, &deposit, None, status, 2)
        .unwrap();
    let first = pay(&mut st, registered.full_viewing_key(), 10000);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(9);
    let range = first..first + 100;
    assert_eq!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    let second = pay(&mut st, registered.full_viewing_key(), 5000);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(8);
    assert_eq!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    // A receipt learned outside compact scanning cannot certify its sibling outputs.
    let db = st.wallet_mut().db_mut();
    let receipt_hash: [u8; 32] = db
        .conn
        .query_row(
            "SELECT hash FROM ironwood_key_scans WHERE height=?1",
            [u32::from(second)],
            |r| r.get(0),
        )
        .unwrap();
    db.conn
        .execute(
            "DELETE FROM ironwood_key_scans WHERE height=?1",
            [u32::from(second)],
        )
        .unwrap();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    assert_eq!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    st.wallet_mut()
        .db_mut()
        .transactionally(|db| {
            scanned(
                db.conn.0,
                &[(account, key)],
                &[(second, BlockHash(receipt_hash))],
            )
        })
        .unwrap();
    st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
    assert!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .is_empty()
    );
    let db = st.wallet_mut().db_mut();
    let corrected = Observation {
        status: OperationStatus::Terminal(ReceiptExpectation::Positive(Some(
            Zatoshis::const_from_u64(16000),
        ))),
        funded: true,
    };
    db.record_operation_status(account, &deposit, None, corrected, 3)
        .unwrap();
    assert_eq!(
        db.one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    assert!(
        db.one_time_local_watch_keys(range.clone(), 86500)
            .unwrap()
            .is_empty()
    );
    pay(&mut st, registered.full_viewing_key(), 1000);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(9);
    assert!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .is_empty()
    );
    st.truncate_to_height_retaining_cache(second - 1);
    assert_eq!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    assert!(
        st.wallet()
            .db()
            .one_time_local_watch_keys(range, 86500)
            .unwrap()
            .is_empty()
    );
}

/// Provider and pre-birthday promotions both invalidate a previously completed derived window.
#[test]
fn block_recovery_every_allocation_promotion_widens_history() {
    for provider in [true, false] {
        let (mut st, account, work) = ready();
        let db = st.wallet_mut().db_mut();
        let key = KeyId::new(Purpose::Refund, 99);
        let (id, _) = db
            .transactionally(|db| {
                one_time_ivk::register(
                    db.conn.0,
                    &db.params,
                    account,
                    key,
                    work.next_height,
                    false,
                    Discovery::Funding,
                    1,
                )
            })
            .unwrap();
        assert!(
            !db.one_time_recovery_state(account)
                .unwrap()
                .unwrap()
                .needs_prepare
        );
        if provider {
            one_time_ivk::swap::reservations::record_provider_seen(&db.conn, id).unwrap();
        } else {
            db.conn.execute("UPDATE ironwood_one_time_keys SET paid_before_birthday=1,advances_allocation=1 WHERE id=?1",[id]).unwrap();
        }
        assert!(
            db.one_time_recovery_state(account)
                .unwrap()
                .unwrap()
                .needs_prepare
        );
        assert!(db.one_time_filter_work(account, 1024).unwrap().is_none());
        db.prepare_one_time_recovery(account, 200, 1).unwrap();
        assert_eq!(
            db.one_time_recovery_state(account)
                .unwrap()
                .unwrap()
                .windows[0]
                .end,
            130
        );
    }
}

/// A corrected unknown receipt amount invalidates an earlier multi-operation settlement.
#[test]
fn block_recovery_ambiguous_amount_reopens_settlement() {
    use zakura_one_time_ivk::swap::{Observation, OperationStatus, ReceiptExpectation};
    let (mut st, account, work) = ready();
    let db = st.wallet_mut().db_mut();
    let (id, _) = db
        .transactionally(|db| {
            one_time_ivk::register(
                db.conn.0,
                &db.params,
                account,
                work.receivers[0].key,
                work.next_height,
                false,
                Discovery::Funding,
                1,
            )
        })
        .unwrap();
    db.conn.execute("INSERT INTO ironwood_one_time_operations(one_time_key_id,reference,deadline,begun_at,expectation,expected_value,local_watch_deadline,local_watch_accepted) VALUES (?1,'first',100,1,2,100,100,1),(?1,'second',100,1,2,100,100,1)",[id]).unwrap();
    db.conn.execute("UPDATE ironwood_one_time_keys SET watch_closed_height=?2,watch_closed_hash=zeroblob(32) WHERE id=?1",params![id,u32::from(work.next_height)]).unwrap();
    let operation: i64 = db
        .conn
        .query_row(
            "SELECT id FROM ironwood_one_time_operations WHERE reference='first'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    one_time_ivk::swap::lifecycle::record(
        &db.conn,
        operation,
        Observation {
            status: OperationStatus::Terminal(ReceiptExpectation::Positive(None)),
            funded: true,
        },
        2,
    )
    .unwrap();
    let range = work.next_height..work.next_height + 1;
    assert_eq!(
        db.one_time_local_watch_keys(range.clone(), 50)
            .unwrap()
            .len(),
        1
    );
    assert!(
        db.one_time_local_watch_keys(range, 86500)
            .unwrap()
            .is_empty()
    );
}
