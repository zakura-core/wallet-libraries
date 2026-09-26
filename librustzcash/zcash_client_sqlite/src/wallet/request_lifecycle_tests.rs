//! Regression tests for independent status and payload obligations. Exercise
//! public writes, not just queue SQL helpers.
use rusqlite::params;
use zcash_client_backend::data_api::{
    TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
    enhance_pir::EnhancePirRead,
    testing::{TestBuilder, TestState},
    wallet::decrypt_and_store_transaction,
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Authorized, TransactionData, TxId, TxVersion},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    local_consensus::LocalNetwork,
};

use crate::{
    error::SqliteClientError,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
};

type State = TestState<BlockCache, TestDb, LocalNetwork>;

fn fixture() -> (State, BlockHeight) {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let (height, _) = st.generate_empty_block();
    st.scan_cached_blocks(height, 1);
    (st, height)
}

fn queue_both(st: &State, txid: TxId, height: BlockHeight, raw: Option<&[u8]>) {
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO transactions (txid, expiry_height, min_observed_height, raw)
         VALUES (?1, 0, ?2, ?3)",
            params![txid.as_ref(), u32::from(height), raw],
        )
        .unwrap();
    for query_type in [0, 1] {
        st.wallet()
            .conn()
            .execute(
                "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (?1, ?2)",
                params![txid.as_ref(), query_type],
            )
            .unwrap();
    }
}

fn queued(st: &State, txid: TxId, query_type: i64) -> bool {
    st.wallet()
        .conn()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tx_retrieval_queue WHERE txid = ?1 AND query_type = ?2)",
            params![txid.as_ref(), query_type],
            |row| row.get(0),
        )
        .unwrap()
}

/// Whether `txid` has payload work routed to public transport.
fn payload_pending(st: &State, txid: TxId) -> bool {
    st.wallet()
        .transaction_enhancement_work()
        .unwrap()
        .contains(&crate::testing::public_work(txid))
}

#[test]
fn typed_requests_follow_independent_status_and_payload_lifecycles() {
    let (mut st, height) = fixture();
    let txid = TxId::from_bytes([71; 32]);
    queue_both(&st, txid, height, None);

    assert!(
        st.wallet()
            .transaction_data_requests()
            .unwrap()
            .contains(&TransactionDataRequest::GetStatus(txid))
    );
    assert!(payload_pending(&st, txid));
    assert!(
        st.wallet()
            .transaction_status_requests()
            .unwrap()
            .iter()
            .any(|request| request.txid() == txid)
    );
    assert!(payload_pending(&st, txid));

    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::Mined(height))
        .unwrap();
    assert!(
        !st.wallet()
            .transaction_status_requests()
            .unwrap()
            .iter()
            .any(|request| request.txid() == txid)
    );
    assert!(payload_pending(&st, txid));

    st.wallet_mut()
        .notify_transaction_enhancement_not_found(txid)
        .unwrap();
    assert!(!payload_pending(&st, txid));
}

#[test]
fn every_status_preserves_payload_work_even_with_stored_bytes() {
    let (mut st, height) = fixture();
    for (i, status) in [
        TransactionStatus::TxidNotRecognized,
        TransactionStatus::NotInMainChain,
        TransactionStatus::Mined(height),
    ]
    .into_iter()
    .enumerate()
    {
        for (j, raw) in [None, Some(&[42][..])].into_iter().enumerate() {
            let txid = TxId::from_bytes([(i * 2 + j) as u8; 32]);
            queue_both(&st, txid, height, raw);
            st.wallet_mut()
                .set_transaction_status(txid, status)
                .unwrap();
            st.wallet_mut()
                .set_transaction_status(txid, status)
                .unwrap();
            assert!(queued(&st, txid, 1));
            assert!(queued(&st, txid, 0));
            let stored: Option<Vec<u8>> = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT raw FROM transactions WHERE txid = ?1",
                    [txid.as_ref()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stored.as_deref(), raw);
        }
    }
}

#[test]
fn terminal_status_only_retires_status_work() {
    let (mut st, height) = fixture();
    let txid = TxId::from_bytes([9; 32]);
    queue_both(&st, txid, height, None);
    st.wallet()
        .conn()
        .execute(
            "UPDATE transactions SET expiry_height = ?1 WHERE txid = ?2",
            params![u32::from(height), txid.as_ref()],
        )
        .unwrap();
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)
        .unwrap();
    assert!(!queued(&st, txid, 0));
    assert!(queued(&st, txid, 1));
    st.wallet_mut()
        .notify_transaction_enhancement_not_found(txid)
        .unwrap();
    assert!(!queued(&st, txid, 1));
}

#[test]
fn explicit_payload_not_found_is_independent_idempotent_and_allows_rediscovery() {
    let (mut st, height) = fixture();
    let txid = TxId::from_bytes([10; 32]);
    queue_both(&st, txid, height, None);
    for _ in 0..2 {
        st.wallet_mut()
            .notify_transaction_enhancement_not_found(txid)
            .unwrap();
        assert!(!queued(&st, txid, 1));
        assert!(queued(&st, txid, 0));
        let status: (Option<u32>, Option<u32>) = st.wallet().conn().query_row(
            "SELECT mined_height, confirmed_unmined_at_height FROM transactions WHERE txid = ?1",
            [txid.as_ref()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(status, (None, None));
    }
    let tx = st.wallet().conn().unchecked_transaction().unwrap();
    super::queue_tx_retrieval(&tx, std::iter::once(txid), None).unwrap();
    tx.commit().unwrap();
    assert!(queued(&st, txid, 1));
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::NotInMainChain)
        .unwrap();
    assert!(
        queued(&st, txid, 1),
        "a late status response cannot erase rediscovery"
    );
    // Parent lookup requests need not have a transaction row yet.
    let unknown = TxId::from_bytes([11; 32]);
    let tx = st.wallet().conn().unchecked_transaction().unwrap();
    super::queue_tx_retrieval(&tx, std::iter::once(unknown), None).unwrap();
    tx.commit().unwrap();
    st.wallet_mut()
        .notify_transaction_enhancement_not_found(unknown)
        .unwrap();
    assert!(!queued(&st, unknown, 1));
}

#[test]
fn explicit_payload_not_found_preserves_pir_routes_in_every_feature_build() {
    let (mut st, height) = fixture();
    for route in [0i64, 1] {
        let txid = TxId::from_bytes([20 + route as u8; 32]);
        queue_both(&st, txid, height, None);
        st.wallet()
            .conn()
            .execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route)
             SELECT id_tx, ?2 FROM transactions WHERE txid = ?1",
                params![txid.as_ref(), route],
            )
            .unwrap();
        st.wallet_mut()
            .notify_transaction_enhancement_not_found(txid)
            .unwrap();
        assert!(queued(&st, txid, 1));
        assert!(queued(&st, txid, 0));
    }
}

#[test]
fn failed_transaction_rolls_back_payload_completion_and_status() {
    let (mut st, height) = fixture();
    let txid = TxId::from_bytes([30; 32]);
    queue_both(&st, txid, height, None);
    let result: Result<(), SqliteClientError> = st.wallet_mut().db_mut().transactionally(|db| {
        db.notify_transaction_enhancement_not_found(txid)?;
        db.set_transaction_status(txid, TransactionStatus::NotInMainChain)?;
        Err(SqliteClientError::CorruptedData("test rollback".into()))
    });
    assert!(result.is_err());
    assert!(queued(&st, txid, 1));
    assert!(queued(&st, txid, 0));
    let observed: Option<u32> = st
        .wallet()
        .conn()
        .query_row(
            "SELECT confirmed_unmined_at_height FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(observed, None);
}

#[test]
fn successful_payload_ingestion_preserves_status_in_both_response_orders() {
    for status_first in [false, true] {
        let (mut st, height) = fixture();
        let transaction = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            height,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let txid = transaction.txid();
        queue_both(&st, txid, height, None);
        let params = *st.network();
        if status_first {
            st.wallet_mut()
                .set_transaction_status(txid, TransactionStatus::NotInMainChain)
                .unwrap();
            assert!(queued(&st, txid, 1));
        }
        // An irrelevant but valid payload completes enhancement too.
        decrypt_and_store_transaction(&params, st.wallet_mut(), &transaction, None).unwrap();
        if !status_first {
            st.wallet_mut()
                .set_transaction_status(txid, TransactionStatus::NotInMainChain)
                .unwrap();
        }
        assert!(!queued(&st, txid, 1));
        assert!(queued(&st, txid, 0));
    }
}

#[test]
fn rewind_reactivates_mined_status_without_completing_enhancement() {
    let (mut st, prior_height) = fixture();
    let (mined_height, _) = st.generate_empty_block();
    st.scan_cached_blocks(mined_height, 1);
    let txid = TxId::from_bytes([40; 32]);
    queue_both(&st, txid, prior_height, None);
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::Mined(mined_height))
        .unwrap();
    assert!(queued(&st, txid, 0));
    assert!(
        !st.wallet()
            .transaction_data_requests()
            .unwrap()
            .contains(&TransactionDataRequest::GetStatus(txid))
    );
    st.wallet_mut()
        .db_mut()
        .truncate_to_height(prior_height)
        .unwrap();
    assert!(
        st.wallet()
            .transaction_data_requests()
            .unwrap()
            .contains(&TransactionDataRequest::GetStatus(txid))
    );
    assert!(payload_pending(&st, txid));
}

/// The routed payload snapshot never carries status work, and status responses and rewinds
/// never change payload routing.
#[cfg(feature = "orchard")]
#[test]
fn routed_enhancement_work_is_independent_of_status_lifecycle() {
    use zcash_client_backend::data_api::enhance_pir::{
        EnhancementMode, TransactionEnhancementWork,
    };

    let (mut st, prior_height) = fixture();
    let (mined_height, _) = st.generate_empty_block();
    st.scan_cached_blocks(mined_height, 1);
    let ordinary = TxId::from_bytes([50; 32]);
    let protected = TxId::from_bytes([51; 32]);
    queue_both(&st, ordinary, prior_height, None);
    queue_both(&st, protected, prior_height, None);
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route)
             SELECT id_tx, 0 FROM transactions WHERE txid = ?1",
            params![protected.as_ref()],
        )
        .unwrap();
    st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);

    let public = |st: &State| {
        let mut txids = st
            .wallet()
            .db()
            .transaction_enhancement_work()
            .unwrap()
            .into_iter()
            .map(|work| match work {
                TransactionEnhancementWork::Public(request) => request.txid(),
                TransactionEnhancementWork::Private(work) => {
                    panic!("no private work was queued: {work:?}")
                }
            })
            .collect::<Vec<_>>();
        txids.sort();
        txids
    };
    let statuses = |st: &State| {
        st.wallet()
            .transaction_status_requests()
            .unwrap()
            .into_iter()
            .map(|request| request.txid())
            .filter(|txid| [ordinary, protected].contains(txid))
            .count()
    };
    assert_eq!(public(&st), vec![ordinary]);
    assert_eq!(
        statuses(&st),
        2,
        "status routing ignores private protection"
    );

    for txid in [ordinary, protected] {
        st.wallet_mut()
            .set_transaction_status(txid, TransactionStatus::Mined(mined_height))
            .unwrap();
    }
    assert_eq!(statuses(&st), 0);
    assert_eq!(public(&st), vec![ordinary]);

    st.wallet_mut()
        .db_mut()
        .truncate_to_height(prior_height)
        .unwrap();
    assert_eq!(statuses(&st), 2);
    assert_eq!(public(&st), vec![ordinary]);

    st.wallet_mut()
        .notify_transaction_enhancement_not_found(ordinary)
        .unwrap();
    assert!(public(&st).is_empty());
    assert_eq!(statuses(&st), 2);
}
