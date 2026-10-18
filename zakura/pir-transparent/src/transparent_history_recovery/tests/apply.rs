use super::*;
use crate::apply::Ungated;
use crate::apply::{ApplyError, Trust};
use crate::batch::unready_batch;
use zcash_client_backend::data_api::testing::{TestBuilder, TestState};
use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;
use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerWrite as _;
use zcash_client_sqlite::{
    AccountUuid,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory},
    },
};
use zcash_protocol::local_consensus::LocalNetwork;

fn wallet() -> TestState<BlockCache, TestDb, LocalNetwork> {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .build();
    let db = st.wallet_mut().db_mut();
    db.apply_transparent_policy(TransparentLedgerMode::PrivateRequired)
        .unwrap();
    db.set_transparent_ledger_mode(TransparentLedgerMode::PrivateRequired);
    st
}

fn retired() -> RecoveryRevision {
    RecoveryRevision {
        source: vec![1; 32],
        revision: vec![2; 32],
        lineage: 1,
        sealed: false,
        publication: zakura_transparent_recovery_types::PublicationAnchor {
            height: block_height(1).unwrap(),
            hash: BlockHash([3; 32]),
        },
    }
}

#[test]
fn an_empty_ready_batch_is_acknowledged_and_spends_its_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
    let mut st = wallet();
    let batch = adapter
        .issue_ready_batch::<AccountUuid>(vec![], vec![], MORE)
        .unwrap();
    let applied = adapter
        .apply_and_acknowledge_gated(
            batch,
            st.wallet_mut().db_mut(),
            Trust::Observed,
            &mut Ungated,
        )
        .unwrap();
    assert_eq!(applied.stats, Default::default());
    assert_eq!(applied.progress, MORE);
    assert_eq!(applied.retired, 0);
    assert_eq!(adapter.outstanding_receipt, None);
}

#[test]
fn unready_and_stale_batches_apply_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
    let mut st = wallet();
    for state in [
        BatchState::Pending,
        BatchState::Withdrawn(WithdrawnCause::Equivocation),
    ] {
        let failure = adapter
            .apply_and_acknowledge_gated(
                unready_batch::<AccountUuid>(state, MORE),
                st.wallet_mut().db_mut(),
                Trust::Trusted,
                &mut Ungated,
            )
            .unwrap_err();
        assert!(matches!(failure.error, ApplyError::NotReady(s) if s == state));
        assert_eq!(failure.stats, Default::default());
    }
    // A batch superseded by a later, different pass is a stale receipt; the later
    // one stays acknowledgeable.
    let earlier = adapter
        .issue_ready_batch::<AccountUuid>(vec![], vec![], MORE)
        .unwrap();
    let later = adapter
        .issue_ready_batch::<AccountUuid>(vec![], vec![retired()], MORE)
        .unwrap();
    let failure = adapter
        .apply_and_acknowledge_gated(
            earlier,
            st.wallet_mut().db_mut(),
            Trust::Trusted,
            &mut Ungated,
        )
        .unwrap_err();
    assert!(matches!(failure.error, ApplyError::StaleReceipt));
    assert!(adapter.is_outstanding_receipt(&later));
}

#[test]
fn a_surrounding_transaction_is_refused_before_anything_applies() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
    let mut st = wallet();
    let batch = adapter
        .issue_ready_batch::<AccountUuid>(vec![], vec![retired()], MORE)
        .unwrap();
    st.wallet().conn().execute_batch("BEGIN").unwrap();
    let failure = adapter
        .apply_and_acknowledge_gated(
            batch,
            st.wallet_mut().db_mut(),
            Trust::Trusted,
            &mut Ungated,
        )
        .unwrap_err();
    assert!(matches!(failure.error, ApplyError::OuterTransaction));
    st.wallet().conn().execute_batch("ROLLBACK").unwrap();
    // Nothing was acknowledged: the receipt stands, though the batch is gone.
    assert!(adapter.outstanding_receipt.is_some());
}

#[test]
fn observed_trust_refuses_retirements_before_applying() {
    let dir = tempfile::tempdir().unwrap();
    let mut adapter =
        TransparentHistoryRecovery::open(dir.path().join("c.sqlite"), config()).unwrap();
    let mut st = wallet();
    let batch = adapter
        .issue_ready_batch::<AccountUuid>(vec![], vec![retired()], MORE)
        .unwrap();
    let failure = adapter
        .apply_and_acknowledge_gated(
            batch,
            st.wallet_mut().db_mut(),
            Trust::Observed,
            &mut Ungated,
        )
        .unwrap_err();
    assert!(matches!(failure.error, ApplyError::Unreconciled));
    assert!(adapter.outstanding_receipt.is_some());
    // This synthetic batch exercises the refusal only. A real Ready
    // retirement has a successor commit, so successful trusted
    // reconciliation belongs to the in-process service integration
    // tests in private_recovery.rs, including stale-prefix replay.
}
