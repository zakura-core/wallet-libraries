//! Finalized input authorization uses full stored bytes and preserves competing-spend checks.
use super::*;
use crate::error::{AuthorityRefusal, RefusalReason, SqliteClientError};
use zcash_client_backend::data_api::{
    InputSource as _,
    wallet::{TargetHeight, decrypt_and_store_transaction},
};
use zcash_primitives::transaction::{Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId};

fn transaction(inputs: Vec<OutPoint>, lock_time: u32) -> Transaction {
    use transparent::{
        address::Script,
        bundle::{Authorized, Bundle, TxIn},
    };
    TransactionData::<zcash_primitives::transaction::Authorized>::from_parts(
        TxVersion::V5,
        BranchId::Nu5,
        lock_time,
        BlockHeight::from_u32(1_000_000),
        Some(Bundle {
            vin: inputs
                .into_iter()
                .map(|p| TxIn::from_parts(p, Script::default(), u32::MAX))
                .collect(),
            vout: vec![TxOut::new(
                Zatoshis::const_from_u64(10_000),
                Script::default(),
            )],
            authorization: Authorized,
        }),
        None,
        None,
        None,
    )
    .freeze()
    .unwrap()
}

fn target(st: &State) -> TargetHeight {
    (st.wallet().chain_height().unwrap().unwrap() + 1).into()
}

#[test]
fn retry_authorization_requires_exact_bytes_and_excludes_only_own_spend() {
    let (mut st, _, outpoint) = funded_wallet();
    let tx = transaction(vec![outpoint.clone()], 0);
    let target = target(&st);
    st.wallet()
        .db()
        .check_transparent_transaction_inputs(&tx, &[], target)
        .unwrap();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None).unwrap();
    assert!(
        st.wallet()
            .db()
            .get_unspent_transparent_output(&outpoint, target)
            .unwrap()
            .is_none()
    );
    st.wallet()
        .db()
        .check_transparent_transaction_inputs(&tx, &[], target)
        .unwrap();
    conn(&st)
        .execute(
            "UPDATE transactions SET raw = X'00' WHERE txid = ?1",
            [tx.txid().as_ref()],
        )
        .unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], target)
            .is_err()
    );
    let mut raw = Vec::new();
    tx.write(&mut raw).unwrap();
    conn(&st)
        .execute(
            "UPDATE transactions SET raw = ?1 WHERE txid = ?2",
            rusqlite::params![raw, tx.txid().as_ref()],
        )
        .unwrap();
    let competitor = transaction(vec![outpoint], 1);
    decrypt_and_store_transaction(&network, st.wallet_mut(), &competitor, None).unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], target)
            .is_err()
    );
    conn(&st)
        .execute(
            "UPDATE transactions SET mined_height = ?1, min_observed_height = ?1 WHERE txid = ?2",
            rusqlite::params![u32::from(target) - 1, competitor.txid().as_ref()],
        )
        .unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], target)
            .is_err()
    );
}

#[test]
fn retry_authorization_preserves_authority_maturity_and_chained_bounds() {
    let (mut st, _, outpoint) = funded_wallet();
    let tx = transaction(vec![outpoint.clone()], 0);
    let target = target(&st);
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None).unwrap();
    conn(&st)
        .execute(
            "UPDATE transactions SET tx_index = 0 WHERE txid = ?1",
            [outpoint.txid().as_ref()],
        )
        .unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], target)
            .is_err()
    );
    conn(&st)
        .execute(
            "UPDATE transactions SET tx_index = 1 WHERE txid = ?1",
            [outpoint.txid().as_ref()],
        )
        .unwrap();
    let unknown = transaction(vec![OutPoint::new([0x99; 32], 0)], 0);
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&unknown, &[], target)
            .is_err()
    );
    let parent = transaction(vec![], 0);
    let child = transaction(vec![OutPoint::new(*parent.txid().as_ref(), 0)], 0);
    st.wallet()
        .db()
        .check_transparent_transaction_inputs(&child, &[&parent], target)
        .unwrap();
    let invalid = transaction(vec![OutPoint::new(*parent.txid().as_ref(), 1)], 0);
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&invalid, &[&parent], target)
            .is_err()
    );
    // A local batch parent does not hide a competing spend recorded before its output.
    let competitor = transaction(
        vec![outpoint.clone(), OutPoint::new(*parent.txid().as_ref(), 0)],
        1,
    );
    decrypt_and_store_transaction(&network, st.wallet_mut(), &competitor, None).unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&child, &[&parent], target)
            .is_err()
    );
    // A matching stored spend cannot bypass a stricter durable policy.
    conn(&st)
        .execute(
            "UPDATE tpir_meta SET applied_mode = 2, policy_generation = 1",
            [],
        )
        .unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], target)
            .is_err()
    );
    conn(&st)
        .execute(
            "UPDATE tpir_meta SET applied_mode = 0, min_reader_version = 999",
            [],
        )
        .unwrap();
    assert!(
        st.wallet()
            .db()
            .check_transparent_transaction_inputs(&tx, &[], target)
            .is_err()
    );
}

#[test]
fn caller_owned_deletion_transaction_rolls_back_without_commit() {
    use crate::{SqlTransaction, WalletDb, util::SystemClock};
    use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;
    let (mut st, _, _) = funded_wallet();
    let account = st.test_account().unwrap().id();
    let network = *st.network();
    {
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        let mut db =
            WalletDb::from_connection(SqlTransaction::new(&tx), network, SystemClock, rand::rng())
                .with_transparent_ledger_mode(TransparentLedgerMode::Public);
        db.delete_account(account).unwrap();
        assert!(db.get_account(account).unwrap().is_none());
        drop(db);
        // Outer owner elects not to commit, including after a consumer cleanup failure.
        tx.rollback().unwrap();
    }
    assert!(st.wallet().get_account(account).unwrap().is_some());
}

/// Checks `outpoint` by direct lookup and as a submitted input at `target`, under public
/// authority: both must exclude it, never fail to read it.
fn excluded_everywhere(st: &State, outpoint: &OutPoint, target: TargetHeight) -> SqliteClientError {
    let db = st.wallet().db();
    assert!(
        db.get_unspent_transparent_output(outpoint, target)
            .unwrap()
            .is_none()
    );
    db.check_transparent_transaction_inputs(&transaction(vec![outpoint.clone()], 0), &[], target)
        .unwrap_err()
}

#[test]
fn a_rewound_public_output_past_its_assumed_expiry_is_excluded() {
    let (st, _, outpoint) = funded_wallet();
    // A rewind leaves the receiving transaction unmined with unknown expiry. Once its assumed
    // expiry passes, the expiry condition is NULL rather than false.
    conn(&st)
        .execute(
            "UPDATE transactions SET mined_height = NULL, expiry_height = NULL, target_height = NULL
             WHERE txid = ?1",
            [outpoint.txid().as_ref()],
        )
        .unwrap();
    let target = TargetHeight::from(BlockHeight::from(target(&st)) + 100);
    assert!(matches!(
        excluded_everywhere(&st, &outpoint, target),
        SqliteClientError::TransparentAuthorityUnavailable(AuthorityRefusal::Refused(
            RefusalReason::Expired
        ))
    ));
}

#[test]
fn a_wallet_internal_ephemeral_output_of_unknown_expiry_is_excluded() {
    let (mut st, taddr, outpoint) = funded_wallet();
    // The output's transaction spends another wallet output to an ephemeral address and has no
    // known expiry, so the likely-spent condition is NULL rather than false.
    let other = OutPoint::new([0x77; 32], 0);
    put_public_utxo(&mut st, &taddr, other.clone(), 50_000);
    conn(&st)
        .execute_batch(&format!(
            "UPDATE transactions SET expiry_height = NULL WHERE txid = X'{funding}';
             UPDATE addresses SET key_scope = 2, diversifier_index_be = X'0000000E00000000000000'
             WHERE id = (
                 SELECT u.address_id FROM transparent_received_outputs u
                 JOIN transactions t ON t.id_tx = u.transaction_id
                 WHERE t.txid = X'{funding}'
             );
             INSERT INTO transparent_received_output_spends (transparent_received_output_id, transaction_id)
             SELECT u.id, (SELECT id_tx FROM transactions WHERE txid = X'{funding}')
             FROM transparent_received_outputs u
             JOIN transactions t ON t.id_tx = u.transaction_id
             WHERE t.txid = X'{spent}';",
            funding = hex::encode(outpoint.txid().as_ref()),
            spent = hex::encode(other.txid().as_ref()),
        ))
        .unwrap();
    assert!(matches!(
        excluded_everywhere(&st, &outpoint, target(&st)),
        SqliteClientError::TransparentAuthorityUnavailable(AuthorityRefusal::Refused(
            RefusalReason::Spent
        ))
    ));
}
