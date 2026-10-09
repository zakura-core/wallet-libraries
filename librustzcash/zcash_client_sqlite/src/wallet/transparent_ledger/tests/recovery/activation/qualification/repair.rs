//! Forward repair and rollback: the projection is rebuilt from durable evidence, and a build
//! that cannot interpret a wallet's ledger state refuses it without changing it.

use zcash_client_backend::data_api::{
    CoinbaseFilter, InputSource as _,
    ll::LowLevelWalletWrite as _,
    status::TransactionStatusWrite as _,
    wallet::{
        TargetHeight,
        input_selection::{LockFilter, LockedInputPolicy},
    },
};

use super::oracle::{assert_authority_agrees, assert_diagnostics_agree, promoted_oracle_wallet};
use super::*;
use crate::wallet::transparent_ledger::{REVISION_READER_VERSION, TPIR_READER_VERSION};

/// The wallet's own tables and the provenance of every output and spend.
fn projection_state(conn: &Connection) -> Vec<(String, Vec<String>)> {
    let mut state = production_dump(conn);
    for (name, query) in [
        (
            "output origins",
            "SELECT output_id, origin FROM tpir_output_origins",
        ),
        (
            "spend origins",
            "SELECT spending_transaction_id, prevout_txid, prevout_output_index, origin
             FROM tpir_spend_origins",
        ),
    ] {
        let mut stmt = conn.prepare(query).unwrap();
        let columns = stmt.column_count();
        let mut rows: Vec<String> = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|i| row.get::<_, Value>(i))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|values| format!("{values:?}"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        state.push((name.to_string(), rows));
    }
    state
}

#[test]
fn a_lost_projection_is_rebuilt_from_durable_evidence() {
    let (mut st, account, chain, owned, _) = promoted_oracle_wallet();
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    assert_authority_agrees(&st, account, &expected);
    let intact = projection_state(conn(&st));

    // The projection's ledger provenance and spends are lost.
    conn(&st)
        .execute_batch(
            "DELETE FROM transparent_received_output_spends
             WHERE transaction_id IN
                 (SELECT spending_transaction_id FROM tpir_spend_origins WHERE origin = 2);
             DELETE FROM tpir_spend_origins WHERE origin = 2;
             DELETE FROM tpir_output_origins WHERE origin = 2;",
        )
        .unwrap();

    // Authority fails closed: nothing without ledger provenance is spendable.
    let s = snapshot(&st, account);
    assert_eq!(
        s.authorized.map(|b| b.regular.spendable_value()),
        Some(Zatoshis::ZERO)
    );
    let addresses: Vec<_> = watch(&st, account)
        .addresses
        .iter()
        .map(|w| w.address)
        .collect();
    let target = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
    assert_eq!(
        st.wallet()
            .db()
            .get_spendable_transparent_outputs_for_addresses(
                &addresses,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .unwrap(),
        vec![]
    );

    // Forward repair: demoting and promoting again rebuilds the projection from the ledger's
    // durable evidence, exactly.
    set_policy(&mut st, Public);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(projection_state(conn(&st)), intact);
    assert_authority_agrees(&st, account, &expected);
}

#[test]
fn a_policy_alone_needs_no_newer_reader_and_nothing_lowers_the_requirement() {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    scan_new_blocks(&mut st, 10);
    // Every reader of the ledger schema honors `PrivateRequired`.
    set_policy(&mut st, PrivateRequired);
    assert_eq!(reader_version(&st), 1);

    // Activation state requires an activation-aware reader, and demotion does not release it:
    // the qualification and the ledger's projection remain.
    set_policy(&mut st, PrivateRequired);
    let account = st.test_account().unwrap().id();
    let fixture = revision(1, true);
    cover(&mut st, account, &fixture, vec![]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    assert_eq!(reader_version(&st), REVISION_READER_VERSION);
    set_policy(&mut st, Public);
    assert_eq!(reader_version(&st), REVISION_READER_VERSION);
}

#[test]
fn a_wallet_requiring_a_newer_reader_is_refused_without_changes() {
    let (mut st, account, chain, owned, fixture) = promoted_oracle_wallet();
    let ws = watch(&st, account);
    let txid = *assert_diagnostics_agree(&st, account, &chain, &owned).receives[0]
        .outpoint
        .txid();
    let spending = conn(&st)
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get::<_, i64>(0).map(crate::TxRef),
        )
        .unwrap();
    let output = zcash_client_backend::wallet::WalletTransparentOutput::from_parts(
        OutPoint::new([0xcc; 32], 0),
        transparent::bundle::TxOut::new(
            Zatoshis::const_from_u64(1_000),
            ws.addresses[0].address.script().into(),
        ),
        Some(ws.target.unwrap().height),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    let newer = TPIR_READER_VERSION + 1;
    conn(&st)
        .execute("UPDATE tpir_meta SET min_reader_version = ?1", [newer])
        .unwrap();
    let before = full_dump(conn(&st));
    let refused = |entry: &str, result: Result<(), SqliteClientError>| {
        assert!(
            matches!(
                result,
                Err(SqliteClientError::TransparentLedgerIncompatible { required })
                    if required == newer
            ),
            "{entry}: {result:?}"
        );
    };

    let db = st.wallet().db();
    refused("mode", db.transparent_ledger_mode().map(|_| ()));
    refused(
        "applied policy",
        db.applied_transparent_policy().map(|_| ()),
    );
    refused(
        "snapshot",
        db.transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
            .map(|_| ()),
    );
    refused("watch set", db.transparent_watch_set(account).map(|_| ()));
    refused(
        "candidate recovery",
        db.transparent_candidate_recovery(account).map(|_| ()),
    );
    refused(
        "history",
        db.transaction_history_details(account, &[txid]).map(|_| ()),
    );
    let target = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
    refused(
        "selector",
        db.get_spendable_transparent_outputs_for_addresses(
            &ws.addresses.iter().map(|w| w.address).collect::<Vec<_>>(),
            target,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
        .map(|_| ()),
    );

    // Nothing weakens the policy or writes ledger state.
    let db = st.wallet_mut().db_mut();
    refused("policy", db.apply_transparent_policy(Public).map(|_| ()));
    let mut c = commit(&ws);
    c.coverage = full_coverage(&ws);
    refused("commit", db.apply_transparent_ledger_commit(c).map(|_| ()));
    refused("promotion", db.promote_transparent_account(account));
    refused("qualification", db.qualify_transparent_revision(&fixture));
    refused("account deletion", db.delete_account(account));
    refused(
        "creation evidence",
        db.record_transaction_created(txid, ws.target.unwrap().height),
    );
    refused(
        "public output",
        db.put_received_transparent_utxo(&output).map(|_| ()),
    );
    refused(
        "low-level output",
        db.transactionally(|db| {
            db.put_transparent_output(&output, ws.target.unwrap().height, true)
        })
        .map(|_| ()),
    );
    refused(
        "low-level spend",
        db.transactionally(|db| db.mark_transparent_utxo_spent(output.outpoint(), spending))
            .map(|_| ()),
    );
    // Nor can this build rewind state it cannot maintain, or re-attribute a receiver's.
    let floor = ws.target.unwrap().height - 3;
    refused("rewind", db.truncate_to_height(floor).map(|_| ()));
    let account_ref = st.test_account().unwrap().account().internal_id();
    refused(
        "re-attribution",
        forget_reattributed_script(conn(&st), account_ref, &ws.addresses[0].address),
    );
    assert_eq!(full_dump(conn(&st)), before);
    assert_eq!(meta_mode(&st), 2);
}

#[test]
fn low_level_provenance_writes_roll_back_with_the_wallet_transaction() {
    let (mut st, account, chain, owned, _) = promoted_oracle_wallet();
    assert_eq!(reader_version(&st), REVISION_READER_VERSION);
    // Exercise the highest supported reader boundary even without shared-origin state.
    conn(&st)
        .execute(
            "UPDATE tpir_meta SET min_reader_version = ?1",
            [TPIR_READER_VERSION],
        )
        .unwrap();
    let expected = assert_diagnostics_agree(&st, account, &chain, &owned);
    let receive = expected.unspent.iter().find(|r| !r.coinbase).unwrap();
    let output = zcash_client_backend::wallet::WalletTransparentOutput::from_parts(
        OutPoint::new([0xcd; 32], 0),
        transparent::bundle::TxOut::new(receive.value, receive.address.script().into()),
        Some(receive.mined_height),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    let spending = conn(&st)
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [receive.outpoint.hash()],
            |row| row.get::<_, i64>(0).map(crate::TxRef),
        )
        .unwrap();
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER fail_output_origin BEFORE INSERT ON tpir_output_origins
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;
         CREATE TEMP TRIGGER fail_spend_link BEFORE INSERT ON transparent_received_output_spends
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let before = full_dump(conn(&st));
    let height = receive.mined_height;
    assert!(
        st.wallet_mut()
            .db_mut()
            .transactionally(|db| db.put_transparent_output(&output, height, true))
            .is_err()
    );
    assert_eq!(full_dump(conn(&st)), before);
    // The origin is written before the injected spend-link failure and must roll back too.
    assert!(
        st.wallet_mut()
            .db_mut()
            .transactionally(|db| db.mark_transparent_utxo_spent(&receive.outpoint, spending))
            .is_err()
    );
    assert_eq!(full_dump(conn(&st)), before);
    conn(&st)
        .execute_batch("DROP TRIGGER fail_output_origin; DROP TRIGGER fail_spend_link")
        .unwrap();
    // A reader exactly at the highest supported version remains usable.
    assert_eq!(reader_version(&st), TPIR_READER_VERSION);
    st.wallet_mut()
        .db_mut()
        .transactionally(|db| db.put_transparent_output(&output, height, true))
        .unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            .transactionally(|db| db.mark_transparent_utxo_spent(output.outpoint(), spending))
            .unwrap()
    );
    st.wallet_mut()
        .db_mut()
        .record_transaction_created(*output.outpoint().txid(), height)
        .unwrap();
    st.wallet_mut().db_mut().delete_account(account).unwrap();
}

fn meta_mode(st: &State) -> i64 {
    conn(st)
        .query_row("SELECT applied_mode FROM tpir_meta", [], |row| row.get(0))
        .unwrap()
}
