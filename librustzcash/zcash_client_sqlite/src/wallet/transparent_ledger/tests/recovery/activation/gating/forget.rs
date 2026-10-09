//! Forgetting removes what the ledger alone contributed, so leaving private recovery cannot
//! keep a bad publication's facts in the wallet.

use transparent::bundle::TxOut;
use zcash_client_backend::{
    data_api::{OutputLockStore as _, transparent_ledger::ForgottenTransparentLedger},
    wallet::{LockOwner, OutputRef, WalletTransparentOutput},
};
use zcash_protocol::PoolType;

use super::*;

fn forget(st: &mut State) -> Result<ForgottenTransparentLedger, SqliteClientError> {
    st.wallet_mut().db_mut().forget_transparent_ledger()
}

fn authorized(st: &State, account: AccountUuid) -> Zatoshis {
    snapshot(st, account).authorized.unwrap().regular.total()
}

fn has_transaction(st: &State, txid: &TxId) -> bool {
    conn(st)
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM transactions WHERE txid = ?1)",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

fn has_output(st: &State, outpoint: &OutPoint) -> bool {
    conn(st)
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM transparent_received_outputs o
                 JOIN transactions t ON t.id_tx = o.transaction_id
                 WHERE t.txid = ?1 AND o.output_index = ?2
             )",
            rusqlite::params![outpoint.hash(), outpoint.n()],
            |row| row.get(0),
        )
        .unwrap()
}

fn queued_for_spend_search(st: &State, outpoint: &OutPoint) -> bool {
    conn(st)
        .query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM transparent_spend_search_queue q
                 JOIN transactions t ON t.id_tx = q.transaction_id
                 WHERE t.txid = ?1 AND q.output_index = ?2
             )",
            rusqlite::params![outpoint.hash(), outpoint.n()],
            |row| row.get(0),
        )
        .unwrap()
}

const RECOVERY_TABLES: [&str; 7] = [
    "tpir_receive_events",
    "tpir_receive_observations",
    "tpir_spend_events",
    "tpir_spend_observations",
    "tpir_coverage",
    "tpir_pending_pages",
    "tpir_transaction_metadata",
];

/// Row counts of every ledger table, which `production_dump` leaves out.
fn ledger_counts(st: &State) -> Vec<(String, i64)> {
    let tables: Vec<String> = conn(st)
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name LIKE 'tpir!_%' ESCAPE '!'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let rows = count(st, &table);
            (table, rows)
        })
        .collect()
}

/// A real output public discovery found, which an active account's publication also reports
/// together with a spend that never happened.
fn falsely_spent_wallet() -> (State, AccountUuid, ReceiveEvent, SpendEvent) {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let real = receive(31, external(&ws), 40_000, below_target(&ws, 4));
    let utxo = WalletTransparentOutput::from_parts(
        real.outpoint.clone(),
        TxOut::new(real.value, real.address.script().into()),
        Some(real.mined_height),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    publicly(&mut st, |st| {
        st.wallet_mut()
            .db_mut()
            .put_received_transparent_utxo(&utxo)
            .unwrap()
    });

    let ws = watch(&st, account);
    let false_spend = spend(32, &real, below_target(&ws, 2));
    let mut c = commit(&ws);
    c.revision = fixture.clone();
    c.receives = vec![real.clone()];
    c.spends = vec![false_spend.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    cover(&mut st, account, &fixture, vec![]);
    qualify(&mut st, &fixture);
    promote(&mut st, account).unwrap();
    assert_eq!(
        super::super::super::super::output_origins(conn(&st), &real.outpoint),
        vec![0, 2]
    );
    assert_eq!(spend_count(&st, &real.outpoint), 1);
    (st, account, real, false_spend)
}

#[test]
fn forgetting_restores_a_real_output_that_a_ledger_spend_hid() {
    let (mut st, account, real, false_spend) = falsely_spent_wallet();
    set_policy(&mut st, Public);
    // Leaving private recovery alone keeps the false spend: the real output stays hidden.
    assert_eq!(authorized(&st, account), Zatoshis::ZERO);
    for selection in selections(
        &st,
        account,
        &[real.address],
        &real.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }

    let forgotten = forget(&mut st).unwrap();
    assert_eq!(
        forgotten,
        ForgottenTransparentLedger {
            spends: 1,
            outputs: 0,
            retained_outputs: 0,
            transactions: 1,
            events: 2,
        }
    );

    // The output keeps its public evidence alone and counts again.
    assert_eq!(
        super::super::super::super::output_origins(conn(&st), &real.outpoint),
        vec![0]
    );
    assert_eq!(spend_count(&st, &real.outpoint), 0);
    assert_eq!(
        super::super::super::super::spend_origins(conn(&st), &real.outpoint),
        Vec::<i64>::new()
    );
    assert!(!has_transaction(&st, &false_spend.spending_txid));
    assert_eq!(authorized(&st, account), real.value);
    for selection in selections(
        &st,
        account,
        &[real.address],
        &real.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![real.outpoint.clone()]);
    }
    // Public discovery looks for its real spend again.
    assert!(queued_for_spend_search(&st, &real.outpoint));
    assert_eq!(
        super::super::super::super::records_without_origin(conn(&st)),
        0
    );
    for table in RECOVERY_TABLES {
        assert_eq!(count(&st, table), 0, "{table}");
    }
}

#[test]
fn forgetting_removes_ledger_only_receives_spends_and_their_transactions() {
    let (mut st, account, unspent, spent) = ready_wallet();
    promote(&mut st, account).unwrap();
    let spender = TxId::from_bytes([3; 32]);
    assert!(has_transaction(&st, &spender));
    let accounts = count(&st, "accounts");
    let addresses = count(&st, "addresses");
    let blocks = count(&st, "blocks");
    set_policy(&mut st, Public);
    // Leaving private recovery alone keeps a ledger-only receive as public value.
    assert_eq!(authorized(&st, account), unspent.value);

    let forgotten = forget(&mut st).unwrap();
    assert_eq!(
        forgotten,
        ForgottenTransparentLedger {
            spends: 1,
            outputs: 2,
            retained_outputs: 0,
            transactions: 3,
            events: 3,
        }
    );
    for received in [&unspent, &spent] {
        assert!(!has_output(&st, &received.outpoint));
        assert!(!has_transaction(&st, received.outpoint.txid()));
    }
    assert!(!has_transaction(&st, &spender));
    assert_eq!(authorized(&st, account), Zatoshis::ZERO);
    for selection in selections(
        &st,
        account,
        &[unspent.address],
        &unspent.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }
    // Detail work for the removed transactions goes with them.
    assert_eq!(count(&st, "transparent_detail_work"), 0);
    assert_eq!(count(&st, "tpir_spend_origins"), 0);
    assert_eq!(count(&st, "tpir_output_origins"), 0);
    // Accounts, addresses, and the scanned chain are not ledger facts.
    assert_eq!(count(&st, "accounts"), accounts);
    assert_eq!(count(&st, "addresses"), addresses);
    assert_eq!(count(&st, "blocks"), blocks);
    assert_eq!(
        super::super::super::super::records_without_origin(conn(&st)),
        0
    );
}

#[test]
fn forgetting_keeps_a_ledger_output_that_a_local_spend_refers_to() {
    let (mut st, account, _, unspent) = eligible_wallet();
    super::coinbase::store_spend(&mut st, account, &unspent).unwrap();
    let local_spend: [u8; 32] = conn(&st)
        .query_row(
            "SELECT txid FROM transactions WHERE created IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    set_policy(&mut st, Public);
    st.wallet().set_transparent_reader_version(4);

    let forgotten = forget(&mut st).unwrap();
    assert_eq!(forgotten.retained_outputs, 1);
    // The local spend keeps its output and its own origin.
    assert!(has_output(&st, &unspent.outpoint));
    assert_eq!(spend_count(&st, &unspent.outpoint), 1);
    assert_eq!(
        super::super::super::super::spend_origins(conn(&st), &unspent.outpoint),
        vec![1]
    );
    assert!(has_transaction(&st, &TxId::from_bytes(local_spend)));
    // Without its receive event the retained row has neither value nor authority, and older
    // readers that would count it are fenced.
    assert_eq!(authorized(&st, account), Zatoshis::ZERO);
    assert!(reader_version(&st) >= crate::wallet::transparent_ledger::ACTIVATION_READER_VERSION);
    assert_eq!(
        super::super::super::super::records_without_origin(conn(&st)),
        0
    );
}

#[test]
fn forgetting_keeps_a_locked_ledger_output_until_it_is_unlocked() {
    let (mut st, account, _, unspent) = eligible_wallet();
    let output = OutputRef::new(
        *unspent.outpoint.txid(),
        PoolType::Transparent,
        unspent.outpoint.n(),
    );
    let owner = LockOwner::new([51; 32]);
    st.wallet_mut()
        .db_mut()
        .lock_outputs(&[output], owner, BlockHeight::from(u32::MAX))
        .unwrap();
    set_policy(&mut st, Public);

    let forgotten = forget(&mut st).unwrap();
    assert_eq!(forgotten.retained_outputs, 1);
    assert!(has_output(&st, &unspent.outpoint));
    assert_eq!(
        st.wallet().db().get_locked_outputs(account).unwrap(),
        vec![output]
    );
    assert_eq!(authorized(&st, account), Zatoshis::ZERO);
    for selection in selections(
        &st,
        account,
        &[unspent.address],
        &unspent.outpoint,
        next_target(&st),
    ) {
        assert_eq!(selection.unwrap(), vec![]);
    }

    // Once its owner releases it, the next forget removes it.
    assert!(
        st.wallet_mut()
            .db_mut()
            .unlock_output(&output, owner)
            .unwrap()
    );
    let forgotten = forget(&mut st).unwrap();
    assert_eq!((forgotten.outputs, forgotten.retained_outputs), (1, 0));
    assert!(!has_output(&st, &unspent.outpoint));
    assert!(!has_transaction(&st, unspent.outpoint.txid()));
}

#[test]
fn forgetting_requires_public_on_the_handle_and_durably() {
    let (mut st, account, _, _) = ready_wallet();
    promote(&mut st, account).unwrap();
    let before = (production_dump(conn(&st)), ledger_counts(&st));
    let refused = |st: &mut State| {
        assert!(matches!(
            forget(st),
            Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
        ));
        assert_eq!((production_dump(conn(st)), ledger_counts(st)), before);
    };

    // Durably and on the handle.
    refused(&mut st);
    // A public handle reads under the durable private policy.
    st.wallet_mut().db_mut().set_transparent_ledger_mode(Public);
    refused(&mut st);
}

#[test]
fn a_private_handle_over_a_public_policy_cannot_forget() {
    let (mut st, account, _, _) = ready_wallet();
    promote(&mut st, account).unwrap();
    set_policy(&mut st, Public);
    st.wallet_mut()
        .db_mut()
        .set_transparent_ledger_mode(PrivateRequired);
    let before = (production_dump(conn(&st)), ledger_counts(&st));
    assert!(matches!(
        forget(&mut st),
        Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
    ));
    assert_eq!((production_dump(conn(&st)), ledger_counts(&st)), before);
}

#[test]
fn a_failed_forget_changes_nothing() {
    let (mut st, account, real, _) = falsely_spent_wallet();
    set_policy(&mut st, Public);
    let before = (production_dump(conn(&st)), ledger_counts(&st));
    // Fail a late step, after the projection was already removed.
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER fail_forget BEFORE DELETE ON tpir_coverage
             BEGIN SELECT RAISE(ABORT, 'injected forget failure'); END;",
        )
        .unwrap();
    assert!(matches!(
        forget(&mut st),
        Err(SqliteClientError::DbError(_))
    ));
    assert_eq!((production_dump(conn(&st)), ledger_counts(&st)), before);
    assert_eq!(spend_count(&st, &real.outpoint), 1);
    assert_eq!(authorized(&st, account), Zatoshis::ZERO);
}

#[test]
fn forgetting_again_removes_nothing() {
    let (mut st, _, _, _) = falsely_spent_wallet();
    set_policy(&mut st, Public);
    assert!(!forget(&mut st).unwrap().removed_nothing());
    let after = (production_dump(conn(&st)), ledger_counts(&st));
    assert!(forget(&mut st).unwrap().removed_nothing());
    assert_eq!((production_dump(conn(&st)), ledger_counts(&st)), after);
}

#[test]
fn a_wallet_requiring_a_newer_reader_cannot_forget() {
    let (mut st, _, _, _) = falsely_spent_wallet();
    set_policy(&mut st, Public);
    let future = crate::wallet::transparent_ledger::TPIR_READER_VERSION + 1;
    st.wallet().set_transparent_reader_version(future);
    let before = production_dump(conn(&st));
    assert!(matches!(
        forget(&mut st),
        Err(SqliteClientError::TransparentLedgerIncompatible { required }) if required == future
    ));
    assert_eq!(production_dump(conn(&st)), before);
}

#[test]
fn private_recovery_works_again_after_forgetting() {
    let (mut st, account, unspent, spent) = ready_wallet();
    promote(&mut st, account).unwrap();
    set_policy(&mut st, Public);
    let revisions = count(&st, "tpir_revisions");
    let qualified = count(&st, "tpir_qualified_revisions");
    let windows = count(&st, "tpir_candidate_windows");
    forget(&mut st).unwrap();
    // Lineage and qualification constrain what a return to private recovery accepts.
    assert_eq!(count(&st, "tpir_revisions"), revisions);
    assert_eq!(count(&st, "tpir_qualified_revisions"), qualified);
    assert_eq!(count(&st, "tpir_candidate_windows"), windows);

    set_policy(&mut st, PrivateRequired);
    let blockers = snapshot(&st, account).blockers;
    assert!(
        blockers.contains(&RecoveryBlocker::NotActivated),
        "{blockers:?}"
    );
    assert!(
        blockers.contains(&RecoveryBlocker::Recovery(
            CandidateBlocker::IncompleteCoverage
        )),
        "{blockers:?}"
    );

    // The same publication recovers and activates the account again.
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let mut c = commit(&ws);
    c.revision = fixture.clone();
    c.receives = vec![unspent.clone(), spent.clone()];
    c.spends = vec![spend(3, &spent, below_target(&ws, 2))];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    cover(&mut st, account, &fixture, vec![]);
    promote(&mut st, account).unwrap();
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert_eq!(s.authorized.unwrap().regular.total(), unspent.value);
    assert!(has_output(&st, &unspent.outpoint));
}

#[test]
fn forgetting_keeps_quarantine() {
    let (mut st, account, _, _) = falsely_spent_wallet();
    conn(&st)
        .execute(
            "INSERT INTO tpir_quarantined_sources (source) VALUES (?1)",
            [b"fixture".as_slice()],
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO tpir_quarantined_accounts (account_id) SELECT id FROM accounts",
            [],
        )
        .unwrap();
    set_policy(&mut st, Public);
    forget(&mut st).unwrap();
    assert_eq!(count(&st, "tpir_quarantined_sources"), 1);
    assert_eq!(quarantined_accounts(&st), vec![account]);
}

#[test]
fn a_wallet_that_never_recovered_privately_forgets_nothing() {
    let (mut st, accounts) = recovery_wallet_with(0);
    let account = accounts[0];
    // Still private and without facts: refused all the same.
    assert!(matches!(
        forget(&mut st),
        Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
    ));
    set_policy(&mut st, Public);
    let ws = watch(&st, account);
    let utxo = WalletTransparentOutput::from_parts(
        OutPoint::new([0x41; 32], 0),
        TxOut::new(
            Zatoshis::const_from_u64(30_000),
            external(&ws).script().into(),
        ),
        Some(below_target(&ws, 1)),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .db_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();
    let before = (production_dump(conn(&st)), ledger_counts(&st));

    let forgotten = forget(&mut st).unwrap();
    assert!(forgotten.removed_nothing());
    assert_eq!(forgotten.retained_outputs, 0);
    assert_eq!((production_dump(conn(&st)), ledger_counts(&st)), before);
    assert_eq!(authorized(&st, account), Zatoshis::const_from_u64(30_000));
}
