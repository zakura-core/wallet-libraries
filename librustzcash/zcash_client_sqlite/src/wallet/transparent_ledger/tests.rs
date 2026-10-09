use std::convert::Infallible;

use rusqlite::Connection;
use sapling::zip32::ExtendedSpendingKey;
use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::TransparentKeyScope,
};
use zcash_client_backend::{
    data_api::{
        Account as _, WalletRead as _, WalletWrite as _,
        testing::{AddressType, TestBuilder, TestState, single_output_change_strategy},
        wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, SpendPolicy, TransparentSpendPolicy},
        },
    },
    fees::{StandardFeeRule, TransparentChangePolicy},
    wallet::{OvkPolicy, WalletTransparentOutput},
};
use zcash_keys::{address::Address, keys::UnifiedAddressRequest};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{ShieldedPool, local_consensus::LocalNetwork, value::Zatoshis};
use zip321::{Payment, TransactionRequest};

use crate::testing::{BlockCache, db::TestDbFactory};

const LEGACY_PUBLIC: i64 = 0;
const LOCAL_CONSTRUCTION: i64 = 1;

type State = TestState<BlockCache, crate::testing::db::TestDb, LocalNetwork>;

/// A fresh wallet state, preserving real migrations and independent database ownership.
fn wallet_state(factory: TestDbFactory) -> State {
    TestBuilder::new()
        .with_data_store_factory(factory)
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build()
}

/// A wallet with one account whose only funds are a publicly discovered transparent UTXO.
fn funded_wallet() -> (State, TransparentAddress, OutPoint) {
    let mut st = wallet_state(TestDbFactory::default());
    let account = st.test_account().cloned().unwrap();
    let taddr = *st
        .wallet()
        .get_last_generated_address_matching(account.id(), UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();

    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let not_our_value = Zatoshis::const_from_u64(10_000);
    let (start, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..10 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }
    st.scan_cached_blocks(start, 10);

    let outpoint = OutPoint::fake();
    put_public_utxo(&mut st, &taddr, outpoint.clone(), 100_000);
    (st, taddr, outpoint)
}

fn put_public_utxo(st: &mut State, taddr: &TransparentAddress, outpoint: OutPoint, value: u64) {
    let account = st.test_account().cloned().unwrap();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let utxo = WalletTransparentOutput::from_parts(
        outpoint,
        TxOut::new(Zatoshis::const_from_u64(value), taddr.script().into()),
        Some(height),
        Some(account.id()),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();
}

fn conn(st: &State) -> &Connection {
    &st.wallet().db().conn
}

fn output_origins(conn: &Connection, outpoint: &OutPoint) -> Vec<i64> {
    conn.prepare(
        "SELECT oo.origin
         FROM tpir_output_origins oo
         JOIN transparent_received_outputs o ON o.id = oo.output_id
         JOIN transactions t ON t.id_tx = o.transaction_id
         WHERE t.txid = ?1 AND o.output_index = ?2
         ORDER BY oo.origin",
    )
    .unwrap()
    .query_map(rusqlite::params![outpoint.hash(), outpoint.n()], |row| {
        row.get(0)
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

fn spend_origins(conn: &Connection, outpoint: &OutPoint) -> Vec<i64> {
    conn.prepare(
        "SELECT origin FROM tpir_spend_origins
         WHERE prevout_txid = ?1 AND prevout_output_index = ?2
         ORDER BY origin",
    )
    .unwrap()
    .query_map(rusqlite::params![outpoint.hash(), outpoint.n()], |row| {
        row.get(0)
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// Returns the number of transparent outputs and spends that lack any projection origin.
pub(super) fn records_without_origin(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT
            (SELECT COUNT(*) FROM transparent_received_outputs o
             WHERE NOT EXISTS (SELECT 1 FROM tpir_output_origins WHERE output_id = o.id))
          + (SELECT COUNT(*) FROM transparent_received_output_spends s
             JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
             JOIN transactions prevout_tx ON prevout_tx.id_tx = o.transaction_id
             WHERE NOT EXISTS (
                 SELECT 1 FROM tpir_spend_origins so
                 WHERE so.spending_transaction_id = s.transaction_id
                 AND so.prevout_txid = prevout_tx.txid
                 AND so.prevout_output_index = o.output_index))
          + (SELECT COUNT(*) FROM transparent_spend_map m
             WHERE NOT EXISTS (
                 SELECT 1 FROM tpir_spend_origins so
                 WHERE so.spending_transaction_id = m.spending_transaction_id
                 AND so.prevout_txid = m.prevout_txid
                 AND so.prevout_output_index = m.prevout_output_index))",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn public_and_local_writes_record_their_origins() {
    let (mut st, _, funded) = funded_wallet();
    assert_eq!(output_origins(conn(&st), &funded), vec![LEGACY_PUBLIC]);

    // Rediscovering the same output is idempotent.
    let taddr = *st
        .wallet()
        .get_last_generated_address_matching(
            st.test_account().unwrap().id(),
            UnifiedAddressRequest::AllAvailableKeys,
        )
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();
    put_public_utxo(&mut st, &taddr, funded.clone(), 100_000);
    assert_eq!(output_origins(conn(&st), &funded), vec![LEGACY_PUBLIC]);

    // A locally constructed t->t payment spends the UTXO and creates transparent change.
    let account = st.test_account().cloned().unwrap();
    let request = TransactionRequest::new(vec![Payment::without_memo(
        Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]))
            .to_zcash_address(st.network()),
        Zatoshis::const_from_u64(40_000),
    )])
    .unwrap();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Sapling)
            .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);
    let proposal = st
        .propose_transfer_with_policy(
            account.id(),
            &GreedyInputSelector::new(),
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
            &SpendPolicy::default().with_transparent(TransparentSpendPolicy::any_account_addr()),
        )
        .unwrap();
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()
        .head;

    assert_eq!(spend_origins(conn(&st), &funded), vec![LOCAL_CONSTRUCTION]);
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    // The store detects transparent inputs from the transaction itself.
    assert!(super::has_transparent_inputs(&tx));
    let vout = &tx.transparent_bundle().unwrap().vout;
    let recipient_script: transparent::address::Script =
        TransparentAddress::PublicKeyHash([7; 20]).script().into();
    let change_index = vout
        .iter()
        .position(|out| out.script_pubkey() != &recipient_script)
        .unwrap();
    let change = OutPoint::new(txid.into(), u32::try_from(change_index).unwrap());
    assert_eq!(output_origins(conn(&st), &change), vec![LOCAL_CONSTRUCTION]);

    // A later public observation of the local change adds legacy provenance and keeps the
    // local origin.
    let change_out = vout[change_index].clone();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let observed = WalletTransparentOutput::from_parts(
        change.clone(),
        change_out,
        Some(height),
        Some(account.id()),
        Some(TransparentKeyScope::INTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&observed)
        .unwrap();
    assert_eq!(
        output_origins(conn(&st), &change),
        vec![LEGACY_PUBLIC, LOCAL_CONSTRUCTION]
    );
    assert_eq!(records_without_origin(conn(&st)), 0);

    // Origins are removed with the records they describe.
    st.wallet_mut().delete_account(account.id()).unwrap();
    let remaining: i64 = conn(&st)
        .query_row(
            "SELECT (SELECT COUNT(*) FROM tpir_output_origins)
                  + (SELECT COUNT(*) FROM tpir_spend_origins)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn origin_write_failure_rolls_back_the_output() {
    let (mut st, taddr, _) = funded_wallet();
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER inject_origin_failure BEFORE INSERT ON tpir_output_origins
             BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END;",
        )
        .unwrap();

    let account = st.test_account().cloned().unwrap();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let outpoint = OutPoint::new([0x42; 32], 0);
    let utxo = WalletTransparentOutput::from_parts(
        outpoint.clone(),
        TxOut::new(Zatoshis::const_from_u64(5_000), taddr.script().into()),
        Some(height),
        Some(account.id()),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    assert!(
        st.wallet_mut()
            .put_received_transparent_utxo(&utxo)
            .is_err()
    );

    let stored: i64 = conn(&st)
        .query_row(
            "SELECT COUNT(*) FROM transactions WHERE txid = ?1",
            [outpoint.hash()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, 0, "no output may be stored without its origin");
    assert_eq!(records_without_origin(conn(&st)), 0);
}

#[test]
fn outbox_creation_evidence_adds_local_origins_in_either_order() {
    use zcash_client_backend::data_api::status::TransactionStatusWrite as _;
    let (mut st, taddr, _) = funded_wallet();
    let height = st.wallet().chain_height().unwrap().unwrap();

    // Creation evidence recorded before the output is projected publicly.
    let before = OutPoint::new([0x51; 32], 0);
    st.wallet_mut()
        .db_mut()
        .record_transaction_created(
            zcash_primitives::transaction::TxId::from_bytes([0x51; 32]),
            height,
        )
        .unwrap();
    put_public_utxo(&mut st, &taddr, before.clone(), 6_000);
    assert_eq!(
        output_origins(conn(&st), &before),
        vec![LEGACY_PUBLIC, LOCAL_CONSTRUCTION]
    );

    // Creation evidence recorded after the output is projected publicly.
    let after = OutPoint::new([0x52; 32], 0);
    put_public_utxo(&mut st, &taddr, after.clone(), 7_000);
    assert_eq!(output_origins(conn(&st), &after), vec![LEGACY_PUBLIC]);
    st.wallet_mut()
        .db_mut()
        .record_transaction_created(
            zcash_primitives::transaction::TxId::from_bytes([0x52; 32]),
            height,
        )
        .unwrap();
    assert_eq!(
        output_origins(conn(&st), &after),
        vec![LEGACY_PUBLIC, LOCAL_CONSTRUCTION]
    );
    assert_eq!(records_without_origin(conn(&st)), 0);
}

#[test]
fn creation_evidence_and_local_origins_commit_together() {
    use zcash_client_backend::data_api::status::TransactionStatusWrite as _;
    let (mut st, taddr, _) = funded_wallet();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let outpoint = OutPoint::new([0x61; 32], 0);
    put_public_utxo(&mut st, &taddr, outpoint.clone(), 8_000);
    conn(&st)
        .execute_batch(
            "CREATE TEMP TRIGGER inject_origin_failure BEFORE INSERT ON tpir_output_origins
             BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END;",
        )
        .unwrap();
    assert!(
        st.wallet_mut()
            .db_mut()
            .record_transaction_created(
                zcash_primitives::transaction::TxId::from_bytes([0x61; 32]),
                height,
            )
            .is_err()
    );
    let target: Option<u32> = conn(&st)
        .query_row(
            "SELECT target_height FROM transactions WHERE txid = ?1",
            [outpoint.hash()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        target, None,
        "creation evidence must not outlive a failed origin write"
    );
    assert_eq!(output_origins(conn(&st), &outpoint), vec![LEGACY_PUBLIC]);
}

#[test]
fn conflicting_output_content_is_refused() {
    let (mut st, taddr, funded) = funded_wallet();
    let account = st.test_account().cloned().unwrap();
    let height = st.wallet().chain_height().unwrap().unwrap();
    let conflicting = WalletTransparentOutput::from_parts(
        funded.clone(),
        TxOut::new(Zatoshis::const_from_u64(99_999), taddr.script().into()),
        Some(height),
        Some(account.id()),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    assert!(
        st.wallet_mut()
            .put_received_transparent_utxo(&conflicting)
            .is_err()
    );
    let value: i64 = conn(&st)
        .query_row(
            "SELECT o.value_zat FROM transparent_received_outputs o
             JOIN transactions t ON t.id_tx = o.transaction_id
             WHERE t.txid = ?1 AND o.output_index = ?2",
            rusqlite::params![funded.hash(), funded.n()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(value, 100_000);
}

mod recovery;

mod handles {
    use std::{
        convert::Infallible,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use rusqlite::hooks::{AuthAction, Authorization};
    use tempfile::NamedTempFile;
    use transparent::{address::TransparentAddress, bundle::OutPoint};
    use zcash_client_backend::{
        data_api::{
            Account as _, CoinbaseFilter, InputSource as _, TargetValue, WalletRead as _,
            WalletWrite as _,
            testing::{AddressType, TestBuilder, single_output_change_strategy},
            transparent_ledger::{
                CandidateBlocker, LastKnownSource, RecoveryBlocker, RecoveryCompletion,
                TransparentAuthority, TransparentLedgerMode, TransparentLedgerRead as _,
                TransparentLedgerWrite as _,
            },
            wallet::{
                ConfirmationsPolicy, TargetHeight,
                input_selection::{
                    GreedyInputSelector, LockFilter, LockedInputPolicy, SpendPolicy,
                    TransparentSpendPolicy,
                },
            },
        },
        fees::{StandardFeeRule, TransparentChangePolicy},
        wallet::OvkPolicy,
    };
    use zcash_keys::address::Address;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{ShieldedPool, consensus::Network, value::Zatoshis};
    use zip321::{Payment, TransactionRequest};

    use super::{State, conn, funded_wallet};
    use crate::{
        AccountUuid, WalletDb,
        error::SqliteClientError,
        testing::{
            BlockCache,
            db::{TestDbFactory, test_clock, test_rng},
        },
        wallet::{
            init::WalletMigrator,
            transparent_ledger::{check_public_discovery, check_transparent_authority},
        },
    };

    use TransparentLedgerMode::{PrivateRequired, PrivateShadow, Public};

    fn meta(st: &State) -> (i64, i64) {
        conn(st)
            .query_row(
                "SELECT applied_mode, policy_generation FROM tpir_meta",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn set_mode(st: &mut State, mode: TransparentLedgerMode) {
        st.wallet_mut().db_mut().set_transparent_ledger_mode(mode);
    }

    fn account_taddr(st: &State) -> (AccountUuid, TransparentAddress) {
        let account = st.test_account().unwrap().id();
        let taddr = *st
            .wallet()
            .get_last_generated_address_matching(
                account,
                zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys,
            )
            .unwrap()
            .unwrap()
            .transparent()
            .unwrap();
        (account, taddr)
    }

    /// Runs every transparent selector and returns their errors, if any.
    fn selector_errors(st: &State, outpoint: &OutPoint) -> Vec<Option<SqliteClientError>> {
        let (account, taddr) = account_taddr(st);
        let db = st.wallet().db();
        let target = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
        let lock = || LockFilter::Policy(&LockedInputPolicy::Exclude);
        vec![
            db.get_unspent_transparent_output(outpoint, target).err(),
            db.get_spendable_transparent_outputs(
                &taddr,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                lock(),
            )
            .err(),
            db.get_spendable_transparent_outputs_for_addresses(
                &[taddr],
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                lock(),
            )
            .err(),
            db.select_spendable_transparent_outputs(
                account,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                None,
                TargetValue::AtLeast(Zatoshis::const_from_u64(1)),
                10,
                &StandardFeeRule::Zip317,
                lock(),
            )
            .err(),
        ]
    }

    #[test]
    fn unconfigured_handles_are_rejected_even_when_empty() {
        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();

        let account = AccountUuid::from_uuid(uuid::Uuid::nil());
        assert!(matches!(
            db.transparent_ledger_mode(),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
        assert!(matches!(
            db.transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
    }

    #[test]
    fn transactional_handles_inherit_and_reopened_handles_do_not() {
        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(PrivateRequired);
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();

        let inner = db
            .transactionally(|wdb| wdb.transparent_ledger_mode())
            .unwrap();
        assert_eq!(inner, PrivateRequired);
        let inner = db
            .transactionally_with_extension(|wdb, _| wdb.transparent_ledger_mode())
            .unwrap();
        assert_eq!(inner, PrivateRequired);

        let reopened =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        assert!(matches!(
            reopened.transparent_ledger_mode(),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
    }

    #[test]
    fn snapshot_reports_authority_by_mode() {
        let (mut st, _, _) = funded_wallet();
        let (account, _) = account_taddr(&st);
        let snapshot = |st: &State| {
            st.wallet()
                .db()
                .transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
                .unwrap()
        };

        for mode in [Public, PrivateShadow] {
            set_mode(&mut st, mode);
            let s = snapshot(&st);
            assert_eq!(s.mode, mode);
            assert_eq!(s.authority, TransparentAuthority::Public);
            let authorized = s.authorized.unwrap();
            assert_eq!(
                authorized.regular.spendable_value(),
                Zatoshis::const_from_u64(100_000)
            );
            assert_eq!(authorized.coinbase.total(), Zatoshis::ZERO);
            assert_eq!(s.last_known, None);
            assert_eq!(s.completion, RecoveryCompletion::NotApplicable);
            assert!(s.blockers.is_empty());
        }

        // The account is not promoted, so private authority is unavailable: the public amount
        // is shown as last-known legacy evidence only, with no verified anchor, never as an
        // authorized balance.
        set_mode(&mut st, PrivateRequired);
        let s = snapshot(&st);
        assert_eq!(s.authority, TransparentAuthority::Unavailable);
        assert_eq!(s.authorized, None);
        let last_known = s.last_known.unwrap();
        assert_eq!(last_known.source, LastKnownSource::LegacyPublic);
        assert_eq!(last_known.at, None);
        assert_eq!(
            last_known.balance.regular.spendable_value(),
            Zatoshis::const_from_u64(100_000)
        );
        assert_eq!(s.completion, RecoveryCompletion::Blocked);
        assert_eq!(
            s.blockers,
            vec![
                RecoveryBlocker::NotActivated,
                RecoveryBlocker::Recovery(CandidateBlocker::IncompleteCoverage),
            ]
        );
        assert_eq!(s.covered_through, None);
        assert_eq!(s.recovered_unverified, Some(Zatoshis::ZERO));
    }

    #[test]
    fn private_required_blocks_transparent_inputs_but_not_shielded_spends() {
        let (mut st, _, funded) = funded_wallet();
        assert!(selector_errors(&st, &funded).iter().all(Option::is_none));

        // A transparent payment proposed while public authority applied.
        let account = st.test_account().cloned().unwrap();
        let t2t = TransactionRequest::new(vec![Payment::without_memo(
            Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]))
                .to_zcash_address(st.network()),
            Zatoshis::const_from_u64(40_000),
        )])
        .unwrap();
        let change_strategy =
            single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Sapling)
                .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);
        let stale_proposal = st
            .propose_transfer_with_policy(
                account.id(),
                &GreedyInputSelector::new(),
                &change_strategy,
                t2t,
                ConfirmationsPolicy::MIN,
                &SpendPolicy::default()
                    .with_transparent(TransparentSpendPolicy::any_account_addr()),
            )
            .unwrap();

        set_mode(&mut st, PrivateRequired);
        for error in selector_errors(&st, &funded) {
            assert!(matches!(
                error,
                Some(SqliteClientError::TransparentAuthorityUnavailable)
            ));
        }

        // Consuming the stale proposal is rejected before anything is stored.
        let transactions = |st: &State| -> i64 {
            conn(st)
                .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))
                .unwrap()
        };
        let before = transactions(&st);
        assert!(
            st.create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                OvkPolicy::Sender,
                &stale_proposal,
            )
            .is_err()
        );
        assert_eq!(transactions(&st), before);

        // Shielded funds remain spendable, including to the wallet's own transparent address.
        let dfvk = account.usk().sapling().to_diversifiable_full_viewing_key();
        let (height, _, _) = st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(200_000),
        );
        st.scan_cached_blocks(height, 1);
        let (_, taddr) = account_taddr(&st);
        let unshield = TransactionRequest::new(vec![Payment::without_memo(
            Address::Transparent(taddr).to_zcash_address(st.network()),
            Zatoshis::const_from_u64(50_000),
        )])
        .unwrap();
        let change_strategy =
            single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Sapling);
        let proposal = st
            .propose_transfer_with_policy(
                account.id(),
                &GreedyInputSelector::new(),
                &change_strategy,
                unshield,
                ConfirmationsPolicy::MIN,
                &SpendPolicy::default(),
            )
            .unwrap();
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();

        // The new own transparent output was recorded by local construction after private
        // authority applied, so the last-known amount is not purely legacy public.
        let snapshot = st
            .wallet()
            .db()
            .transparent_ledger_snapshot(account.id(), ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(
            snapshot.last_known.unwrap().source,
            LastKnownSource::LegacyPublicAndLocal
        );

        // A spend by an expired transaction does not remove the local output from the balance,
        // so it still counts toward provenance.
        conn(&st)
            .execute_batch(
                "INSERT INTO transactions (id_tx, txid, expiry_height, min_observed_height)
                 VALUES (9999, X'77', 1, 1);
                 INSERT INTO transparent_received_output_spends
                     (transparent_received_output_id, transaction_id)
                 SELECT o.id, 9999 FROM transparent_received_outputs o
                 WHERE NOT EXISTS (
                     SELECT 1 FROM tpir_output_origins oo
                     WHERE oo.output_id = o.id AND oo.origin = 0
                 );",
            )
            .unwrap();
        let snapshot = st
            .wallet()
            .db()
            .transparent_ledger_snapshot(account.id(), ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(
            snapshot.last_known.unwrap().source,
            LastKnownSource::LegacyPublicAndLocal
        );

        // Missing provenance is corruption, never evidence of local construction.
        conn(&st)
            .execute_batch("DELETE FROM tpir_output_origins")
            .unwrap();
        assert!(matches!(
            st.wallet()
                .db()
                .transparent_ledger_snapshot(account.id(), ConfirmationsPolicy::MIN),
            Err(SqliteClientError::CorruptedData(_))
        ));

        // A shadow snapshot keeps public authority and does not read the provenance of a
        // last-known amount it would not report, so the same state cannot fail it.
        set_mode(&mut st, PrivateShadow);
        let snapshot = st
            .wallet()
            .db()
            .transparent_ledger_snapshot(account.id(), ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(snapshot.authority, TransparentAuthority::Public);
        assert!(snapshot.authorized.is_some());
        assert!(snapshot.last_known.is_none());
    }

    #[test]
    fn received_transparent_outputs_are_unspendable_without_authority() {
        let (mut st, _, funded) = funded_wallet();
        let txid = zcash_primitives::transaction::TxId::from_bytes(*funded.hash());
        let target = TargetHeight::from(st.wallet().chain_height().unwrap().unwrap() + 1);
        let transparent_confirmations = |st: &State| {
            st.wallet()
                .db()
                .get_received_outputs(txid, target, ConfirmationsPolicy::MIN)
                .unwrap()
                .into_iter()
                .find(|o| o.pool_type() == zcash_protocol::PoolType::Transparent)
                .unwrap()
                .confirmations_until_spendable()
        };
        assert!(transparent_confirmations(&st) < u32::MAX);
        set_mode(&mut st, PrivateRequired);
        assert_eq!(transparent_confirmations(&st), u32::MAX);
    }

    #[test]
    fn durable_private_policy_is_never_weakened() {
        let (mut st, _, funded) = funded_wallet();
        let (account, _) = account_taddr(&st);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();

        // The reference: a matching handle operates, with transparent inputs unavailable.
        set_mode(&mut st, PrivateRequired);
        let required_selectors = format!("{:?}", selector_errors(&st, &funded));
        let required_snapshot = format!(
            "{:?}",
            st.wallet()
                .db()
                .transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
                .unwrap()
        );
        assert!(matches!(
            selector_errors(&st, &funded)[0],
            Some(SqliteClientError::TransparentAuthorityUnavailable)
        ));

        // A weaker handle resolves to the durable policy and reads exactly what a matching
        // handle reads, without changing its own configuration.
        for mode in [Public, PrivateShadow] {
            set_mode(&mut st, mode);
            let db = st.wallet().db();
            assert_eq!(db.transparent_ledger_mode().unwrap(), PrivateRequired);
            assert_eq!(db.transparent_ledger_mode, Some(mode));
            assert_eq!(
                format!(
                    "{:?}",
                    db.transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
                        .unwrap()
                ),
                required_snapshot
            );
            assert_eq!(
                format!("{:?}", selector_errors(&st, &funded)),
                required_selectors
            );
            assert!(matches!(
                check_transparent_authority(conn(&st), Some(mode)),
                Err(SqliteClientError::TransparentAuthorityUnavailable)
            ));
            assert!(
                !crate::wallet::transparent_ledger::public_discovery_permitted(
                    conn(&st),
                    Some(mode)
                )
                .unwrap()
            );
        }
        // An unconfigured handle is blocked.
        assert!(matches!(
            check_transparent_authority(conn(&st), None),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));

        // Nothing weakened or rewrote the stored policy.
        assert_eq!(meta(&st), (2, 1));
    }

    #[test]
    fn newer_reader_requirement_fails_closed() {
        let (st, _, funded) = funded_wallet();
        let newer = crate::wallet::transparent_ledger::TPIR_READER_VERSION + 1;
        conn(&st)
            .execute("UPDATE tpir_meta SET min_reader_version = ?1", [newer])
            .unwrap();
        let incompatible = |e: &SqliteClientError| {
            matches!(
                e,
                SqliteClientError::TransparentLedgerIncompatible { required } if *required == newer
            )
        };
        assert!(incompatible(
            &st.wallet().db().transparent_ledger_mode().unwrap_err()
        ));
        for error in selector_errors(&st, &funded) {
            assert!(incompatible(&error.unwrap()));
        }
    }

    #[test]
    fn unconfigured_handle_fails_before_the_chain_is_known() {
        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        assert_eq!(db.chain_height().unwrap(), None);
        assert!(matches!(
            db.transaction_data_requests(),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
    }

    #[test]
    fn transaction_data_requests_use_one_policy_snapshot() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::file_backed())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let tip = st.test_account().unwrap().birthday().height();
        assert_eq!(st.wallet().chain_height().unwrap(), None);

        st.wallet()
            .conn()
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        let mut writer = WalletDb::for_path(
            st.wallet().data_file_path(),
            *st.network(),
            test_clock(),
            test_rng(),
        )
        .unwrap()
        .with_transparent_ledger_mode(Public);

        let transition_started = Arc::new(AtomicBool::new(false));
        let transition_error = Arc::new(Mutex::new(None));
        let callback_started = Arc::clone(&transition_started);
        let callback_error = Arc::clone(&transition_error);
        st.wallet()
            .conn()
            .authorizer(Some(move |ctx: rusqlite::hooks::AuthContext<'_>| {
                if matches!(
                    ctx.action,
                    AuthAction::Read {
                        table_name: "scan_queue",
                        ..
                    }
                ) && !callback_started.swap(true, Ordering::SeqCst)
                {
                    let result = writer
                        .apply_transparent_policy(PrivateRequired)
                        .and_then(|_| writer.update_chain_tip(tip));
                    if let Err(error) = result {
                        *callback_error.lock().unwrap() = Some(error.to_string());
                    }
                }
                Authorization::Allow
            }));

        let requests = st.wallet().transaction_data_requests().unwrap();
        assert!(transition_started.load(Ordering::SeqCst));
        assert_eq!(transition_error.lock().unwrap().take(), None);
        assert!(
            requests.is_empty(),
            "the read must not combine pre-transition public authority with the new chain tip"
        );
    }

    #[test]
    fn unconfigured_handles_cannot_authorize_or_discover_transparent_funds() {
        assert!(matches!(
            check_transparent_authority(conn(&funded_wallet().0), None),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
        assert!(matches!(
            check_public_discovery(conn(&funded_wallet().0), None),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
    }

    #[test]
    fn private_required_stops_public_discovery_and_current_balances() {
        let (mut st, taddr, _) = funded_wallet();
        let (account, _) = account_taddr(&st);
        let transparent_total = |st: &State| {
            st.wallet()
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .unwrap()
                .unwrap()
                .account_balances()[&account]
                .unshielded_balance()
                .total()
        };
        assert_eq!(transparent_total(&st), Zatoshis::const_from_u64(100_000));
        assert!(!st.wallet().transaction_data_requests().unwrap().is_empty());

        set_mode(&mut st, PrivateRequired);
        // Public history requests are withheld, and publicly discovered outputs are refused.
        assert!(st.wallet().transaction_data_requests().unwrap().is_empty());
        let height = st.wallet().chain_height().unwrap().unwrap();
        let utxo = zcash_client_backend::wallet::WalletTransparentOutput::from_parts(
            OutPoint::new([0x43; 32], 0),
            transparent::bundle::TxOut::new(Zatoshis::const_from_u64(5_000), taddr.script().into()),
            Some(height),
            Some(account),
            Some(transparent::keys::TransparentKeyScope::EXTERNAL),
            None,
        )
        .unwrap();
        assert!(matches!(
            st.wallet_mut()
                .db_mut()
                .put_received_transparent_utxo(&utxo),
            Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
        ));
        // The summary no longer reports the public amount as current funds.
        assert_eq!(transparent_total(&st), Zatoshis::ZERO);
        // Direct balance reads report unavailable authority rather than current funds.
        let target = TargetHeight::from(height + 1);
        assert!(matches!(
            st.wallet()
                .db()
                .get_transparent_balances(account, target, ConfirmationsPolicy::MIN),
            Err(SqliteClientError::TransparentAuthorityUnavailable)
        ));

        // A durable private policy has the same effect on a weaker handle's summary.
        set_mode(&mut st, Public);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();
        assert_eq!(transparent_total(&st), Zatoshis::ZERO);
    }

    #[test]
    fn missing_policy_row_is_corruption() {
        let (st, _, funded) = funded_wallet();
        conn(&st).execute("DELETE FROM tpir_meta", []).unwrap();
        assert!(matches!(
            st.wallet().db().transparent_ledger_mode(),
            Err(SqliteClientError::CorruptedData(_))
        ));
        for error in selector_errors(&st, &funded) {
            assert!(matches!(error, Some(SqliteClientError::CorruptedData(_))));
        }
    }

    #[test]
    fn dropped_policy_table_after_migration_is_corruption() {
        let (st, _, funded) = funded_wallet();
        conn(&st).execute_batch("DROP TABLE tpir_meta").unwrap();
        assert!(matches!(
            st.wallet().db().transparent_ledger_mode(),
            Err(SqliteClientError::CorruptedData(_))
        ));
        for error in selector_errors(&st, &funded) {
            assert!(matches!(error, Some(SqliteClientError::CorruptedData(_))));
        }
    }

    #[test]
    fn unknown_chain_has_no_public_authority() {
        let st = zcash_client_backend::data_api::testing::TestBuilder::new()
            .with_data_store_factory(crate::testing::db::TestDbFactory::default())
            .with_block_cache(crate::testing::BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        if st.wallet().chain_height().unwrap().is_some() {
            conn(&st)
                .execute_batch("DELETE FROM blocks; DELETE FROM scan_queue;")
                .unwrap();
        }
        assert_eq!(st.wallet().chain_height().unwrap(), None);
        let account = st.test_account().unwrap().id();
        let snapshot = st
            .wallet()
            .db()
            .transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(snapshot.authority, TransparentAuthority::Unavailable);
        assert_eq!(snapshot.authorized, None);
        assert_eq!(snapshot.completion, RecoveryCompletion::Blocked);
        assert_eq!(snapshot.blockers, vec![RecoveryBlocker::ChainUnknown]);
        // Selectors and stores cannot authorize transparent inputs without a known chain tip,
        // matching the snapshot.
        assert!(matches!(
            check_transparent_authority(conn(&st), Some(Public)),
            Err(SqliteClientError::TransparentAuthorityUnavailable)
        ));
        // Balance reads apply the same availability rule for any caller-supplied target.
        assert!(matches!(
            st.wallet().db().get_transparent_balances(
                account,
                TargetHeight::from(zcash_protocol::consensus::BlockHeight::from(1)),
                ConfirmationsPolicy::MIN,
            ),
            Err(SqliteClientError::TransparentAuthorityUnavailable)
        ));
    }

    #[test]
    fn policy_transition_increments_generation_once_per_mode_change() {
        let (mut st, _, _) = funded_wallet();
        let first = st
            .wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateShadow)
            .unwrap();
        assert_eq!(
            first,
            zcash_client_backend::data_api::transparent_ledger::AppliedTransparentPolicy {
                mode: PrivateShadow,
                generation: 1,
            }
        );
        let same = st
            .wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateShadow)
            .unwrap();
        assert_eq!(same.generation, 1);
        let private = st
            .wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();
        assert_eq!(private.generation, 2);
        let back = st
            .wallet_mut()
            .db_mut()
            .apply_transparent_policy(Public)
            .unwrap();
        assert_eq!(back.generation, 3);
    }

    #[test]
    fn policy_transition_failure_rolls_the_row_back() {
        let (mut st, _, _) = funded_wallet();
        assert_eq!(meta(&st), (0, 0));
        conn(&st)
            .execute_batch(
                "CREATE TRIGGER fail_policy_write BEFORE UPDATE ON tpir_meta
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert!(
            st.wallet_mut()
                .db_mut()
                .apply_transparent_policy(PrivateRequired)
                .is_err()
        );
        assert_eq!(meta(&st), (0, 0));
    }

    #[test]
    fn second_connection_fails_generation_check_without_changing_memory_mode() {
        use crate::testing::db::{test_clock, test_rng};
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(Public);
        WalletMigrator::new().init_or_migrate(&mut writer).unwrap();
        let captured = writer.applied_transparent_policy().unwrap();
        assert_eq!(captured.generation, 0);

        let reader =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(Public);
        assert_eq!(reader.transparent_ledger_mode().unwrap(), Public);

        writer.apply_transparent_policy(PrivateRequired).unwrap();
        assert!(matches!(
            reader.check_transparent_policy_generation(captured.generation),
            Err(SqliteClientError::StaleTransparentPolicy {
                expected: 0,
                applied: 1,
            })
        ));
        // The open handle's in-memory configuration is unchanged, but it resolves to the
        // policy the other connection applied, at its next read.
        assert_eq!(reader.transparent_ledger_mode, Some(Public));
        assert_eq!(reader.transparent_ledger_mode().unwrap(), PrivateRequired);
        assert_eq!(
            reader.applied_transparent_policy().unwrap(),
            zcash_client_backend::data_api::transparent_ledger::AppliedTransparentPolicy {
                mode: PrivateRequired,
                generation: 1,
            }
        );
        assert!(
            !crate::wallet::transparent_ledger::public_discovery_permitted(
                &reader.conn,
                reader.transparent_ledger_mode
            )
            .unwrap()
        );
        assert!(matches!(
            crate::wallet::transparent_ledger::check_public_discovery(
                &reader.conn,
                reader.transparent_ledger_mode
            ),
            Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
        ));

        // Only an explicit transition lowers the policy; the reader then resolves to its own
        // configured mode again, under the new generation.
        writer.apply_transparent_policy(Public).unwrap();
        assert_eq!(reader.transparent_ledger_mode().unwrap(), Public);
        assert_eq!(reader.applied_transparent_policy().unwrap().generation, 2);
    }

    #[test]
    fn weaker_handle_reads_never_write_or_lower_the_durable_policy() {
        use crate::testing::db::{test_clock, test_rng};
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(PrivateRequired);
        WalletMigrator::new().init_or_migrate(&mut writer).unwrap();
        writer.apply_transparent_policy(PrivateRequired).unwrap();
        let mut reader =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(Public);
        let changes = || {
            let conn = rusqlite::Connection::open(file.path()).unwrap();
            conn.query_row(
                "SELECT applied_mode, policy_generation FROM tpir_meta",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap()
        };
        let before = changes();
        for _ in 0..3 {
            assert_eq!(reader.transparent_ledger_mode().unwrap(), PrivateRequired);
            reader.applied_transparent_policy().unwrap();
            reader.pending_private_transparent_details().unwrap();
        }
        assert_eq!(changes(), before);
        // A weaker handle reads under the durable policy but grants no authority under it.
        assert!(
            !crate::wallet::transparent_ledger::grants_private_authority(
                &reader.conn,
                reader.transparent_ledger_mode
            )
            .unwrap()
        );
        reader.set_transparent_ledger_mode(PrivateShadow);
        assert!(
            !crate::wallet::transparent_ledger::grants_private_authority(
                &reader.conn,
                reader.transparent_ledger_mode
            )
            .unwrap()
        );
        assert_eq!(changes(), before);
    }

    #[test]
    fn unreadable_policy_fails_closed_for_every_configured_handle() {
        use crate::testing::db::{test_clock, test_rng};
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        // Unconfigured fails before reading.
        assert!(matches!(
            db.transparent_ledger_mode(),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
        // A corrupt mode code fails every configured handle, whatever its mode.
        db.conn
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE tpir_meta SET applied_mode = 9;
                 PRAGMA ignore_check_constraints = OFF;",
            )
            .unwrap();
        for mode in [Public, PrivateShadow, PrivateRequired] {
            db.set_transparent_ledger_mode(mode);
            assert!(
                matches!(
                    db.transparent_ledger_mode(),
                    Err(SqliteClientError::CorruptedData(_))
                ),
                "{mode:?}"
            );
        }
        // So does a missing policy row.
        db.conn.execute("DELETE FROM tpir_meta", []).unwrap();
        for mode in [Public, PrivateShadow, PrivateRequired] {
            db.set_transparent_ledger_mode(mode);
            assert!(
                matches!(
                    db.transparent_ledger_mode(),
                    Err(SqliteClientError::CorruptedData(_))
                ),
                "{mode:?}"
            );
            assert!(matches!(
                db.applied_transparent_policy(),
                Err(SqliteClientError::CorruptedData(_))
            ));
        }
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn parent_retrieval_is_withheld_under_private_required() {
        use zcash_client_backend::data_api::{
            PublicTransactionEnhancementRequest,
            enhance_pir::{EnhancePirRead, TransactionEnhancementWork},
            transparent_ledger::PrivateTransparentDetail,
        };
        let (mut st, _taddr, funded) = funded_wallet();
        let account = st.test_account().unwrap().id();
        let parent = zcash_primitives::transaction::TxId::from_bytes([0x11; 32]);
        let child = zcash_primitives::transaction::TxId::from_bytes(*funded.hash());
        let child_ref: i64 = conn(&st)
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [child.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        // Queue a parent-transaction retrieval under public authority.
        let tx = conn(&st).unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(
            &tx,
            std::iter::once(parent),
            Some(crate::TxRef(child_ref)),
        )
        .unwrap();
        tx.commit().unwrap();
        st.wallet_mut().db_mut().set_enhancement_mode(
            zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard,
        );
        let public =
            TransactionEnhancementWork::Public(PublicTransactionEnhancementRequest::new(parent));
        assert!(
            st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .contains(&public)
        );

        set_mode(&mut st, PrivateRequired);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();
        assert!(
            st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            st.wallet()
                .db()
                .pending_private_transparent_details()
                .unwrap(),
            vec![PrivateTransparentDetail::ParentTransaction { txid: parent }]
        );
        // The obligation stays queued under its stable identity while current policy controls
        // whether it may be dispatched publicly.
        let still_queued: bool = conn(&st)
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM tx_retrieval_queue WHERE txid = ?1 AND query_type = 1)",
                [parent.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(still_queued);
        let notes: i64 = conn(&st)
            .query_row(
                "SELECT COUNT(*) FROM transparent_received_outputs WHERE account_id = (
                     SELECT id FROM accounts WHERE uuid = ?1)",
                [account.0],
                |row| row.get(0),
            )
            .unwrap();
        assert!(notes > 0);
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn stale_generation_is_restamped_after_public_to_private_shadow() {
        use zcash_client_backend::data_api::{
            PublicTransactionEnhancementRequest,
            enhance_pir::{EnhancePirRead, TransactionEnhancementWork},
        };
        let (mut st, _, _) = funded_wallet();
        let stale = zcash_primitives::transaction::TxId::from_bytes([0x22; 32]);
        let fresh = zcash_primitives::transaction::TxId::from_bytes([0x33; 32]);
        let tx = conn(&st).unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(&tx, std::iter::once(stale), None).unwrap();
        tx.commit().unwrap();
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateShadow)
            .unwrap();
        set_mode(&mut st, PrivateShadow);
        let tx = conn(&st).unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(&tx, std::iter::once(fresh), None).unwrap();
        tx.commit().unwrap();
        st.wallet_mut().db_mut().set_enhancement_mode(
            zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard,
        );
        let work = st.wallet().transaction_enhancement_work().unwrap();
        assert!(work.contains(&TransactionEnhancementWork::Public(
            PublicTransactionEnhancementRequest::new(stale)
        )));
        assert!(work.contains(&TransactionEnhancementWork::Public(
            PublicTransactionEnhancementRequest::new(fresh)
        )));
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn private_required_withholds_queue_rows_and_reports_lwd() {
        use zcash_client_backend::data_api::{
            PublicTransactionEnhancementRequest,
            enhance_pir::{EnhancePirRead, TransactionEnhancementWork},
            transparent_ledger::PrivateTransparentDetail,
        };
        let (mut st, _, _) = funded_wallet();
        let lwd = zcash_primitives::transaction::TxId::from_bytes([0x61; 32]);
        conn(&st)
            .execute(
                "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, 1)",
                [lwd.as_ref()],
            )
            .unwrap();
        let tx_ref: i64 = conn(&st)
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [lwd.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        conn(&st)
            .execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 1)",
                [tx_ref],
            )
            .unwrap();
        let tx = conn(&st).unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(&tx, std::iter::once(lwd), None).unwrap();
        tx.commit().unwrap();

        set_mode(&mut st, PrivateRequired);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();
        st.wallet_mut().db_mut().set_enhancement_mode(
            zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard,
        );

        let queued: i64 = conn(&st)
            .query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queued, 1);
        let route: i64 = conn(&st)
            .query_row(
                "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = ?1",
                [tx_ref],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(route, 2);
        assert!(
            st.wallet()
                .db()
                .pending_private_transparent_details()
                .unwrap()
                .contains(&PrivateTransparentDetail::MixedTransaction { txid: lwd })
        );

        set_mode(&mut st, Public);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(Public)
            .unwrap();
        assert!(
            st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .contains(&TransactionEnhancementWork::Public(
                    PublicTransactionEnhancementRequest::new(lwd)
                ))
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn handle_only_private_required_route_two_is_public_again_after_handle_switch() {
        use zcash_client_backend::data_api::{
            PublicTransactionEnhancementRequest,
            enhance_pir::{EnhancePirRead, TransactionEnhancementWork},
        };
        let (mut st, _, _) = funded_wallet();
        let mixed = zcash_primitives::transaction::TxId::from_bytes([0x62; 32]);
        conn(&st)
            .execute(
                "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, 1)",
                [mixed.as_ref()],
            )
            .unwrap();
        let tx_ref: i64 = conn(&st)
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [mixed.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        // Durable policy stays Public; only the handle is PrivateRequired when routing.
        set_mode(&mut st, PrivateRequired);
        conn(&st)
            .execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
                [tx_ref],
            )
            .unwrap();
        let tx = conn(&st).unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(&tx, std::iter::once(mixed), None).unwrap();
        tx.commit().unwrap();
        st.wallet_mut().db_mut().set_enhancement_mode(
            zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard,
        );
        assert!(
            !st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .contains(&TransactionEnhancementWork::Public(
                    PublicTransactionEnhancementRequest::new(mixed)
                ))
        );

        // Switching the handle back to Public (no durable mode change) must expose LWD work.
        set_mode(&mut st, Public);
        assert!(
            st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .contains(&TransactionEnhancementWork::Public(
                    PublicTransactionEnhancementRequest::new(mixed)
                ))
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn restoring_public_authority_requeues_unresolved_mixed_details() {
        use zcash_client_backend::data_api::{
            PublicTransactionEnhancementRequest,
            enhance_pir::{EnhancePirRead, TransactionEnhancementWork},
        };
        let (mut st, _, _) = funded_wallet();
        let mixed = zcash_primitives::transaction::TxId::from_bytes([0x52; 32]);
        conn(&st)
            .execute(
                "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, 1)",
                [mixed.as_ref()],
            )
            .unwrap();
        let tx_ref: i64 = conn(&st)
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [mixed.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        // Sticky route 2 under PrivateRequired; no raw means details remain pending.
        conn(&st)
            .execute(
                "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
                [tx_ref],
            )
            .unwrap();
        set_mode(&mut st, PrivateRequired);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(PrivateRequired)
            .unwrap();
        st.wallet_mut().db_mut().set_enhancement_mode(
            zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard,
        );
        assert!(
            st.wallet()
                .db()
                .pending_private_transparent_details()
                .unwrap()
                .contains(
                    &zcash_client_backend::data_api::transparent_ledger::PrivateTransparentDetail::MixedTransaction {
                        txid: mixed,
                    }
                )
        );
        assert!(
            !st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .contains(&TransactionEnhancementWork::Public(
                    PublicTransactionEnhancementRequest::new(mixed)
                ))
        );

        set_mode(&mut st, Public);
        st.wallet_mut()
            .db_mut()
            .apply_transparent_policy(Public)
            .unwrap();
        let route: i64 = conn(&st)
            .query_row(
                "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = ?1",
                [tx_ref],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(route, 1);
        assert!(
            st.wallet()
                .transaction_enhancement_work()
                .unwrap()
                .contains(&TransactionEnhancementWork::Public(
                    PublicTransactionEnhancementRequest::new(mixed)
                ))
        );
        assert!(
            st.wallet()
                .db()
                .pending_private_transparent_details()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn status_work_requires_ledger_mode_even_without_a_chain_tip() {
        use zcash_client_backend::data_api::status::{
            TransactionStatusMode, TransactionStatusRead,
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new().init_or_migrate(&mut db).unwrap();
        db.set_status_mode(TransactionStatusMode::Public);
        assert!(matches!(
            db.transaction_status_work(),
            Err(SqliteClientError::TransparentLedgerModeNotConfigured)
        ));
        db.set_transparent_ledger_mode(Public);
        assert!(db.transaction_status_work().unwrap().is_empty());
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn public_dispatch_does_not_mix_stale_authority_with_new_generation() {
        use std::time::Duration;
        use zcash_client_backend::data_api::{
            PublicTransactionEnhancementRequest,
            enhance_pir::{EnhancementMode, TransactionEnhancementWork},
            status::{
                PublicTransactionStatusRequest, TransactionStatusMode, TransactionStatusWork,
            },
        };

        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(Public);
        WalletMigrator::new().init_or_migrate(&mut writer).unwrap();
        writer.conn.busy_timeout(Duration::from_secs(2)).unwrap();
        let journal: String = writer
            .conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal.to_lowercase(), "wal");

        let stale = zcash_primitives::transaction::TxId::from_bytes([0x41; 32]);
        let fresh = zcash_primitives::transaction::TxId::from_bytes([0x42; 32]);
        let tx = writer.conn.unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(&tx, std::iter::once(stale), None).unwrap();
        crate::wallet::queue_tx_status(&tx, stale).unwrap();
        tx.commit().unwrap();

        let reader =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(Public);
        reader.conn.busy_timeout(Duration::from_secs(2)).unwrap();

        // Pin a snapshot after public authority is observed, then transition on another
        // connection. Dispatch on the snapshot must not emit work stamped at the new
        // generation as public.
        let snapshot = reader.conn.unchecked_transaction().unwrap();
        assert!(
            crate::wallet::transparent_ledger::retains_public_authority(&snapshot, Some(Public))
                .unwrap()
        );

        writer.apply_transparent_policy(PrivateRequired).unwrap();
        let tx = writer.conn.unchecked_transaction().unwrap();
        crate::wallet::queue_tx_retrieval(&tx, std::iter::once(fresh), None).unwrap();
        crate::wallet::queue_tx_status(&tx, fresh).unwrap();
        tx.commit().unwrap();

        let enhancement = crate::wallet::enhance_pir::transaction_enhancement_work(
            &snapshot,
            EnhancementMode::Standard,
            Some(Public),
        )
        .unwrap();
        assert!(enhancement.contains(&TransactionEnhancementWork::Public(
            PublicTransactionEnhancementRequest::new(stale)
        )));
        assert!(!enhancement.contains(&TransactionEnhancementWork::Public(
            PublicTransactionEnhancementRequest::new(fresh)
        )));

        let status = crate::wallet::transaction_status_work(
            &snapshot,
            TransactionStatusMode::Public,
            Some(Public),
        )
        .unwrap();
        assert!(status.contains(&TransactionStatusWork::Public(
            PublicTransactionStatusRequest::new(stale)
        )));
        assert!(!status.contains(&TransactionStatusWork::Public(
            PublicTransactionStatusRequest::new(fresh)
        )));

        snapshot.commit().unwrap();

        // After the snapshot, the still-`Public` handle resolves to the applied
        // `PrivateRequired` policy: neither transaction is public work any longer.
        let enhancement = crate::wallet::enhance_pir::transaction_enhancement_work(
            &reader.conn,
            EnhancementMode::Standard,
            Some(Public),
        )
        .unwrap();
        assert!(
            !enhancement
                .iter()
                .any(|work| matches!(work, TransactionEnhancementWork::Public(_))),
            "{enhancement:?}"
        );
        let status = crate::wallet::transaction_status_work(
            &reader.conn,
            TransactionStatusMode::Public,
            Some(Public),
        )
        .unwrap();
        assert!(
            !status
                .iter()
                .any(|work| matches!(work, TransactionStatusWork::Public(_))),
            "{status:?}"
        );
    }

    #[test]
    fn commit_with_old_generation_inserts_nothing() {
        use crate::testing::db::{test_clock, test_rng};
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap()
                .with_transparent_ledger_mode(Public);
        WalletMigrator::new().init_or_migrate(&mut writer).unwrap();
        let old_generation = writer.applied_transparent_policy().unwrap().generation;
        writer.apply_transparent_policy(PrivateShadow).unwrap();

        // Simulate a commit path that captured the old generation before the transition.
        assert!(matches!(
            writer.check_transparent_policy_generation(old_generation),
            Err(SqliteClientError::StaleTransparentPolicy { .. })
        ));
        let before: i64 = writer
            .conn
            .query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        let tx = writer.conn.unchecked_transaction().unwrap();
        // Direct insert attempt after a concurrent transition: ensure_policy_generation fails.
        let result = (|| {
            crate::wallet::transparent_ledger::ensure_policy_generation(&tx, old_generation)?;
            crate::wallet::queue_tx_retrieval(
                &tx,
                std::iter::once(zcash_primitives::transaction::TxId::from_bytes([9; 32])),
                None,
            )
        })();
        assert!(matches!(
            result,
            Err(SqliteClientError::StaleTransparentPolicy { .. })
        ));
        tx.rollback().unwrap();
        let after: i64 = writer
            .conn
            .query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(before, after);
    }
}

mod transaction_inputs;
