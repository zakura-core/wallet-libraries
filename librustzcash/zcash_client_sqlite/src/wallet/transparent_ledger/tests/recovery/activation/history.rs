//! History completeness: owned effects, payment details, fees, and classification.

use zcash_client_backend::data_api::transparent_ledger::{
    AggregatePayment, DetailCompleteness, EffectCompleteness, FeeState, HistoryClassification,
    PoolEffect, PrivateTransparentDetail, TransactionFunding, TransactionHistoryDetails,
    TransactionMetadata, WholeTransactionFee,
};
use zcash_protocol::PoolType;

use super::*;

fn history(st: &State, account: AccountUuid, txid: TxId) -> TransactionHistoryDetails {
    let mut entries = st
        .wallet()
        .db()
        .transaction_history_details(account, &[txid])
        .unwrap();
    assert_eq!(entries.len(), 1, "expected one entry for {txid}");
    entries.remove(0)
}

fn effect(entry: &TransactionHistoryDetails, pool: PoolType) -> PoolEffect {
    *entry.effects.iter().find(|e| e.pool == pool).unwrap()
}

fn transparent(entry: &TransactionHistoryDetails) -> PoolEffect {
    effect(entry, PoolType::Transparent)
}

fn sapling(entry: &TransactionHistoryDetails) -> PoolEffect {
    effect(entry, PoolType::SAPLING)
}

fn zat(value: u64) -> Zatoshis {
    Zatoshis::const_from_u64(value)
}

/// Covers only `address` of `account` through the target, with `receives`.
fn cover_one(
    st: &mut State,
    account: AccountUuid,
    address: TransparentAddress,
    receives: Vec<ReceiveEvent>,
    spends: Vec<SpendEvent>,
) {
    let ws = watch(st, account);
    let mut c = commit(&ws);
    c.receives = receives;
    c.spends = spends;
    c.coverage = full_coverage(&ws)
        .into_iter()
        .filter(|range| range.address == address)
        .collect();
    apply(st, c).unwrap();
}

#[test]
fn every_supported_pool_has_an_entry_and_other_transactions_are_omitted() {
    let (st, account, unspent) = active_wallet();
    let unrelated = TxId::from_bytes([0xee; 32]);
    let entries = st
        .wallet()
        .db()
        .transaction_history_details(account, &[unrelated, *unspent.outpoint.txid()])
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].funding, TransactionFunding::NotFunded);
    assert_eq!(
        entries[0]
            .effects
            .iter()
            .map(|e| e.pool)
            .collect::<Vec<_>>(),
        vec![
            PoolType::Transparent,
            PoolType::SAPLING,
            #[cfg(feature = "orchard")]
            PoolType::ORCHARD,
            #[cfg(feature = "orchard")]
            PoolType::IRONWOOD,
        ]
    );

    // Another account sees none of this account's transactions.
    let mut st = st;
    let other = import_account(&mut st, 9);
    assert_eq!(
        st.wallet()
            .db()
            .transaction_history_details(other, &[*unspent.outpoint.txid()])
            .unwrap(),
        vec![]
    );
}

#[test]
fn private_transparent_effects_follow_ledger_coverage() {
    let (mut st, account, unspent) = active_wallet();

    // A receive within the active ledger's coverage is complete.
    let entry = history(&st, account, *unspent.outpoint.txid());
    assert_eq!(entry.mined_height, Some(unspent.mined_height));
    assert_eq!(
        transparent(&entry),
        PoolEffect {
            pool: PoolType::Transparent,
            received: zat(40_000),
            spent: Zatoshis::ZERO,
            completeness: EffectCompleteness::Complete,
        }
    );
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.fee, FeeState::NotApplicable);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
    assert_eq!(entry.pending_private_details, vec![]);

    // A newer receive, while another watched address is not yet covered through its height, is
    // known but incomplete: the account may have spent in it too, so its fee is unknown.
    let ws = watch(&st, account);
    let address = external(&ws);
    let fresh = receive(5, address, 60_000, below_target(&ws, 0));
    cover_one(&mut st, account, address, vec![fresh.clone()], vec![]);
    let entry = history(&st, account, *fresh.outpoint.txid());
    assert_eq!(transparent(&entry).received, zat(60_000));
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::Incomplete
    );
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);

    // Covering every address completes it, under the same transaction identity.
    cover(&mut st, account, &revision(1, true), vec![]);
    let entry = history(&st, account, *fresh.outpoint.txid());
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::Complete
    );
    assert_eq!(entry.fee, FeeState::NotApplicable);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
}

#[test]
fn a_debit_with_change_and_no_known_recipient_stays_visible() {
    let (mut st, account, unspent) = active_wallet();
    // A seed-restored payment from the account's transparent funds: the ledger recovers the
    // spend and the change, but not the external recipient or the fee.
    let ws = watch(&st, account);
    let at = below_target(&ws, 0);
    let payment = spend(6, &unspent, at);
    let change = ReceiveEvent {
        outpoint: OutPoint::new([6; 32], 1),
        ..receive(6, external(&ws), 15_000, at)
    };
    let mut c = commit(&ws);
    c.receives = vec![change];
    c.spends = vec![payment.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    cover(&mut st, account, &revision(1, true), vec![]);

    let entry = history(&st, account, payment.spending_txid);
    assert_eq!(
        transparent(&entry),
        PoolEffect {
            pool: PoolType::Transparent,
            received: zat(15_000),
            spent: zat(40_000),
            completeness: EffectCompleteness::Complete,
        }
    );
    // Every owned effect is known, but the recipients are not, and the fee is unknown rather
    // than zero. Nothing is queued, which does not make the details complete.
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.pending_private_details, vec![]);
    assert_eq!(entry.funding, TransactionFunding::Undetermined);
    assert_eq!(
        st.wallet()
            .db()
            .pending_private_transparent_details()
            .unwrap(),
        vec![]
    );
}

#[test]
fn transaction_metadata_establishes_payment_only_for_complete_sole_funding() {
    for (inputs, shielded, fee, expected) in [
        (
            1,
            false,
            WholeTransactionFee::Exact(zat(1_000)),
            AggregatePayment::Exact(zat(24_000)),
        ),
        (
            1,
            false,
            WholeTransactionFee::Exact(zat(0)),
            AggregatePayment::Exact(zat(25_000)),
        ),
        (
            2,
            false,
            WholeTransactionFee::Exact(zat(1_000)),
            AggregatePayment::Unknown,
        ),
        (
            1,
            true,
            WholeTransactionFee::Exact(zat(1_000)),
            AggregatePayment::Unknown,
        ),
        (
            1,
            false,
            WholeTransactionFee::Unknown,
            AggregatePayment::Unknown,
        ),
    ] {
        let (mut st, account, unspent) = active_wallet();
        let ws = watch(&st, account);
        let at = below_target(&ws, 0);
        let metadata = TransactionMetadata {
            fee,
            transparent_input_count: inputs,
            has_shielded_components: shielded,
        };
        let mut payment = spend(6, &unspent, at);
        payment.metadata = Some(metadata);
        let change = ReceiveEvent {
            outpoint: OutPoint::new([6; 32], 1),
            metadata: Some(metadata),
            ..receive(6, external(&ws), 15_000, at)
        };
        let mut c = commit(&ws);
        c.receives = vec![change];
        c.spends = vec![payment.clone()];
        c.coverage = full_coverage(&ws);
        apply(&mut st, c).unwrap();
        let entry = history(&st, account, payment.spending_txid);
        assert_eq!(entry.aggregate_payment, expected);
        assert!(
            st.wallet()
                .get_transaction(payment.spending_txid)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            entry.funding,
            if inputs > 1 {
                TransactionFunding::Shared
            } else if shielded {
                TransactionFunding::Undetermined
            } else {
                TransactionFunding::Sole
            }
        );
        let evidence = entry.transaction_metadata.unwrap();
        assert_eq!(evidence.metadata, metadata);
        assert_eq!(evidence.provenance.len(), 1);
        assert_eq!(evidence.provenance[0].source, b"fixture");
        assert_eq!(evidence.provenance[0].revision, b"r1");
        assert_eq!(entry.account_movement.net(), -25_000);
        assert!(entry.account_movement.complete);
        assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
        assert_eq!(
            entry.fee,
            if inputs == 1 && !shielded {
                match fee {
                    WholeTransactionFee::Exact(f) => FeeState::Known(f),
                    _ => FeeState::Unknown,
                }
            } else {
                FeeState::Unknown
            }
        );
        assert_eq!(
            conn(&st)
                .query_row(
                    "SELECT min_reader_version FROM tpir_meta WHERE id = 0",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            7
        );
    }
}

#[test]
fn metadata_funding_requires_complete_owned_effects() {
    for inputs in [1, 2] {
        let (mut st, account, unspent) = active_wallet();
        let ws = watch(&st, account);
        let mut payment = spend(6, &unspent, below_target(&ws, 0));
        payment.metadata = Some(TransactionMetadata {
            fee: WholeTransactionFee::Exact(zat(1_000)),
            transparent_input_count: inputs,
            has_shielded_components: false,
        });
        cover_one(
            &mut st,
            account,
            external(&ws),
            vec![],
            vec![payment.clone()],
        );

        let entry = history(&st, account, payment.spending_txid);
        assert_eq!(
            transparent(&entry).completeness,
            EffectCompleteness::Incomplete
        );
        assert_eq!(entry.funding, TransactionFunding::Undetermined);
        assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);

        cover(&mut st, account, &revision(1, true), vec![]);
        let entry = history(&st, account, payment.spending_txid);
        assert_eq!(
            transparent(&entry).completeness,
            EffectCompleteness::Complete
        );
        assert_eq!(
            entry.funding,
            if inputs == 1 {
                TransactionFunding::Sole
            } else {
                TransactionFunding::Shared
            }
        );
    }
}

#[test]
fn conflicting_metadata_rejects_the_commit_and_preserves_existing_evidence() {
    let (mut st, account, unspent) = active_wallet();
    let ws = watch(&st, account);
    let at = below_target(&ws, 0);
    let metadata = TransactionMetadata {
        fee: WholeTransactionFee::Exact(zat(1_000)),
        transparent_input_count: 1,
        has_shielded_components: false,
    };
    let mut payment = spend(6, &unspent, at);
    payment.metadata = Some(metadata);
    let mut c = commit(&ws);
    c.spends = vec![payment.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let original = history(&st, account, payment.spending_txid);
    let mut c = commit(&watch(&st, account));
    let mut contradiction = payment;
    contradiction.metadata.as_mut().unwrap().fee = WholeTransactionFee::Exact(zat(2_000));
    c.spends = vec![contradiction];
    c.receives = vec![receive(77, external(&ws), 5_000, at)];
    assert_eq!(
        rejected(&mut st, c),
        CommitRejection::Integrity(IntegrityFailure::TransactionMetadata(TxId::from_bytes(
            [6; 32]
        )))
    );
    assert_eq!(history(&st, account, TxId::from_bytes([6; 32])), original);
    assert!(
        st.wallet()
            .db()
            .transaction_history_details(account, &[TxId::from_bytes([77; 32])])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn candidate_metadata_survives_reopen_without_granting_authority() {
    let (mut st, account) = shadow_wallet();
    let ws = watch(&st, account);
    let at = below_target(&ws, 0);
    let metadata = TransactionMetadata {
        fee: WholeTransactionFee::Exact(zat(0)),
        transparent_input_count: 1,
        has_shielded_components: false,
    };
    let legacy = receive(81, external(&ws), 40_000, at - 1);
    let mut change = receive(82, external(&ws), 15_000, at);
    change.metadata = Some(metadata);
    let mut payment = spend(82, &legacy, at);
    payment.metadata = Some(metadata);
    let mut c = commit(&ws);
    c.receives = vec![legacy, change];
    c.spends = vec![payment];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();
    let before = recovery(&st, account);
    assert_eq!(before.receives[0].metadata, None);
    assert_eq!(before.receives[1].metadata, Some(metadata));
    assert_eq!(before.spends[0].metadata, Some(metadata));
    assert_eq!(count(&st, "tpir_qualified_revisions"), 0);
    assert_eq!(count(&st, "tpir_active_accounts"), 0);

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reopened.sqlite");
    conn(&st)
        .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
        .unwrap();
    let reopened = crate::WalletDb::from_connection(
        Connection::open(path).unwrap(),
        *st.network(),
        crate::util::SystemClock,
        zcash_client_backend::data_api::testing::TestRng::seed_from_u64(0),
    )
    .with_transparent_ledger_mode(PrivateShadow);
    assert_eq!(
        reopened.transparent_candidate_recovery(account).unwrap(),
        before
    );
    assert_eq!(
        reopened.transparent_watch_set(account).unwrap().lifecycle,
        zcash_client_backend::data_api::transparent_ledger::AccountLifecycle::Candidate
    );
}

#[test]
fn a_spend_of_an_unrecovered_output_is_incomplete() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    // The spent output was never recovered, so the spend's value is unknown.
    let missing = receive(7, external(&ws), 10_000, below_target(&ws, 1));
    let payment = spend(8, &missing, below_target(&ws, 0));
    let change = ReceiveEvent {
        outpoint: OutPoint::new([8; 32], 1),
        ..receive(8, external(&ws), 5_000, below_target(&ws, 0))
    };
    let mut c = commit(&ws);
    c.receives = vec![change];
    c.spends = vec![payment.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    let entry = history(&st, account, payment.spending_txid);
    assert_eq!(transparent(&entry).received, zat(5_000));
    assert_eq!(transparent(&entry).spent, Zatoshis::ZERO);
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::Incomplete
    );
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.funding, TransactionFunding::Undetermined);
}

#[test]
fn public_rows_are_unverified_and_incomplete_once_private_authority_applies() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    let address = external(&watch(&st, account));
    let outpoint = OutPoint::new([0x42; 32], 0);
    super::super::super::put_public_utxo(&mut st, &address, outpoint.clone(), 70_000);
    let txid = *outpoint.txid();

    // Public discovery holds authority: the receive is treated as settled but not verified.
    let entry = history(&st, account, txid);
    assert_eq!(
        transparent(&entry),
        PoolEffect {
            pool: PoolType::Transparent,
            received: zat(70_000),
            spent: Zatoshis::ZERO,
            completeness: EffectCompleteness::PublicDiscovery,
        }
    );
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.fee, FeeState::NotApplicable);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);

    // Under `PrivateRequired`, the candidate account's legacy row is no longer authoritative.
    set_policy(&mut st, PrivateRequired);
    let entry = history(&st, account, txid);
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::Incomplete
    );
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
}

fn check_local_intent_survives_discovery(with_metadata: bool) {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    // A shielded-funded payment to the account's own transparent address.
    let taddr = external(&watch(&st, account));
    let (txid, output_index) = pay_from_sapling(&mut st, taddr, 50_000);
    let fee: i64 = conn(&st)
        .query_row(
            "SELECT fee FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    let fee = Zatoshis::from_nonnegative_i64(fee).unwrap();

    let local = history(&st, account, txid);
    assert_eq!(local.mined_height, None);
    assert_eq!(local.classification, HistoryClassification::LocalIntent);
    assert_eq!(local.payment_details, DetailCompleteness::Complete);
    assert_eq!(local.fee, FeeState::Known(fee));
    assert!(
        local
            .effects
            .iter()
            .all(|e| e.completeness == EffectCompleteness::Complete)
    );
    assert_eq!(transparent(&local).received, zat(50_000));
    assert_eq!(sapling(&local).spent, zat(200_000));
    assert_eq!(
        (sapling(&local).received + zat(50_000) + fee).unwrap(),
        zat(200_000)
    );

    // The private ledger then recovers the output as mined, and the account is promoted.
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let recovered = ReceiveEvent {
        metadata: with_metadata.then_some(TransactionMetadata {
            fee: WholeTransactionFee::Exact(fee),
            transparent_input_count: 0,
            has_shielded_components: true,
        }),
        outpoint: OutPoint::new(*txid.as_ref(), output_index),
        address: taddr,
        value: zat(50_000),
        coinbase: false,
        mined_height: below_target(&ws, 0),
    };
    cover(&mut st, account, &fixture, vec![recovered.clone()]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();

    // The local record is kept: only the placement changed.
    let discovered = history(&st, account, txid);
    assert_eq!(discovered.fee, FeeState::Known(fee));
    assert_eq!(
        discovered.transaction_metadata.as_ref().map(|e| e.metadata),
        recovered.metadata
    );
    assert_eq!(
        discovered,
        TransactionHistoryDetails {
            mined_height: Some(recovered.mined_height),
            transaction_metadata: discovered.transaction_metadata.clone(),
            ..local
        }
    );
}

#[test]
fn local_intent_survives_discovery_of_the_same_transaction() {
    check_local_intent_survives_discovery(false);
}

#[test]
fn local_intent_and_fee_survive_mixed_transaction_metadata() {
    check_local_intent_survives_discovery(true);
}

#[test]
fn cross_account_transfers_report_each_side() {
    let (mut st, accounts) = shadow_wallet_with(1);
    let (sender, recipient) = (accounts[0], accounts[1]);
    let to = external(&watch(&st, recipient));
    let (txid, _) = pay_from_sapling(&mut st, to, 30_000);

    let sent = history(&st, sender, txid);
    assert_eq!(sent.classification, HistoryClassification::LocalIntent);
    assert!(matches!(sent.fee, FeeState::Known(_)));
    assert_eq!(transparent(&sent).received, Zatoshis::ZERO);

    let received = history(&st, recipient, txid);
    assert_eq!(received.classification, HistoryClassification::LocalIntent);
    assert_eq!(transparent(&received).received, zat(30_000));
    assert_eq!(sapling(&received).spent, Zatoshis::ZERO);
    assert_eq!(received.fee, FeeState::NotApplicable);
}

#[test]
fn a_rewind_reopens_completeness_until_recovered_again() {
    let (mut st, account, unspent) = active_wallet();
    let txid = *unspent.outpoint.txid();
    assert_eq!(
        history(&st, account, txid).classification,
        HistoryClassification::Reconstructed
    );

    let floor = unspent.mined_height - 1;
    st.truncate_to_height(floor);
    let entry = history(&st, account, txid);
    assert_eq!(entry.mined_height, None);
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::Incomplete
    );
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Incomplete);
    assert_eq!(entry.classification, HistoryClassification::Provisional);

    // Re-mined on the replacement chain and recovered, the transaction is complete again.
    scan_new_blocks(&mut st, 3);
    let remined = ReceiveEvent {
        mined_height: floor + 2,
        ..unspent.clone()
    };
    cover(&mut st, account, &revision(1, true), vec![remined.clone()]);
    let entry = history(&st, account, txid);
    assert_eq!(entry.mined_height, Some(remined.mined_height));
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
}

#[test]
fn shielded_effects_follow_the_contiguously_scanned_height() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = st.test_account().cloned().unwrap();
    assert_eq!(account.id(), accounts[0]);
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let dfvk = account.usk().sapling().to_diversifiable_full_viewing_key();

    // A gap block, then a block paying the account; only the second is scanned.
    let (gap, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, zat(10_000));
    let (paid, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, zat(80_000));
    st.scan_cached_blocks(paid, 1);
    let txid: TxId = conn(&st)
        .query_row(
            "SELECT t.txid FROM sapling_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.mined_height = ?1",
            [u32::from(paid)],
            |row| row.get::<_, [u8; 32]>(0).map(TxId::from_bytes),
        )
        .unwrap();

    let entry = history(&st, account.id(), txid);
    assert_eq!(sapling(&entry).received, zat(80_000));
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);

    // Scanning the gap makes the scanned chain contiguous through the payment. Compact scanning
    // does not retrieve the memo, so only the payment details stay incomplete.
    st.scan_cached_blocks(gap, 1);
    let entry = history(&st, account.id(), txid);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert_eq!(entry.fee, FeeState::NotApplicable);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
}

#[test]
fn pending_private_details_belong_to_their_transaction() {
    let (mut st, account, unspent) = active_wallet();
    let txid = *unspent.outpoint.txid();
    let id: i64 = conn(&st)
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (?1, 2)",
            [id],
        )
        .unwrap();
    conn(&st)
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type, dependent_transaction_id)
             VALUES (?1, 1, ?2)",
            rusqlite::params![[9u8; 32], id],
        )
        .unwrap();

    let entry = history(&st, account, txid);
    assert_eq!(
        entry.pending_private_details,
        vec![
            PrivateTransparentDetail::ParentTransaction {
                txid: TxId::from_bytes([9; 32]),
            },
            PrivateTransparentDetail::MixedTransaction { txid },
        ]
    );
    // Another transaction has none of them.
    let ws = watch(&st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, 0));
    cover(&mut st, account, &revision(1, true), vec![fresh.clone()]);
    assert_eq!(
        history(&st, account, *fresh.outpoint.txid()).pending_private_details,
        vec![]
    );

    // Public authority withholds nothing.
    set_policy(&mut st, PrivateShadow);
    assert_eq!(history(&st, account, txid).pending_private_details, vec![]);
}

#[test]
fn history_requires_a_configured_handle_and_a_known_account() {
    let (mut st, account, unspent) = active_wallet();
    let txid = *unspent.outpoint.txid();
    assert!(matches!(
        st.wallet()
            .db()
            .transaction_history_details(AccountUuid::from_uuid(uuid::Uuid::nil()), &[txid]),
        Err(SqliteClientError::AccountUnknown)
    ));
    st.wallet_mut().db_mut().transparent_ledger_mode = None;
    assert!(matches!(
        st.wallet()
            .db()
            .transaction_history_details(account, &[txid]),
        Err(SqliteClientError::TransparentLedgerModeNotConfigured)
    ));
}

/// Pays an external transparent address from a fresh Sapling note, then erases the local
/// construction evidence, leaving what payload ingestion would store for a seed-restored send:
/// the full transaction, its fee, and the outputs the wallet can decrypt.
fn discovered_payment(st: &mut State) -> TxId {
    let external = TransparentAddress::PublicKeyHash([7; 20]);
    let (txid, _) = pay_from_sapling(st, external, 50_000);
    conn(st)
        .execute(
            "UPDATE transactions SET created = NULL, target_height = NULL WHERE txid = ?1",
            [txid.as_ref()],
        )
        .unwrap();
    txid
}

#[test]
fn full_data_completes_details_only_when_every_spent_unit_is_accounted_for() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    let txid = discovered_payment(&mut st);

    // The spend, the change, the recovered payment, and the fee account for every unit.
    let entry = history(&st, account, txid);
    assert_eq!(sapling(&entry).spent, zat(200_000));
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert!(matches!(entry.fee, FeeState::Known(_)));
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);

    // An output the wallet cannot decrypt, such as one sent with the outgoing viewing key
    // discarded, leaves a payment unknown although the full transaction is stored.
    conn(&st)
        .execute(
            "DELETE FROM sent_notes WHERE output_pool = 0
             AND transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?1)",
            [txid.as_ref()],
        )
        .unwrap();
    let entry = history(&st, account, txid);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert!(matches!(entry.fee, FeeState::Known(_)));
    assert_eq!(entry.classification, HistoryClassification::Provisional);
}

fn account_row(st: &State, account: AccountUuid) -> i64 {
    conn(st)
        .query_row(
            "SELECT id FROM accounts WHERE uuid = ?1",
            [account.expose_uuid()],
            |row| row.get(0),
        )
        .unwrap()
}

fn tx_row(st: &State, txid: TxId) -> i64 {
    conn(st)
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [txid.as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

const NONEMPTY_MEMO: [u8; 512] = [7; 512];
const EMPTY_MEMO: [u8; 1] = [0xf6];

fn set_sapling_memo(st: &State, tx: i64, output_index: i64, memo: Option<&[u8]>) {
    conn(st)
        .execute(
            "UPDATE sapling_received_notes SET memo = ?3
             WHERE transaction_id = ?1 AND output_index = ?2",
            rusqlite::params![tx, output_index, memo],
        )
        .unwrap();
}

/// Records output `(pool, output_index)` as sent by `from` to itself without its memo, as
/// scanning does for an output the account both sent and received.
fn record_sent_without_memo(
    st: &State,
    tx: i64,
    from: i64,
    pool: i64,
    output_index: i64,
    value: i64,
) {
    conn(st)
        .execute(
            "INSERT INTO sent_notes
                 (transaction_id, output_pool, output_index, from_account_id, to_account_id,
                  value, memo)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, NULL)
             ON CONFLICT (transaction_id, output_pool, output_index)
             DO UPDATE SET memo = NULL",
            rusqlite::params![tx, pool, output_index, from, value],
        )
        .unwrap();
}

#[test]
fn a_sent_output_memo_is_known_only_from_the_same_owned_receipt() {
    let (mut st, accounts) = shadow_wallet_with(1);
    let (account, other) = (accounts[0], accounts[1]);
    let (a, b) = (account_row(&st, account), account_row(&st, other));
    let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
    let dfvk = st
        .test_account()
        .unwrap()
        .usk()
        .sapling()
        .to_diversifiable_full_viewing_key();
    let receipt_at = |st: &State, height: BlockHeight| -> (TxId, i64, i64) {
        conn(st)
            .query_row(
                "SELECT t.txid, t.id_tx, n.output_index FROM sapling_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE t.mined_height = ?1",
                [u32::from(height)],
                |row| {
                    Ok((
                        row.get::<_, [u8; 32]>(0).map(TxId::from_bytes)?,
                        row.get(1)?,
                        row.get(2)?,
                    ))
                },
            )
            .unwrap()
    };

    // A receipt behind an unscanned gap, and another receipt.
    let (gap, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, zat(10_000));
    let (paid, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, zat(80_000));
    let (other_paid, _, _) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, zat(30_000));
    st.scan_cached_blocks(paid, 2);
    let (txid, tx, _) = receipt_at(&st, paid);
    let (_, other_tx, other_index) = receipt_at(&st, other_paid);
    // Keep this receipt's index apart from the other receipt's.
    let index = other_index + 1;
    conn(&st)
        .execute(
            "UPDATE sapling_received_notes SET output_index = ?2 WHERE transaction_id = ?1",
            rusqlite::params![tx, index],
        )
        .unwrap();

    // Both records of the output lack the memo.
    record_sent_without_memo(&st, tx, a, 2, index, 80_000);
    assert_eq!(
        history(&st, account, txid).payment_details,
        DetailCompleteness::Incomplete
    );

    // A retrieved receipt memo does not settle the effects behind the gap.
    set_sapling_memo(&st, tx, index, Some(&NONEMPTY_MEMO));
    let entry = history(&st, account, txid);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Incomplete);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);

    // Once settled, the receipt's memo is the sent row's memo; nothing else changes.
    st.scan_cached_blocks(gap, 1);
    let entry = history(&st, account, txid);
    assert_eq!(
        sapling(&entry),
        PoolEffect {
            pool: PoolType::SAPLING,
            received: zat(80_000),
            spent: Zatoshis::ZERO,
            completeness: EffectCompleteness::Complete,
        }
    );
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.fee, FeeState::NotApplicable);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
    conn(&st)
        .execute("DELETE FROM sent_notes WHERE transaction_id = ?1", [tx])
        .unwrap();
    assert_eq!(history(&st, account, txid), entry);
    record_sent_without_memo(&st, tx, a, 2, index, 80_000);

    // A known empty memo is a retrieved memo.
    set_sapling_memo(&st, tx, index, Some(&EMPTY_MEMO));
    assert_eq!(history(&st, account, txid), entry);

    // Both copies lacking the memo.
    set_sapling_memo(&st, tx, index, None);
    assert_eq!(
        history(&st, account, txid).payment_details,
        DetailCompleteness::Incomplete
    );
    set_sapling_memo(&st, tx, index, Some(&NONEMPTY_MEMO));

    // A memo-less sent row is resolved only by a receipt at its exact output.
    set_sapling_memo(&st, other_tx, other_index, Some(&NONEMPTY_MEMO));
    let resolved = |st: &State, pool: i64, output_index: i64| {
        conn(st)
            .execute(
                "UPDATE sent_notes SET output_pool = ?2, output_index = ?3
                 WHERE transaction_id = ?1",
                rusqlite::params![tx, pool, output_index],
            )
            .unwrap();
        history(st, account, txid).payment_details
    };
    // Another output index.
    assert_eq!(resolved(&st, 2, index + 1), DetailCompleteness::Incomplete);
    // Another pool.
    #[cfg(feature = "orchard")]
    assert_eq!(resolved(&st, 3, index), DetailCompleteness::Incomplete);
    // Another transaction's receipt at that output index.
    assert_eq!(
        resolved(&st, 2, other_index),
        DetailCompleteness::Incomplete
    );
    // Another account's receipt of that output.
    conn(&st)
        .execute(
            "INSERT INTO sapling_received_notes
                 (transaction_id, output_index, account_id, diversifier, value, rcm, is_change,
                  memo, commitment_tree_position, recipient_key_scope)
             SELECT transaction_id, ?2 + 1, ?3, diversifier, value, rcm, is_change,
                    ?4, commitment_tree_position, recipient_key_scope
             FROM sapling_received_notes WHERE transaction_id = ?1 AND output_index = ?2",
            rusqlite::params![tx, index, b, &NONEMPTY_MEMO[..]],
        )
        .unwrap();
    assert_eq!(resolved(&st, 2, index + 1), DetailCompleteness::Incomplete);
    // The exact receipt.
    assert_eq!(resolved(&st, 2, index), DetailCompleteness::Complete);

    // Another receipt of the account still lacking its memo.
    conn(&st)
        .execute(
            "INSERT INTO sapling_received_notes
                 (transaction_id, output_index, account_id, diversifier, value, rcm, is_change,
                  memo, commitment_tree_position, recipient_key_scope)
             SELECT transaction_id, ?2 + 2, account_id, diversifier, value, rcm, is_change,
                    NULL, commitment_tree_position, recipient_key_scope
             FROM sapling_received_notes WHERE transaction_id = ?1 AND output_index = ?2",
            rusqlite::params![tx, index],
        )
        .unwrap();
    assert_eq!(
        history(&st, account, txid).payment_details,
        DetailCompleteness::Incomplete
    );
}

#[test]
fn an_accounted_payment_takes_its_change_memo_from_the_owned_receipt() {
    let (mut st, accounts) = shadow_wallet_with(1);
    let (account, other) = (accounts[0], accounts[1]);
    let txid = discovered_payment(&mut st);
    let tx = tx_row(&st, txid);
    let (index, change): (i64, i64) = conn(&st)
        .query_row(
            "SELECT output_index, value FROM sapling_received_notes WHERE transaction_id = ?1",
            [tx],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let fee: i64 = conn(&st)
        .query_row(
            "SELECT fee FROM transactions WHERE id_tx = ?1",
            [tx],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(200_000, 50_000 + change + fee);

    // Scanning recorded the change as sent without a memo, and its receipt without one too.
    record_sent_without_memo(&st, tx, account_row(&st, account), 2, index, change);
    set_sapling_memo(&st, tx, index, None);
    let entry = history(&st, account, txid);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);

    // Enhancement retrieves the memo for the receipt only.
    for memo in [&NONEMPTY_MEMO[..], &EMPTY_MEMO[..]] {
        set_sapling_memo(&st, tx, index, Some(memo));
        let entry = history(&st, account, txid);
        assert_eq!(
            sapling(&entry),
            PoolEffect {
                pool: PoolType::SAPLING,
                received: Zatoshis::from_u64(change as u64).unwrap(),
                spent: zat(200_000),
                completeness: EffectCompleteness::Complete,
            }
        );
        assert_eq!(entry.payment_details, DetailCompleteness::Complete);
        assert_eq!(
            entry.fee,
            FeeState::Known(Zatoshis::from_u64(fee as u64).unwrap())
        );
        assert_eq!(
            entry.aggregate_payment,
            AggregatePayment::Partial(zat(50_000))
        );
        assert_eq!(entry.classification, HistoryClassification::Reconstructed);
    }
    let sent_memo: Option<Vec<u8>> = conn(&st)
        .query_row(
            "SELECT memo FROM sent_notes WHERE transaction_id = ?1 AND output_pool = 2",
            [tx],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sent_memo, None);

    // An unknown fee leaves the payment unaccounted for.
    conn(&st)
        .execute("UPDATE transactions SET fee = NULL WHERE id_tx = ?1", [tx])
        .unwrap();
    let entry = history(&st, account, txid);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    conn(&st)
        .execute(
            "UPDATE transactions SET fee = ?2 WHERE id_tx = ?1",
            rusqlite::params![tx, fee],
        )
        .unwrap();

    // Received by another account, the output is a payment the account sent elsewhere, which
    // still balances; that account's memo is not the sender's.
    conn(&st)
        .execute(
            "UPDATE sapling_received_notes SET account_id = ?2 WHERE transaction_id = ?1",
            rusqlite::params![tx, account_row(&st, other)],
        )
        .unwrap();
    let entry = history(&st, account, txid);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
}

#[test]
fn unmined_shielded_spends_are_incomplete_until_the_scanned_chain_reaches_the_tip() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    let txid = discovered_payment(&mut st);
    assert_eq!(
        sapling(&history(&st, account, txid)).completeness,
        EffectCompleteness::Complete
    );

    // Unscanned blocks may hold notes the unmined transaction spends, which are not linked yet.
    let tip = st.wallet().chain_height().unwrap().unwrap();
    st.wallet_mut().update_chain_tip(tip + 5).unwrap();
    let entry = history(&st, account, txid);
    assert_eq!(entry.mined_height, None);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Incomplete);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
}

fn check_unlinked_unmined_spend(pool: zcash_protocol::ShieldedPool) {
    use zcash_protocol::ShieldedPool;

    let mut network = TestBuilder::<(), ()>::DEFAULT_NETWORK;
    if pool == ShieldedPool::Ironwood {
        let activation = Some(BlockHeight::from_u32(100_000));
        network.nu6 = activation;
        network.nu6_1 = activation;
        network.nu6_2 = activation;
        network.nu6_3 = activation;
    }
    let mut st = TestBuilder::new()
        .with_network(network)
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    scan_new_blocks(&mut st, 10);
    set_policy(&mut st, PrivateShadow);
    let test_account = st.test_account().cloned().unwrap();
    let account = test_account.id();
    let height = match pool {
        ShieldedPool::Sapling => {
            st.generate_next_block(
                &test_account
                    .usk()
                    .sapling()
                    .to_diversifiable_full_viewing_key(),
                AddressType::DefaultExternal,
                zat(200_000),
            )
            .0
        }
        #[cfg(feature = "orchard")]
        ShieldedPool::Orchard | ShieldedPool::Ironwood => {
            let fvk = orchard::keys::FullViewingKey::from(test_account.usk().orchard());
            if pool == ShieldedPool::Orchard {
                st.generate_next_block(&fvk, AddressType::DefaultExternal, zat(200_000))
                    .0
            } else {
                st.generate_next_block(
                    &zcash_client_backend::data_api::testing::IronwoodFvk(fvk),
                    AddressType::DefaultExternal,
                    zat(200_000),
                )
                .0
            }
        }
        #[cfg(not(feature = "orchard"))]
        _ => unreachable!("the tests request only supported pools"),
    };
    st.scan_cached_blocks(height, 1);
    let to = zcash_keys::address::Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]));
    let request = zip321::TransactionRequest::new(vec![zip321::Payment::without_memo(
        to.to_zcash_address(st.network()),
        zat(50_000),
    )])
    .unwrap();
    let change = zcash_client_backend::data_api::testing::single_output_change_strategy(
        zcash_client_backend::fees::StandardFeeRule::Zip317,
        None,
        pool,
    );
    let proposal = st
        .propose_transfer_with_policy(
            account,
            &zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector::new(),
            &change,
            request,
            ConfirmationsPolicy::MIN,
            &Default::default(),
        )
        .unwrap();
    let txid = st
        .create_proposed_transactions::<std::convert::Infallible, _, std::convert::Infallible, _>(
            test_account.usk(),
            zcash_client_backend::wallet::OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];
    conn(&st)
        .execute(
            "UPDATE transactions SET created = NULL, target_height = NULL WHERE txid = ?1",
            [txid.as_ref()],
        )
        .unwrap();
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let funding_height = st.wallet().chain_height().unwrap().unwrap();
    let params = *st.network();

    // Restore the pre-funding scan state, retaining the cached block for the later scan. Remove
    // construction details and the funding note to model a restored wallet seeing this payload
    // before its funding block. The spend link goes with the removed note.
    st.truncate_to_height_retaining_cache(funding_height - 1);
    conn(&st)
        .execute("DELETE FROM sent_notes WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?1)", [txid.as_ref()])
        .unwrap();
    conn(&st)
        .execute(
            &format!(
                "DELETE FROM {}_received_notes WHERE value = 200000",
                crate::wallet::common::table_constants::<SqliteClientError>(pool)
                    .unwrap()
                    .table_prefix
            ),
            [],
        )
        .unwrap();
    zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
        &params,
        st.wallet_mut(),
        &tx,
        None,
    )
    .unwrap();
    st.wallet_mut().update_chain_tip(funding_height).unwrap();
    assert_eq!(
        effect(&history(&st, account, txid), PoolType::Shielded(pool)).spent,
        Zatoshis::ZERO
    );

    // Scanning catches up and recovers the spent note, but cannot link an unmined spender through
    // the block nullifier map. Its change must not become a certified receive-only transaction.
    st.scan_cached_blocks(funding_height, 1);
    let entry = history(&st, account, txid);
    assert_eq!(entry.mined_height, None);
    assert_eq!(
        effect(&entry, PoolType::Shielded(pool)).spent,
        Zatoshis::ZERO
    );
    assert_eq!(
        effect(&entry, PoolType::Shielded(pool)).completeness,
        EffectCompleteness::Incomplete
    );
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.classification, HistoryClassification::Provisional);

    // Reingestion can now link the known funding note; completeness and fee attribution recover.
    zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
        &params,
        st.wallet_mut(),
        &tx,
        None,
    )
    .unwrap();
    let entry = history(&st, account, txid);
    assert_eq!(effect(&entry, PoolType::Shielded(pool)).spent, zat(200_000));
    assert_eq!(
        effect(&entry, PoolType::Shielded(pool)).completeness,
        EffectCompleteness::Complete
    );
    assert!(matches!(entry.fee, FeeState::Known(_)));
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
}

#[test]
fn scanning_a_funding_note_does_not_complete_an_unlinked_unmined_sapling_spend() {
    check_unlinked_unmined_spend(zcash_protocol::ShieldedPool::Sapling);
}

#[cfg(feature = "orchard")]
#[test]
fn scanning_a_funding_note_does_not_complete_an_unlinked_unmined_orchard_spend() {
    check_unlinked_unmined_spend(zcash_protocol::ShieldedPool::Orchard);
}

#[cfg(feature = "orchard")]
#[test]
fn scanning_a_funding_note_does_not_complete_an_unlinked_unmined_ironwood_spend() {
    check_unlinked_unmined_spend(zcash_protocol::ShieldedPool::Ironwood);
}

#[test]
fn unmined_spend_inspection_accepts_zero_expiry_and_rejects_malformed_data() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    let txid = discovered_payment(&mut st);
    let data = st
        .wallet()
        .get_transaction(txid)
        .unwrap()
        .unwrap()
        .into_data();
    // Inspecting nullifiers needs neither a mined height nor a nonzero expiry height.
    let tx = zcash_primitives::transaction::TransactionData::from_parts(
        data.version(),
        data.consensus_branch_id(),
        data.lock_time(),
        BlockHeight::from_u32(0),
        data.transparent_bundle().cloned(),
        data.sprout_bundle().cloned(),
        data.sapling_bundle().cloned(),
        data.orchard_bundle().cloned(),
    )
    .freeze()
    .unwrap();
    let params = *st.network();
    zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
        &params,
        st.wallet_mut(),
        &tx,
        None,
    )
    .unwrap();
    let entry = history(&st, account, tx.txid());
    assert_eq!(sapling(&entry).spent, zat(200_000));
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);

    conn(&st)
        .execute(
            "UPDATE transactions SET raw = X'01' WHERE txid = ?1",
            [tx.txid().as_ref()],
        )
        .unwrap();
    assert!(matches!(
        st.wallet()
            .db()
            .transaction_history_details(account, &[tx.txid()]),
        Err(SqliteClientError::Io(_))
    ));
}

#[test]
fn creation_evidence_alone_does_not_certify_effects_or_details() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    // An outbox records only that the wallet created the transaction; its signed bytes, inputs,
    // and recipients live outside the wallet database.
    let outpoint = OutPoint::new([0x51; 32], 0);
    let tip = st.wallet().chain_height().unwrap().unwrap();
    crate::wallet::record_transaction_created(conn(&st), *outpoint.txid(), tip + 1).unwrap();
    // Discovery then records only its output to the account.
    let address = external(&watch(&st, account));
    super::super::super::put_public_utxo(&mut st, &address, outpoint.clone(), 20_000);

    let entry = history(&st, account, *outpoint.txid());
    assert_eq!(entry.classification, HistoryClassification::LocalIntent);
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::PublicDiscovery
    );
    // Every effect is settled, yet the wallet likely funded it through spends it has not
    // recorded, so it is not known to be a receipt.
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
}

#[test]
fn an_unresolved_spend_alone_makes_the_account_a_party() {
    let (mut st, account, _) = active_wallet();
    let ws = watch(&st, account);
    // A payment with no change, recovered before the output it spends.
    let missing = receive(7, external(&ws), 10_000, below_target(&ws, 1));
    let payment = spend(8, &missing, below_target(&ws, 0));
    let mut c = commit(&ws);
    c.spends = vec![payment.clone()];
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    let entry = history(&st, account, payment.spending_txid);
    assert_eq!(
        transparent(&entry),
        PoolEffect {
            pool: PoolType::Transparent,
            received: Zatoshis::ZERO,
            spent: Zatoshis::ZERO,
            completeness: EffectCompleteness::Incomplete,
        }
    );
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.funding, TransactionFunding::Undetermined);
}

#[test]
fn a_candidate_ledger_spend_stays_out_of_history() {
    let (mut st, account) = shadow_wallet();
    let ws = watch(&st, account);
    let missing = receive(7, external(&ws), 10_000, below_target(&ws, 1));
    let payment = spend(8, &missing, below_target(&ws, 0));
    let mut c = commit(&ws);
    c.spends = vec![payment.clone()];
    apply(&mut st, c).unwrap();
    assert_eq!(
        st.wallet()
            .db()
            .transaction_history_details(account, &[payment.spending_txid])
            .unwrap(),
        vec![]
    );
}

#[test]
fn a_constructed_payment_to_an_own_shielded_address_is_incomplete_until_scanned() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = st.test_account().cloned().unwrap();
    assert_eq!(account.id(), accounts[0]);
    let own = account
        .usk()
        .sapling()
        .to_diversifiable_full_viewing_key()
        .default_address()
        .1;
    let txid =
        pay_address_from_sapling(&mut st, zcash_keys::address::Address::Sapling(own), 50_000);

    // Local construction defers the receipt until scanning finds it, so the Sapling receipts are
    // not yet all known.
    let entry = history(&st, account.id(), txid);
    assert_eq!(entry.classification, HistoryClassification::LocalIntent);
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(sapling(&entry).spent, zat(200_000));
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Incomplete);
    let change = sapling(&entry).received;

    // Once mined and scanned, the payment is an owned receipt and the pool is complete.
    let (height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(height, 1);
    let entry = history(&st, account.id(), txid);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert_eq!(sapling(&entry).received, (change + zat(50_000)).unwrap());
}

#[test]
fn an_account_without_a_full_viewing_key_never_completes_shielded_effects() {
    let (mut st, accounts) = shadow_wallet_with(1);
    let viewer = accounts[1];
    // The imported account's Sapling key, from `import_account(st, 7)`.
    let dfvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        st.network(),
        &[7; 32],
        zip32::AccountId::ZERO,
    )
    .unwrap()
    .sapling()
    .to_diversifiable_full_viewing_key();
    let (height, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, zat(30_000));
    st.scan_cached_blocks(height, 1);
    let txid: TxId = conn(&st)
        .query_row(
            "SELECT t.txid FROM transactions t WHERE t.mined_height = ?1",
            [u32::from(height)],
            |row| row.get::<_, [u8; 32]>(0).map(TxId::from_bytes),
        )
        .unwrap();
    let entry = history(&st, viewer, txid);
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Complete);
    assert_eq!(entry.fee, FeeState::NotApplicable);

    // With only an incoming viewing key, the account's spends are never detected, so the receipt
    // may have been funded by its own notes.
    conn(&st)
        .execute(
            "UPDATE accounts SET ufvk = NULL WHERE uuid = ?1",
            [viewer.expose_uuid()],
        )
        .unwrap();
    let entry = history(&st, viewer, txid);
    assert_eq!(sapling(&entry).received, zat(30_000));
    assert_eq!(sapling(&entry).completeness, EffectCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
}

/// Records that `child` has a transparent input spending `parent`'s first output, which the
/// wallet does not hold, and queues `parent` for retrieval on behalf of `dependent`.
fn queue_parent(st: &State, child: TxId, parent: [u8; 32], dependent: TxId) {
    let id = |txid: TxId| -> i64 {
        conn(st)
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .unwrap()
    };
    conn(st)
        .execute(
            "INSERT INTO transparent_spend_map
                 (spending_transaction_id, prevout_txid, prevout_output_index)
             VALUES (?1, ?2, 0)",
            rusqlite::params![id(child), parent],
        )
        .unwrap();
    conn(st)
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type, dependent_transaction_id)
             VALUES (?1, 1, ?2)
             ON CONFLICT (txid, query_type) DO UPDATE
             SET dependent_transaction_id = excluded.dependent_transaction_id",
            rusqlite::params![parent, id(dependent)],
        )
        .unwrap();
}

#[test]
fn a_queued_parent_keeps_public_transparent_effects_open() {
    let (mut st, accounts) = shadow_wallet_with(0);
    let account = accounts[0];
    let address = external(&watch(&st, account));
    let outpoint = OutPoint::new([0x42; 32], 0);
    super::super::super::put_public_utxo(&mut st, &address, outpoint.clone(), 70_000);
    let txid = *outpoint.txid();
    assert_eq!(
        history(&st, account, txid).classification,
        HistoryClassification::Reconstructed
    );

    // One of its inputs spends an output of a parent that public discovery has yet to retrieve,
    // which may be the account's own.
    queue_parent(&st, txid, [0x43; 32], txid);
    let entry = history(&st, account, txid);
    assert_eq!(
        transparent(&entry).completeness,
        EffectCompleteness::Incomplete
    );
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
}

#[test]
fn a_parent_shared_by_two_transactions_is_pending_for_both() {
    let (mut st, account, unspent) = active_wallet();
    let first = *unspent.outpoint.txid();
    let ws = watch(&st, account);
    let fresh = receive(5, external(&ws), 60_000, below_target(&ws, 0));
    cover(&mut st, account, &revision(1, true), vec![fresh.clone()]);
    let second = *fresh.outpoint.txid();

    // The queue records only the latest dependent of the shared parent.
    queue_parent(&st, first, [0x44; 32], first);
    queue_parent(&st, second, [0x44; 32], second);
    let parent = PrivateTransparentDetail::ParentTransaction {
        txid: TxId::from_bytes([0x44; 32]),
    };
    assert_eq!(
        history(&st, account, first).pending_private_details,
        vec![parent]
    );
    assert_eq!(
        history(&st, account, second).pending_private_details,
        vec![parent]
    );
}

#[test]
fn deleting_the_funding_account_removes_the_construction_evidence() {
    let (mut st, accounts) = shadow_wallet_with(1);
    let (sender, recipient) = (accounts[0], accounts[1]);
    let to = external(&watch(&st, recipient));
    let (txid, _) = pay_from_sapling(&mut st, to, 30_000);
    assert_eq!(
        history(&st, recipient, txid).payment_details,
        DetailCompleteness::Complete
    );

    // The sender's recorded outputs go with it; the recipient's receipt stays.
    st.wallet_mut().delete_account(sender).unwrap();
    let entry = history(&st, recipient, txid);
    assert_eq!(transparent(&entry).received, zat(30_000));
    assert_eq!(entry.classification, HistoryClassification::LocalIntent);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
}
