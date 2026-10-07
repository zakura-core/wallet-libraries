//! Private recovery of transparent-to-Ironwood shielding transactions.
//!
//! These fixtures exercise the whole private path for one account: transparent private recovery
//! (spend events with qualified transaction metadata), compact Ironwood scanning, Enhance PIR
//! record application, and the history read. Each owned fact is asserted separately so a
//! regression in one recovery step cannot hide behind an aggregate classification.

use orchard::note_encryption::IronwoodNoteEncryption;
use zcash_client_backend::data_api::{
    enhance_pir::{
        EnhancePirBatchResult, EnhancePirRead as _, EnhancePirRequest, EnhancePirStoreResult,
        EnhancePirWork, EnhancePirWrite as _, EnhanceRecord, EnhanceRecordParts,
        EnhanceTransactionMetadata, EnhancementMode, TransactionEnhancementWork,
    },
    testing::{
        FakeCompactOutput, IronwoodFvk, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
    },
    transparent_ledger::{
        AggregatePayment, DetailCompleteness, EffectCompleteness, FeeState, HistoryClassification,
        PoolEffect, PrivateTransparentDetail, TransactionHistoryDetails, TransactionMetadata,
        WholeTransactionFee,
    },
};
use zcash_protocol::{PoolType, local_consensus::LocalNetwork};

use super::*;

const FEE: u64 = 20_000;
const MEMO: [u8; 512] = [0xf6; 512];

/// One accounting shape from the reported mainnet transactions.
struct Shape {
    inputs: [u64; 2],
    shielded: u64,
}

/// Case A (mined at 3,498,120) and case B (mined at 3,506,624).
const CASES: [Shape; 2] = [
    Shape {
        inputs: [120_000, 80_000],
        shielded: 180_000,
    },
    Shape {
        inputs: [300_000, 120_000],
        shielded: 400_000,
    },
];

fn zat(value: u64) -> Zatoshis {
    Zatoshis::const_from_u64(value)
}

fn ironwood_network() -> LocalNetwork {
    let activation = BlockHeight::from_u32(100_000);
    LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

/// The recovered state of one shielding transaction.
struct Shielding {
    st: State,
    account: AccountUuid,
    txid: TxId,
    tx_ref: i64,
    height: BlockHeight,
}

/// A promoted `PrivateRequired` account under `PrivateIronwood` enhancement whose two recovered
/// transparent outputs fund `shape`'s shielding transaction: its Ironwood output to the account's
/// internal address is compact-scanned, and private transparent recovery publishes both spends
/// with `metadata`. Enhance PIR has not run yet.
fn shielding(shape: &Shape, metadata: Option<TransactionMetadata>) -> Shielding {
    padded_shielding(shape, metadata, None, false)
}

/// Like [`shielding`], with `action0` (if any) as a first Ironwood action to a key the wallet
/// does not hold: a standard builder's zero-value padding, or another party's output.
/// With `own_action0`, import that key as another wallet account to exercise shared ownership.
fn padded_shielding(
    shape: &Shape,
    metadata: Option<TransactionMetadata>,
    action0: Option<u64>,
    own_action0: bool,
) -> Shielding {
    let mut st = TestBuilder::new()
        .with_network(ironwood_network())
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    if own_action0 {
        import_account(&mut st, 0x77);
    }
    scan_new_blocks(&mut st, 10);
    set_policy(&mut st, PrivateShadow);
    let account = st.test_account().unwrap().id();
    let fixture = revision(1, true);
    let ws = watch(&st, account);
    let receives = [
        receive(0x51, external(&ws), shape.inputs[0], below_target(&ws, 4)),
        receive(0x52, external(&ws), shape.inputs[1], below_target(&ws, 3)),
    ];
    cover(&mut st, account, &fixture, receives.to_vec());
    assert_eq!(recovery(&st, account).blockers, vec![]);
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);

    // The shielding account's only owned shielded effect: its Ironwood output to the
    // account's internal address. Compact scanning finds it without its memo.
    let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
    let foreign = IronwoodFvk(if own_action0 {
        orchard::keys::FullViewingKey::from(
            zcash_keys::keys::UnifiedSpendingKey::from_seed(
                st.network(),
                &[0x77; 32],
                zip32::AccountId::ZERO,
            )
            .unwrap()
            .orchard(),
        )
    } else {
        orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0x77; 32]).unwrap(),
        )
    });
    let mut outputs = vec![];
    if let Some(value) = action0 {
        outputs.push(FakeCompactOutput::new(
            &foreign,
            AddressType::DefaultExternal,
            zat(value),
        ));
    }
    outputs.push(FakeCompactOutput::new(
        &fvk,
        AddressType::Internal,
        zat(shape.shielded),
    ));
    let (height, _, _) = st.generate_next_block_multi(&outputs);
    st.scan_cached_blocks(height, 1);
    scan_new_blocks(&mut st, 2);
    let (tx_ref, txid): (i64, [u8; 32]) = conn(&st)
        .query_row(
            "SELECT id_tx, txid FROM transactions WHERE mined_height = ?1",
            [u32::from(height)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let txid = TxId::from_bytes(txid);
    // The fake block's only transaction occupies index 0, the coinbase position; a transaction
    // spending transparent inputs follows the coinbase.
    conn(&st)
        .execute(
            "UPDATE transactions SET tx_index = 1 WHERE id_tx = ?1",
            [tx_ref],
        )
        .unwrap();

    // Private transparent recovery publishes both owned inputs of the same transaction.
    let ws = watch(&st, account);
    let spends = receives
        .iter()
        .enumerate()
        .map(|(index, prevout)| SpendEvent {
            metadata,
            spending_txid: txid,
            input_index: u32::try_from(index).unwrap(),
            prevout: prevout.outpoint.clone(),
            prevout_address: prevout.address,
            mined_height: height,
        })
        .collect();
    let mut c = commit(&ws);
    c.revision = fixture;
    c.spends = spends;
    c.coverage = full_coverage(&ws);
    apply(&mut st, c).unwrap();

    Shielding {
        st,
        account,
        txid,
        tx_ref,
        height,
    }
}

fn reported_metadata() -> TransactionMetadata {
    TransactionMetadata {
        fee: WholeTransactionFee::Exact(zat(FEE)),
        transparent_input_count: 2,
        has_shielded_components: true,
    }
}

fn history(st: &State, account: AccountUuid, txid: TxId) -> TransactionHistoryDetails {
    let mut entries = st
        .wallet()
        .db()
        .transaction_history_details(account, &[txid])
        .unwrap();
    assert_eq!(entries.len(), 1);
    entries.remove(0)
}

fn effect(entry: &TransactionHistoryDetails, pool: PoolType) -> PoolEffect {
    *entry.effects.iter().find(|e| e.pool == pool).unwrap()
}

/// The private queries the wallet currently asks for.
fn private_queries(st: &State) -> Vec<EnhancePirRequest> {
    st.wallet()
        .transaction_enhancement_work()
        .unwrap()
        .into_iter()
        .filter_map(|work| match work {
            TransactionEnhancementWork::Private(EnhancePirWork::Query(request)) => Some(request),
            TransactionEnhancementWork::Public(request) => {
                panic!(
                    "PrivateRequired exposed public payload work for {}",
                    request.txid()
                )
            }
            _ => None,
        })
        .collect()
}

/// The service's record for the account's received action: the authentic ciphertext of the
/// scanned note, the service's transparent shape flags, and its transaction metadata.
fn record(st: &State, request: EnhancePirRequest, fee: Option<u64>) -> EnhanceRecord {
    record_with_outputs(st, request, fee, false)
}

fn record_with_outputs(
    st: &State,
    request: EnhancePirRequest,
    fee: Option<u64>,
    outputs: bool,
) -> EnhanceRecord {
    let pending =
        crate::wallet::enhance_pir::pending(st.wallet().conn(), st.network(), request.position())
            .unwrap()
            .or_else(|| {
                crate::wallet::enhance_pir::pending_metadata_note(
                    st.wallet().conn(),
                    st.network(),
                    request.position(),
                )
                .unwrap()
            })
            .expect("the received note binds the memo or metadata query");
    let encryptor = IronwoodNoteEncryption::new(None, pending.note, MEMO);
    EnhanceRecord::from_parts(EnhanceRecordParts {
        enc_ciphertext_suffix: encryptor.encrypt_note_plaintext()[52..].try_into().unwrap(),
        cv_net: [0; 32],
        out_ciphertext: [0; 80],
        has_transparent_inputs: true,
        has_transparent_outputs: outputs,
        metadata: EnhanceTransactionMetadata::new(0, fee).unwrap(),
    })
}

fn apply_records(
    st: &mut State,
    records: &[(EnhancePirRequest, EnhanceRecord)],
) -> Vec<EnhancePirStoreResult> {
    match st
        .wallet_mut()
        .db_mut()
        .apply_ironwood_enhance_records(records)
        .unwrap()
    {
        EnhancePirBatchResult::Committed(results) => results,
        rejected => panic!("unexpected batch rejection {rejected:?}"),
    }
}

/// Facts stored for the transaction: (route, fee, received memo, raw present).
fn stored(st: &State, tx_ref: i64) -> (Option<i64>, Option<i64>, Option<Vec<u8>>, bool) {
    st.wallet()
        .conn()
        .query_row(
            "SELECT (SELECT route FROM ironwood_enhance_routing WHERE transaction_id = t.id_tx),
                    t.fee,
                    (SELECT memo FROM ironwood_received_notes WHERE transaction_id = t.id_tx),
                    t.raw IS NOT NULL
             FROM transactions t WHERE t.id_tx = ?1",
            [tx_ref],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

/// Private work rows left for the transaction, across every Enhance PIR queue.
fn queued(st: &State, tx_ref: i64) -> i64 {
    st.wallet()
        .conn()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM ironwood_memo_retrieval_queue q
                     JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
                     WHERE rn.transaction_id = :tx)
                  + (SELECT COUNT(*) FROM ironwood_enhance_outgoing_queue WHERE transaction_id = :tx)
                  + (SELECT COUNT(*) FROM ironwood_enhance_metadata_queue WHERE transaction_id = :tx)
                  + (SELECT COUNT(*) FROM ironwood_enhance_discovery_queue WHERE transaction_id = :tx)",
            rusqlite::named_params![":tx": tx_ref],
            |row| row.get(0),
        )
        .unwrap()
}

/// Owned financial effects are recovered before, and independently of, enhancement.
fn assert_owned_effects(case: &Shielding, shape: &Shape) {
    let entry = history(&case.st, case.account, case.txid);
    assert_eq!(
        effect(&entry, PoolType::Transparent),
        PoolEffect {
            pool: PoolType::Transparent,
            received: Zatoshis::ZERO,
            spent: zat(shape.inputs[0] + shape.inputs[1]),
            completeness: EffectCompleteness::Complete,
        }
    );
    assert_eq!(
        effect(&entry, PoolType::IRONWOOD),
        PoolEffect {
            pool: PoolType::IRONWOOD,
            received: zat(shape.shielded),
            spent: Zatoshis::ZERO,
            completeness: EffectCompleteness::Complete,
        }
    );
    assert!(entry.account_movement.complete);
    assert_eq!(
        entry.account_movement.net(),
        i128::from(shape.shielded) - i128::from(shape.inputs[0] + shape.inputs[1])
    );
}

/// Queries the received action's memo privately and applies the service's record for it.
fn recover_memo(case: &mut Shielding, fee: Option<u64>) -> Vec<EnhancePirStoreResult> {
    let queries = private_queries(&case.st);
    assert_eq!(queries.len(), 1, "one memo query for the received action");
    let request = queries[0];
    assert_eq!(request.request_id().txid(), case.txid);
    let record = record(&case.st, request, fee);
    apply_records(&mut case.st, &[(request, record)])
}

/// Spend links, notes, and fee facts that must never be duplicated or lost.
fn financial_rows(st: &State, tx_ref: i64) -> (i64, i64, i64, i64) {
    st.wallet()
        .conn()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM ironwood_received_notes WHERE transaction_id = :tx),
                    (SELECT COUNT(*) FROM transparent_received_output_spends WHERE transaction_id = :tx),
                    (SELECT COUNT(*) FROM tpir_spend_events e
                     JOIN transactions t ON t.txid = e.spending_txid WHERE t.id_tx = :tx),
                    (SELECT COUNT(*) FROM sent_notes WHERE transaction_id = :tx)",
            rusqlite::named_params![":tx": tx_ref],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

/// The supported shape: every transparent input is the account's, the whole-transaction fee is
/// exact (and agrees with any canonical fee), and the account's spent value is exactly its
/// shielded receipt plus that fee.
fn assert_reconstructed_shielding(case: &Shielding, shape: &Shape) {
    assert_owned_effects(case, shape);
    let entry = history(&case.st, case.account, case.txid);
    // The received memo is recovered, so the payment details are complete.
    assert_eq!(
        entry.payment_details,
        DetailCompleteness::Complete,
        "{entry:?}"
    );
    // The account's net movement is final; whether its debit was the fee is not proven.
    assert_eq!(
        entry.classification,
        HistoryClassification::NetReconstructed
    );
    // The whole-transaction fee is exact; the account's share of it is not attributed.
    assert_eq!(
        entry.transaction_metadata.as_ref().unwrap().metadata.fee,
        WholeTransactionFee::Exact(zat(FEE))
    );
    assert_eq!(entry.fee, FeeState::Unknown);
    // No exact payment is fabricated: no outgoing record exists, only the balance.
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
    // The full transaction remains unavailable under PrivateRequired.
    assert_eq!(
        entry.pending_private_details,
        vec![PrivateTransparentDetail::MixedTransaction { txid: case.txid }]
    );
}

/// Both reported shapes recover their memo and whole-transaction fee privately and reconstruct
/// as a net shielding: the account's transparent inputs became its Ironwood output and the fee.
#[test]
fn reported_shielding_shapes_reconstruct_from_private_evidence() {
    for shape in &CASES {
        let mut case = shielding(shape, Some(reported_metadata()));
        assert_owned_effects(&case, shape);
        let before = history(&case.st, case.account, case.txid);
        assert_eq!(before.classification, HistoryClassification::Provisional);
        assert_eq!(before.payment_details, DetailCompleteness::Incomplete);
        let rows = financial_rows(&case.st, case.tx_ref);

        assert_eq!(
            recover_memo(&mut case, Some(FEE)),
            vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
        );
        // The memo and whole-transaction fee are stored; the transparent details stay
        // unsupported and nothing is queued, publicly or privately.
        assert_eq!(
            stored(&case.st, case.tx_ref),
            (
                Some(2),
                Some(i64::try_from(FEE).unwrap()),
                Some(MEMO.to_vec()),
                false
            )
        );
        assert_eq!(queued(&case.st, case.tx_ref), 0);
        assert!(private_queries(&case.st).is_empty());
        // Sender linkage: the account's own output has no outgoing record, which only the
        // full transaction could provide. Nothing else changed.
        assert_eq!(financial_rows(&case.st, case.tx_ref), rows);
        assert_eq!(rows.3, 0);

        assert_reconstructed_shielding(&case, shape);
    }
}

/// Another party funded a transparent input: the balance alone could hide a payment to them.
#[test]
fn another_transparent_funder_leaves_payment_and_fee_unattributed() {
    let shape = &CASES[0];
    let mut case = shielding(
        shape,
        Some(TransactionMetadata {
            transparent_input_count: 3,
            ..reported_metadata()
        }),
    );
    recover_memo(&mut case, Some(FEE));
    // The independently recoverable details are kept ...
    assert_eq!(
        stored(&case.st, case.tx_ref),
        (
            Some(2),
            Some(i64::try_from(FEE).unwrap()),
            Some(MEMO.to_vec()),
            false
        )
    );
    // ... but the account's debit equals the fee only by the balance, so nothing is attributed.
    let entry = history(&case.st, case.account, case.txid);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
}

/// The account's funds paid someone else besides the fee: an owned shielded output does not make
/// the transaction a shielding.
#[test]
fn an_external_payment_is_not_reconstructed_as_shielding() {
    let shape = Shape {
        inputs: [120_000, 80_000],
        shielded: 150_000,
    };
    let mut case = shielding(&shape, Some(reported_metadata()));
    recover_memo(&mut case, Some(FEE));
    assert_owned_effects(&case, &shape);
    let entry = history(&case.st, case.account, case.txid);
    assert_eq!(entry.account_movement.net(), -50_000);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
}

/// The account's debit equals the network fee, but the evidence that it was the only funder, or
/// that the fee is that exact amount, is missing or contradicted: the ambiguity is retained.
#[test]
fn a_fee_sized_debit_without_sole_funding_evidence_stays_ambiguous() {
    let shape = &CASES[0];
    for (metadata, record_fee) in [
        // No qualified transaction metadata at all.
        (None, Some(FEE)),
        // The transparent publisher could not establish the fee.
        (
            Some(TransactionMetadata {
                fee: WholeTransactionFee::Unknown,
                ..reported_metadata()
            }),
            Some(FEE),
        ),
        // The two private sources disagree about the fee.
        (
            Some(TransactionMetadata {
                fee: WholeTransactionFee::Exact(zat(15_000)),
                ..reported_metadata()
            }),
            Some(FEE),
        ),
    ] {
        let mut case = shielding(shape, metadata);
        recover_memo(&mut case, record_fee);
        let entry = history(&case.st, case.account, case.txid);
        assert_eq!(entry.account_movement.net(), -i128::from(FEE));
        assert_eq!(entry.classification, HistoryClassification::Provisional);
        assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
        assert_eq!(entry.fee, FeeState::Unknown);
        assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
    }
}

/// Qualified transparent metadata supplies the whole fee when the mixed enhancement cannot.
#[test]
fn qualified_fee_reconstructs_without_an_enhancement_fee() {
    for shape in &CASES {
        let mut case = shielding(shape, Some(reported_metadata()));
        assert_eq!(
            recover_memo(&mut case, None),
            vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
        );
        assert_eq!(
            stored(&case.st, case.tx_ref),
            (Some(2), None, Some(MEMO.to_vec()), false)
        );
        assert_eq!(queued(&case.st, case.tx_ref), 0);
        assert_reconstructed_shielding(&case, shape);
    }
}

/// A service shape flag is required separately from the wallet's absence of owned outputs.
#[test]
fn transparent_outputs_or_unknown_shape_prevent_net_reconstruction() {
    for outputs in [Some(true), None] {
        let mut case = shielding(&CASES[0], Some(reported_metadata()));
        let request = private_queries(&case.st)[0];
        let record = record_with_outputs(&case.st, request, None, true);
        apply_records(&mut case.st, &[(request, record)]);
        if outputs.is_none() {
            // Models a recovered memo from an older build, without its discarded shape evidence.
            conn(&case.st).execute("UPDATE ironwood_enhance_routing SET has_transparent_outputs = NULL WHERE transaction_id = ?", [case.tx_ref]).unwrap();
        }
        let entry = history(&case.st, case.account, case.txid);
        assert_eq!(entry.has_transparent_outputs, outputs);
        assert_eq!(entry.classification, HistoryClassification::Provisional);
        assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
        assert_eq!(entry.fee, FeeState::Unknown);
    }
}

/// Enhancement shape reaches consumers without upgrading incomplete payment details, and
/// survives opening the recovered database again without local construction records.
#[test]
fn enhance_output_presence_is_exposed_by_history_after_reopen() {
    let shape = Shape {
        inputs: [300_000, 120_000],
        shielded: 205_000,
    };
    for outputs in [false, true] {
        let mut case = shielding(&shape, Some(reported_metadata()));
        assert_eq!(
            history(&case.st, case.account, case.txid).has_transparent_outputs,
            None
        );
        let request = private_queries(&case.st)[0];
        let response = record_with_outputs(&case.st, request, Some(FEE), outputs);
        apply_records(&mut case.st, &[(request, response)]);
        let entry = history(&case.st, case.account, case.txid);
        assert_eq!(entry.has_transparent_outputs, Some(outputs));
        assert_eq!(entry.classification, HistoryClassification::Provisional);
        assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
        assert_eq!(entry.account_movement.net(), -215_000);
        assert_eq!(entry.fee, FeeState::Unknown);
        assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
        assert!(
            !stored(&case.st, case.tx_ref).3,
            "no full transaction record"
        );
        private_queries(&case.st); // Fails if private recovery exposes public payload work.

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reopened.sqlite");
        conn(&case.st)
            .execute("VACUUM INTO ?", [path.to_str().unwrap()])
            .unwrap();
        let reopened = crate::WalletDb::for_path(
            path,
            *case.st.network(),
            crate::testing::db::test_clock(),
            crate::testing::db::test_rng(),
        )
        .unwrap()
        .with_transparent_ledger_mode(PrivateRequired);
        let reopened_entry = reopened
            .transaction_history_details(case.account, &[case.txid])
            .unwrap()
            .remove(0);
        assert_eq!(reopened_entry, entry);
    }
}

/// Conflicting shape assertions cannot overwrite a recovered absence flag or finish work.
#[test]
fn conflicting_transparent_output_shape_is_rejected_atomically() {
    let mut case = shielding(&CASES[0], Some(reported_metadata()));
    recover_memo(&mut case, None);
    let (position, index): (u64, u32) = conn(&case.st).query_row(
        "SELECT commitment_tree_position, action_index FROM ironwood_received_notes WHERE transaction_id = ?",
        [case.tx_ref], |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    conn(&case.st).execute(
        "INSERT INTO ironwood_enhance_metadata_queue (transaction_id, commitment_tree_position, output_index) VALUES (?1, ?2, ?3)",
        rusqlite::params![case.tx_ref, position, index],
    ).unwrap();
    let request = private_queries(&case.st)[0];
    let response = record_with_outputs(&case.st, request, Some(FEE), true);
    assert!(matches!(
        case.st
            .wallet_mut()
            .db_mut()
            .apply_ironwood_enhance_records(&[(request, response)])
            .unwrap(),
        EnhancePirBatchResult::Rejected { .. }
    ));
    assert_eq!(queued(&case.st, case.tx_ref), 1);
    assert_eq!(
        stored(&case.st, case.tx_ref),
        (Some(2), None, Some(MEMO.to_vec()), false)
    );
    assert_reconstructed_shielding(&case, &CASES[0]);
    assert_eq!(
        history(&case.st, case.account, case.txid).has_transparent_outputs,
        Some(false)
    );
}

/// Memo recovery must not substitute a missing fee, an input count, or a balanced account flow.
#[test]
fn qualified_fee_workaround_rejects_incomplete_or_ambiguous_evidence() {
    for (metadata, shielded) in [
        (None, 400_000),
        (
            Some(TransactionMetadata {
                fee: WholeTransactionFee::Unknown,
                ..reported_metadata()
            }),
            400_000,
        ),
        (
            Some(TransactionMetadata {
                fee: WholeTransactionFee::Exact(zat(15_000)),
                ..reported_metadata()
            }),
            400_000,
        ),
        (
            Some(TransactionMetadata {
                transparent_input_count: 3,
                ..reported_metadata()
            }),
            400_000,
        ),
        (Some(reported_metadata()), 390_000),
    ] {
        let shape = Shape {
            shielded,
            ..CASES[1]
        };
        let mut case = shielding(&shape, metadata);
        recover_memo(&mut case, None);
        let entry = history(&case.st, case.account, case.txid);
        assert_eq!(entry.classification, HistoryClassification::Provisional);
        assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
        assert_eq!(entry.fee, FeeState::Unknown);
        assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
        assert_eq!(stored(&case.st, case.tx_ref).1, None);
    }
    // The qualified fee cannot override a contradictory canonical fee either.
    let mut case = shielding(&CASES[1], Some(reported_metadata()));
    conn(&case.st)
        .execute(
            "UPDATE transactions SET fee = 15000 WHERE id_tx = ?",
            [case.tx_ref],
        )
        .unwrap();
    recover_memo(&mut case, None);
    assert_eq!(
        history(&case.st, case.account, case.txid).classification,
        HistoryClassification::Provisional
    );
    assert_eq!(stored(&case.st, case.tx_ref).1, Some(15_000));
}

/// A response that contradicts stored facts, or no longer matches pending work, changes nothing.
#[test]
fn conflicting_or_stale_responses_leave_recovered_facts_intact() {
    let shape = &CASES[0];
    let mut case = shielding(shape, Some(reported_metadata()));
    let request = private_queries(&case.st)[0];
    let record = record(&case.st, request, Some(FEE));

    // A known fee that the response contradicts rejects the whole response.
    conn(&case.st)
        .execute(
            "UPDATE transactions SET fee = 25000 WHERE id_tx = ?1",
            [case.tx_ref],
        )
        .unwrap();
    assert!(matches!(
        case.st
            .wallet_mut()
            .db_mut()
            .apply_ironwood_enhance_records(&[(request, record.clone())])
            .unwrap(),
        EnhancePirBatchResult::Rejected { .. }
    ));
    assert_eq!(
        stored(&case.st, case.tx_ref),
        (Some(0), Some(25_000), None, false)
    );
    assert_eq!(private_queries(&case.st), vec![request]);

    // So does a conflicting displayed expiry.
    conn(&case.st)
        .execute_batch(&format!(
            "UPDATE transactions SET fee = NULL WHERE id_tx = {tx};
             UPDATE ironwood_enhance_routing SET history_expiry_height = 7
             WHERE transaction_id = {tx};",
            tx = case.tx_ref
        ))
        .unwrap();
    assert!(matches!(
        case.st
            .wallet_mut()
            .db_mut()
            .apply_ironwood_enhance_records(&[(request, record.clone())])
            .unwrap(),
        EnhancePirBatchResult::Rejected { .. }
    ));
    assert_eq!(stored(&case.st, case.tx_ref), (Some(0), None, None, false));
    conn(&case.st)
        .execute(
            "UPDATE ironwood_enhance_routing SET history_expiry_height = NULL
             WHERE transaction_id = ?1",
            [case.tx_ref],
        )
        .unwrap();

    // The consistent response applies once; replaying it is stale and changes nothing.
    let rows = financial_rows(&case.st, case.tx_ref);
    assert_eq!(
        apply_records(&mut case.st, &[(request, record.clone())]),
        vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
    );
    let recovered = stored(&case.st, case.tx_ref);
    assert_eq!(
        apply_records(&mut case.st, &[(request, record)]),
        vec![EnhancePirStoreResult::AlreadyResolved]
    );
    assert_eq!(stored(&case.st, case.tx_ref), recovered);
    assert_eq!(financial_rows(&case.st, case.tx_ref), rows);
    assert_reconstructed_shielding(&case, shape);
}

/// A database whose earlier routing cleared the memo work of a route-2 transaction resumes it on
/// upgrade, privately and without a reset.
#[test]
fn an_existing_route_two_database_resumes_private_memo_recovery_after_upgrade() {
    use crate::wallet::init::{
        WalletMigrator,
        migrations::ironwood_transparent_output_shape::MIGRATION_ID as SHAPE_MIGRATION,
    };

    let shape = &CASES[1];
    let mut case = shielding(shape, Some(reported_metadata()));
    // The state the previous routing left behind: route 2, every queue cleared, memo and fee
    // unknown, recorded by a database that predates the retry migration.
    conn(&case.st)
        .execute_batch(&format!(
            "UPDATE ironwood_enhance_routing SET route = 2 WHERE transaction_id = {tx};
             DELETE FROM ironwood_memo_retrieval_queue;
             DELETE FROM ironwood_enhance_outgoing_queue WHERE transaction_id = {tx};
             DELETE FROM ironwood_enhance_metadata_queue WHERE transaction_id = {tx};
             DELETE FROM ironwood_enhance_discovery_queue WHERE transaction_id = {tx};",
            tx = case.tx_ref
        ))
        .unwrap();
    conn(&case.st)
        .execute_batch("ALTER TABLE ironwood_enhance_routing DROP COLUMN has_transparent_outputs")
        .unwrap();
    conn(&case.st)
        .execute(
            "DELETE FROM schemer_migrations WHERE id = ?1",
            [SHAPE_MIGRATION.as_bytes().to_vec()],
        )
        .unwrap();
    assert_eq!(stored(&case.st, case.tx_ref), (Some(2), None, None, false));
    assert_eq!(queued(&case.st, case.tx_ref), 0);
    assert!(private_queries(&case.st).is_empty(), "stuck before upgrade");
    let rows = financial_rows(&case.st, case.tx_ref);

    // Upgrading, and reopening afterwards, queues the memo once.
    for _ in 0..2 {
        WalletMigrator::new()
            .init_or_migrate(case.st.wallet_mut().db_mut())
            .unwrap();
    }
    assert_eq!(queued(&case.st, case.tx_ref), 1);
    assert_eq!(stored(&case.st, case.tx_ref), (Some(2), None, None, false));
    assert_eq!(financial_rows(&case.st, case.tx_ref), rows);

    assert_eq!(
        recover_memo(&mut case, Some(FEE)),
        vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
    );
    assert_eq!(financial_rows(&case.st, case.tx_ref), rows);
    assert_reconstructed_shielding(&case, shape);
}

/// Recovery interrupted before its write commits leaves the work queued; retrying applies it
/// once, and replayed scans do not requeue it or duplicate any fact.
#[test]
fn interrupted_recovery_retries_without_duplicates() {
    let shape = &CASES[0];
    let mut case = shielding(shape, Some(reported_metadata()));
    let rows = financial_rows(&case.st, case.tx_ref);
    // The response was fetched but never applied.
    let interrupted = private_queries(&case.st);
    assert_eq!(private_queries(&case.st), interrupted);
    assert_eq!(
        recover_memo(&mut case, Some(FEE)),
        vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
    );
    // A replayed scan of the transaction finds nothing more to queue.
    crate::wallet::enhance_pir::route_transparent_details(
        conn(&case.st),
        Some(PrivateRequired),
        crate::TxRef(case.tx_ref),
    )
    .unwrap();
    assert_eq!(queued(&case.st, case.tx_ref), 0);
    assert_eq!(financial_rows(&case.st, case.tx_ref), rows);
    assert_reconstructed_shielding(&case, shape);
}

/// Classification follows its evidence: losing coverage or a block reverts it to provisional,
/// while the recovered memo and fee are retained for when the evidence returns.
#[test]
fn coverage_loss_and_reorg_reevaluate_the_classification() {
    let shape = &CASES[0];
    let mut case = shielding(shape, Some(reported_metadata()));
    recover_memo(&mut case, None);
    assert_reconstructed_shielding(&case, shape);

    // A quarantined source no longer covers the account or qualifies its metadata.
    conn(&case.st)
        .execute(
            "INSERT INTO tpir_quarantined_sources (source) VALUES (?1)",
            [b"fixture".to_vec()],
        )
        .unwrap();
    let entry = history(&case.st, case.account, case.txid);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.transaction_metadata, None);
    super::super::lift_quarantine(&case.st);
    assert_reconstructed_shielding(&case, shape);

    // A reorg unmines the transaction: no private work is dispatched for it, its recovered memo
    // and fee are retained, and the history is provisional.
    case.st.truncate_to_height(case.height - 1);
    let entry = history(&case.st, case.account, case.txid);
    assert_eq!(entry.mined_height, None);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert!(private_queries(&case.st).is_empty());
    let (route, fee, memo, raw) = stored(&case.st, case.tx_ref);
    assert_eq!(
        (route, fee, memo, raw),
        (Some(2), None, Some(MEMO.to_vec()), false)
    );
}

/// The standard padded shape and the adversarial one have identical evidence. Both spend the
/// account's two transparent inputs (200,000), have no transparent outputs, a 20,000 fee, and
/// two Ironwood actions with the account's 180,000 output at action 1. In the pure shielding,
/// action 0 is the builder's zero-value padding (outgoing ciphertext encrypted to no key, spends
/// enabled by default flags). In the other, another party spends 100,000 of its own shielded
/// funds into action 0's output, leaving the pool's net inflow at 180,000. Neither action 0 is
/// decryptable or OVK-recoverable by the wallet, so neither is even queued for recovery; the
/// transparent metadata, Enhance PIR record, and owned effects agree, and so does the history.
/// The result is a net movement in both cases, never a proven self-transfer.
#[test]
fn foreign_self_balanced_shielded_participation_is_indistinguishable() {
    let shape = &CASES[0];
    let details = [Some(0), Some(100_000)].map(|action0| {
        let mut case = padded_shielding(shape, Some(reported_metadata()), action0, false);
        // Action 0 is no outgoing candidate: the account spent no Ironwood note.
        let outgoing: i64 = conn(&case.st)
            .query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_outgoing_queue WHERE transaction_id = ?1",
                [case.tx_ref],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outgoing, 0);
        assert_eq!(
            recover_memo(&mut case, None),
            vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
        );
        let entry = history(&case.st, case.account, case.txid);
        assert_eq!(
            entry.classification,
            HistoryClassification::NetReconstructed
        );
        assert_eq!(entry.fee, FeeState::Unknown);
        assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
        TransactionHistoryDetails {
            txid: TxId::from_bytes([0; 32]),
            mined_height: None,
            ..entry
        }
    });
    assert_eq!(details[0], details[1]);
}

/// Existing memo-complete route-2 wallets recover discarded shape evidence without a reset or
/// a public payload request, and reopen with the canonical fee still NULL.
#[test]
fn existing_memo_complete_wallet_recovers_shape_and_survives_reopen() {
    use crate::wallet::init::{
        WalletMigrator,
        migrations::ironwood_transparent_output_shape::MIGRATION_ID as SHAPE_MIGRATION,
    };
    use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerRead;
    let mut case = shielding(&CASES[1], Some(reported_metadata()));
    recover_memo(&mut case, None);
    let rows = financial_rows(&case.st, case.tx_ref);
    conn(&case.st)
        .execute_batch("ALTER TABLE ironwood_enhance_routing DROP COLUMN has_transparent_outputs")
        .unwrap();
    conn(&case.st)
        .execute(
            "DELETE FROM schemer_migrations WHERE id = ?",
            [SHAPE_MIGRATION.as_bytes().to_vec()],
        )
        .unwrap();
    assert_eq!(queued(&case.st, case.tx_ref), 0);
    WalletMigrator::new()
        .init_or_migrate(case.st.wallet_mut().db_mut())
        .unwrap();
    assert_eq!(queued(&case.st, case.tx_ref), 1);
    assert_eq!(
        history(&case.st, case.account, case.txid).classification,
        HistoryClassification::Provisional
    );
    assert_eq!(
        recover_memo(&mut case, None),
        vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
    );
    assert_eq!(queued(&case.st, case.tx_ref), 0);
    assert_eq!(financial_rows(&case.st, case.tx_ref), rows);
    assert_eq!(
        stored(&case.st, case.tx_ref),
        (Some(2), None, Some(MEMO.to_vec()), false)
    );
    assert_reconstructed_shielding(&case, &CASES[1]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reopened.sqlite");
    conn(&case.st)
        .execute("VACUUM INTO ?", [path.to_str().unwrap()])
        .unwrap();
    let reopened = crate::WalletDb::for_path(
        path,
        *case.st.network(),
        crate::testing::db::test_clock(),
        crate::testing::db::test_rng(),
    )
    .unwrap()
    .with_transparent_ledger_mode(PrivateRequired);
    let entry = reopened
        .transaction_history_details(case.account, &[case.txid])
        .unwrap()
        .remove(0);
    assert_eq!(
        entry.classification,
        HistoryClassification::NetReconstructed
    );
    assert_eq!(entry.fee, FeeState::Unknown);
}

/// A pending shape response cannot survive restoration of public authority. Returning to
/// PrivateRequired requeues the same private note binding without allowing public fallback.
#[test]
fn shape_only_recovery_obeys_public_authority_transitions() {
    let mut case = shielding(&CASES[1], Some(reported_metadata()));
    recover_memo(&mut case, None);
    conn(&case.st).execute("UPDATE ironwood_enhance_routing SET has_transparent_outputs = NULL WHERE transaction_id = ?", [case.tx_ref]).unwrap();
    crate::wallet::enhance_pir::queue_unsupported_memos(
        conn(&case.st),
        Some(crate::TxRef(case.tx_ref)),
    )
    .unwrap();
    let request = private_queries(&case.st)[0];
    let response = record(&case.st, request, None);
    set_policy(&mut case.st, Public);
    assert_eq!(
        apply_records(&mut case.st, &[(request, response.clone())]),
        vec![EnhancePirStoreResult::AlreadyResolved]
    );
    assert_eq!(queued(&case.st, case.tx_ref), 0);
    set_policy(&mut case.st, PrivateRequired);
    promote(&mut case.st, case.account).unwrap();
    assert_eq!(private_queries(&case.st), vec![request]);
    assert_eq!(
        apply_records(&mut case.st, &[(request, response)]),
        vec![EnhancePirStoreResult::PrivateDetailsUnsupported]
    );
    assert_reconstructed_shielding(&case, &CASES[1]);
}

/// Deleting the account chosen for shape recovery must retain the shared transaction's
/// obligation and rebind it to another owned note, without accepting the old response.
#[test]
fn deleting_the_shape_binding_account_rebinds_to_a_surviving_note() {
    let mut case = padded_shielding(&CASES[1], Some(reported_metadata()), Some(100_000), true);
    let queries = private_queries(&case.st);
    assert_eq!(queries.len(), 2);
    let records = queries
        .iter()
        .map(|request| (*request, record(&case.st, *request, None)))
        .collect::<Vec<_>>();
    apply_records(&mut case.st, &records);
    assert_reconstructed_shielding(&case, &CASES[1]);
    // Model an older memo-complete wallet whose shape was discarded.
    conn(&case.st).execute("UPDATE ironwood_enhance_routing SET has_transparent_outputs = NULL WHERE transaction_id = ?", [case.tx_ref]).unwrap();
    crate::wallet::enhance_pir::queue_unsupported_memos(
        conn(&case.st),
        Some(crate::TxRef(case.tx_ref)),
    )
    .unwrap();
    let stale = private_queries(&case.st)[0];
    let stale_record = record(&case.st, stale, None);
    let removed: AccountUuid = conn(&case.st).query_row(
        "SELECT a.uuid FROM ironwood_enhance_metadata_queue q JOIN ironwood_received_notes rn ON rn.transaction_id = q.transaction_id AND rn.action_index = q.output_index JOIN accounts a ON a.id = rn.account_id WHERE q.transaction_id = ?",
        [case.tx_ref], |row| row.get::<_, uuid::Uuid>(0).map(AccountUuid::from_uuid),
    ).unwrap();
    assert_ne!(removed, case.account);
    case.st.wallet_mut().delete_account(removed).unwrap();
    let rebound = private_queries(&case.st);
    assert_eq!(
        rebound.len(),
        1,
        "surviving account must retain a bound private shape query"
    );
    assert_ne!(rebound[0], stale);
    assert_eq!(
        apply_records(&mut case.st, &[(stale, stale_record)]),
        vec![EnhancePirStoreResult::AlreadyResolved]
    );
    assert_eq!(private_queries(&case.st), rebound);
    // A reopen must retain the new binding, not rely on an in-memory retry.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rebound.sqlite");
    conn(&case.st)
        .execute("VACUUM INTO ?", [path.to_str().unwrap()])
        .unwrap();
    let mut reopened = crate::WalletDb::for_path(
        path,
        *case.st.network(),
        crate::testing::db::test_clock(),
        crate::testing::db::test_rng(),
    )
    .unwrap()
    .with_transparent_ledger_mode(PrivateRequired);
    reopened.set_enhancement_mode(EnhancementMode::PrivateIronwood);
    assert_eq!(
        reopened.transaction_enhancement_work().unwrap(),
        vec![TransactionEnhancementWork::Private(EnhancePirWork::Query(
            rebound[0]
        ))]
    );
    let response = record(&case.st, rebound[0], None);
    assert_eq!(
        reopened
            .apply_ironwood_enhance_records(&[(rebound[0], response)])
            .unwrap(),
        EnhancePirBatchResult::Committed(vec![EnhancePirStoreResult::PrivateDetailsUnsupported])
    );
    let entry = reopened
        .transaction_history_details(case.account, &[case.txid])
        .unwrap()
        .remove(0);
    assert_eq!(
        entry.classification,
        HistoryClassification::NetReconstructed
    );
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
    assert!(reopened.transaction_enhancement_work().unwrap().is_empty());
}
