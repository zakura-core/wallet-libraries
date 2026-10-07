//! Activity for a fresh restore of an Ironwood send with transparent outputs.
//!
//! A sender wallet builds the reported mainnet shape as a real transaction: one owned Ironwood
//! note of 107,485,000 zatoshis pays 250,000 to a transparent address and returns 107,220,000 as
//! Ironwood change, with a 15,000 fee. A second wallet restored from the same seed then recovers
//! it as a fresh `PrivateRequired` restore does: compact scanning finds the spend and the change,
//! and Enhance PIR applies the service's records for the transaction's Ironwood actions, which
//! assert transparent outputs. No full transaction is ever stored. A third, public restore of
//! the same chain stores the full transaction and is the control.

use std::convert::Infallible;

use zcash_client_backend::{
    data_api::{
        enhance_pir::{
            EnhancePirBatchResult, EnhancePirRead as _, EnhancePirRequest, EnhancePirStoreResult,
            EnhancePirWork, EnhancePirWrite as _, EnhanceRecord, EnhanceRecordParts,
            EnhanceTransactionMetadata, EnhancementMode, TransactionEnhancementWork,
        },
        testing::single_output_change_strategy,
        testing::{IronwoodFvk, orchard::OrchardPoolTester, pool::ShieldedPoolTester},
        transparent_ledger::{
            AggregatePayment, DetailCompleteness, EffectCompleteness, FeeState,
            HistoryClassification, PoolEffect, TransactionHistoryDetails, TransactionMetadata,
            WholeTransactionFee,
        },
        wallet::decrypt_and_store_transaction,
        wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
    },
    fees::StandardFeeRule,
    wallet::OvkPolicy,
};
use zcash_keys::address::Address;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{PoolType, ShieldedPool, local_consensus::LocalNetwork};
use zip321::{Payment, TransactionRequest};

use super::*;

const SPENT: u64 = 107_485_000;
const CHANGE: u64 = 107_220_000;
const SENT: u64 = 250_000;
const FEE: u64 = 15_000;

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

/// A wallet holding the account's single Ironwood note of `SPENT`, compact-scanned. Every wallet
/// built this way holds the same chain and the same note: the test builder is deterministic, and
/// `prepare` runs between the shared blocks and the note without generating blocks.
fn funded(prepare: impl FnOnce(&mut State)) -> State {
    let mut st = TestBuilder::new()
        .with_network(ironwood_network())
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    scan_new_blocks(&mut st, 10);
    prepare(&mut st);
    let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
    let (height, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, zat(SPENT));
    st.scan_cached_blocks(height, 1);
    st
}

/// Where the reported transaction sends its 250,000 zatoshis.
#[derive(Clone, Copy)]
enum Destination {
    /// The account's own first external transparent address, as reported.
    OwnTransparent,
    /// A transparent address no wallet account holds.
    ExternalTransparent,
    /// An Ironwood address no wallet account holds, with the sender's outgoing viewing key
    /// discarded: no transparent output, and no outgoing recovery.
    ExternalShieldedWithoutOvk,
}

fn own_transparent(st: &State) -> TransparentAddress {
    let account = st.test_account().unwrap().id();
    external(&watch(st, account))
}

/// Builds the reported transaction in a sender wallet that holds the same note.
fn sent_transaction(destination: Destination) -> Transaction {
    let mut st = funded(|st| set_policy(st, Public));
    let to = match destination {
        Destination::OwnTransparent => Address::from(own_transparent(&st)),
        Destination::ExternalTransparent => {
            Address::from(TransparentAddress::PublicKeyHash([7; 20]))
        }
        Destination::ExternalShieldedWithoutOvk => {
            OrchardPoolTester::sk_default_address(&OrchardPoolTester::sk(&[0xf5; 32]))
        }
    };
    let request = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        zat(SENT),
    )])
    .unwrap();
    let account = st.test_account().cloned().unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Orchard),
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    let ovk_policy = match destination {
        Destination::ExternalShieldedWithoutOvk => OvkPolicy::Discard,
        _ => OvkPolicy::Sender,
    };
    let txid = *st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            ovk_policy,
            &proposal,
        )
        .unwrap()
        .first();
    st.wallet().get_transaction(txid).unwrap().unwrap()
}

/// A restored wallet that has mined and compact-scanned the transaction.
struct Restored {
    st: State,
    account: AccountUuid,
    tx: Transaction,
    tx_ref: i64,
    height: BlockHeight,
}

impl Restored {
    fn history(&self) -> TransactionHistoryDetails {
        let mut entries = self
            .st
            .wallet()
            .db()
            .transaction_history_details(self.account, &[self.tx.txid()])
            .unwrap();
        assert_eq!(entries.len(), 1);
        entries.remove(0)
    }

    fn count(&self, sql: &str) -> i64 {
        conn(&self.st)
            .query_row(sql, [self.tx_ref], |row| row.get(0))
            .unwrap()
    }

    /// The value of the transparent outputs the account's recorded sends paid.
    fn recorded_transparent_sends(&self) -> u64 {
        u64::try_from(self.count(
            "SELECT COALESCE(SUM(value), 0) FROM sent_notes
             WHERE transaction_id = ?1 AND output_pool = 0",
        ))
        .unwrap()
    }
}

/// Mines `tx` in a restored wallet's chain and scans it, with two more blocks above it.
fn restore(tx: Transaction, prepare: impl FnOnce(&mut State)) -> Restored {
    let mut st = funded(prepare);
    let account = st.test_account().unwrap().id();
    assert_eq!(
        st.wallet()
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap()
            .account_balances()[&account]
            .ironwood_balance()
            .total(),
        zat(SPENT),
        "the restore holds the note the sender spent"
    );
    let (height, _) = st.generate_next_block_from_tx(1, &tx);
    st.scan_cached_blocks(height, 1);
    scan_new_blocks(&mut st, 2);
    let tx_ref = conn(&st)
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?1",
            [tx.txid().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    Restored {
        st,
        account,
        tx,
        tx_ref,
        height,
    }
}

/// Covers the account's transparent addresses privately, with `receives`, and qualifies and
/// promotes it under `PrivateRequired` with private Ironwood enhancement.
fn recover_transparent(st: &mut State, receives: Vec<ReceiveEvent>) {
    let account = st.test_account().unwrap().id();
    let fixture = revision(1, true);
    cover(st, account, &fixture, receives);
    qualify(st, &fixture);
    set_policy(st, PrivateRequired);
    promote(st, account).unwrap();
    st.wallet_mut()
        .db_mut()
        .set_enhancement_mode(EnhancementMode::PrivateIronwood);
}

/// The service's record for one Ironwood action of `tx`: its ciphertexts and value commitment,
/// the transaction's transparent shape, and its metadata.
fn record(tx: &Transaction, index: u32, outputs: bool, fee: Option<u64>) -> EnhanceRecord {
    let bundle = tx.ironwood_bundle().unwrap();
    let action = &bundle.actions()[usize::try_from(index).unwrap()];
    let note = action.encrypted_note();
    EnhanceRecord::from_parts(EnhanceRecordParts {
        enc_ciphertext_suffix: note.enc_ciphertext[52..].try_into().unwrap(),
        cv_net: action.cv_net().to_bytes(),
        out_ciphertext: note.out_ciphertext,
        has_transparent_inputs: false,
        has_transparent_outputs: outputs,
        metadata: EnhanceTransactionMetadata::new(u32::from(tx.expiry_height()), fee).unwrap(),
    })
}

/// Answers every private query for the transaction with the service's records.
fn enhance(case: &mut Restored, outputs: bool, fee: Option<u64>) -> Vec<EnhancePirStoreResult> {
    let requests: Vec<EnhancePirRequest> = case
        .st
        .wallet()
        .transaction_enhancement_work()
        .unwrap()
        .into_iter()
        .filter_map(|work| match work {
            // The funding note's memo is queued too; only this transaction is answered.
            TransactionEnhancementWork::Private(EnhancePirWork::Query(request))
                if request.request_id().txid() == case.tx.txid() =>
            {
                Some(request)
            }
            TransactionEnhancementWork::Public(request) => {
                panic!("PrivateRequired exposed public payload work for {request:?}")
            }
            _ => None,
        })
        .collect();
    assert!(!requests.is_empty());
    let records: Vec<_> = requests
        .iter()
        .map(|request| {
            let index = request.request_id().output_index();
            (*request, record(&case.tx, index, outputs, fee))
        })
        .collect();
    match case
        .st
        .wallet_mut()
        .db_mut()
        .apply_ironwood_enhance_records(&records)
        .unwrap()
    {
        EnhancePirBatchResult::Committed(results) => results,
        rejected => panic!("unexpected batch rejection {rejected:?}"),
    }
}

/// The receive of the transaction's transparent output to the account's own address, as private
/// transparent recovery publishes it.
fn own_output(case: &Restored, metadata: Option<TransactionMetadata>) -> ReceiveEvent {
    let vout = &case.tx.transparent_bundle().unwrap().vout;
    let index = vout
        .iter()
        .position(|out| out.value() == zat(SENT))
        .unwrap();
    ReceiveEvent {
        metadata,
        outpoint: OutPoint::new(case.tx.txid().into(), u32::try_from(index).unwrap()),
        address: own_transparent(&case.st),
        value: zat(SENT),
        coinbase: false,
        mined_height: case.height,
    }
}

/// The reported transaction recovered privately. With `own_output`, private transparent
/// recovery also publishes the account's receipt of its transparent output, carrying `metadata`.
fn privately_recovered(
    destination: Destination,
    own_output_metadata: Option<Option<TransactionMetadata>>,
    record_outputs: bool,
    record_fee: Option<u64>,
) -> Restored {
    let tx = sent_transaction(destination);
    let mut case = restore(tx, |st| set_policy(st, PrivateShadow));
    let receives = own_output_metadata
        .map(|metadata| vec![own_output(&case, metadata)])
        .unwrap_or_default();
    recover_transparent(&mut case.st, receives);
    let results = enhance(&mut case, record_outputs, record_fee);
    assert!(
        results.iter().all(|result| matches!(
            result,
            EnhancePirStoreResult::PrivateDetailsUnsupported
                | EnhancePirStoreResult::Stored
                | EnhancePirStoreResult::NotRecoverable
                | EnhancePirStoreResult::AlreadyResolved
        )),
        "{results:?}"
    );
    case
}

/// The same chain restored publicly: the wallet stores the full transaction it would retrieve.
fn publicly_recovered(destination: Destination) -> Restored {
    let tx = sent_transaction(destination);
    let mut case = restore(tx, |st| set_policy(st, Public));
    let network = *case.st.network();
    decrypt_and_store_transaction(&network, case.st.wallet_mut(), &case.tx, Some(case.height))
        .unwrap();
    case
}

fn effect(entry: &TransactionHistoryDetails, pool: PoolType) -> PoolEffect {
    *entry.effects.iter().find(|e| e.pool == pool).unwrap()
}

/// Only Activity is inferred: the payment, its details, the account's fee and the classification
/// keep what the evidence establishes.
fn assert_only_activity_inferred(entry: &TransactionHistoryDetails) {
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
}

/// The reported transaction: private recovery shows the same outgoing Activity and network fee
/// as the public control, from compact scanning and Enhance PIR alone, and with the account's
/// recovered receipt of its own transparent output.
#[test]
fn reported_send_shows_its_outgoing_value_and_network_fee() {
    let public = publicly_recovered(Destination::OwnTransparent);
    let control = public.history();
    assert_eq!(control.fee, FeeState::Known(zat(FEE)));
    assert_eq!(control.whole_fee, Some(zat(FEE)));
    assert_eq!(control.inferred_outgoing, None);
    assert_eq!(public.recorded_transparent_sends(), SENT);
    assert_eq!(effect(&control, PoolType::IRONWOOD).spent, zat(SPENT));
    assert_eq!(effect(&control, PoolType::IRONWOOD).received, zat(CHANGE));

    // Without any transparent rows or transparent metadata.
    let private = privately_recovered(Destination::OwnTransparent, None, true, Some(FEE));
    let entry = private.history();
    for table in [
        "transparent_received_outputs",
        "transparent_received_output_spends",
    ] {
        assert_eq!(
            private.count(&format!(
                "SELECT COUNT(*) FROM {table} WHERE transaction_id = ?1"
            )),
            0,
            "{table}"
        );
    }
    // Compact scanning records the change as the account's output to itself, and nothing else.
    assert_eq!(
        private.count(
            "SELECT COUNT(*) FROM sent_notes s
             JOIN ironwood_received_notes rn
                  ON rn.transaction_id = s.transaction_id AND rn.action_index = s.output_index
             WHERE s.transaction_id = ?1 AND s.output_pool = 4 AND rn.value = s.value"
        ),
        private.count("SELECT COUNT(*) FROM sent_notes WHERE transaction_id = ?1"),
        "only the change is recorded as sent"
    );
    assert_eq!(
        private.count("SELECT raw IS NOT NULL FROM transactions WHERE id_tx = ?1"),
        0,
        "no full transaction"
    );
    assert_eq!(count(&private.st, "tpir_transaction_metadata"), 0);
    assert_eq!(entry.transaction_metadata, None);
    assert_eq!(entry.has_transparent_outputs, Some(true));
    assert_eq!(
        effect(&entry, PoolType::IRONWOOD),
        PoolEffect {
            pool: PoolType::IRONWOOD,
            received: zat(CHANGE),
            spent: zat(SPENT),
            completeness: EffectCompleteness::Complete,
        }
    );
    assert_eq!(entry.whole_fee, Some(zat(FEE)));
    assert_eq!(entry.inferred_outgoing, Some(zat(SENT)));
    assert_eq!(
        entry.inferred_outgoing.map(Zatoshis::into_u64),
        Some(public.recorded_transparent_sends())
    );
    assert_only_activity_inferred(&entry);

    // With the account's receipt of its own transparent output recovered privately: the net
    // movement is the fee alone, but the outgoing value is unchanged.
    let owned = privately_recovered(Destination::OwnTransparent, Some(None), true, Some(FEE));
    let entry = owned.history();
    assert_eq!(effect(&entry, PoolType::Transparent).received, zat(SENT));
    assert_eq!(
        effect(&entry, PoolType::Transparent).completeness,
        EffectCompleteness::Complete
    );
    assert_eq!(entry.account_movement.net(), -i128::from(FEE));
    assert_eq!(entry.whole_fee, Some(zat(FEE)));
    assert_eq!(entry.inferred_outgoing, Some(zat(SENT)));
    assert_only_activity_inferred(&entry);

    // A payment to someone else has the same Activity, publicly and privately.
    let public = publicly_recovered(Destination::ExternalTransparent);
    assert_eq!(public.recorded_transparent_sends(), SENT);
    let entry =
        privately_recovered(Destination::ExternalTransparent, None, true, Some(FEE)).history();
    assert_eq!(entry.inferred_outgoing, Some(zat(SENT)));
    assert_only_activity_inferred(&entry);
}

/// The whole fee, from either private source, is required, and must agree with the other.
#[test]
fn unknown_or_contradicted_fee_infers_nothing() {
    let metadata = |fee, inputs| TransactionMetadata {
        fee,
        transparent_input_count: inputs,
        has_shielded_components: true,
    };
    // Neither Enhance nor transparent recovery establishes the fee.
    for own in [None, Some(Some(metadata(WholeTransactionFee::Unknown, 0)))] {
        let entry = privately_recovered(Destination::OwnTransparent, own, true, None).history();
        assert_eq!(entry.whole_fee, None);
        assert_eq!(entry.inferred_outgoing, None);
        assert_only_activity_inferred(&entry);
    }
    // Qualified transparent metadata alone establishes it.
    let entry = privately_recovered(
        Destination::OwnTransparent,
        Some(Some(metadata(WholeTransactionFee::Exact(zat(FEE)), 0))),
        true,
        None,
    )
    .history();
    assert_eq!(entry.whole_fee, Some(zat(FEE)));
    assert_eq!(entry.inferred_outgoing, Some(zat(SENT)));
    // The two sources disagree.
    let entry = privately_recovered(
        Destination::OwnTransparent,
        Some(Some(metadata(WholeTransactionFee::Exact(zat(20_000)), 0))),
        true,
        Some(FEE),
    )
    .history();
    assert!(entry.transaction_metadata.is_some());
    assert_eq!(entry.whole_fee, None);
    assert_eq!(entry.inferred_outgoing, None);
    assert_only_activity_inferred(&entry);
    // A fee the account's shielded debit cannot have paid contradicts the owned effects.
    let case = privately_recovered(Destination::OwnTransparent, None, true, Some(FEE));
    conn(&case.st)
        .execute(
            "UPDATE transactions SET fee = ?1 WHERE id_tx = ?2",
            rusqlite::params![SPENT - CHANGE, case.tx_ref],
        )
        .unwrap();
    let entry = case.history();
    assert_eq!(entry.whole_fee, Some(zat(SPENT - CHANGE)));
    assert_eq!(entry.inferred_outgoing, None);
}

/// Another party's transparent input could have paid part of the fee or the outputs.
#[test]
fn shared_transparent_funding_infers_nothing() {
    let entry = privately_recovered(
        Destination::OwnTransparent,
        Some(Some(TransactionMetadata {
            fee: WholeTransactionFee::Exact(zat(FEE)),
            transparent_input_count: 1,
            has_shielded_components: true,
        })),
        true,
        Some(FEE),
    )
    .history();
    assert_eq!(entry.whole_fee, Some(zat(FEE)));
    assert_eq!(entry.inferred_outgoing, None);
    assert_only_activity_inferred(&entry);
}

/// Without the service's assertion of transparent outputs, absent or unknown, nothing says the
/// value left through outputs outgoing recovery cannot see.
#[test]
fn absent_or_unknown_transparent_shape_infers_nothing() {
    let case = privately_recovered(Destination::OwnTransparent, None, false, Some(FEE));
    // The record asserts no transparent inputs or outputs, so the transaction is Ironwood-only.
    let entry = case.history();
    assert_eq!(entry.has_transparent_outputs, None);
    assert_eq!(entry.inferred_outgoing, None);

    let case = privately_recovered(Destination::OwnTransparent, None, true, Some(FEE));
    conn(&case.st)
        .execute(
            "UPDATE ironwood_enhance_routing
             SET has_transparent_outputs = NULL, has_transparent_outputs_height = NULL
             WHERE transaction_id = ?1",
            [case.tx_ref],
        )
        .unwrap();
    let entry = case.history();
    assert_eq!(entry.has_transparent_outputs, None);
    assert_eq!(entry.inferred_outgoing, None);
    assert_only_activity_inferred(&entry);
}

/// A shielded payment whose outgoing viewing key was discarded has no transparent output and is
/// not recoverable privately: it stays a provisional debit, without an inferred amount.
#[test]
fn unrecoverable_shielded_payment_infers_nothing() {
    let case = privately_recovered(
        Destination::ExternalShieldedWithoutOvk,
        None,
        false,
        Some(FEE),
    );
    // Only the change is recorded; the payment is not.
    assert_eq!(
        case.count(
            "SELECT COUNT(*) FROM sent_notes s WHERE s.transaction_id = ?1
             AND NOT EXISTS (SELECT 1 FROM ironwood_received_notes rn
                 WHERE rn.transaction_id = s.transaction_id AND rn.action_index = s.output_index)"
        ),
        0
    );
    let entry = case.history();
    assert_eq!(entry.whole_fee, Some(zat(FEE)));
    assert_eq!(entry.inferred_outgoing, None);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
}

/// A recorded send would show in Activity itself; the inference never adds a second amount.
#[test]
fn a_recorded_send_suppresses_the_inference() {
    let case = privately_recovered(Destination::OwnTransparent, None, true, Some(FEE));
    assert_eq!(case.history().inferred_outgoing, Some(zat(SENT)));
    conn(&case.st)
        .execute(
            "INSERT INTO sent_notes (transaction_id, output_pool, output_index, from_account_id,
                 to_address, value)
             SELECT ?1, 0, 0, id, 't1fixture', ?2 FROM accounts",
            rusqlite::params![case.tx_ref, SENT],
        )
        .unwrap();
    let entry = case.history();
    assert_eq!(entry.inferred_outgoing, None);
}

/// Classification follows its evidence: an unmined transaction infers nothing.
#[test]
fn reorg_withdraws_the_inference() {
    let mut case = privately_recovered(Destination::OwnTransparent, None, true, Some(FEE));
    assert_eq!(case.history().inferred_outgoing, Some(zat(SENT)));
    case.st.truncate_to_height(case.height - 1);
    let entry = case.history();
    assert_eq!(entry.mined_height, None);
    assert_eq!(entry.inferred_outgoing, None);
}
