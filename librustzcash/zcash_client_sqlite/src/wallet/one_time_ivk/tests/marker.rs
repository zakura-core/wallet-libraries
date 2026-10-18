use std::{collections::HashMap, convert::Infallible};

use zcash_client_backend::{
    TransferType,
    data_api::{
        MaxSpendMode,
        error::Error,
        wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, LockedInputPolicy},
            propose_send_max_transfer,
        },
    },
    decrypt_transaction,
    fees::{
        ChangeValue, DustAction, DustOutputPolicy, StandardFeeRule, TransactionBalance,
        standard::SingleOutputChangeStrategy,
    },
    wallet::OvkPolicy,
};
use zcash_primitives::transaction::TxId;

use super::*;

/// A wallet whose only funds are one spendable one-time note of `value` zatoshis.
fn one_time_funded(value: u64) -> State {
    let mut st = ironwood_wallet();
    let account = st.test_account().unwrap().id();
    let start = st.sapling_activation_height();
    let refund = reserve_key(st.wallet_mut().db_mut(), account, Purpose::Refund, start);
    pay(&mut st, refund.full_viewing_key(), value);
    st.generate_and_scan_empty_blocks_with_one_time_ivks(2);
    st
}

/// Mines and scans `txid`, then returns the values of its Ironwood outputs that the test
/// account's ordinary keys alone decrypt as account-internal, as a restore would see them.
fn markers(st: &mut State, txid: TxId) -> Vec<u64> {
    let (height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks_with_one_time_ivks(height, 1);
    let account = st.test_account().cloned().unwrap();
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let ufvks = HashMap::from([(account.id(), account.usk().to_unified_full_viewing_key())]);
    let decrypted = decrypt_transaction(st.network(), Some(height), None, &tx, &ufvks);
    decrypted
        .ironwood_outputs()
        .iter()
        .filter(|output| output.transfer_type() == TransferType::AccountInternal)
        .map(|output| output.note().0.value().inner())
        .collect()
}

/// A one-time note spent with nothing left over still carries a zero-value marker, and
/// building the same spend without it is refused, even when it pays the account's own
/// internal address, which the built transaction's check alone would take for a marker.
#[test]
fn exact_one_time_spend_carries_a_zero_value_marker() {
    let mut st = one_time_funded(2_000_000);
    let account = st.test_account().cloned().unwrap();
    // One spend and two outputs pad to two actions, a 10000 zatoshi fee.
    let to = payment(&unified(foreign_receiver()), 1_990_000, None);
    let change = (None, zcash_protocol::ShieldedPool::Orchard);
    let (proposal, txid) = transfer(&mut st, (account.id(), account.usk()), vec![to], change);
    let step = &proposal.steps()[0];
    assert_eq!(
        step.balance().proposed_change(),
        [ChangeValue::ironwood(Zatoshis::ZERO, None)]
    );

    // The same spend with its zero-value change dropped still balances.
    let unmarked = Proposal::single_step(
        step.transaction_request().clone(),
        step.payment_pools().clone(),
        vec![],
        step.shielded_inputs().cloned(),
        step.anchor_height().unwrap(),
        TransactionBalance::new(vec![], step.balance().fee_required()).unwrap(),
        *proposal.fee_rule(),
        proposal.min_target_height(),
        proposal.confirmations_policy(),
        false,
        true,
    )
    .unwrap();
    let created = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &unmarked,
    );
    assert!(matches!(created, Err(Error::OneTimeSpendWithoutMarker)));
    // The payment is made in Ironwood, so a payment to self there decrypts as internal.
    assert_eq!(step.payment_pools()[&0], zcash_protocol::PoolType::IRONWOOD);
    let internal = FullViewingKey::from(account.usk().orchard()).address_at(0u32, Scope::Internal);
    let to_self = payment(&unified(internal), 1_990_000, None);
    let to_self = Proposal::single_step(
        zip321::TransactionRequest::new(vec![to_self]).unwrap(),
        step.payment_pools().clone(),
        vec![],
        step.shielded_inputs().cloned(),
        step.anchor_height().unwrap(),
        TransactionBalance::new(vec![], step.balance().fee_required()).unwrap(),
        *proposal.fee_rule(),
        proposal.min_target_height(),
        proposal.confirmations_policy(),
        false,
        true,
    )
    .unwrap();
    let created = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &to_self,
    );
    assert!(matches!(created, Err(Error::OneTimeSpendWithoutMarker)));

    assert_eq!(markers(&mut st, txid.unwrap()), [0]);
}

/// Sending the whole balance of a one-time note keeps a zero-value marker, which costs
/// no extra action.
#[test]
fn sending_a_one_time_note_max_carries_a_zero_value_marker() {
    let mut st = one_time_funded(2_000_000);
    let account = st.test_account().cloned().unwrap();
    let to = unified(foreign_receiver()).to_zcash_address(&ironwood_network());
    let proposal = propose_send_max_transfer::<_, _, _, Infallible>(
        st.wallet_mut(),
        &ironwood_network(),
        account.id(),
        &[zcash_protocol::ShieldedPool::Ironwood],
        &StandardFeeRule::Zip317,
        to,
        None,
        MaxSpendMode::MaxSpendable,
        ConfirmationsPolicy::MIN,
        &LockedInputPolicy::Exclude,
        None,
    )
    .unwrap();
    let balance = proposal.steps()[0].balance();
    assert_eq!(
        balance.proposed_change(),
        [ChangeValue::ironwood(Zatoshis::ZERO, None)]
    );
    assert_eq!(balance.fee_required(), Zatoshis::const_from_u64(10_000));
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];
    assert_eq!(markers(&mut st, txid), [0]);
}

/// A one-time spend proposed with its dust added to the fee still carries its zero-value
/// marker. Input selection hands the change strategy whether each input is one-time.
#[test]
fn a_one_time_spend_adding_dust_to_the_fee_keeps_its_marker() {
    let mut st = one_time_funded(2_000_000);
    let account = st.test_account().cloned().unwrap();
    let strategy = SingleOutputChangeStrategy::<TestDb>::new(
        StandardFeeRule::Zip317,
        None,
        zcash_protocol::ShieldedPool::Orchard,
        DustOutputPolicy::new(DustAction::AddDustToFee, None),
    );
    // 100 zatoshis are left over, too little for change, so they go to the fee.
    let to = payment(&unified(foreign_receiver()), 1_989_900, None);
    let request = zip321::TransactionRequest::new(vec![to]).unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    let balance = proposal.steps()[0].balance();
    assert_eq!(
        balance.proposed_change(),
        [ChangeValue::ironwood(Zatoshis::ZERO, None)]
    );
    assert_eq!(balance.fee_required(), Zatoshis::const_from_u64(10_100));
}
