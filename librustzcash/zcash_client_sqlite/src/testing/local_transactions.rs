//! Scanning, under the external-when-linear policy, of transactions this wallet created itself
//! whose spends the scan cannot match: it must recognize them by their txids.

use rusqlite::named_params;
use zcash_client_backend::{
    data_api::{
        Account as _, TransactionStatus, WalletRead, WalletWrite,
        chain::{LinearScanGuarantee, TransparentHistory, TrialDecryptionPolicy},
        testing::{
            AddressType, TestBuilder, TestState, orchard::OrchardPoolTester,
            pool::ShieldedPoolTester, single_output_change_strategy,
        },
        wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
    },
    fees::StandardFeeRule,
    wallet::{OvkPolicy, WalletTransparentOutput},
};
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::{block::BlockHash, transaction::TxId};
use zcash_protocol::{
    ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

use ::transparent::bundle::{OutPoint, TxOut};
use ::transparent::keys::TransparentKeyScope;

use crate::{
    AccountUuid,
    testing::{BlockCache, db::TestDb, db::TestDbFactory},
};

/// The external-when-linear policy, declaring transparent history over every block. The wallet
/// here holds every transaction this declaration is about, so the declaration costs nothing to
/// keep: each is one the wallet created itself, or involves no transparent address of the wallet.
const POLICY: TrialDecryptionPolicy =
    TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(BlockHeight::from_u32(u32::MAX)),
    ));
/// The minimum transparent value the wallet shields.
const SHIELDING_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(10_000);

/// The value of the note that funds each spend.
const FUNDING: Zatoshis = Zatoshis::const_from_u64(100_000);
/// The value each spend pays away.
const SENT: Zatoshis = Zatoshis::const_from_u64(20_000);
type St = TestState<BlockCache, TestDb, LocalNetwork>;

fn wallet() -> (St, AccountUuid) {
    let st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let account = st.test_account().unwrap().id();
    (st, account)
}

/// Scans the next block, which contains only `txid`, under the policy.
fn mine_and_scan(st: &mut St, txid: TxId) {
    let (height, _) = st.generate_next_block_including(txid);
    st.wallet_mut().update_chain_tip(height).unwrap();
    st.scan_cached_blocks_with_policy(height, 1, POLICY);
}

/// Funds the wallet with an Orchard note, scanned under the policy, then creates (but does not
/// mine) a transaction spending it, returning change.
fn fund_and_spend(st: &mut St) -> TxId {
    let fvk = OrchardPoolTester::test_account_fvk(st);
    let (funded_at, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, FUNDING);
    st.wallet_mut().update_chain_tip(funded_at).unwrap();
    st.scan_cached_blocks_with_policy(funded_at, 1, POLICY);

    // In this tree the spending anchor is one block lower than the confirmation count asks
    // for. Thus one more block, and a scan of it, must come before a note is spendable. An
    // empty block adds no note.
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(height).unwrap();
    st.scan_cached_blocks(height, 1);

    let to = OrchardPoolTester::random_address(st.rng_mut()).to_zcash_address(st.network());
    let usk = st.test_account().unwrap().usk().clone();
    st.spend(
        &GreedyInputSelector::new(),
        &single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Orchard),
        &usk,
        TransactionRequest::new(vec![Payment::without_memo(to, SENT)]).unwrap(),
        OvkPolicy::Sender,
        ConfirmationsPolicy::MIN,
    )
    .unwrap()[0]
}

fn assert_change_spendable(st: &mut St, account: AccountUuid) {
    // In this tree the spending anchor is one block lower than the confirmation count asks
    // for. Thus one more block, and a scan of it, must come before a note is spendable. An
    // empty block adds no note.
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(height).unwrap();
    st.scan_cached_blocks(height, 1);

    // The fee of this tree is not the fee of the tree these tests come from, so the exact
    // change is not asserted. Without the known-txid trigger the change is not found at all,
    // and then the balance is zero.
    let total = st.get_total_balance(account);
    assert!(total > Zatoshis::ZERO, "the change was found");
    assert_eq!(
        st.get_spendable_balance(account, ConfirmationsPolicy::MIN),
        total
    );
}

/// The wallet learns that its transaction was mined before scanning the block containing it, so
/// the spent note's nullifier is no longer among those the scan matches.
#[test]
fn change_found_when_mined_status_is_learned_before_scan() {
    let (mut st, account) = wallet();
    let txid = fund_and_spend(&mut st);
    let mined_at = st.latest_cached_block().unwrap().height() + 1;
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::Mined(mined_at))
        .unwrap();
    mine_and_scan(&mut st, txid);
    assert_change_spendable(&mut st, account);
}

/// The wallet's transaction never expires, so the spent note's nullifier is no longer among those
/// the scan matches.
#[test]
fn change_found_for_a_transaction_that_never_expires() {
    let (mut st, account) = wallet();
    let txid = fund_and_spend(&mut st);
    // Take the transaction before the expiry height changes. `generate_next_block_including`
    // rebuilds a transaction from the wallet, and that rebuild drops an Ironwood bundle and so
    // gives a different txid, which no trigger can then match.
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    st.wallet_mut()
        .conn_mut()
        .execute(
            "UPDATE transactions SET expiry_height = 0 WHERE txid = :txid",
            named_params! {":txid": txid.as_ref()},
        )
        .unwrap();
    let (height, _) = st.generate_next_block_from_tx(1, &tx);
    st.wallet_mut().update_chain_tip(height).unwrap();
    st.scan_cached_blocks_with_policy(height, 1, POLICY);

    assert_change_spendable(&mut st, account);
}

/// The wallet shields a UTXO it learned of outside scanning; the compact block carries no
/// transparent inputs for the transaction, so neither a spend match nor the transparent-input
/// trigger applies.
#[test]
fn shielded_output_found_for_a_local_shielding_transaction() {
    let (mut st, account) = wallet();
    let (first, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(first).unwrap();
    st.scan_cached_blocks_with_policy(first, 1, POLICY);

    let taddr = *st
        .wallet()
        .get_last_generated_address_matching(account, UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();
    let utxo = WalletTransparentOutput::from_parts(
        OutPoint::fake(),
        TxOut::new(FUNDING, taddr.script().into()),
        Some(first),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    let usk = st.test_account().unwrap().usk().clone();
    let txid = *st
        .shield_transparent_funds(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Orchard),
            SHIELDING_THRESHOLD,
            &usk,
            &[taddr],
            account,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()
        .first();
    mine_and_scan(&mut st, txid);

    // In this tree the shielded output lands in Ironwood, not Orchard: the turnstile forbids
    // value that enters a shielded pool from a transparent flow to enter Orchard, so
    // `select_change_pool` sends it on to Ironwood. Thus the test reads the total.
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(height).unwrap();
    st.scan_cached_blocks(height, 1);

    let shielded = st.get_total_balance(account);
    assert!(shielded > Zatoshis::ZERO, "the shielded output was found");
    assert_eq!(
        st.get_spendable_balance(account, ConfirmationsPolicy::MIN),
        shielded
    );
}
