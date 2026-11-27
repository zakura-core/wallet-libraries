//! Scanning, under the external-when-linear policy, of transactions the wallet did not create.
//!
//! The policy trial-decrypts with internal keys only the transactions its triggers select, so
//! every note in these tests must be reached through a trigger. The wallet never sees any of
//! these transactions before they are scanned, which rules out the known-txid trigger; what
//! remains is the spend of a tracked note, or the coinbase position.

use zcash_client_backend::data_api::{
    Account as _, WalletWrite,
    chain::{LinearScanGuarantee, TransparentHistory, TrialDecryptionPolicy},
    testing::{
        AddressType, IronwoodFvk, TestBuilder, TestState, orchard::OrchardPoolTester,
        pool::ShieldedPoolTester, sapling::SaplingPoolTester,
    },
    wallet::ConfirmationsPolicy,
};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

use crate::{
    AccountUuid, PRUNING_DEPTH,
    testing::{BlockCache, db::TestDb, db::TestDbFactory},
};

/// The external-when-linear policy, declaring transparent history over every block. No
/// transaction in this module involves a transparent address of the wallet, so the declaration
/// is one the tests keep.
const POLICY: TrialDecryptionPolicy =
    TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(BlockHeight::from_u32(u32::MAX)),
    ));
/// The value of the note that funds each spend.
const FUNDING: Zatoshis = Zatoshis::const_from_u64(100_000);
/// The value each spend pays away; the remainder returns to the wallet as change.
const SENT: Zatoshis = Zatoshis::const_from_u64(20_000);
/// Empty blocks between a receipt and its spend: more than the spend-map retention window, so
/// that a single batch covering them includes blocks the wallet elects not to track spends for.
const LONG_GAP: u32 = PRUNING_DEPTH + 10;

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

fn usk(st: &St) -> UnifiedSpendingKey {
    st.test_account().unwrap().usk().clone()
}

/// The account's Ironwood viewing key, which is its Orchard key applied to the Ironwood pool.
fn ironwood_fvk(st: &St) -> IronwoodFvk {
    IronwoodFvk(::orchard::keys::FullViewingKey::from(usk(st).orchard()))
}

/// Scans `blocks` blocks from `from` as one batch under the policy, after notifying the wallet of
/// the chain tip, as a linear catch-up does.
fn scan_one_batch(st: &mut St, from: BlockHeight, blocks: u32) {
    let tip = st.latest_cached_block().unwrap().height();
    st.wallet_mut().update_chain_tip(tip).unwrap();
    st.scan_cached_blocks_with_policy(from, usize::try_from(blocks).unwrap(), POLICY);
}

fn assert_only_change(st: &mut St, account: AccountUuid, change: Zatoshis) {
    // The last block of the batch holds the change note. In this tree the spending anchor is one
    // block lower than the confirmation count asks for. Thus one more block must come, and a scan
    // of it, before the note is spendable. An empty block adds no note.
    let (height, _) = st.generate_empty_block();
    st.wallet_mut().update_chain_tip(height).unwrap();
    st.scan_cached_blocks(height, 1);

    assert_eq!(st.get_total_balance(account), change);
    assert_eq!(
        st.get_spendable_balance(account, ConfirmationsPolicy::MIN),
        change
    );
}

/// Receives a note, then spends it in a transaction the wallet never saw, which returns change to
/// the wallet's internal receiver in the same pool. Both blocks are scanned in one batch.
fn change_in_pool<T: ShieldedPoolTester>(st: &mut St, account: AccountUuid) {
    let fvk = T::test_account_fvk(st);
    let (funded_at, _, nf) = st.generate_next_block(&fvk, AddressType::DefaultExternal, FUNDING);
    let change = (FUNDING - SENT).unwrap();
    st.generate_next_block_spending_to_internal(&fvk, (nf, FUNDING), &fvk, change);

    scan_one_batch(st, funded_at, 2);
    assert_only_change(st, account, change);
}

#[test]
fn change_is_found_in_sapling() {
    let (mut st, account) = wallet();
    change_in_pool::<SaplingPoolTester>(&mut st, account);
}

#[test]
fn change_is_found_in_orchard() {
    let (mut st, account) = wallet();
    change_in_pool::<OrchardPoolTester>(&mut st, account);
}

#[test]
fn change_is_found_in_ironwood() {
    let (mut st, account) = wallet();
    let fvk = ironwood_fvk(&st);
    let (funded_at, _, nf) = st.generate_next_block(&fvk, AddressType::DefaultExternal, FUNDING);
    let change = (FUNDING - SENT).unwrap();
    st.generate_next_block_spending_to_internal(&fvk, (nf, FUNDING), &fvk, change);

    scan_one_batch(&mut st, funded_at, 2);
    assert_only_change(&mut st, account, change);
}

/// A spend whose change lands in a different pool from the note it spent. The spend is the only
/// signal that the transaction is the wallet's own, and it is recorded in the pool of the spent
/// note, while the note to find lies in another.
#[test]
fn cross_pool_change_is_found_from_sapling_to_orchard() {
    let (mut st, account) = wallet();
    let spend_fvk = SaplingPoolTester::test_account_fvk(&st);
    let change_fvk = OrchardPoolTester::test_account_fvk(&st);
    let (funded_at, _, nf) =
        st.generate_next_block(&spend_fvk, AddressType::DefaultExternal, FUNDING);
    let change = (FUNDING - SENT).unwrap();
    st.generate_next_block_spending_to_internal(&spend_fvk, (nf, FUNDING), &change_fvk, change);

    scan_one_batch(&mut st, funded_at, 2);
    assert_only_change(&mut st, account, change);
}

#[test]
fn cross_pool_change_is_found_from_sapling_to_ironwood() {
    let (mut st, account) = wallet();
    let spend_fvk = SaplingPoolTester::test_account_fvk(&st);
    let change_fvk = ironwood_fvk(&st);
    let (funded_at, _, nf) =
        st.generate_next_block(&spend_fvk, AddressType::DefaultExternal, FUNDING);
    let change = (FUNDING - SENT).unwrap();
    st.generate_next_block_spending_to_internal(&spend_fvk, (nf, FUNDING), &change_fvk, change);

    scan_one_batch(&mut st, funded_at, 2);
    assert_only_change(&mut st, account, change);
}

#[test]
fn cross_pool_change_is_found_from_orchard_to_ironwood() {
    let (mut st, account) = wallet();
    let spend_fvk = OrchardPoolTester::test_account_fvk(&st);
    let change_fvk = ironwood_fvk(&st);
    let (funded_at, _, nf) =
        st.generate_next_block(&spend_fvk, AddressType::DefaultExternal, FUNDING);
    let change = (FUNDING - SENT).unwrap();
    st.generate_next_block_spending_to_internal(&spend_fvk, (nf, FUNDING), &change_fvk, change);

    scan_one_batch(&mut st, funded_at, 2);
    assert_only_change(&mut st, account, change);
}

/// Change spent in turn, and its own change spent again, all within one batch. Each spend can
/// only be matched against a note the same batch brought into the wallet, so the identifiers the
/// scan matches against must be extended as the batch proceeds.
#[test]
fn change_is_found_along_a_chain_of_spends() {
    let (mut st, account) = wallet();
    let fvk = OrchardPoolTester::test_account_fvk(&st);
    let (funded_at, _, nf) = st.generate_next_block(&fvk, AddressType::DefaultExternal, FUNDING);

    let first_change = (FUNDING - SENT).unwrap();
    let (_, _, first_change_nf) =
        st.generate_next_block_spending_to_internal(&fvk, (nf, FUNDING), &fvk, first_change);
    let second_change = (first_change - SENT).unwrap();
    st.generate_next_block_spending_to_internal(
        &fvk,
        (first_change_nf, first_change),
        &fvk,
        second_change,
    );

    scan_one_batch(&mut st, funded_at, 3);
    assert_only_change(&mut st, account, second_change);
}

/// A spend separated from the note it spends by more blocks than the spend-map retention window,
/// scanned as one batch. The wallet does not record spends for the blocks of such a batch that
/// lie far below its end, so the spend must be matched during the scan itself.
#[test]
fn change_is_found_across_a_long_gap() {
    let (mut st, account) = wallet();
    let fvk = OrchardPoolTester::test_account_fvk(&st);
    let (funded_at, _, nf) = st.generate_next_block(&fvk, AddressType::DefaultExternal, FUNDING);
    for _ in 0..LONG_GAP {
        st.generate_empty_block();
    }
    let change = (FUNDING - SENT).unwrap();
    st.generate_next_block_spending_to_internal(&fvk, (nf, FUNDING), &fvk, change);

    scan_one_batch(&mut st, funded_at, LONG_GAP + 2);
    assert_only_change(&mut st, account, change);
}

/// A scan that is not linear falls back to trial-decrypting with every scope, so the change of a
/// transaction whose spend cannot yet be matched is still found.
#[test]
fn change_is_found_when_the_spend_is_scanned_first() {
    let (mut st, account) = wallet();
    let fvk = OrchardPoolTester::test_account_fvk(&st);
    let (funded_at, _, nf) = st.generate_next_block(&fvk, AddressType::DefaultExternal, FUNDING);
    let change = (FUNDING - SENT).unwrap();
    let (spent_at, _, _) =
        st.generate_next_block_spending_to_internal(&fvk, (nf, FUNDING), &fvk, change);

    scan_one_batch(&mut st, spent_at, 1);
    scan_one_batch(&mut st, funded_at, 1);
    assert_only_change(&mut st, account, change);
}

/// A coinbase transaction paying an internal receiver of the wallet. Nothing identifies it as the
/// wallet's own but its position in the block.
#[test]
fn coinbase_output_to_an_internal_receiver_is_found() {
    let (mut st, account) = wallet();
    let fvk = OrchardPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(&fvk, AddressType::Internal, FUNDING);

    scan_one_batch(&mut st, height, 1);
    assert_eq!(st.get_total_balance(account), FUNDING);
}

/// Verifies that internal Ironwood keys stay in the main batch while an account is within
/// `recover_until_height` (regardless of PIR recovery state) and drop to external-only once
/// recovery finishes or on fresh accounts, while Orchard remains external-only throughout.
#[test]
fn internal_ironwood_keys_are_scoped_to_recovery_window() {
    let change = (FUNDING - SENT).unwrap();
    let foreign_nf = |seed: u8| ::orchard::note::Nullifier::from_bytes(&[seed; 32]).unwrap();
    let policy = TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(BlockHeight::from_u32(u32::MAX)),
    ));

    // Helper: creates a wallet with an Ironwood internal-receiver spend at h2 (and an Orchard
    // internal-receiver spend at h3) using foreign nullifiers so no trigger fires.
    let run_case = |recover_until_offset: Option<i32>, enable_pir: bool| -> (Zatoshis, Zatoshis) {
        let (mut st, account) = wallet();
        let iw_fvk = ironwood_fvk(&st);
        let orch_fvk = OrchardPoolTester::test_account_fvk(&st);
        let (h1, _) = st.generate_empty_block();
        let (h2, _, _) = st.generate_next_block_spending_to_internal(
            &iw_fvk,
            (foreign_nf(10), FUNDING),
            &iw_fvk,
            change,
        );
        let (h3, _, _) = st.generate_next_block_spending_to_internal(
            &orch_fvk,
            (foreign_nf(11), FUNDING),
            &orch_fvk,
            change,
        );
        if let Some(offset) = recover_until_offset {
            let until = if offset >= 0 {
                u32::from(h2) + (offset as u32)
            } else {
                u32::from(h2) - ((-offset) as u32)
            };
            st.wallet_mut()
                .conn_mut()
                .execute("UPDATE accounts SET recover_until_height = ?1", [until])
                .unwrap();
        }
        if enable_pir {
            st.wallet_mut()
                .db_mut()
                .enable_one_time_recovery(account)
                .unwrap();
        }
        st.wallet_mut().update_chain_tip(h3).unwrap();
        st.scan_cached_blocks_with_policy(h1, 1, policy);
        st.scan_cached_blocks_with_policy(h2, 1, policy);
        let after_iw = st.get_total_balance(account);
        st.scan_cached_blocks_with_policy(h3, 1, policy);
        let after_orch = st.get_total_balance(account);
        (after_iw, after_orch)
    };

    // 1. Fresh account (recover_until_height IS NULL): external-only Ironwood & Orchard.
    assert_eq!(run_case(None, false), (Zatoshis::ZERO, Zatoshis::ZERO));

    // 2. Restored account within recover_until_height (PIR disabled): internal Ironwood key stays
    // in batch (Ironwood canary found), while Orchard stays external-only (Orchard missed).
    assert_eq!(run_case(Some(1), false), (change, change));

    // 3. Restored account within recover_until_height (PIR enabled): internal Ironwood key still
    // stays in batch so journal coverage is written throughout restore; Orchard stays external.
    assert_eq!(run_case(Some(1), true), (change, change));

    // 4. Restored account PAST recover_until_height (recover_until_height < h2): external-only
    // Ironwood resumes once recovery finishes.
    assert_eq!(run_case(Some(-1), false), (Zatoshis::ZERO, Zatoshis::ZERO));
    assert_eq!(run_case(Some(-1), true), (Zatoshis::ZERO, Zatoshis::ZERO));
}
