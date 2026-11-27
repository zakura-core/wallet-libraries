//! A wallet restored from seed, scanning compact blocks without transparent data, whose history
//! contains a shielding transaction made before the restore and a later spend of its output.
//!
//! The restored wallet cannot recognize the shielding transaction from compact data: it spends no
//! shielded note, the wallet has no record of it, and the compact block omits its transparent
//! input. It learns of the transaction only from the history of its transparent addresses, which
//! is what [`TransparentHistory::SyncedTo`] declares the caller has fetched and stored. These
//! tests check each of the three cases against an all-scopes scan of the same chain: the caller
//! declares nothing, the caller declares what it has stored, and the caller declares a history it
//! never fetched.

use ::transparent::keys::TransparentKeyScope;
use zcash_client_backend::data_api::{
    Account as _, WalletRead, WalletWrite,
    chain::{
        LinearScanGuarantee, TransparentHistory, TrialDecryptionPolicy, testing::ForcedScanMode,
    },
    scanning::ScanPriority,
    testing::{
        TestBuilder, TestState, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
        single_output_change_strategy,
    },
    wallet::{
        ConfirmationsPolicy, decrypt_and_store_transaction, input_selection::GreedyInputSelector,
    },
};
use zcash_client_backend::{
    fees::StandardFeeRule,
    wallet::{OvkPolicy, WalletTransparentOutput},
};
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::{block::BlockHash, transaction::Transaction};
use zcash_protocol::{
    ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

use ::transparent::bundle::{OutPoint, TxOut};

use crate::{
    AccountUuid, PRUNING_DEPTH,
    testing::{BlockCache, db::TestDb, db::TestDbFactory},
};

/// The external-when-linear policy, under the given transparent-history declaration.
const fn policy(history: TransparentHistory) -> ForcedScanMode {
    ForcedScanMode::Policy(TrialDecryptionPolicy::ExternalWhenLinear(
        LinearScanGuarantee::new(history),
    ))
}
/// The transparent value the original wallet shields.
const FUNDING: Zatoshis = Zatoshis::const_from_u64(200_000);
/// The value the original wallet later pays away from the shielded note.
const SENT: Zatoshis = Zatoshis::const_from_u64(20_000);
/// The minimum value of transparent funds the original wallet shields.
const SHIELDING_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(10_000);
/// Empty blocks between the shielding and the spend, and after the spend: enough that a single
/// batch covering them extends past the wallet's spend-map retention window.
const GAP_BLOCKS: u32 = PRUNING_DEPTH + 10;
/// The sync driver's batch size, as Vizor uses in the foreground.
const BATCH: u32 = 1000;

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

/// The original wallet's history: it shields a transparent UTXO to its internal Orchard receiver,
/// then spends the shielded note, returning change.
fn original_history() -> (Transaction, Transaction) {
    let (mut st, account) = wallet();
    let (first, _) = st.generate_empty_block();
    st.scan_cached_blocks(first, 1);

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
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Orchard);
    let shield = *st
        .shield_transparent_funds(
            &GreedyInputSelector::new(),
            &change_strategy,
            SHIELDING_THRESHOLD,
            &usk,
            &[taddr],
            account,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()
        .first();
    let (shielded_at, _) = st.generate_next_block_including(shield);
    st.scan_cached_blocks(shielded_at, 1);
    // In this tree the spending anchor is one block lower than the confirmation count asks for.
    // Thus the shielded note is spendable only after one more block.
    let (after_shield, _) = st.generate_empty_block();
    st.scan_cached_blocks(after_shield, 1);

    let to = OrchardPoolTester::random_address(st.rng_mut()).to_zcash_address(st.network());
    let spend = st
        .spend(
            &GreedyInputSelector::new(),
            &change_strategy,
            &usk,
            TransactionRequest::new(vec![Payment::without_memo(to, SENT)]).unwrap(),
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    (
        st.wallet().get_transaction(shield).unwrap().unwrap(),
        st.wallet().get_transaction(spend).unwrap().unwrap(),
    )
}

/// A freshly restored wallet over a chain containing the original wallet's two transactions,
/// compact blocks carrying no transparent data. Returns the wallet, its account, the height of
/// the shielding transaction and the chain tip.
fn restored(
    shield: &Transaction,
    spend: &Transaction,
) -> (St, AccountUuid, BlockHeight, BlockHeight) {
    let (mut st, account) = wallet();
    st.generate_empty_block();
    let (shielded_at, _) = st.generate_next_block_from_tx(1, shield);
    for _ in 0..GAP_BLOCKS {
        st.generate_empty_block();
    }
    st.generate_next_block_from_tx(1, spend);
    let mut tip = shielded_at;
    for _ in 0..GAP_BLOCKS {
        tip = st.generate_empty_block().0;
    }
    st.wallet_mut().update_chain_tip(tip).unwrap();
    (st, account, shielded_at, tip)
}

/// The height of the spend of the shielded note, in a chain built by [`restored`].
fn spend_height(shielded_at: BlockHeight) -> BlockHeight {
    shielded_at + 1 + GAP_BLOCKS
}

/// Scans whatever the wallet asks for, in batches, as a sync driver does, and returns the number
/// of blocks scanned.
fn sync(st: &mut St, mode: ForcedScanMode) -> u32 {
    let mut scanned = 0;
    while let Some(range) = st
        .wallet()
        .suggest_scan_ranges()
        .unwrap()
        .into_iter()
        .find(|r| r.priority() > ScanPriority::Scanned)
    {
        let range = range.block_range().clone();
        let len = std::cmp::min(BATCH, u32::from(range.end) - u32::from(range.start));
        st.scan_cached_blocks_forced(range.start, usize::try_from(len).unwrap(), mode);
        scanned += len;
    }
    scanned
}

/// Fetches the shielding transaction as the history of the wallet's transparent addresses
/// delivers it, and decrypts and stores it.
fn learn_from_transparent_history(st: &mut St, shield: &Transaction, mined_at: BlockHeight) {
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), shield, Some(mined_at)).unwrap();
}

fn balances(st: &St, account: AccountUuid) -> (Zatoshis, Zatoshis) {
    (
        st.get_total_balance(account),
        st.get_spendable_balance(account, ConfirmationsPolicy::MIN),
    )
}

/// The all-scopes scan of the restored chain, the reference outcome.
fn all_scopes_outcome(shield: &Transaction, spend: &Transaction) -> ((Zatoshis, Zatoshis), u32) {
    let (mut st, account, _, _) = restored(shield, spend);
    let scanned = sync(&mut st, ForcedScanMode::AllScopes);
    (balances(&st, account), scanned)
}

#[test]
fn restore_with_unsynced_history_falls_back_to_all_scopes() {
    let (shield, spend) = original_history();
    let (expected, full_scan) = all_scopes_outcome(&shield, &spend);
    assert!(expected.0 > Zatoshis::ZERO);

    // A caller that promises nothing gets the behaviour of `scan_cached_blocks`, so a wallet that
    // cannot fetch its transparent history ahead of the scan loses no funds by using the policy.
    let (mut st, account, _, _) = restored(&shield, &spend);
    let scanned = sync(&mut st, policy(TransparentHistory::Unsynced));

    assert_eq!(balances(&st, account), expected);
    assert_eq!(scanned, full_scan);
}

#[test]
fn restore_with_synced_history_needs_no_rescan() {
    let (shield, spend) = original_history();
    let (expected, full_scan) = all_scopes_outcome(&shield, &spend);

    let (mut st, account, shielded_at, tip) = restored(&shield, &spend);
    learn_from_transparent_history(&mut st, &shield, shielded_at);
    let scanned = sync(&mut st, policy(TransparentHistory::SyncedTo(tip)));

    println!(
        "history synced first: all-scopes scanned {full_scan} blocks; policy scanned {scanned}"
    );
    // The scan runs in external-only mode, as
    // `restore_with_history_declared_but_not_fetched_misses_the_shielded_funds` shows for this
    // same chain and declaration, and still reaches the all-scopes result in one pass.
    assert_eq!(balances(&st, account), expected);
    assert_eq!(scanned, full_scan, "no block was scanned twice");
}

#[test]
fn restore_with_history_declared_but_not_fetched_misses_the_shielded_funds() {
    let (shield, spend) = original_history();
    let (expected, _) = all_scopes_outcome(&shield, &spend);
    assert!(expected.0 > Zatoshis::ZERO);

    // The declaration is a precondition the caller must meet, not one the scan can check: with it
    // unmet, neither the shielded note nor the change of its spend is found.
    let (mut st, account, _, tip) = restored(&shield, &spend);
    sync(&mut st, policy(TransparentHistory::SyncedTo(tip)));

    assert_eq!(balances(&st, account), (Zatoshis::ZERO, Zatoshis::ZERO));
}

/// Scans only the block holding the spend, leaving every earlier block unscanned, and returns the
/// wallet's balance. The spend's change pays an internal receiver, and the wallet holds neither
/// the spent note nor this transaction, so no trigger fires: an external-only scan misses the
/// change and an all-scopes scan finds it. The balance therefore reports which mode ran.
fn balance_after_scanning_the_spend_alone(
    shield: &Transaction,
    spend: &Transaction,
    mode: ForcedScanMode,
) -> Zatoshis {
    let (mut st, account, shielded_at, _) = restored(shield, spend);
    let at = spend_height(shielded_at);
    st.scan_cached_blocks_forced(at, 1, mode);
    st.get_total_balance(account)
}

#[test]
fn a_gap_before_the_batch_falls_back_to_all_scopes() {
    let (shield, spend) = original_history();

    // Every block from the birthday to this batch is unscanned, so the scan is not linear and the
    // policy keeps every scope. The change of the spend is found.
    let found = balance_after_scanning_the_spend_alone(
        &shield,
        &spend,
        policy(TransparentHistory::SyncedTo(BlockHeight::from_u32(
            u32::MAX,
        ))),
    );

    assert!(found > Zatoshis::ZERO);
}

#[test]
fn writes_issued_through_falls_back_to_all_scopes_over_a_gap() {
    let (shield, spend) = original_history();
    let (_, _, shielded_at, _) = restored(&shield, &spend);
    let at = spend_height(shielded_at);

    // At scan time, linearity is verified against the stored frontier alone; `writes_issued_through`
    // is a prefetch prediction hint only. Over a real gap the scan falls back to all scopes and
    // finds the spend's internal change instead of missing it.
    let found = balance_after_scanning_the_spend_alone(
        &shield,
        &spend,
        ForcedScanMode::Policy(TrialDecryptionPolicy::ExternalWhenLinear(
            LinearScanGuarantee::new(TransparentHistory::SyncedTo(BlockHeight::from_u32(
                u32::MAX,
            )))
            .with_writes_issued_through(at - 1),
        )),
    );

    assert!(found > Zatoshis::ZERO);
}

#[test]
fn prefetch_falls_back_to_all_scopes_when_frontier_is_misdeclared() {
    use zcash_client_backend::data_api::chain::decrypt_cached_blocks_with_policy;

    let (shield, spend) = original_history();
    let (mut st, account, shielded_at, _) = restored(&shield, &spend);
    let at = spend_height(shielded_at);

    // Prefetch predicts external-only using the misdeclared frontier; scan_decrypted_blocks checks
    // the stored frontier, marks the decryption stale, and rescans with all scopes.
    let network = *st.network();
    let decryption = decrypt_cached_blocks_with_policy(
        &network,
        st.cache(),
        st.wallet(),
        at,
        1,
        TrialDecryptionPolicy::ExternalWhenLinear(
            LinearScanGuarantee::new(TransparentHistory::SyncedTo(BlockHeight::from_u32(
                u32::MAX,
            )))
            .with_writes_issued_through(at - 1),
        ),
    )
    .unwrap();
    st.scan_decrypted_blocks(at, 1, decryption);

    assert!(st.get_total_balance(account) > Zatoshis::ZERO);
}

#[test]
fn prefetch_external_only_stays_external_when_prior_batch_commits_and_falls_back_on_gap() {
    use zcash_client_backend::data_api::chain::decrypt_cached_blocks_with_policy;

    let canary_value = Zatoshis::const_from_u64(50_000);
    let foreign_nf = |seed: u8| ::orchard::note::Nullifier::from_bytes(&[seed; 32]).unwrap();
    let policy_at = |issued_through: BlockHeight| {
        TrialDecryptionPolicy::ExternalWhenLinear(
            LinearScanGuarantee::new(TransparentHistory::SyncedTo(BlockHeight::from_u32(
                u32::MAX,
            )))
            .with_writes_issued_through(issued_through),
        )
    };

    // Case 1 (control): pipelined prefetch of block 2 while block 1 has not committed yet. Once
    // block 1 commits before scan_decrypted_blocks(2), block 2 stays external-only and misses the
    // foreign payment to the account's internal receiver (canary).
    {
        let (mut st, account) = wallet();
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        let (h1, _) = st.generate_empty_block();
        // Put the canary at tx_index = 1 (non-coinbase) paying an internal receiver with no wallet
        // spend so no trigger fires.
        let (h2, _, _) = st.generate_next_block_spending_to_internal(
            &fvk,
            (foreign_nf(1), canary_value),
            &fvk,
            canary_value,
        );
        st.wallet_mut().update_chain_tip(h2).unwrap();

        let network = *st.network();
        let decryption = decrypt_cached_blocks_with_policy(
            &network,
            st.cache(),
            st.wallet(),
            h2,
            1,
            policy_at(h1),
        )
        .unwrap();
        // Commit batch 1 before scanning batch 2.
        st.scan_cached_blocks(h1, 1);
        st.scan_decrypted_blocks(h2, 1, decryption);
        assert_eq!(
            st.get_total_balance(account),
            Zatoshis::ZERO,
            "pipelined external-only decryption was used and missed the internal-receiver canary"
        );
    }

    // Case 2: prefetch block 2 linearly, then introduce a gap before scanning it -> Rule 3 marks
    // the decryption stale and all-scopes finds the canary.
    {
        let (mut st, account) = wallet();
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        let (h1, _) = st.generate_empty_block();
        let (h2, _, _) = st.generate_next_block_spending_to_internal(
            &fvk,
            (foreign_nf(2), canary_value),
            &fvk,
            canary_value,
        );
        st.wallet_mut().update_chain_tip(h2).unwrap();
        st.scan_cached_blocks(h1, 1);

        let network = *st.network();
        let decryption = decrypt_cached_blocks_with_policy(
            &network,
            st.cache(),
            st.wallet(),
            h2,
            1,
            policy_at(h1),
        )
        .unwrap();
        // Truncate back below h1 so a gap now exists before h2.
        st.wallet_mut().truncate_to_height(h1 - 1).unwrap();
        st.scan_decrypted_blocks(h2, 1, decryption);
        assert_eq!(
            st.get_total_balance(account),
            canary_value,
            "scan-time linearity check fell back to all scopes after a gap opened"
        );
    }
}

#[test]
fn rescan_of_stored_blocks_always_uses_all_scopes() {
    let canary_value = Zatoshis::const_from_u64(50_000);
    let foreign_nf = |seed: u8| ::orchard::note::Nullifier::from_bytes(&[seed; 32]).unwrap();
    let pol = TrialDecryptionPolicy::ExternalWhenLinear(LinearScanGuarantee::new(
        TransparentHistory::SyncedTo(BlockHeight::from_u32(u32::MAX)),
    ));

    // Control + single-block rescan: first scan runs external-only and misses the internal canary;
    // rescanning a batch straddling stored block h2 and fresh block h3 under the same policy vetoes
    // the fast path (Rule 2) and finds both canaries.
    let (mut st, account) = wallet();
    let fvk = OrchardPoolTester::test_account_fvk(&st);
    let (h1, _) = st.generate_empty_block();
    let (h2, _, _) = st.generate_next_block_spending_to_internal(
        &fvk,
        (foreign_nf(3), canary_value),
        &fvk,
        canary_value,
    );
    let (h3, _, _) = st.generate_next_block_spending_to_internal(
        &fvk,
        (foreign_nf(4), canary_value),
        &fvk,
        canary_value,
    );
    st.wallet_mut().update_chain_tip(h3).unwrap();

    // First scan of h1..=h2 runs external-only: canary at h2 is missed.
    st.scan_cached_blocks_with_policy(h1, 2, pol);
    assert_eq!(st.get_total_balance(account), Zatoshis::ZERO);

    // Rescan a batch straddling stored block h2 and fresh block h3 under the same policy:
    // Rule 2 vetoes the fast path because h2 is already stored, so all scopes run and BOTH
    // canaries (h2 and h3) are found.
    st.scan_cached_blocks_with_policy(h2, 2, pol);
    assert_eq!(
        st.get_total_balance(account),
        (canary_value + canary_value).unwrap()
    );
}
