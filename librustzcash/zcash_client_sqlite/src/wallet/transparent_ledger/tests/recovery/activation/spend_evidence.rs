//! Spends the wallet learns of only from public evidence: an output missing from its address's
//! unspent outputs, or a spend whose only known spender expired.

use zcash_client_backend::data_api::{
    CoinbaseFilter, InputSource as _, TargetValue, TransactionDataRequest,
    transparent_ledger::FeeState,
    wallet::{
        decrypt_and_store_transaction,
        input_selection::{LockFilter, LockedInputPolicy},
    },
};
use zcash_client_backend::fees::StandardFeeRule;
use zcash_primitives::transaction::Transaction;

use super::public_fixtures::{
    EXTERNAL, expiring_transaction, external_of, funding, history, outpoint, public_wallet,
    sent_outputs, store, transaction, zat,
};
use super::*;

fn tip(st: &State) -> BlockHeight {
    st.wallet().chain_height().unwrap().unwrap()
}

fn spendable(st: &State, outpoint: &OutPoint) -> bool {
    st.wallet()
        .db()
        .get_unspent_transparent_output(outpoint, (tip(st) + 1).into())
        .unwrap()
        .is_some()
}

/// The `[start, end)` ranges of the spend searches requested for `address`.
#[cfg(not(feature = "spend-index"))]
fn spend_searches(st: &State, address: TransparentAddress) -> Vec<(BlockHeight, BlockHeight)> {
    st.wallet()
        .transaction_data_requests()
        .unwrap()
        .into_iter()
        .filter_map(|request| match request {
            TransactionDataRequest::TransactionsInvolvingAddress(req)
                if req.address() == address =>
            {
                Some((req.block_range_start(), req.block_range_end().unwrap()))
            }
            _ => None,
        })
        .collect()
}

fn chain_point(st: &State, height: BlockHeight) -> ChainPoint {
    ChainPoint {
        height,
        hash: crate::wallet::get_block_hash(conn(st), height)
            .unwrap()
            .unwrap(),
    }
}

fn observe(st: &mut State, address: TransparentAddress, as_of: BlockHeight, unspent: &[OutPoint]) {
    let point = chain_point(st, as_of);
    st.wallet_mut()
        .notify_transparent_utxos_observed(
            &address,
            BlockHeight::from_u32(0),
            point,
            point,
            unspent,
        )
        .unwrap();
}

fn store_unmined(st: &mut State, tx: &Transaction) {
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), tx, None).unwrap();
}

#[cfg(not(feature = "spend-index"))]
#[test]
fn an_output_missing_from_its_addresses_unspent_outputs_is_spent_until_its_spender_is_found() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let address = external_of(&st, account);
    let parent = funding(0xd0, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let h = tip(&st);
    observe(&mut st, address, h, std::slice::from_ref(&received));
    assert!(spendable(&st, &received));
    assert_eq!(spend_searches(&st, address), vec![]);

    // A later query no longer returns the output: a transaction the wallet has not seen spent it.
    scan_new_blocks(&mut st, 3);
    let later = tip(&st);
    observe(&mut st, address, later, &[]);
    assert!(!spendable(&st, &received));
    // The search for its spender covers everything since it was last seen unspent.
    assert_eq!(spend_searches(&st, address), vec![(h + 1, later + 1)]);

    // Enhancement retrieves and stores the spender, which resolves the search.
    let spend = transaction(vec![received.clone()], vec![(EXTERNAL, 990_000)]);
    store(&mut st, &spend);
    assert!(!spendable(&st, &received));
    assert_eq!(spend_searches(&st, address), vec![]);
    assert_eq!(sent_outputs(&st, &spend), vec![(account, 0, None, 990_000)]);
    assert_eq!(
        history(&st, account, &spend).fee,
        FeeState::Known(zat(10_000))
    );
}

#[test]
fn later_evidence_or_a_rewind_supersedes_an_absence() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let address = external_of(&st, account);
    let parent = funding(0xd1, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let h = tip(&st);

    // A stale snapshot cannot speak for the current tip, and a query starting above the
    // receipt cannot judge that receipt.
    let stale = chain_point(&st, h - 1);
    assert!(matches!(
        st.wallet_mut().notify_transparent_utxos_observed(
            &address,
            BlockHeight::from_u32(0),
            stale,
            stale,
            &[],
        ),
        Err(SqliteClientError::InvalidTransparentUtxoObservation)
    ));
    assert!(spendable(&st, &received));
    let point = chain_point(&st, h);
    st.wallet_mut()
        .notify_transparent_utxos_observed(&address, h + 1, point, point, &[])
        .unwrap();
    assert!(spendable(&st, &received));

    scan_new_blocks(&mut st, 1);
    observe(&mut st, address, h + 1, &[]);
    assert!(!spendable(&st, &received));
    // A later query that returns it again (after a reorganization, say) supersedes the absence.
    scan_new_blocks(&mut st, 1);
    observe(&mut st, address, h + 2, std::slice::from_ref(&received));
    assert!(spendable(&st, &received));

    // So does a rewind below the height the absence was observed at.
    scan_new_blocks(&mut st, 1);
    observe(&mut st, address, h + 3, &[]);
    assert!(!spendable(&st, &received));
    st.wallet_mut().truncate_to_height(h + 2).unwrap();
    assert_eq!(count(&st, "transparent_utxo_absences"), 0);
    assert!(spendable(&st, &received));
}

#[cfg(not(feature = "spend-index"))]
#[test]
fn a_spend_that_expired_resumes_the_search_for_the_outputs_spend() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let parent = funding(0xd2, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let mined = tip(&st);

    // The wallet's own spend of the output, never mined. Meanwhile, nothing is searched for.
    let withheld =
        expiring_transaction(vec![received.clone()], vec![(EXTERNAL, 990_000)], mined + 2);
    store_unmined(&mut st, &withheld);
    assert_eq!(spend_searches(&st, address), vec![]);

    // Once it expires, another transaction may have spent the output: the search resumes.
    st.wallet_mut().update_chain_tip(mined + 5).unwrap();
    assert_eq!(spend_searches(&st, address), vec![(mined, mined + 6)]);
}

#[test]
fn public_absence_does_not_override_a_complete_private_ledger() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let address = external_of(&st, account);
    let parent = funding(0xd3, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let mined = tip(&st);
    scan_new_blocks(&mut st, 1);
    let observed = tip(&st);
    observe(&mut st, address, observed, &[]);
    assert!(!spendable(&st, &received));

    set_policy(&mut st, PrivateShadow);
    let fixture = revision(1, true);
    cover(
        &mut st,
        account,
        &fixture,
        vec![ReceiveEvent {
            outpoint: received.clone(),
            ..receive(0, address, 1_000_000, mined)
        }],
    );
    qualify(&mut st, &fixture);
    set_policy(&mut st, PrivateRequired);
    promote(&mut st, account).unwrap();
    let s = snapshot(&st, account);
    assert_eq!(s.authority, TransparentAuthority::Private);
    assert!(s.blockers.is_empty());
    assert_eq!(s.authorized.unwrap().regular.total(), zat(1_000_000));
    assert!(spendable(&st, &received));
    let target = (tip(&st) + 1).into();
    let lock = || LockFilter::Policy(&LockedInputPolicy::Exclude);
    let db = st.wallet().db();
    let selections = [
        db.get_spendable_transparent_outputs(
            &address,
            target,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            lock(),
        )
        .unwrap(),
        db.get_spendable_transparent_outputs_for_addresses(
            &[address],
            target,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            lock(),
        )
        .unwrap(),
        db.select_spendable_transparent_outputs(
            account,
            target,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            None,
            TargetValue::AtLeast(zat(1)),
            10,
            &StandardFeeRule::Zip317,
            lock(),
        )
        .unwrap(),
    ];
    for outputs in selections {
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].outpoint(), &received);
    }
    let spend = transaction(vec![received.clone()], vec![(EXTERNAL, 990_000)]);
    db.check_transparent_transaction_inputs(&spend, &[], target)
        .unwrap();
    // New public absence evidence remains forbidden while private authority is active.
    let point = chain_point(&st, tip(&st));
    assert!(matches!(
        st.wallet_mut().notify_transparent_utxos_observed(
            &address,
            BlockHeight::from_u32(0),
            point,
            point,
            &[],
        ),
        Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
    ));
    // Private recovery does not erase the public evidence: returning to public authority
    // must still honor it until a new public query or rewind supersedes it.
    assert_eq!(count(&st, "transparent_utxo_absences"), 1);
    set_policy(&mut st, Public);
    assert!(!spendable(&st, &received));
}

#[cfg(not(feature = "spend-index"))]
#[test]
fn completing_a_search_after_expiry_advances_its_frontier() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let parent = funding(0xd4, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let mined = tip(&st);
    let withheld = expiring_transaction(vec![received], vec![(EXTERNAL, 990_000)], mined + 2);
    store_unmined(&mut st, &withheld);
    st.wallet_mut().update_chain_tip(mined + 5).unwrap();
    let requests = st.wallet().transaction_data_requests().unwrap();
    let request = requests
        .into_iter()
        .find_map(|request| match request {
            TransactionDataRequest::TransactionsInvolvingAddress(req)
                if req.address() == address =>
            {
                Some(req)
            }
            _ => None,
        })
        .unwrap();
    st.wallet_mut()
        .notify_address_checked(request, mined + 5)
        .unwrap();
    assert_eq!(spend_searches(&st, address), vec![]);
    st.wallet_mut().update_chain_tip(mined + 100).unwrap();
    assert_eq!(spend_searches(&st, address), vec![(mined + 6, mined + 47)]);
}

#[test]
fn a_query_crossing_a_block_or_reorg_cannot_record_absence() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let parent = funding(0xd5, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let before = chain_point(&st, tip(&st));
    scan_new_blocks(&mut st, 1);
    let after = chain_point(&st, tip(&st));
    let wrong_hash = ChainPoint {
        hash: BlockHash([0xff; 32]),
        ..after
    };
    let future = ChainPoint {
        height: after.height + 1,
        ..after
    };
    for (start, end) in [
        (before, after),
        (after, wrong_hash),
        (wrong_hash, wrong_hash),
        (future, future),
        (before, before),
    ] {
        let unchanged = production_dump(conn(&st));
        assert!(matches!(
            st.wallet_mut().notify_transparent_utxos_observed(
                &address,
                BlockHeight::from_u32(0),
                start,
                end,
                &[],
            ),
            Err(SqliteClientError::InvalidTransparentUtxoObservation)
        ));
        assert_eq!(production_dump(conn(&st)), unchanged);
        assert!(spendable(&st, &received));
    }
    // A retry at a stable accepted point may record absence. Its search includes the new
    // block, and rewinding that block restores spendability.
    observe(&mut st, address, after.height, &[]);
    assert!(!spendable(&st, &received));
    #[cfg(not(feature = "spend-index"))]
    assert!(
        spend_searches(&st, address)
            .iter()
            .any(|(start, end)| *start <= after.height && after.height < *end)
    );
    #[cfg(feature = "spend-index")]
    assert_eq!(spending_outpoints(&st), vec![received.clone()]);
    st.wallet_mut().truncate_to_height(before.height).unwrap();
    assert_eq!(count(&st, "transparent_utxo_absences"), 0);
    assert!(spendable(&st, &received));
}

#[cfg(not(feature = "spend-index"))]
#[test]
fn completing_an_old_range_uses_expiry_at_the_current_tip() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let parent = funding(0xd6, address, 1_000_000);
    store(&mut st, &parent);
    let mined = tip(&st);
    let withheld = expiring_transaction(
        vec![outpoint(&parent, 0)],
        vec![(EXTERNAL, 990_000)],
        mined + 80,
    );
    store_unmined(&mut st, &withheld);
    st.wallet_mut().update_chain_tip(mined + 100).unwrap();
    let request = st
        .wallet()
        .transaction_data_requests()
        .unwrap()
        .into_iter()
        .find_map(|request| match request {
            TransactionDataRequest::TransactionsInvolvingAddress(req)
                if req.address() == address =>
            {
                Some(req)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(request.block_range_end(), Some(mined + 41));
    st.wallet_mut()
        .notify_address_checked(request, mined + 40)
        .unwrap();
    assert_eq!(spend_searches(&st, address), vec![(mined + 41, mined + 82)]);
}

#[cfg(not(feature = "spend-index"))]
#[test]
fn a_later_search_cannot_clear_an_earlier_absence_at_the_same_address() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let earlier_parent = funding(0xd7, address, 1_000_000);
    store(&mut st, &earlier_parent);
    let earlier = outpoint(&earlier_parent, 0);
    let mined = tip(&st);
    let withheld =
        expiring_transaction(vec![earlier.clone()], vec![(EXTERNAL, 990_000)], mined + 2);
    store_unmined(&mut st, &withheld);
    scan_new_blocks(&mut st, 5);
    let later_parent = funding(0xd8, address, 2_000_000);
    store(&mut st, &later_parent);
    let later = outpoint(&later_parent, 0);
    // The earlier output was spent outside the later output's search range. Its local
    // spender has expired, and the actual spender has not yet been retrieved.
    let observed = tip(&st);
    observe(&mut st, address, observed, &[later]);
    assert!(!spendable(&st, &earlier));
    scan_new_blocks(&mut st, 1);
    let checked = tip(&st);
    let request = st
        .wallet()
        .transaction_data_requests()
        .unwrap()
        .into_iter()
        .find_map(|request| match request {
            TransactionDataRequest::TransactionsInvolvingAddress(req)
                if req.address() == address && req.block_range_start() == observed + 1 =>
            {
                Some(req)
            }
            _ => None,
        })
        .unwrap();
    st.wallet_mut()
        .notify_address_checked(request, checked)
        .unwrap();
    assert!(!spendable(&st, &earlier));
    assert_eq!(spend_searches(&st, address), vec![(mined, checked + 1)]);
    let network = *st.network();
    let actual = transaction(vec![earlier.clone()], vec![(EXTERNAL, 990_000)]);
    decrypt_and_store_transaction(&network, st.wallet_mut(), &actual, Some(mined + 3)).unwrap();
    assert_eq!(spend_searches(&st, address), vec![]);
    assert!(!spendable(&st, &earlier));
}

#[cfg(feature = "spend-index")]
fn spending_outpoints(st: &State) -> Vec<OutPoint> {
    st.wallet()
        .transaction_data_requests()
        .unwrap()
        .into_iter()
        .filter_map(|request| match request {
            TransactionDataRequest::GetSpendingTx(outpoint) => Some(outpoint),
            _ => None,
        })
        .collect()
}

#[cfg(feature = "spend-index")]
#[test]
fn per_outpoint_search_resumes_and_completes_after_expiry() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let parent = funding(0xd9, address, 1_000_000);
    store(&mut st, &parent);
    let received = outpoint(&parent, 0);
    let mined = tip(&st);
    let withheld =
        expiring_transaction(vec![received.clone()], vec![(EXTERNAL, 990_000)], mined + 2);
    store_unmined(&mut st, &withheld);
    assert_eq!(spending_outpoints(&st), vec![]);
    scan_new_blocks(&mut st, 3);
    assert_eq!(spending_outpoints(&st), vec![received.clone()]);
    let checked = tip(&st);
    st.wallet_mut()
        .notify_output_verified_unspent(received.clone(), checked)
        .unwrap();
    assert_eq!(spending_outpoints(&st), vec![]);
    scan_new_blocks(&mut st, 1);
    assert_eq!(spending_outpoints(&st), vec![received.clone()]);
    let actual = transaction(vec![received.clone()], vec![(EXTERNAL, 990_000)]);
    store(&mut st, &actual);
    assert_eq!(spending_outpoints(&st), vec![]);
    assert!(!spendable(&st, &received));
}

#[cfg(feature = "spend-index")]
#[test]
fn per_outpoint_completion_does_not_clear_another_outputs_absence() {
    let (mut st, accounts) = public_wallet(0);
    let address = external_of(&st, accounts[0]);
    let earlier_parent = funding(0xda, address, 1_000_000);
    let later_parent = funding(0xdb, address, 2_000_000);
    store(&mut st, &earlier_parent);
    store(&mut st, &later_parent);
    let earlier = outpoint(&earlier_parent, 0);
    let later = outpoint(&later_parent, 0);
    let mined = tip(&st);
    let withheld =
        expiring_transaction(vec![earlier.clone()], vec![(EXTERNAL, 990_000)], mined + 2);
    store_unmined(&mut st, &withheld);
    scan_new_blocks(&mut st, 3);
    let observed = tip(&st);
    observe(&mut st, address, observed, std::slice::from_ref(&later));
    assert_eq!(spending_outpoints(&st), vec![earlier.clone()]);
    st.wallet_mut()
        .notify_output_verified_unspent(later, observed)
        .unwrap();
    assert_eq!(spending_outpoints(&st), vec![earlier.clone()]);
    assert!(!spendable(&st, &earlier));
    let actual = transaction(vec![earlier.clone()], vec![(EXTERNAL, 990_000)]);
    store(&mut st, &actual);
    assert_eq!(spending_outpoints(&st), vec![]);
    assert!(!spendable(&st, &earlier));
}
