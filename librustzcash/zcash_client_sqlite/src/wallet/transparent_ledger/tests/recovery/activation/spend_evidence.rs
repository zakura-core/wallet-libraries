//! Spends the wallet learns of only from public evidence: an output missing from its address's
//! unspent outputs, or a spend whose only known spender expired.

use zcash_client_backend::data_api::{
    InputSource as _, TransactionDataRequest, TransactionStatus, transparent_ledger::FeeState,
    wallet::decrypt_and_store_transaction,
};
use zcash_primitives::transaction::Transaction;

use super::attribution::{
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

fn observe(st: &mut State, address: TransparentAddress, as_of: BlockHeight, unspent: &[OutPoint]) {
    st.wallet_mut()
        .notify_transparent_utxos_observed(&address, BlockHeight::from_u32(0), as_of, unspent)
        .unwrap();
}

fn store_unmined(st: &mut State, tx: &Transaction) {
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), tx, None).unwrap();
}

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

    // A query reflecting a chain state below the receipt cannot speak for it, and neither can
    // one starting above it.
    observe(&mut st, address, h - 1, &[]);
    assert!(spendable(&st, &received));
    st.wallet_mut()
        .notify_transparent_utxos_observed(&address, h + 1, h, &[])
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

fn status_work(st: &State) -> Vec<TxId> {
    use zcash_client_backend::data_api::status::TransactionStatusRead as _;
    st.wallet()
        .db()
        .transaction_status_work()
        .unwrap()
        .into_iter()
        .map(|work| work.txid())
        .collect()
}

fn mined_height(st: &State, tx: &Transaction) -> Option<u32> {
    conn(st)
        .query_row(
            "SELECT mined_height FROM transactions WHERE txid = ?1",
            [tx.txid().as_ref()],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn importing_an_account_below_the_scanned_tip_requests_status_for_transactions_scanning_cannot_see()
{
    use zcash_client_backend::data_api::status::TransactionStatusMode;

    // The first account syncs a transparent receive and a transparent send.
    let (mut st, accounts) = public_wallet(0);
    st.wallet_mut()
        .db_mut()
        .set_status_mode(TransactionStatusMode::Public);
    let account = accounts[0];
    let parent = funding(0xe0, external_of(&st, account), 1_000_000);
    let send = transaction(vec![outpoint(&parent, 0)], vec![(EXTERNAL, 990_000)]);
    store(&mut st, &parent);
    store(&mut st, &send);
    let h = u32::from(tip(&st));
    assert_eq!(mined_height(&st, &send), Some(h));
    assert_eq!(status_work(&st), vec![]);

    // Importing a second account with an earlier birthday rewinds the wallet, un-mining both.
    // Rescanning cannot mark them mined again, so each needs a status observation.
    import_account(&mut st, 9);
    assert_eq!(mined_height(&st, &send), None);
    let mut expected = vec![parent.txid(), send.txid()];
    expected.sort();
    let mut work = status_work(&st);
    work.sort();
    assert_eq!(work, expected);

    // The observation restores the mined height and settles the obligation.
    st.wallet_mut()
        .set_transaction_status(send.txid(), TransactionStatus::Mined(BlockHeight::from(h)))
        .unwrap();
    assert_eq!(mined_height(&st, &send), Some(h));
    assert_eq!(status_work(&st), vec![parent.txid()]);
}
