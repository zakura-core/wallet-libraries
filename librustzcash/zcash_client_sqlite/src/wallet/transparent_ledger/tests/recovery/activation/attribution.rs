//! Funding attribution: which account a transaction's sent outputs are recorded for, whatever
//! order the wallet discovers a transaction and the outputs it spends in.

use zcash_client_backend::data_api::transparent_ledger::{
    DetailCompleteness, FeeState, HistoryClassification,
};
use zcash_primitives::transaction::Transaction;

use super::public_fixtures::*;
use super::*;

/// `(account_balance_delta, total_spent, total_received)` of `account`'s row for `tx`.
fn movement(st: &State, account: AccountUuid, tx: &Transaction) -> (i64, i64, i64) {
    conn(st)
        .query_row(
            "SELECT account_balance_delta, total_spent, total_received FROM v_transactions
             WHERE txid = ?1 AND account_uuid = ?2",
            rusqlite::params![tx.txid().as_ref(), account.expose_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// A send of 600_000 to an outside address with 390_000 of change, spending a 1_000_000 receive.
fn send_with_change(st: &State, account: AccountUuid) -> (Transaction, Transaction) {
    let parent = funding(0xa0, external_of(st, account), 1_000_000);
    let send = transaction(
        vec![outpoint(&parent, 0)],
        vec![(EXTERNAL, 600_000), (internal_of(st, account), 390_000)],
    );
    (parent, send)
}

#[test]
fn a_send_with_own_change_moves_the_account_once() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let (parent, send) = send_with_change(&st, account);
    store(&mut st, &parent);
    store(&mut st, &send);

    // The change is an output the account both sent and received; it must not multiply the
    // send's rows in `v_transactions`.
    assert_eq!(
        sent_outputs(&st, &send),
        vec![
            (account, 0, None, 600_000),
            (account, 1, Some(account), 390_000)
        ]
    );
    assert_eq!(
        movement(&st, account, &send),
        (-610_000, 1_000_000, 390_000)
    );
}

#[test]
fn a_transfer_to_another_account_moves_each_account_once() {
    let (mut st, accounts) = public_wallet(1);
    let (sender, recipient) = (accounts[0], accounts[1]);
    let parent = funding(0xa2, external_of(&st, sender), 1_000_000);
    let transfer = transaction(
        vec![outpoint(&parent, 0)],
        vec![
            (external_of(&st, recipient), 400_000),
            (internal_of(&st, sender), 590_000),
        ],
    );
    store(&mut st, &parent);
    store(&mut st, &transfer);

    assert_eq!(
        sent_outputs(&st, &transfer),
        vec![
            (sender, 0, Some(recipient), 400_000),
            (sender, 1, Some(sender), 590_000)
        ]
    );
    assert_eq!(
        movement(&st, sender, &transfer),
        (-410_000, 1_000_000, 590_000)
    );
    assert_eq!(movement(&st, recipient, &transfer), (400_000, 0, 400_000));
}

/// History reading of `tx` for `account`: classification, detail completeness and fee.
fn reading(
    st: &State,
    account: AccountUuid,
    tx: &Transaction,
) -> (HistoryClassification, DetailCompleteness, FeeState) {
    let entry = history(st, account, tx);
    (entry.classification, entry.payment_details, entry.fee)
}

/// The H09 shape: one input of `account` pays 600_000 to an outside address and 390_000 to one of
/// the account's own external addresses, with a fee of 10_000.
fn send_paying_self_and_other(st: &State, account: AccountUuid) -> (Transaction, Transaction) {
    let parent = funding(0xb0, external_of(st, account), 1_000_000);
    let own = derived(st, account, TransparentKeyScope::EXTERNAL, 1);
    let send = transaction(
        vec![outpoint(&parent, 0)],
        vec![(EXTERNAL, 600_000), (own, 390_000)],
    );
    (parent, send)
}

/// The send's payment to the outside address and the account's own receipt are recorded.
fn assert_attributed_send(st: &State, account: AccountUuid, send: &Transaction) {
    assert_eq!(
        sent_outputs(st, send),
        vec![
            (account, 0, None, 600_000),
            (account, 1, Some(account), 390_000)
        ]
    );
    assert_eq!(movement(st, account, send), (-610_000, 1_000_000, 390_000));
}

fn assert_reconstructed(st: &State, account: AccountUuid, send: &Transaction) {
    assert_eq!(
        reading(st, account, send),
        (
            HistoryClassification::Reconstructed,
            DetailCompleteness::Complete,
            FeeState::Known(zat(10_000))
        )
    );
}

#[test]
fn a_send_stored_before_its_input_is_attributed_once_the_input_is_stored() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let (parent, send) = send_paying_self_and_other(&st, account);

    // A restored wallet finds the send through the output it pays the account first. Nothing
    // shows who funded it, so its payment is unknown.
    store(&mut st, &send);
    assert_eq!(sent_outputs(&st, &send), vec![]);
    assert_eq!(
        reading(&st, account, &send).0,
        HistoryClassification::Provisional
    );

    store(&mut st, &parent);
    assert_attributed_send(&st, account, &send);
    assert_reconstructed(&st, account, &send);
}

#[test]
fn a_send_stored_before_its_input_is_attributed_once_the_input_is_a_received_utxo() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let (parent, send) = send_paying_self_and_other(&st, account);
    store(&mut st, &send);

    let height = st.wallet().chain_height().unwrap().unwrap();
    let utxo = zcash_client_backend::wallet::WalletTransparentOutput::from_parts(
        outpoint(&parent, 0),
        parent.transparent_bundle().unwrap().vout[0].clone(),
        Some(height),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .db_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    assert_attributed_send(&st, account, &send);
    // Retrieval of the send's parent is still queued, so public discovery is not yet
    // authoritative for its transparent effects.
    assert_eq!(
        reading(&st, account, &send).0,
        HistoryClassification::Provisional
    );

    store(&mut st, &parent);
    assert_attributed_send(&st, account, &send);
    assert_reconstructed(&st, account, &send);
}

#[test]
fn a_send_an_outside_party_helped_fund_stays_unattributed() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let parent = funding(0xb2, external_of(&st, account), 1_000_000);
    let own = derived(&st, account, TransparentKeyScope::EXTERNAL, 1);
    // The second input belongs to no wallet account.
    let send = transaction(
        vec![outpoint(&parent, 0), OutPoint::new([0xb3; 32], 0)],
        vec![(EXTERNAL, 1_600_000), (own, 390_000)],
    );
    store(&mut st, &send);
    store(&mut st, &parent);

    assert_eq!(sent_outputs(&st, &send), vec![]);
    let (classification, details, _) = reading(&st, account, &send);
    assert_eq!(classification, HistoryClassification::Provisional);
    assert_eq!(details, DetailCompleteness::Incomplete);
}

#[test]
fn a_send_another_account_helped_fund_stays_unattributed() {
    let (mut st, accounts) = public_wallet(1);
    let (first, second) = (accounts[0], accounts[1]);
    let first_parent = funding(0xb4, external_of(&st, first), 1_000_000);
    let second_parent = funding(0xb5, external_of(&st, second), 1_000_000);
    let send = transaction(
        vec![outpoint(&first_parent, 0), outpoint(&second_parent, 0)],
        vec![(EXTERNAL, 1_600_000), (internal_of(&st, first), 390_000)],
    );
    store(&mut st, &send);
    store(&mut st, &first_parent);
    store(&mut st, &second_parent);

    // Two accounts funded it: no output can be attributed to either.
    assert_eq!(sent_outputs(&st, &send), vec![]);
    for account in [first, second] {
        assert_eq!(
            reading(&st, account, &send).0,
            HistoryClassification::Provisional
        );
    }
}

#[test]
fn a_send_paying_another_account_records_the_transfer_once_attributed() {
    let (mut st, accounts) = public_wallet(1);
    let (sender, recipient) = (accounts[0], accounts[1]);
    let parent = funding(0xb6, external_of(&st, sender), 1_000_000);
    let send = transaction(
        vec![outpoint(&parent, 0)],
        vec![(EXTERNAL, 200_000), (external_of(&st, recipient), 790_000)],
    );
    store(&mut st, &send);
    store(&mut st, &parent);

    assert_eq!(
        sent_outputs(&st, &send),
        vec![
            (sender, 0, None, 200_000),
            (sender, 1, Some(recipient), 790_000)
        ]
    );
    assert_eq!(movement(&st, sender, &send), (-1_000_000, 1_000_000, 0));
    assert_eq!(movement(&st, recipient, &send), (790_000, 0, 790_000));
}
