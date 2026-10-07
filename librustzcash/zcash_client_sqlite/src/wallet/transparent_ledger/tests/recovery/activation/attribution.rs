//! Funding attribution: which account a transaction's sent outputs are recorded for, whatever
//! order the wallet discovers a transaction and the outputs it spends in.

use zcash_client_backend::data_api::transparent_ledger::{
    AggregatePayment, DetailCompleteness, FeeState, HistoryClassification, TransactionFunding,
};
use zcash_primitives::transaction::Transaction;

use super::public_fixtures::*;
use super::*;
use crate::wallet::init::WalletMigrator;

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

pub(super) fn queued(st: &State) -> i64 {
    count(st, "tx_attribution_queue")
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

fn assert_send_with_change(st: &State, account: AccountUuid, send: &Transaction) {
    assert_eq!(
        sent_outputs(st, send),
        vec![
            (account, 0, None, 600_000),
            (account, 1, Some(account), 390_000)
        ]
    );
    assert_eq!(movement(st, account, send), (-610_000, 1_000_000, 390_000));
    let entry = history(st, account, send);
    assert_eq!(
        entry.aggregate_payment,
        AggregatePayment::Exact(zat(600_000))
    );
    assert_eq!(entry.fee, FeeState::Known(zat(10_000)));
    assert_eq!(entry.payment_details, DetailCompleteness::Complete);
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
    assert_eq!(entry.funding, TransactionFunding::Sole);
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
    assert_send_with_change(&st, account, &send);
    assert_eq!(queued(&st), 0);
}

#[test]
fn a_send_stored_before_its_input_records_its_payments_once_the_input_arrives() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let (parent, send) = send_with_change(&st, account);

    // A restored wallet finds the send through its unspent change, before the output it spends.
    store(&mut st, &send);
    assert_eq!(sent_outputs(&st, &send), vec![]);
    assert_eq!(
        history(&st, account, &send).classification,
        HistoryClassification::Provisional
    );

    // Storing the parent establishes the account as the send's sole funder.
    store(&mut st, &parent);
    assert_send_with_change(&st, account, &send);
    assert_eq!(queued(&st), 0);
    // The parent is stored, so nothing waits on its retrieval.
    let parent_queued: bool = conn(&st)
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM tx_retrieval_queue WHERE txid = ?1)",
            [parent.txid().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!parent_queued);
}

#[test]
fn a_self_transfer_restored_out_of_order_is_not_a_gross_receive() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let parent = funding(0xa1, external_of(&st, account), 2_000_000);
    let second_external = derived(&st, account, TransparentKeyScope::EXTERNAL, 1);
    let transfer = transaction(
        vec![outpoint(&parent, 0)],
        vec![
            (second_external, 1_200_000),
            (internal_of(&st, account), 790_000),
        ],
    );
    store(&mut st, &transfer);
    store(&mut st, &parent);

    // Both outputs are the account's own: sent from and to it, with only the fee leaving.
    assert_eq!(
        sent_outputs(&st, &transfer),
        vec![
            (account, 0, Some(account), 1_200_000),
            (account, 1, Some(account), 790_000)
        ]
    );
    assert_eq!(
        movement(&st, account, &transfer),
        (-10_000, 2_000_000, 1_990_000)
    );
    let entry = history(&st, account, &transfer);
    assert_eq!(
        entry.aggregate_payment,
        AggregatePayment::Exact(Zatoshis::ZERO)
    );
    assert_eq!(entry.fee, FeeState::Known(zat(10_000)));
    assert_eq!(entry.classification, HistoryClassification::Reconstructed);
    assert_eq!(entry.funding, TransactionFunding::Sole);
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
    let entry = history(&st, sender, &transfer);
    assert_eq!(
        entry.aggregate_payment,
        AggregatePayment::Exact(zat(400_000))
    );
    assert_eq!(entry.funding, TransactionFunding::Sole);
    assert_eq!(
        history(&st, recipient, &transfer).funding,
        TransactionFunding::NotFunded
    );
}

/// Two wallet accounts each fund one input of a payment to an outside address, with change to the
/// first account.
fn joint_payment(st: &State, a: AccountUuid, b: AccountUuid) -> [Transaction; 3] {
    let from_a = funding(0xb0, external_of(st, a), 500_000);
    let from_b = funding(0xb1, external_of(st, b), 700_000);
    let joint = transaction(
        vec![outpoint(&from_a, 0), outpoint(&from_b, 0)],
        vec![(EXTERNAL, 1_000_000), (internal_of(st, a), 190_000)],
    );
    [from_a, from_b, joint]
}

fn assert_joint_payment(st: &State, a: AccountUuid, b: AccountUuid, joint: &Transaction) {
    // No account paid the outside address on its own, and neither paid the other's change.
    assert_eq!(sent_outputs(st, joint), vec![]);
    assert_eq!(movement(st, a, joint), (-310_000, 500_000, 190_000));
    assert_eq!(movement(st, b, joint), (-700_000, 700_000, 0));
    for account in [a, b] {
        let entry = history(st, account, joint);
        // Each account's own effects and the whole fee, but no payment amount or fee share.
        assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
        assert_eq!(entry.fee, FeeState::Known(zat(10_000)));
        assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
        assert_eq!(entry.classification, HistoryClassification::Provisional);
        assert_eq!(entry.funding, TransactionFunding::Shared);
    }
}

#[test]
fn a_jointly_funded_payment_is_attributed_to_no_single_account() {
    let (mut st, accounts) = public_wallet(1);
    let (a, b) = (accounts[0], accounts[1]);
    let [from_a, from_b, joint] = joint_payment(&st, a, b);
    store(&mut st, &from_a);
    store(&mut st, &from_b);
    store(&mut st, &joint);
    assert_joint_payment(&st, a, b, &joint);
}

#[test]
fn a_shared_contribution_equal_to_the_whole_fee_does_not_prove_a_zero_payment() {
    for contributed in [9_999, 10_000, 10_001] {
        let (mut st, accounts) = public_wallet(1);
        let (a, b) = (accounts[0], accounts[1]);
        let from_a = funding(0xb2, external_of(&st, a), contributed);
        let from_b = funding(0xb3, external_of(&st, b), 700_000);
        let joint = transaction(
            vec![outpoint(&from_a, 0), outpoint(&from_b, 0)],
            vec![(EXTERNAL, contributed + 700_000 - 10_000)],
        );
        for tx in [&from_a, &from_b, &joint] {
            store(&mut st, tx);
        }
        assert_eq!(sent_outputs(&st, &joint), vec![]);
        for account in [a, b] {
            let entry = history(&st, account, &joint);
            assert_eq!(entry.funding, TransactionFunding::Shared);
            assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
            assert_eq!(entry.payment_details, DetailCompleteness::Incomplete);
            assert_eq!(entry.classification, HistoryClassification::Provisional);
            assert_eq!(entry.fee, FeeState::Known(zat(10_000)));
        }
    }
}

#[test]
fn joint_funding_found_input_by_input_is_attributed_to_no_single_account() {
    let (mut st, accounts) = public_wallet(1);
    let (a, b) = (accounts[0], accounts[1]);
    let [from_a, from_b, joint] = joint_payment(&st, a, b);
    store(&mut st, &joint);
    // With one funder known, the other input's owner is still unknown.
    store(&mut st, &from_a);
    assert_eq!(sent_outputs(&st, &joint), vec![]);
    store(&mut st, &from_b);
    assert_joint_payment(&st, a, b, &joint);
    assert_eq!(queued(&st), 0);
}

#[test]
fn a_payment_shared_with_an_outside_party_is_not_attributed() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let from_account = funding(0xc0, external_of(&st, account), 500_000);
    let outside = funding(0xc1, EXTERNAL, 600_000);
    let shared = transaction(
        vec![outpoint(&from_account, 0), outpoint(&outside, 0)],
        vec![(EXTERNAL, 1_000_000), (internal_of(&st, account), 190_000)],
    );
    store(&mut st, &from_account);
    store(&mut st, &shared);

    // The outside party's input may have paid for any output, including the account's change.
    assert_eq!(sent_outputs(&st, &shared), vec![]);
    assert_eq!(
        movement(&st, account, &shared),
        (-310_000, 500_000, 190_000)
    );
    let entry = history(&st, account, &shared);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
    assert_eq!(entry.fee, FeeState::Unknown);
    assert_eq!(entry.classification, HistoryClassification::Provisional);
    // Until the other input's parent is retrieved, that input may still be the account's own.
    assert_eq!(entry.funding, TransactionFunding::Undetermined);

    // Its parent pays nobody in the wallet, so the input belongs to another party.
    store(&mut st, &outside);
    assert_eq!(sent_outputs(&st, &shared), vec![]);
    let entry = history(&st, account, &shared);
    assert_eq!(entry.funding, TransactionFunding::Shared);
    assert_eq!(entry.aggregate_payment, AggregatePayment::Unknown);
}

#[test]
fn upgrading_rederives_history_that_earlier_writers_stored() {
    let (mut st, accounts) = public_wallet(1);
    let (a, b) = (accounts[0], accounts[1]);
    let (parent, send) = send_with_change(&st, a);
    let [from_a, from_b, joint] = joint_payment(&st, a, b);
    for tx in [&parent, &send, &from_a, &from_b, &joint] {
        store(&mut st, tx);
    }

    let view: String = conn(&st)
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'v_transactions'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let earlier_view = view.replace(
        "GROUP BY sent_notes.from_account_id, sent_notes.transaction_id",
        "GROUP BY account_id, sent_notes.transaction_id",
    );
    assert_ne!(view, earlier_view);
    conn(&st)
        .execute_batch(&format!("DROP VIEW v_transactions; {earlier_view}"))
        .unwrap();
    // Earlier writers' view counted the send's notes once per receiving account.
    assert_eq!(movement(&st, a, &send), (-1_220_000, 2_000_000, 780_000));

    // Recreate what earlier writers stored: no payments for a send stored before its input, and
    // a jointly funded payment attributed to one of its funders.
    // Earlier writers ran neither the view fix nor the attribution migration.
    let migration = crate::wallet::init::migrations::FUNDING_ATTRIBUTION_ID;
    let view_migration = crate::wallet::init::migrations::V_TRANSACTIONS_SENDER_GROUPING_ID;
    conn(&st)
        .execute_batch(&format!(
            "DELETE FROM sent_notes WHERE transaction_id =
                 (SELECT id_tx FROM transactions WHERE txid = X'{send}');
             INSERT INTO sent_notes (transaction_id, output_pool, output_index, from_account_id,
                                     to_address, value)
             SELECT id_tx, 0, 0, (SELECT id FROM accounts WHERE uuid = X'{a}'), 'external',
                    1000000
             FROM transactions WHERE txid = X'{joint}';
             DROP TABLE tx_attribution_queue;
             DELETE FROM schemer_migrations WHERE id IN (X'{migration}', X'{view_migration}');",
            send = hex::encode(send.txid().as_ref()),
            joint = hex::encode(joint.txid().as_ref()),
            a = hex::encode(a.expose_uuid().as_bytes()),
            migration = hex::encode(migration.as_bytes()),
            view_migration = hex::encode(view_migration.as_bytes()),
        ))
        .unwrap();
    WalletMigrator::new()
        .init_or_migrate(st.wallet_mut().db_mut())
        .unwrap();
    // The migrations fix the view and queue both transactions; the next storage operation
    // re-derives them.
    assert_eq!(movement(&st, a, &send), (-610_000, 1_000_000, 390_000));
    assert_eq!(queued(&st), 2);
    assert_eq!(
        history(&st, a, &send).classification,
        HistoryClassification::Provisional
    );
    store(&mut st, &parent);
    assert_eq!(queued(&st), 0);
    assert_send_with_change(&st, a, &send);
    assert_joint_payment(&st, a, b, &joint);
}

#[test]
fn a_shielded_spender_stored_before_its_note_was_linked_is_rederived_when_scanned() {
    let (mut st, accounts) = public_wallet(0);
    let account = accounts[0];
    let (txid, output_index) = pay_from_sapling(&mut st, EXTERNAL, 50_000);
    let send = st.wallet().get_transaction(txid).unwrap().unwrap();

    // What a restored wallet holds for a send it retrieved from the mempool before scanning
    // found the note it spends: the transaction's data, but no link to the note and no
    // construction records.
    conn(&st)
        .execute_batch(&format!(
            "UPDATE transactions SET created = NULL, target_height = NULL WHERE txid = X'{tx}';
             DELETE FROM sent_notes WHERE transaction_id =
                 (SELECT id_tx FROM transactions WHERE txid = X'{tx}');
             DELETE FROM sapling_received_note_spends WHERE transaction_id =
                 (SELECT id_tx FROM transactions WHERE txid = X'{tx}');",
            tx = hex::encode(txid.as_ref()),
        ))
        .unwrap();
    assert!(
        !sent_outputs(&st, &send)
            .iter()
            .any(|(_, index, _, _)| *index == output_index)
    );

    // Scanning the block that mines it links the spend, which establishes the account as the
    // send's funder.
    let (height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(height, 1);
    assert_eq!(queued(&st), 0);
    assert!(sent_outputs(&st, &send).contains(&(account, output_index, None, 50_000)));
    assert_eq!(
        history(&st, account, &send).funding,
        TransactionFunding::Sole
    );
}

#[test]
fn upgrading_rederives_a_sole_shielded_spender_with_an_existing_spend_link() {
    for constructed in [false, true] {
        let (mut st, accounts) = public_wallet(0);
        let account = accounts[0];
        let (txid, output_index) = pay_from_sapling(&mut st, EXTERNAL, 50_000);
        let send = st.wallet().get_transaction(txid).unwrap().unwrap();
        let (height, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(height, 1);
        let construction_records = sent_outputs(&st, &send);
        assert!(construction_records.contains(&(account, output_index, None, 50_000)));
        let linked_spends: i64 = conn(&st)
            .query_row(
                "SELECT COUNT(*) FROM sapling_received_note_spends s
                 JOIN transactions t ON t.id_tx = s.transaction_id WHERE t.txid = ?1",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked_spends, 1);
        assert!(send.transparent_bundle().unwrap().vin.is_empty());

        if !constructed {
            // An earlier restored wallet already linked the sole shielded spend, but never
            // re-derived the external transparent payment from the raw transaction.
            conn(&st)
                .execute_batch(&format!(
                    "UPDATE transactions SET created = NULL, target_height = NULL
                     WHERE txid = X'{tx}';
                     DELETE FROM sent_notes WHERE transaction_id =
                         (SELECT id_tx FROM transactions WHERE txid = X'{tx}');",
                    tx = hex::encode(txid.as_ref()),
                ))
                .unwrap();
        }

        let migration = crate::wallet::init::migrations::FUNDING_ATTRIBUTION_ID;
        conn(&st)
            .execute_batch(&format!(
                "DROP TABLE tx_attribution_queue;
                 DELETE FROM schemer_migrations WHERE id = X'{migration}';",
                migration = hex::encode(migration.as_bytes()),
            ))
            .unwrap();
        WalletMigrator::new()
            .init_or_migrate(st.wallet_mut().db_mut())
            .unwrap();
        assert_eq!(queued(&st), if constructed { 0 } else { 1 });

        // An unrelated storage call must repair the backfill without rediscovering the spend.
        let unrelated = funding(0xa1, external_of(&st, account), 100_000);
        store(&mut st, &unrelated);
        assert_eq!(queued(&st), 0);
        assert!(sent_outputs(&st, &send).contains(&(account, output_index, None, 50_000)));
        assert_eq!(
            history(&st, account, &send).funding,
            TransactionFunding::Sole
        );
        if constructed {
            assert_eq!(sent_outputs(&st, &send), construction_records);
        }
    }
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
