//! Deriving transparent addresses, and reconciling a UTXO sweep.
//!
//! The sweep is the destructive one. Its second half marks outputs *spent* on
//! the strength of the server not having mentioned them, which is the only way
//! to learn about a purely transparent spend made from another installation of
//! the same seed — and also the only place in this wallet where silence is
//! treated as information. Getting its range or its exclusions wrong would
//! quietly erase real funds from the balance.

use zakura_wallet_core::AccountId;
use zakura_wallet_store::{GapLimits, SweptOutput, WalletDb, testing::test_db};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, Network},
};

fn params() -> Network {
    Network::MainNetwork
}

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

fn wallet() -> (WalletDb, AccountId) {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(
            &params(),
            &[5u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            h(100),
        )
        .unwrap();
    db.update_chain_tip(&params(), h(1_000)).unwrap();
    (db, id)
}

fn watched_addresses(db: &WalletDb) -> Vec<(i64, String)> {
    db.connection()
        .prepare(
            "SELECT id, transparent_address FROM cache.addresses
             WHERE transparent_address IS NOT NULL
             ORDER BY key_scope, transparent_child_index",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn an_account_derives_a_full_window_of_watchable_addresses() {
    // Without this the wallet is watching nothing, and a transparent payment
    // has no second chance: there is no trial decryption to find it later.
    let (mut db, id) = wallet();
    let limits = GapLimits::default();

    // Creating the account derived the window; there is nothing left to add.
    // Waiting to be asked would leave a gap between the account existing and
    // the wallet watching anything, and a payment arriving in that gap is one
    // it can never recognise afterwards.
    let added = db
        .maintain_transparent_addresses(&params(), id, &limits)
        .expect("the account has a transparent key");
    assert_eq!(added, 0, "creating the account already filled the window");

    let addresses = watched_addresses(&db);
    assert_eq!(
        addresses.len(),
        (limits.external + limits.internal) as usize,
        "both scopes are watched, at their own widths"
    );

    // Real addresses, not placeholders, and all distinct: two indices deriving
    // the same address would mean the derivation is not doing anything.
    let encoded: std::collections::BTreeSet<_> =
        addresses.iter().map(|(_, a)| a.clone()).collect();
    assert_eq!(encoded.len(), addresses.len(), "every address is distinct");
    assert!(
        addresses.iter().all(|(_, a)| a.starts_with('t')),
        "mainnet transparent addresses are t-addresses"
    );

    // Idempotent, which is what lets it run after every batch.
    let again = db
        .maintain_transparent_addresses(&params(), id, &limits)
        .unwrap();
    assert_eq!(again, 0, "a full window needs no widening");
    assert_eq!(watched_addresses(&db).len(), addresses.len());
}

#[test]
fn the_watch_set_covers_every_derived_address() {
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();

    let watch = db.transparent_watch().expect("the watch set builds");
    assert_eq!(watch.addresses.len(), watched_addresses(&db).len());
    assert!(
        watch.addresses.iter().all(|a| !a.script.is_empty()),
        "a watched address without a script matches nothing"
    );
    assert!(watch.unspent.is_empty(), "nothing has been received yet");
}

/// Stores an output at `address_id`, mined at `height`.
fn receive(db: &WalletDb, account: AccountId, address_id: i64, height: u32, value: i64, n: u8) {
    let conn = db.connection();
    conn.execute(
        "INSERT INTO cache.transactions (txid, mined_height) VALUES (:txid, :h)",
        rusqlite::named_params![":txid": &[n; 32][..], ":h": height],
    )
    .unwrap();
    let tx_ref: i64 = conn
        .query_row(
            "SELECT id FROM cache.transactions WHERE txid = :txid",
            rusqlite::named_params![":txid": &[n; 32][..]],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO cache.transparent_received_outputs
            (transaction_id, output_index, account_id, address_id, script, value, is_coinbase)
         VALUES (:tx, 0, :account, :address, X'00', :value, 0)",
        rusqlite::named_params![
            ":tx": tx_ref,
            ":account": account.0,
            ":address": address_id,
            ":value": value,
        ],
    )
    .unwrap();
}

#[test]
fn a_sweep_marks_only_the_outputs_it_did_not_return() {
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();
    let addresses = watched_addresses(&db);
    let (first_id, first_address) = addresses[0].clone();
    let (second_id, _) = addresses[1].clone();

    receive(&db, id, first_id, 500, 100_000, 1);
    receive(&db, id, second_id, 600, 200_000, 2);

    // The server reports only the first. The second is gone: spent somewhere
    // this wallet cannot see.
    db.apply_utxo_sweep(
        id,
        h(400),
        h(1_000),
        &[SweptOutput {
            address: first_address,
            txid: TxId::from_bytes([1u8; 32]),
            output_index: 0,
            script: vec![0],
            value: 100_000,
            height: h(500),
        }],
    )
    .expect("the sweep applies");

    let (kept, gone): (i64, i64) = db
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM cache.transparent_received_outputs
                     WHERE observed_spent_at_height IS NULL),
                    (SELECT COUNT(*) FROM cache.transparent_received_outputs
                     WHERE observed_spent_at_height IS NOT NULL)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kept, 1, "the output the server returned is still unspent");
    assert_eq!(gone, 1, "the one it did not mention is spent");

    // And the balance follows.
    let balance = db.transparent_balance(id).unwrap();
    assert_eq!(balance.total().into_u64(), 100_000);
}

#[test]
fn a_sweep_does_not_touch_outputs_outside_the_range_it_covered() {
    // The exclusion that keeps a sweep from erasing history it never looked at.
    // A sweep starting at height 400 says nothing about an output mined at 300,
    // and treating its silence as evidence would delete real funds.
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();
    let addresses = watched_addresses(&db);

    receive(&db, id, addresses[0].0, 300, 100_000, 1);
    receive(&db, id, addresses[1].0, 700, 200_000, 2);

    db.apply_utxo_sweep(id, h(400), h(1_000), &[])
        .expect("an empty sweep is a valid answer");

    let below: Option<u32> = db
        .connection()
        .query_row(
            "SELECT observed_spent_at_height FROM cache.transparent_received_outputs o
             JOIN cache.transactions t ON t.id = o.transaction_id
             WHERE t.mined_height = 300",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(below, None, "an output below the swept range is untouched");

    let inside: Option<u32> = db
        .connection()
        .query_row(
            "SELECT observed_spent_at_height FROM cache.transparent_received_outputs o
             JOIN cache.transactions t ON t.id = o.transaction_id
             WHERE t.mined_height = 700",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(inside, Some(1_000), "one inside it is marked spent");
}

#[test]
fn a_sweep_refuses_an_address_the_wallet_never_derived() {
    // The server answering about somebody else's address is not something to
    // absorb quietly: storing it would credit another person's funds to this
    // wallet's balance.
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();

    let err = db
        .apply_utxo_sweep(
            id,
            h(400),
            h(1_000),
            &[SweptOutput {
                address: "t1SomebodyElsesAddress".to_owned(),
                txid: TxId::from_bytes([9u8; 32]),
                output_index: 0,
                script: vec![0],
                value: 100_000,
                height: h(500),
            }],
        )
        .expect_err("an unknown address must be refused");
    assert!(
        format!("{err}").contains("never derived"),
        "the error should say why it was refused, got: {err}"
    );
}

#[test]
fn a_swept_output_becomes_visible_and_is_not_yet_spendable() {
    // A sweep is how a restored wallet finds funds at addresses it had not
    // derived when the blocks carrying them were scanned. It carries no
    // transaction index, so coinbase-ness is unknown — and unknown is treated
    // as immature, which is why the value shows as pending rather than
    // spendable.
    let (mut db, id) = wallet();
    db.maintain_transparent_addresses(&params(), id, &GapLimits::default())
        .unwrap();
    let (_, address) = watched_addresses(&db)[0].clone();

    db.apply_utxo_sweep(
        id,
        h(400),
        h(1_000),
        &[SweptOutput {
            address,
            txid: TxId::from_bytes([3u8; 32]),
            output_index: 0,
            script: vec![0],
            value: 250_000,
            height: h(500),
        }],
    )
    .unwrap();

    let balance = db.transparent_balance(id).unwrap();
    assert_eq!(balance.total().into_u64(), 250_000, "the funds are visible");
    assert_eq!(
        balance.spendable.into_u64(),
        0,
        "but not spendable, because a sweep cannot say whether it is coinbase"
    );

    assert!(
        db.spendable_utxos(id, zakura_wallet_store::TransparentSpendPolicy::AnyAddress)
            .unwrap()
            .is_empty(),
        "and selection must not offer it"
    );
}
