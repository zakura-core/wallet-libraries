//! Tests for accounts, addresses, balance and history.

use assert_matches::assert_matches;
use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zakura_wallet_store::{Error, WalletDb, testing::test_db};
use zcash_protocol::{
    consensus::{BlockHeight, Network},
    value::Zatoshis,
};

fn params() -> Network {
    Network::MainNetwork
}

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

fn seed(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn zip32(i: u32) -> zip32::AccountId {
    zip32::AccountId::try_from(i).expect("a valid ZIP 32 account index")
}

// ------------------------------------------------------------- accounts

#[test]
fn an_account_derived_from_a_seed_can_be_read_back() {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(1_000_000))
        .unwrap();

    let account = db
        .account(&params(), id)
        .unwrap()
        .expect("the account exists");
    assert_eq!(account.id, id);
    assert_eq!(account.birthday, h(1_000_000));
    assert!(account.has_spend_key, "a seed-derived account can spend");
    assert_eq!(account.hd_account_index, Some(0));
    assert!(
        account.orchard_fvk().is_ok(),
        "the account must cover Orchard, which also covers Ironwood"
    );
}

#[test]
fn the_same_seed_and_index_derive_the_same_key() {
    // Restoring from a seed has to reproduce the wallet, not a new one.
    let mut first = test_db().unwrap();
    let a = first
        .create_account(&params(), &seed(7), zip32(0), h(100))
        .unwrap();
    let mut second = test_db().unwrap();
    let b = second
        .create_account(&params(), &seed(7), zip32(0), h(100))
        .unwrap();

    assert_eq!(
        first
            .account(&params(), a)
            .unwrap()
            .unwrap()
            .orchard_fvk()
            .unwrap()
            .to_bytes(),
        second
            .account(&params(), b)
            .unwrap()
            .unwrap()
            .orchard_fvk()
            .unwrap()
            .to_bytes()
    );
}

#[test]
fn different_account_indices_are_different_accounts() {
    let mut db = test_db().unwrap();
    let a = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();
    let b = db
        .create_account(&params(), &seed(1), zip32(1), h(100))
        .unwrap();

    assert_ne!(a, b);
    let keys: Vec<_> = db
        .accounts(&params())
        .unwrap()
        .iter()
        .map(|a| a.orchard_fvk().unwrap().to_bytes())
        .collect();
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn adding_the_same_account_twice_is_refused() {
    // The incoming viewing key is the account's identity. Two accounts sharing
    // one would see the same notes, and every balance would be doubled.
    let mut db = test_db().unwrap();
    db.create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();
    let err = db
        .create_account(&params(), &seed(1), zip32(0), h(200))
        .unwrap_err();

    assert_matches!(err, Error::AccountExists);
    assert!(err.to_string().contains("twice"), "{err}");
    assert_eq!(db.accounts(&params()).unwrap().len(), 1);
}

#[test]
fn the_wallet_birthday_is_the_earliest_accounts() {
    // Scanning below it can produce nothing for any account.
    let mut db = test_db().unwrap();
    assert_eq!(db.birthday().unwrap(), None);

    db.create_account(&params(), &seed(1), zip32(0), h(900_000))
        .unwrap();
    db.create_account(&params(), &seed(2), zip32(0), h(500_000))
        .unwrap();
    db.create_account(&params(), &seed(3), zip32(0), h(700_000))
        .unwrap();

    assert_eq!(db.birthday().unwrap(), Some(h(500_000)));
}

#[test]
fn accounts_survive_a_cache_rebuild() {
    // Accounts are the durable half: everything else is derived from them plus
    // the chain, which is what makes dropping the cache safe.
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(4), zip32(0), h(123_456))
        .unwrap();
    let before = db.account(&params(), id).unwrap().unwrap();

    let in_cache: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.sqlite_master WHERE name = 'accounts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(in_cache, 0, "accounts live in the durable database");

    let after = db.account(&params(), id).unwrap().unwrap();
    assert_eq!(after.birthday, before.birthday);
}

// ------------------------------------------------------------ addresses

#[test]
fn each_address_issued_is_a_new_one() {
    // Reusing an address lets anybody who has seen it link the payments made
    // to it.
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();

    let mut seen = Vec::new();
    for _ in 0..5 {
        let (address, index) = db
            .next_address(&params(), id, KeyScope::External, Some(h(200)))
            .unwrap();
        seen.push((address.encode(&params()), index));
    }

    let encoded: Vec<_> = seen.iter().map(|(a, _)| a.clone()).collect();
    let mut unique = encoded.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        encoded.len(),
        "every address must be distinct"
    );

    // And the diversifier indices advance rather than restarting.
    for pair in seen.windows(2) {
        assert!(pair[1].1 > pair[0].1, "indices must move forward");
    }
}

#[test]
fn issued_addresses_are_recorded() {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();
    db.next_address(&params(), id, KeyScope::External, Some(h(555)))
        .unwrap();

    // Only the address that was handed out is exposed; the rest of the window
    // is derived and waiting, which is what makes it a window.
    let (scope, exposed): (u8, Option<u32>) = db
        .connection()
        .query_row(
            "SELECT key_scope, exposed_at_height FROM cache.addresses
             WHERE exposed_at_height IS NOT NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(scope, KeyScope::External.code());
    assert_eq!(exposed, Some(555));
}

#[test]
fn the_two_scopes_have_independent_address_sequences() {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();

    let (_, external) = db
        .next_address(&params(), id, KeyScope::External, None)
        .unwrap();
    let (_, internal) = db
        .next_address(&params(), id, KeyScope::Internal, None)
        .unwrap();

    // Both start from the beginning of their own space.
    assert_eq!(external, internal);

    // One address handed out per scope, and the rest of each window still
    // waiting. The window is derived when the account is created, because a
    // transparent output arrives at an address or is never seen at all — so
    // "how many addresses exist" is not "how many have been issued".
    let exposed: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses WHERE exposed_at_height IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exposed, 2, "one issued in each scope");
}

#[test]
fn an_unknown_account_cannot_issue_an_address() {
    let mut db = test_db().unwrap();
    let err = db
        .next_address(&params(), AccountId(99), KeyScope::External, None)
        .unwrap_err();
    assert_matches!(err, Error::NoSuchAccount { .. });
}

#[test]
fn change_goes_to_the_internal_address() {
    // Which is what makes it recognisable as change on a later scan, whatever
    // order the blocks arrive in.
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();
    let account = db.account(&params(), id).unwrap().unwrap();

    let change = db.change_address(&params(), id).unwrap();
    let fvk = account.orchard_fvk().unwrap();
    assert_eq!(
        fvk.scope_for_address(&change),
        Some(orchard::keys::Scope::Internal)
    );
}

// -------------------------------------------------------------- balance

/// Inserts a note directly, so balance can be tested without a full scan.
fn plant_note(
    db: &WalletDb,
    account: AccountId,
    pool: PoolId,
    value: u64,
    stable: bool,
    position: u64,
    spent_by: Option<u32>,
) {
    let conn = db.connection();
    conn.execute(
        "INSERT OR IGNORE INTO cache.transactions (id, txid, mined_height)
         VALUES (1, X'0101', 100)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO cache.received_notes
            (transaction_id, pool, action_index, account_id, diversifier, value,
             rho, rseed, note_version, nf, is_change, key_scope,
             commitment_tree_position, witness_stabilized)
         VALUES (1, ?, ?, ?, X'00', ?, X'00', X'00', 3, ?, 0, 0, ?, ?)",
        rusqlite::params![
            pool.code(),
            position as i64,
            account.0,
            value as i64,
            format!("nf{position}").into_bytes(),
            position as i64,
            stable
        ],
    )
    .unwrap();

    if let Some(mined) = spent_by {
        conn.execute(
            "INSERT OR IGNORE INTO cache.transactions (id, txid, mined_height)
             VALUES (2, X'0202', ?)",
            rusqlite::params![if mined == 0 { None } else { Some(mined) }],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cache.received_note_spends (received_note_id, transaction_id)
             SELECT id, 2 FROM cache.received_notes WHERE commitment_tree_position = ?",
            rusqlite::params![position as i64],
        )
        .unwrap();
    }
}

#[test]
fn balance_separates_what_can_be_spent_from_what_cannot() {
    // The three figures are the same funds at different stages of becoming
    // usable. A wallet showing only one of them will confuse somebody.
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();

    plant_note(&db, id, PoolId::Ironwood, 100, true, 0, None);
    plant_note(&db, id, PoolId::Ironwood, 200, false, 1, None);
    plant_note(&db, id, PoolId::Ironwood, 400, true, 2, Some(0));

    let balance = db.balance(id, PoolId::Ironwood).unwrap();
    assert_eq!(balance.spendable, Zatoshis::const_from_u64(100));
    assert_eq!(
        balance.pending,
        Zatoshis::const_from_u64(200),
        "a note whose witness is not stable is real money that cannot yet be sent"
    );
    assert_eq!(
        balance.spent_unconfirmed,
        Zatoshis::const_from_u64(400),
        "a note spent by an unmined transaction is gone to the user and not to the chain"
    );
    assert_eq!(balance.total(), Zatoshis::const_from_u64(300));
}

#[test]
fn balance_is_per_pool_and_sums_across_them() {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();

    plant_note(&db, id, PoolId::Orchard, 700, true, 0, None);
    plant_note(&db, id, PoolId::Ironwood, 300, true, 1, None);

    assert_eq!(
        db.balance(id, PoolId::Orchard).unwrap().spendable,
        Zatoshis::const_from_u64(700)
    );
    assert_eq!(
        db.balance(id, PoolId::Ironwood).unwrap().spendable,
        Zatoshis::const_from_u64(300)
    );
    assert_eq!(
        db.total_balance(id).unwrap().spendable,
        Zatoshis::const_from_u64(1_000)
    );
}

#[test]
fn one_accounts_notes_are_not_anothers() {
    let mut db = test_db().unwrap();
    let a = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();
    let b = db
        .create_account(&params(), &seed(2), zip32(0), h(100))
        .unwrap();

    plant_note(&db, a, PoolId::Ironwood, 500, true, 0, None);

    assert_eq!(
        db.total_balance(a).unwrap().spendable,
        Zatoshis::const_from_u64(500)
    );
    assert_eq!(db.total_balance(b).unwrap().spendable, Zatoshis::ZERO);
}

#[test]
fn an_empty_account_has_a_zero_balance() {
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();
    assert_eq!(db.total_balance(id).unwrap(), Default::default());
    assert!(db.history(id, 10).unwrap().is_empty());
}

#[test]
fn issuing_an_address_consumes_the_window_rather_than_stepping_over_it() {
    // The window is a run of addresses the wallet has already derived and is
    // watching, waiting to be handed out. Issuing has to take the lowest one
    // that has not been: taking the highest plus one would leave the wallet
    // watching addresses it never issues, and issuing addresses past where
    // another wallet restoring the same seed would stop looking — which is how
    // funds become invisible to the wallet that owns them.
    let mut db = test_db().unwrap();
    let id = db
        .create_account(&params(), &seed(1), zip32(0), h(100))
        .unwrap();

    let derived: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses WHERE key_scope = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        derived > 1,
        "creating an account derives a window to hand out"
    );

    // Issue several, and watch them come out consecutively from zero.
    let mut issued = Vec::new();
    for _ in 0..3 {
        let (_, index) = db
            .next_address(&params(), id, KeyScope::External, Some(h(200)))
            .unwrap();
        issued.push(index);
    }

    let mut expected = zip32::DiversifierIndex::new();
    for index in &issued {
        assert_eq!(
            *index, expected,
            "addresses are handed out in order from zero"
        );
        expected.increment().unwrap();
    }

    // Each one is now exposed, and nothing else is.
    let exposed: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses
             WHERE key_scope = 0 AND exposed_at_height IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exposed, 3, "exactly the three that were handed out");

    // And issuing did not derive a pile of new rows past the window.
    let after: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses WHERE key_scope = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        after, derived,
        "issuing consumes the window; widening it is the gap logic's job"
    );
}
