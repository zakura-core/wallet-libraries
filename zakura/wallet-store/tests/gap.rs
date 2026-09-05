//! Tests for transparent address discovery and the gap limit.

use zakura_wallet_core::{AccountId, KeyScope};
use zakura_wallet_store::{GapLimits, WalletDb, testing::test_db};
use zcash_protocol::consensus::{BlockHeight, Network};

fn params() -> Network {
    Network::MainNetwork
}

fn account(db: &mut WalletDb) -> AccountId {
    db.create_account(
        &params(),
        &[5u8; 32],
        zip32::AccountId::try_from(0).unwrap(),
        BlockHeight::from_u32(100),
    )
    .unwrap()
}

/// Records `count` transparent addresses, indices 0..count.
fn watch(db: &mut WalletDb, id: AccountId, scope: KeyScope, count: u32) {
    for index in 0..count {
        db.record_transparent_address(
            id,
            scope,
            index,
            &format!("t-addr-{scope:?}-{index}"),
            &[index as u8; 4],
        )
        .unwrap();
    }
}

/// Marks the address at `index` as having received something.
fn receive_at(db: &WalletDb, index: u32, scope: KeyScope) {
    let conn = db.connection();
    conn.execute(
        "INSERT OR IGNORE INTO cache.transactions (id, txid, mined_height)
         VALUES (1, X'01', 100)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO cache.transparent_received_outputs
            (transaction_id, output_index, account_id, address, script, value)
         VALUES (1, ?, 1, ?, X'00', 100)",
        rusqlite::params![index as i64, format!("t-addr-{scope:?}-{index}")],
    )
    .unwrap();
}

#[test]
fn the_default_limits_are_below_the_bip44_convention() {
    // Not an oversight. A light server sees every address a wallet asks about
    // together and can cluster them into one wallet on that basis, so the
    // window is kept as narrow as discovery tolerates.
    let limits = GapLimits::default();
    assert!(limits.external < 20, "BIP 44 suggests twenty");
    assert_eq!(limits.external, 10);
    assert!(
        limits.internal < limits.external,
        "only the wallet uses its internal addresses, so fewer need watching"
    );
    assert_eq!(limits.internal, 5);
    assert_eq!(limits.for_scope(KeyScope::External), 10);
    assert_eq!(limits.for_scope(KeyScope::Internal), 5);
}

#[test]
fn a_fresh_account_needs_a_full_window() {
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();

    let state = db.gap_state(id, KeyScope::External).unwrap();
    assert_eq!(state.highest_known, None);
    assert_eq!(state.remaining, 0);
    assert!(state.needs_widening(limits.external));

    let to_generate = db
        .addresses_to_generate(id, KeyScope::External, &limits)
        .unwrap();
    assert_eq!(to_generate, (0..10).collect::<Vec<_>>());
}

#[test]
fn an_unused_window_needs_no_widening() {
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();
    watch(&mut db, id, KeyScope::External, 10);

    let state = db.gap_state(id, KeyScope::External).unwrap();
    assert_eq!(state.highest_known, Some(9));
    assert_eq!(state.highest_used, None);
    assert_eq!(state.remaining, 10);
    assert!(!state.needs_widening(limits.external));

    assert!(
        db.addresses_to_generate(id, KeyScope::External, &limits)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn using_an_address_obliges_the_wallet_to_look_further() {
    // Being paid at an address is what consumes the window; generating one
    // costs nothing and reveals nothing.
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();
    watch(&mut db, id, KeyScope::External, 10);
    receive_at(&db, 3, KeyScope::External);

    let state = db.gap_state(id, KeyScope::External).unwrap();
    assert_eq!(state.highest_used, Some(3));
    assert_eq!(state.remaining, 6, "indices 4 through 9 are still unused");
    assert!(state.needs_widening(limits.external));

    // The window must extend ten past the used one, so 10..=13.
    assert_eq!(
        db.addresses_to_generate(id, KeyScope::External, &limits)
            .unwrap(),
        vec![10, 11, 12, 13]
    );
}

#[test]
fn widening_the_window_settles_it() {
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();
    watch(&mut db, id, KeyScope::External, 10);
    receive_at(&db, 3, KeyScope::External);

    for index in db
        .addresses_to_generate(id, KeyScope::External, &limits)
        .unwrap()
    {
        db.record_transparent_address(
            id,
            KeyScope::External,
            index,
            &format!("t-addr-External-{index}"),
            &[index as u8; 4],
        )
        .unwrap();
    }

    assert!(
        db.addresses_to_generate(id, KeyScope::External, &limits)
            .unwrap()
            .is_empty(),
        "one widening should be enough"
    );
}

#[test]
fn the_two_scopes_have_independent_windows() {
    // The internal window is narrower, because nobody else can pay an address
    // they were never given.
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();

    watch(&mut db, id, KeyScope::External, 10);
    assert!(
        db.addresses_to_generate(id, KeyScope::External, &limits)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.addresses_to_generate(id, KeyScope::Internal, &limits)
            .unwrap(),
        (0..5).collect::<Vec<_>>(),
        "the internal scope is untouched by external addresses"
    );
}

#[test]
fn recording_an_address_twice_does_not_duplicate_it() {
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    watch(&mut db, id, KeyScope::External, 3);
    watch(&mut db, id, KeyScope::External, 3);

    let count: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses WHERE key_scope = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
}
