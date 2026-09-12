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

/// Marks the address at `index` as having received something in a mined block.
fn receive_at(db: &WalletDb, index: u32, scope: KeyScope) {
    receive_at_height(db, index, scope, Some(100));
}

/// Records a receipt at `index`, mined or still in the mempool.
///
/// Goes through the real relationship — a foreign key onto the address row —
/// rather than fabricating the address string. An earlier version of this
/// fixture wrote the string by hand, which meant it agreed with itself while
/// the production writer used a different encoding entirely, and the join
/// between them could never match in a real wallet.
fn receive_at_height(db: &WalletDb, index: u32, scope: KeyScope, mined: Option<u32>) {
    let conn = db.connection();
    let address_id: i64 = conn
        .query_row(
            "SELECT id FROM cache.addresses
             WHERE account_id = 1 AND key_scope = ? AND transparent_child_index = ?",
            rusqlite::params![scope.code(), index],
            |row| row.get(0),
        )
        .expect("the address must be watched before anything is received at it");

    // A distinct transaction per receipt, so several can coexist.
    let tx_id = i64::from(index) + 1 + if scope == KeyScope::Internal { 1000 } else { 0 };
    conn.execute(
        "INSERT OR IGNORE INTO cache.transactions (id, txid, mined_height)
         VALUES (?, ?, ?)",
        rusqlite::params![tx_id, &tx_id.to_le_bytes()[..], mined],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO cache.transparent_received_outputs
            (transaction_id, output_index, account_id, address_id, script, value)
         VALUES (?, ?, 1, ?, X'00', 100)",
        rusqlite::params![tx_id, index as i64, address_id],
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
fn a_fresh_account_starts_with_a_full_window() {
    // Creating an account derives the window immediately. A transparent output
    // is recognised only if its address existed before the block carrying it
    // was scanned, so an account that had to be told to derive first would miss
    // anything paid to it in the meantime.
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();

    let state = db.gap_state(id, KeyScope::External).unwrap();
    assert_eq!(
        state.highest_known,
        Some(limits.external - 1),
        "the whole window is derived up front"
    );
    assert_eq!(state.highest_used, None, "and none of it has been paid yet");
    assert!(!state.needs_widening(limits.external));

    assert!(
        db.addresses_to_generate(id, KeyScope::External, &limits)
            .unwrap()
            .is_empty(),
        "a window that is already full needs nothing generated"
    );

    // An account with no window at all is what actually needs one.
    let bare = AccountId(999);
    let to_generate = db
        .addresses_to_generate(bare, KeyScope::External, &limits)
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

    // Both windows are derived at creation, at their own widths.
    assert_eq!(
        db.gap_state(id, KeyScope::External).unwrap().highest_known,
        Some(limits.external - 1)
    );
    assert_eq!(
        db.gap_state(id, KeyScope::Internal).unwrap().highest_known,
        Some(limits.internal - 1),
        "the internal window is narrower, and separate"
    );
}

#[test]
fn recording_an_address_twice_does_not_duplicate_it() {
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let before: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses WHERE key_scope = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();

    // Recording the same indices again must not add rows. Idempotence is what
    // lets the window be topped up after every batch without the table growing
    // a copy of itself each time.
    watch(&mut db, id, KeyScope::External, 3);
    watch(&mut db, id, KeyScope::External, 3);

    let after: u32 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM cache.addresses WHERE key_scope = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after, before, "re-recording derived addresses adds nothing");
}

#[test]
fn only_a_mined_receipt_moves_the_window() {
    // A payment sitting in the mempool may never be mined. If it advanced the
    // window, anybody able to put a transaction in the mempool could push a
    // wallet's addresses forward — and a wallet that then generated addresses
    // past its real history would be unrecoverable from its seed elsewhere,
    // because another wallet would stop looking before reaching them.
    let mut db = test_db().unwrap();
    let id = account(&mut db);
    let limits = GapLimits::default();
    watch(&mut db, id, KeyScope::External, limits.external);

    let before = db.gap_state(id, KeyScope::External).unwrap();

    receive_at_height(&db, 3, KeyScope::External, None);
    let after_mempool = db.gap_state(id, KeyScope::External).unwrap();
    assert_eq!(
        after_mempool, before,
        "an unmined receipt must not advance the window"
    );

    // The same transaction is mined, which is what really happens: the output
    // does not arrive twice.
    db.connection()
        .execute(
            "UPDATE cache.transactions SET mined_height = 100 WHERE id = 4",
            [],
        )
        .unwrap();
    let after_mined = db.gap_state(id, KeyScope::External).unwrap();
    assert_eq!(
        after_mined.highest_used,
        Some(3),
        "a mined receipt is what obliges the wallet to look further"
    );
}
