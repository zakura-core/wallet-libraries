//! Shared fixtures for the transaction tests.

use orchard::keys::FullViewingKey;
use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zakura_wallet_scan::{
    NullifierSnapshot, ScanKeys, TransparentWatch, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zcash_protocol::consensus::BlockHeight;

/// The account every fixture funds.
pub const ALICE: AccountId = AccountId(1);

/// Where the synthetic chains start.
pub const START: u32 = IRONWOOD_ACTIVATION + 10;

/// Builds a wallet holding `count` notes of `value` in `pool`, scanned from a
/// synthetic chain and buried deep enough to be spendable.
pub fn funded_wallet(pool: PoolId, count: usize, value: u64, fvk: &FullViewingKey) -> WalletDb {
    let mut db = test_db().unwrap();
    db.set_birthday(BlockHeight::from_u32(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            for i in 0..count {
                t.receive(pool, fvk, KeyScope::External, value + i as u64);
            }
        });
    });
    // Bury the notes: a note whose shard is not fully scanned and confirmed has
    // no witness a reorg cannot invalidate, and is deliberately not spendable.
    chain.empty_blocks(2);

    let keys = ScanKeys::from_accounts([(ALICE, fvk.clone())]);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("the chain scans cleanly");
    db.put_batch(&test_params(), &batch).expect("the batch applies");

    register_account(&db, ALICE);

    db
}

/// Gives the wallet an `accounts` row for an account the fixtures fund.
///
/// Scanning does not need one — a note carries its own account id — but
/// recording an outgoing payment does, because `sent_outputs.from_account_id`
/// is a foreign key onto it. A fixture without this looks fine right up until
/// something writes the wallet's own history.
///
/// Deliberately a bare row rather than a real derivation: these tests hold
/// Orchard spending keys directly, not ZIP 32 seeds, so there is no unified
/// key to derive and nothing here reads one back.
pub fn register_account(db: &WalletDb, account: AccountId) {
    db.connection()
        .execute(
            "INSERT OR IGNORE INTO main.accounts
                (id, uuid, uivk, birthday_height, has_spend_key)
             VALUES (:id, :uuid, :uivk, :birthday, 1)",
            rusqlite::named_params![
                ":id": account.0,
                ":uuid": &account.0.to_le_bytes()[..],
                ":uivk": format!("test-account-{}", account.0),
                ":birthday": START,
            ],
        )
        .expect("the fixture account inserts");
}
