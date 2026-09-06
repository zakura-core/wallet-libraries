//! The wallet handle: opening it, creating an account, and reading it back.
//!
//! This exercises the parts that only exist once there is a real file on disk —
//! the two connections over the same pair of databases, and the writer moving
//! in and out of the synchronisation engine. Scanning is covered by the core's
//! own suite, so nothing here needs a chain.

use zakura_wallet_facade::{ErrorCode, NetworkKind, Wallet, WalletConfig, mnemonic};
use zeroize::Zeroizing;

fn open() -> (tempfile::TempDir, Wallet) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir.path(),
        "https://testnet.example.invalid:443",
    );
    let wallet = Wallet::open(config).expect("the wallet opens");
    (dir, wallet)
}

fn seed() -> Zeroizing<Vec<u8>> {
    mnemonic::to_seed(&mnemonic::generate(), "").expect("a generated phrase is valid")
}

#[test]
fn a_new_wallet_has_no_accounts() {
    let (_dir, wallet) = open();
    assert!(wallet.accounts().unwrap().is_empty());
    assert!(!wallet.is_syncing());
}

#[test]
fn opening_creates_both_databases() {
    let (dir, _wallet) = open();
    assert!(dir.path().join("wallet.db").exists());
    assert!(dir.path().join("cache.db").exists());
}

#[test]
fn an_account_is_created_and_read_back() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let accounts = wallet.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    assert_eq!(accounts[0].birthday, 3_000_000);
    assert!(accounts[0].can_spend, "a seeded account can spend");
    assert_eq!(accounts[0].hd_account_index, Some(0));
}

/// A new wallet is worth nothing, and says so in all three figures rather than
/// leaving any of them unset.
#[test]
fn a_new_account_is_worth_nothing() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let balance = wallet.balance(id).unwrap();
    assert_eq!(balance.spendable, 0);
    assert_eq!(balance.pending, 0);
    assert_eq!(balance.spent_unconfirmed, 0);
    assert_eq!(balance.total(), 0);
    assert!(wallet.history(id, 10).unwrap().is_empty());
}

/// Two calls must not return the same address: reusing one lets anybody who has
/// seen it link the payments made to it.
#[test]
fn each_address_is_issued_once() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let first = wallet.next_address(id, Some(3_000_000)).unwrap();
    let second = wallet.next_address(id, Some(3_000_000)).unwrap();

    assert!(first.starts_with('u'), "a unified address");
    assert_ne!(first, second);
}

#[test]
fn an_unknown_account_is_named_as_such() {
    let (_dir, wallet) = open();
    let code = wallet.balance(99).err().map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::NoSuchAccount));
}

/// The wallet survives being closed and reopened, which is the whole point of
/// the durable half of the schema.
#[test]
fn an_account_outlives_the_handle_that_made_it() {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir.path(),
        "https://testnet.example.invalid:443",
    );

    let id = {
        let wallet = Wallet::open(config.clone()).unwrap();
        wallet.create_account(&seed(), 0, 3_000_000).unwrap()
    };

    let reopened = Wallet::open(config).unwrap();
    let accounts = reopened.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
}

/// Deleting the cache must not cost the account, only the scanning.
#[test]
fn the_cache_can_be_rebuilt_without_losing_the_account() {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir.path(),
        "https://testnet.example.invalid:443",
    );

    let id = {
        let wallet = Wallet::open(config.clone()).unwrap();
        wallet.create_account(&seed(), 0, 3_000_000).unwrap()
    };

    for suffix in ["", "-wal", "-shm"] {
        let path = dir.path().join(format!("cache.db{suffix}"));
        let _ = std::fs::remove_file(path);
    }

    let reopened = Wallet::open(config).unwrap();
    assert_eq!(reopened.accounts().unwrap()[0].id, id);
}

/// Stopping a sync that was never started is not an error: an interface should
/// be able to call it on the way out without checking first.
#[test]
fn stopping_a_sync_that_never_started_is_harmless() {
    let (_dir, wallet) = open();
    wallet.stop_sync();
    assert!(!wallet.is_syncing());
}

/// The scanner matches the scripts the wallet has recorded, so an address that
/// was never derived is one nothing is looking for and a payment to it goes
/// unseen. Creating an account has to derive them.
#[test]
fn creating_an_account_derives_the_transparent_addresses_to_watch() {
    let (_dir, wallet) = open();
    wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let watched = wallet.watched_transparent_addresses().unwrap();
    assert!(
        watched > 0,
        "no transparent address was derived, so nothing is watching for one"
    );
}

/// Issuing an address may consume the last of the unused window, and a window
/// that is not topped up silently stops the wallet seeing new payments.
#[test]
fn issuing_addresses_keeps_the_watch_window_full() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();
    let before = wallet.watched_transparent_addresses().unwrap();

    for _ in 0..5 {
        wallet.next_address(id, None).unwrap();
    }

    assert!(
        wallet.watched_transparent_addresses().unwrap() >= before,
        "the window shrank"
    );
}

/// Transparent value is reported, and kept apart from what can be sent
/// directly: spending it needs a shielding step first.
#[test]
fn a_balance_separates_transparent_from_sendable() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let balance = wallet.balance(id).unwrap();
    assert_eq!(balance.transparent, 0);
    assert_eq!(balance.shielded(), 0);
    assert_eq!(balance.total(), 0);
}
