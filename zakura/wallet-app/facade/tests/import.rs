//! Restoring an existing wallet.
//!
//! The birthday is the one number a restore can get catastrophically wrong.
//! Too high and the wallet silently skips the blocks its money arrived in,
//! showing a balance that is simply missing funds with nothing to suggest
//! anything is amiss. Too low only costs scanning time. Most of these tests are
//! about keeping that asymmetry the right way round.

use zakura_wallet_facade::{ErrorCode, NetworkKind, Wallet, WalletConfig, mnemonic};
use zeroize::Zeroizing;

fn open() -> (tempfile::TempDir, Wallet) {
    let dir = tempfile::tempdir().unwrap();
    // Nothing is listening, so anything needing the network fails rather than
    // silently succeeding against a real server.
    let config = WalletConfig::in_dir(NetworkKind::Test, dir.path(), "https://127.0.0.1:1/");
    (dir, Wallet::open(config).unwrap())
}

fn phrase() -> String {
    mnemonic::generate().to_string()
}

fn seed_of(phrase: &str) -> Zeroizing<Vec<u8>> {
    mnemonic::to_seed(phrase, "").unwrap()
}

#[test]
fn a_restored_wallet_can_be_read_back() {
    let (_dir, wallet) = open();
    let id = wallet
        .import_wallet(&seed_of(&phrase()), Some(2_500_000))
        .unwrap();

    let accounts = wallet.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    assert_eq!(accounts[0].birthday, 2_500_000);
    assert!(accounts[0].can_spend, "a restored seed can spend");
}

/// The whole point of restoring: the same phrase gives back the same wallet,
/// with the same addresses.
#[test]
fn the_same_phrase_restores_the_same_wallet() {
    let words = phrase();

    let (dir_a, a) = open();
    let id_a = a.import_wallet(&seed_of(&words), Some(2_500_000)).unwrap();
    let address_a = a.next_address(id_a, None).unwrap();

    let (dir_b, b) = open();
    let id_b = b.import_wallet(&seed_of(&words), Some(2_500_000)).unwrap();
    let address_b = b.next_address(id_b, None).unwrap();

    assert_eq!(
        address_a, address_b,
        "the same seed issues the same address"
    );
    drop((dir_a, dir_b));
}

/// A different phrase is a different wallet, which is the other half of the
/// same property.
#[test]
fn a_different_phrase_restores_a_different_wallet() {
    let (_dir, wallet) = open();
    let first = wallet
        .import_wallet(&seed_of(&phrase()), Some(2_500_000))
        .unwrap();
    let second = wallet
        .import_wallet(&seed_of(&phrase()), Some(2_500_000))
        .unwrap();

    assert_ne!(first, second);
    assert_eq!(wallet.accounts().unwrap().len(), 2);
    assert_ne!(
        wallet.next_address(first, None).unwrap(),
        wallet.next_address(second, None).unwrap()
    );
}

/// Two accounts sharing a viewing key would see the same notes and double every
/// balance, so importing the same wallet twice is refused rather than quietly
/// creating a second one.
#[test]
fn importing_the_same_wallet_twice_is_refused() {
    let (_dir, wallet) = open();
    let words = phrase();
    wallet
        .import_wallet(&seed_of(&words), Some(2_500_000))
        .unwrap();

    let code = wallet
        .import_wallet(&seed_of(&words), Some(2_500_000))
        .err()
        .map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::AccountExists));
    assert_eq!(wallet.accounts().unwrap().len(), 1, "and nothing was added");
}

/// An unknown birthday scans from the earliest height that could hold the
/// wallet's money, rather than guessing. A guess that is too high loses
/// transactions and does so silently.
#[test]
fn an_unknown_birthday_starts_from_the_earliest_possible_height() {
    let (_dir, wallet) = open();
    let id = wallet.import_wallet(&seed_of(&phrase()), None).unwrap();

    let birthday = wallet.accounts().unwrap()[0].birthday;
    assert_eq!(birthday, wallet.earliest_birthday());
    assert!(birthday > 0);
    assert_eq!(wallet.accounts().unwrap()[0].id, id);
}

/// And that floor is a real activation height, not zero: scanning from genesis
/// would be correct and needlessly slow.
#[test]
fn the_earliest_birthday_is_the_pools_activation() {
    let (_dir, wallet) = open();
    assert!(
        wallet.earliest_birthday() > 1,
        "the floor should be where the pool activated"
    );
}

/// A brand-new wallet cannot have been paid before it existed, so it starts at
/// the tip. With no server to ask it falls back to the floor — slower, and
/// never wrong in the direction that loses money.
#[test]
fn a_new_wallet_falls_back_to_the_floor_when_the_tip_is_unknown() {
    let (_dir, wallet) = open();
    wallet.create_wallet(&seed_of(&phrase())).unwrap();

    assert_eq!(
        wallet.accounts().unwrap()[0].birthday,
        wallet.earliest_birthday()
    );
}

/// A restored wallet is watched for transparent payments from the moment it is
/// imported; an address nothing derived is one nothing is looking for.
#[test]
fn a_restored_wallet_is_watched_for_transparent_payments() {
    let (_dir, wallet) = open();
    wallet
        .import_wallet(&seed_of(&phrase()), Some(2_500_000))
        .unwrap();

    assert!(wallet.watched_transparent_addresses().unwrap() > 0);
}

#[test]
fn nonsense_is_not_a_viewing_key() {
    let (_dir, wallet) = open();
    let code = wallet
        .import_viewing_key("not a viewing key", None)
        .err()
        .map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::BadViewingKey));
}

/// The store refuses a duplicate viewing key however it got there, so creating
/// a wallet and then importing the same phrase is the same mistake as importing
/// it twice.
#[test]
fn a_created_wallet_cannot_then_be_imported() {
    let (_dir, wallet) = open();
    let words = phrase();
    wallet.create_wallet(&seed_of(&words)).unwrap();

    let code = wallet
        .import_wallet(&seed_of(&words), Some(2_500_000))
        .err()
        .map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::AccountExists));
}

/// A wallet reopened from the same files still has its account, which is what
/// lets an application skip onboarding for somebody who already has one.
#[test]
fn a_restored_wallet_is_found_again_when_the_wallet_is_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(NetworkKind::Test, dir.path(), "https://127.0.0.1:1/");

    let id = {
        let wallet = Wallet::open(config.clone()).unwrap();
        wallet
            .import_wallet(&seed_of(&phrase()), Some(2_500_000))
            .unwrap()
    };

    let reopened = Wallet::open(config).unwrap();
    let accounts = reopened.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    assert_eq!(accounts[0].birthday, 2_500_000);
}
