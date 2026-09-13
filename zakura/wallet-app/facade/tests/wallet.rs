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

/// The window is consumed by scanning, not by issuing, so it is topped up as a
/// sync starts. A window that runs out is a silent failure: the scanner keeps
/// matching the addresses it knows and never sees a payment to one it does not.
#[test]
fn starting_a_sync_keeps_the_watch_window_full() {
    let (_dir, wallet) = open();
    wallet.create_account(&seed(), 0, 3_000_000).unwrap();
    let before = wallet.watched_transparent_addresses().unwrap();
    assert!(before > 0);

    wallet.start_sync().unwrap();
    wallet.stop_sync();

    assert!(
        wallet.watched_transparent_addresses().unwrap() >= before,
        "the window shrank"
    );
}

/// Issuing a unified address does not consume the transparent window, and must
/// not quietly change it either.
#[test]
fn issuing_a_unified_address_leaves_the_window_alone() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();
    let before = wallet.watched_transparent_addresses().unwrap();

    for _ in 0..5 {
        wallet.next_address(id, None).unwrap();
    }

    assert_eq!(wallet.watched_transparent_addresses().unwrap(), before);
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

/// A payment of nothing is not a payment, and letting one through would hand
/// the builder a proposal with no outputs worth making.
#[test]
fn a_payment_of_nothing_is_refused() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let quoted = wallet.quote(id, "u1whatever", 0).err().map(|e| e.code());
    assert_eq!(quoted, Some(ErrorCode::Build));

    let sent = wallet
        .send(id, "u1whatever", 0, &seed())
        .err()
        .map(|e| e.code());
    assert_eq!(sent, Some(ErrorCode::Build));
}

/// An address the wallet cannot pay is refused before any work is done, and is
/// told apart from a typo: they are different problems for whoever typed it.
#[test]
fn an_unpayable_address_is_refused_before_anything_expensive() {
    let (_dir, wallet) = open();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    let code = wallet
        .quote(id, "not an address at all", 100_000)
        .err()
        .map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::BadAddress));
}

/// Forgetting a wallet leaves nothing on disk, and the next open is empty.
#[test]
fn destroy_removes_the_wallet_and_a_reopen_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir.path(),
        "https://testnet.example.invalid:443",
    );

    {
        let wallet = Wallet::open(config.clone()).unwrap();
        wallet.create_account(&seed(), 0, 3_000_000).unwrap();
    }

    zakura_wallet_facade::destroy(&config).unwrap();

    for name in ["wallet.db", "cache.db"] {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.path().join(format!("{name}{suffix}"));
            assert!(!path.exists(), "{} survived", path.display());
        }
    }

    let reopened = Wallet::open(config).unwrap();
    assert!(reopened.accounts().unwrap().is_empty());
}

/// A wallet that was never created, or was already forgotten, is fine to
/// forget again.
#[test]
fn destroy_of_a_wallet_that_is_not_there_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir.path(),
        "https://testnet.example.invalid:443",
    );

    zakura_wallet_facade::destroy(&config).unwrap();
    zakura_wallet_facade::destroy(&config).unwrap();
}

/// The re-import guarantee: a forgotten wallet is not "already here".
#[test]
fn a_forgotten_wallet_accepts_the_same_seed_again() {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir.path(),
        "https://testnet.example.invalid:443",
    );
    let seed = seed();

    {
        let wallet = Wallet::open(config.clone()).unwrap();
        wallet.import_wallet(&seed, Some(3_000_000)).unwrap();
        assert_eq!(
            wallet
                .import_wallet(&seed, Some(3_000_000))
                .unwrap_err()
                .code(),
            ErrorCode::AccountExists,
            "the second import of a live wallet is refused"
        );
    }

    zakura_wallet_facade::destroy(&config).unwrap();

    let reopened = Wallet::open(config).unwrap();
    reopened.import_wallet(&seed, Some(3_000_000)).unwrap();
    assert_eq!(reopened.accounts().unwrap().len(), 1);
}

// ------------------------------------------------- recovery-only (M2)

fn recovery_config(dir: &std::path::Path) -> WalletConfig {
    let mut config = WalletConfig::in_dir(
        NetworkKind::Test,
        dir,
        "https://testnet.example.invalid:443",
    );
    config.recovery_only = true;
    config.transparent = Some(zakura_wallet_facade::TransparentEndpoints::new(
        "https://filters.example.invalid",
        "https://shards.example.invalid",
    ));
    config
}

/// A recovery-only wallet refuses to send before it looks at anything it was
/// given: not the address, not the amount, and not the seed.
#[test]
fn a_recovery_only_wallet_cannot_send_or_quote() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::open(recovery_config(dir.path())).unwrap();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();

    // An address that would otherwise be refused as unreadable, and an amount
    // that would otherwise be refused as nothing: neither is reached.
    let quoted = wallet
        .quote(id, "not an address", 0)
        .err()
        .map(|e| e.code());
    assert_eq!(quoted, Some(ErrorCode::SendDisabled));
    let sent = wallet
        .send(id, "not an address", 0, &seed())
        .err()
        .map(|e| e.code());
    assert_eq!(sent, Some(ErrorCode::SendDisabled));
    assert_eq!(ErrorCode::SendDisabled.as_u32(), 20);

    // Everything a recovery needs still works.
    assert_eq!(wallet.accounts().unwrap().len(), 1);
    assert_eq!(wallet.balance(id).unwrap().total(), 0);
    assert!(wallet.history(id, 10).unwrap().is_empty());
    let (_, coverage) = wallet.balance_with_coverage(id).unwrap();
    assert_eq!(coverage.covered_through, None, "nothing read, and not zero");
}

/// A recovery with no transparent services would recover a transparent
/// balance of nothing and call it recovered. It is refused at open, and
/// leaves no files behind to be found by the next attempt.
#[test]
fn a_recovery_only_wallet_needs_both_transparent_services() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = recovery_config(dir.path());
    config.transparent = None;
    let error = Wallet::open(config).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::Configuration);
    assert_eq!(ErrorCode::Configuration.as_u32(), 21);
    assert!(
        error.to_string().contains("not an empty history"),
        "{error}"
    );
    assert!(!dir.path().join("wallet.db").exists(), "a file was created");
    assert!(!dir.path().join("cache.db").exists());
}

/// One host serving both halves could join the public filter reads to the
/// private queries; a recovery does not run that way.
#[test]
fn a_recovery_only_wallet_refuses_one_host_for_both_services() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = recovery_config(dir.path());
    config.transparent = Some(zakura_wallet_facade::TransparentEndpoints::new(
        "https://one.example.invalid/filters",
        "https://one.example.invalid/shards",
    ));
    let error = Wallet::open(config).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::Configuration);
    assert!(error.to_string().contains("one host"), "{error}");
}

/// A private query over plaintext is not private, and a light server over
/// plaintext hands the wallet's whole scan to the path.
#[test]
fn a_recovery_only_wallet_refuses_plaintext_services() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = recovery_config(dir.path());
    config.transparent = Some(zakura_wallet_facade::TransparentEndpoints::new(
        "http://filters.example.invalid",
        "https://shards.example.invalid",
    ));
    let error = Wallet::open(config).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::Configuration);
    assert!(error.to_string().contains("TLS"), "{error}");

    let mut config = recovery_config(dir.path());
    config.lightwalletd_url = "http://lwd.example.invalid:9067".to_owned();
    let error = Wallet::open(config).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::Configuration);
}

/// The same configuration with recovery off is the library's ordinary one,
/// and nothing about it is refused: the requirements belong to the mode.
#[test]
fn an_ordinary_wallet_is_not_held_to_the_recovery_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = recovery_config(dir.path());
    config.recovery_only = false;
    config.transparent = None;
    let wallet = Wallet::open(config).unwrap();
    let id = wallet.create_account(&seed(), 0, 3_000_000).unwrap();
    assert_ne!(
        wallet
            .quote(id, "not an address", 1)
            .err()
            .map(|e| e.code()),
        Some(ErrorCode::SendDisabled)
    );
}

/// A wallet another build wrote is refused with the remedy and left alone.
#[test]
fn an_unsupported_layout_is_refused_and_left_as_found() {
    let dir = tempfile::tempdir().unwrap();
    let config = recovery_config(dir.path());
    let wallet = Wallet::open(config.clone()).unwrap();
    wallet.create_account(&seed(), 0, 3_000_000).unwrap();
    drop(wallet);
    {
        let conn = rusqlite::Connection::open(dir.path().join("wallet.db")).unwrap();
        conn.execute(
            "UPDATE wallet_meta SET value = 3 WHERE key = 'layout_version'",
            [],
        )
        .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
    }
    let before = std::fs::read(dir.path().join("wallet.db")).unwrap();
    let error = Wallet::open(config).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::VersionMismatch);
    assert!(error.to_string().contains("rebuild"), "{error}");
    assert_eq!(std::fs::read(dir.path().join("wallet.db")).unwrap(), before);
}

/// The chain a server names is compared with the one the wallet is on.
#[test]
fn a_server_is_judged_by_the_chain_it_names() {
    let identity = zakura_wallet_facade::NetworkIdentity {
        chain_name: "main".into(),
        sapling_activation_height: 419_200,
        consensus_branch_id: "c8e71055".into(),
        block_height: 3_477_098,
        vendor: "test".into(),
        version: "0".into(),
    };
    assert!(identity.serves(NetworkKind::Main));
    assert!(!identity.serves(NetworkKind::Test));
}

// ------------------------------------------------- interrupted runs (M3)

/// A wallet whose process died in the middle of a transparent run opens
/// saying so. The run's own bookkeeping cannot: it writes its reason on the
/// way out, and a killed process has no way out.
#[test]
fn a_wallet_left_mid_sync_opens_as_interrupted_not_in_progress() {
    let dir = tempfile::tempdir().unwrap();
    let config = recovery_config(dir.path());
    let wallet = Wallet::open(config.clone()).unwrap();
    let account = wallet.create_account(&seed(), 0, 2_000_000).unwrap();
    drop(wallet);

    // What a run leaves behind when it is killed between two requests.
    {
        let mut db =
            zakura_wallet_store::WalletDb::open(&config.wallet_path, &config.cache_path).unwrap();
        db.put_transparent_completion("sync-in-progress").unwrap();
    }
    let wallet = Wallet::open(config.clone()).unwrap();
    let coverage = wallet.transparent_coverage(account).unwrap();
    assert_eq!(coverage.completion.as_deref(), Some("interrupted"));
    let (_, from_balance) = wallet.balance_with_coverage(account).unwrap();
    assert_eq!(from_balance.completion.as_deref(), Some("interrupted"));
    assert_eq!(coverage.anchor_height, None);
    assert_eq!(coverage.covered_through, None);
    drop(wallet);

    // Any other word is the run's own, and stays.
    {
        let mut db =
            zakura_wallet_store::WalletDb::open(&config.wallet_path, &config.cache_path).unwrap();
        db.put_transparent_completion("query-budget").unwrap();
    }
    let wallet = Wallet::open(config).unwrap();
    assert_eq!(
        wallet
            .transparent_coverage(account)
            .unwrap()
            .completion
            .as_deref(),
        Some("query-budget")
    );
}
