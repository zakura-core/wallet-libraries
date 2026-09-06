//! The sync session's lifecycle, which is where a wallet handle gets it wrong.
//!
//! Every test here corresponds to a defect that was present and is not any
//! more. They use an address nothing is listening on, so the engine fails to
//! connect and the thread finishes almost immediately — which is exactly the
//! shape that made the original defects invisible.

use zakura_wallet_facade::{ErrorCode, NetworkKind, Wallet, WalletConfig, mnemonic};

/// Waits for `condition`, rather than sleeping a fixed time.
///
/// How long a failed connection takes to give up is the transport's business
/// and changes with it, so a fixed sleep makes these tests fail for reasons
/// that have nothing to do with what they check.
fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn open() -> (tempfile::TempDir, Wallet) {
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig::in_dir(NetworkKind::Test, dir.path(), "https://127.0.0.1:1/");
    let wallet = Wallet::open(config).unwrap();
    (dir, wallet)
}

fn account(wallet: &Wallet) -> u32 {
    let seed = mnemonic::to_seed(&mnemonic::generate(), "").unwrap();
    wallet.create_account(&seed, 0, 3_000_000).unwrap()
}

/// A sync ends by itself as soon as there is nothing left to scan, which in
/// ordinary use is most of the time. If the session outlived the thread, the
/// wallet could sync exactly once and then refuse forever.
#[test]
fn a_finished_sync_can_be_started_again() {
    let (_dir, wallet) = open();
    account(&wallet);

    wallet.start_sync().unwrap();
    wait_until("the sync to end", || !wallet.is_syncing());

    wallet.start_sync().expect("a second sync is allowed");
}

/// The engine owns the writing handle while it runs. A wallet that could not be
/// paid into or spent from while catching up would be useless, because catching
/// up is the normal state.
#[test]
fn the_wallet_can_be_written_to_while_syncing() {
    let (_dir, wallet) = open();
    let id = account(&wallet);
    wallet.start_sync().unwrap();

    let first = wallet.next_address(id, None).expect("an address is issued");
    let second = wallet.next_address(id, None).expect("and another");
    assert_ne!(first, second);
}

/// Creating an account during a sync must not leave the scanner blind to it:
/// restarting rebuilds the key set.
#[test]
fn an_account_created_during_a_sync_is_recorded() {
    let (_dir, wallet) = open();
    account(&wallet);
    wallet.start_sync().unwrap();

    let second = account(&wallet);
    let accounts = wallet.accounts().unwrap();
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().any(|a| a.id == second));
}

/// An unreachable server leaves the engine stopped with nothing queued, which
/// is exactly what having caught up looks like. Telling somebody their wallet
/// is up to date when it has not spoken to a server is a lie about their money.
#[test]
fn an_unreachable_server_is_reported_as_a_failure() {
    let (_dir, wallet) = open();
    account(&wallet);

    wallet.start_sync().unwrap();
    wait_until("the failure to be reported", || wallet.progress().failed);

    assert!(
        wallet.sync_failure().is_some_and(|e| e.contains("127.0.0.1")),
        "the reason names no server"
    );
}

/// And starting again clears it, so a recovered server does not leave a stale
/// warning on screen.
#[test]
fn starting_again_clears_the_previous_failure() {
    let (_dir, wallet) = open();
    account(&wallet);

    wallet.start_sync().unwrap();
    wait_until("the failure to be recorded", || {
        wallet.sync_failure().is_some()
    });

    wait_until("the sync to end", || !wallet.is_syncing());
    wallet.start_sync().unwrap();
    assert!(wallet.sync_failure().is_none(), "the failure was not cleared");
}

/// Stopping is idempotent, so an interface can call it on the way out without
/// checking first.
#[test]
fn stopping_is_safe_at_any_point() {
    let (_dir, wallet) = open();
    account(&wallet);

    wallet.stop_sync();
    wallet.start_sync().unwrap();
    wallet.stop_sync();
    wallet.stop_sync();
    assert!(!wallet.is_syncing());
}

/// Two syncs at once would mean two engines owning one database.
#[test]
fn a_second_sync_is_refused_while_the_first_runs() {
    let (_dir, wallet) = open();
    account(&wallet);

    wallet.start_sync().unwrap();
    let code = wallet.start_sync().err().map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::AlreadySyncing));
}

/// The engine owns the database while it runs, and it carries debug assertions
/// about what a server is allowed to return. One firing takes the database down
/// with it — and if the thread simply died, the wallet would be left with no
/// writing handle at all, refusing every write as though a sync were still
/// going, forever. That is not hypothetical: it happened against mainnet.
///
/// Driven here by a source whose connection cannot be made, which ends the
/// thread on an unusual path; the guard that puts the wallet back is the same
/// one a panic unwinds through.
#[test]
fn a_sync_that_dies_leaves_a_usable_wallet() {
    let (_dir, wallet) = open();
    let id = account(&wallet);

    wallet.start_sync().unwrap();
    wait_until("the sync to end", || !wallet.is_syncing());

    // The wallet still works: it can be written to, read from, and synced
    // again. Any of these hanging or refusing would mean it had been wedged.
    wallet.next_address(id, None).expect("it can still issue an address");
    wallet.balance(id).expect("it can still be read");
    wallet.accounts().expect("its accounts are still there");
    wallet.start_sync().expect("and it can sync again");
}

/// And a wallet whose sync ended badly says so, rather than showing a sync that
/// is starting and never will.
#[test]
fn a_sync_that_dies_is_reported_rather_than_left_starting() {
    let (_dir, wallet) = open();
    account(&wallet);

    wallet.start_sync().unwrap();
    wait_until("the failure to be reported", || wallet.progress().failed);

    let progress = wallet.progress();
    assert!(!progress.is_running(), "it must not look like it is still going");
    assert!(wallet.sync_failure().is_some());
}
