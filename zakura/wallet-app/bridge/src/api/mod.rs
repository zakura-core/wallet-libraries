//! The functions Dart calls.
//!
//! One open wallet per process, held in a global. An opaque handle passed back
//! and forth would be tidier, but a wallet is a process-wide thing — it owns
//! two database files and a thread — and pretending otherwise invites a second
//! one to be opened over the same files.
//!
//! Every function returns `Result<_, ApiError>` so a failure crosses as a code
//! and a message rather than as a panic. Panicking across a foreign-function
//! boundary is undefined behaviour in the general case and an unhelpful crash
//! in the best case.

pub mod types;

use std::sync::{Arc, RwLock};

use zakura_wallet_facade::{
    NetworkKind, Wallet, WalletConfig,
    mnemonic::{self},
};

use types::{
    ApiAccount, ApiBalance, ApiError, ApiHistoryEntry, ApiPoolAmounts, ApiSendReceipt, ApiSpendQuote,
    ApiSyncPhase, ApiSyncProgress,
};

/// The open wallet.
static WALLET: RwLock<Option<Arc<Wallet>>> = RwLock::new(None);

/// Returns the open wallet, or an error naming the fact that there is none.
fn wallet() -> Result<Arc<Wallet>, ApiError> {
    WALLET
        .read()
        .expect("the wallet lock is never poisoned")
        .clone()
        .ok_or_else(|| ApiError {
            // `Storage`, because from the application's side an unopened wallet
            // is the same class of problem as one that could not be read.
            code: 1,
            message: "no wallet is open".to_owned(),
        })
}

/// Generates a new seed phrase.
///
/// The phrase is the wallet. Whatever receives it is responsible for showing it
/// once and then storing it where the operating system protects it — this
/// library does not store it, by design.
pub fn generate_mnemonic() -> String {
    mnemonic::generate().to_string()
}

/// Returns whether a phrase is a valid mnemonic.
pub fn validate_mnemonic(phrase: String) -> bool {
    mnemonic::validate(&phrase)
}

/// Opens or creates the wallet in `directory`.
///
/// Replaces any wallet already open, stopping its sync first.
pub fn open(
    directory: String,
    lightwalletd_url: String,
    mainnet: bool,
) -> Result<(), ApiError> {
    let config = WalletConfig::in_dir(
        if mainnet {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        },
        std::path::Path::new(&directory),
        lightwalletd_url,
    );

    let opened = Wallet::open(config)?;
    let mut guard = WALLET.write().expect("the wallet lock is never poisoned");
    // Dropping the old one stops its sync thread, which holds the database
    // files the new one is about to open.
    *guard = None;
    *guard = Some(Arc::new(opened));
    Ok(())
}

/// Creates a new wallet from a seed phrase, and returns its account.
///
/// For a wallet that has never existed before. Its birthday is the current
/// chain tip, because an account created now cannot have been paid earlier —
/// so there is nothing below the tip worth scanning. If the server cannot be
/// reached the earliest possible height is used instead: slower, and never
/// wrong in the direction that loses money.
///
/// The seed is derived, used and dropped. Only the viewing key is stored, so
/// the ability to spend never sits in the same file as the ability to see —
/// which is also why the phrase has to be supplied again to send.
pub fn create_account(phrase: String, birthday: Option<u32>) -> Result<u32, ApiError> {
    let wallet = wallet()?;
    let seed = mnemonic::to_seed(&phrase, "")?;
    match birthday {
        Some(height) => Ok(wallet.create_account(&seed, 0, height)?),
        None => Ok(wallet.create_wallet(&seed)?),
    }
}

/// Restores an existing wallet from its seed phrase.
///
/// `birthday` is the height below which the wallet is known to have no history.
/// Leaving it unset means "not known", and scans from [`earliest_birthday`]
/// rather than guessing: a guess that is too high skips the blocks the money
/// arrived in, and the wallet then shows a balance that is simply missing
/// funds, with nothing to say so.
///
/// Fails with the `AccountExists` code if this wallet is already here. Two
/// accounts sharing a viewing key would see the same notes and double every
/// balance.
pub fn import_account(phrase: String, birthday: Option<u32>) -> Result<u32, ApiError> {
    let wallet = wallet()?;
    let seed = mnemonic::to_seed(&phrase, "")?;
    Ok(wallet.import_wallet(&seed, birthday)?)
}

/// Imports a watch-only account from a unified full viewing key.
///
/// It can see everything and sign nothing. Sending from it is refused with the
/// `WatchOnly` code.
pub fn import_viewing_key(key: String, birthday: Option<u32>) -> Result<u32, ApiError> {
    Ok(wallet()?.import_viewing_key(&key, birthday)?)
}

/// Returns the earliest height an account on this network could have history
/// at.
///
/// What an unknown birthday falls back to, and what to offer somebody who does
/// not know theirs.
pub fn earliest_birthday() -> Result<u32, ApiError> {
    Ok(wallet()?.earliest_birthday())
}

/// Asks the server for the current chain tip.
///
/// Useful for showing somebody restoring what the range of sensible birthdays
/// is.
pub fn chain_tip() -> Result<u32, ApiError> {
    Ok(wallet()?.fetch_chain_tip()?)
}

/// Returns every account, in creation order.
pub fn accounts() -> Result<Vec<ApiAccount>, ApiError> {
    Ok(wallet()?
        .accounts()?
        .into_iter()
        .map(|a| ApiAccount {
            id: a.id,
            birthday: a.birthday,
            can_spend: a.can_spend,
            hd_account_index: a.hd_account_index,
        })
        .collect())
}

/// Returns an account's balance across every shielded pool.
///
/// Transparent value is not included: this build cannot spend it, and a balance
/// the wallet cannot back is worse than no balance.
pub fn balance(account: u32) -> Result<ApiBalance, ApiError> {
    let b = wallet()?.balance(account)?;
    Ok(ApiBalance {
        spendable: b.spendable,
        pending: b.pending,
        spent_unconfirmed: b.spent_unconfirmed,
        transparent: b.transparent,
    })
}

/// Returns an account's transactions, most recent first.
pub fn history(account: u32, limit: u32) -> Result<Vec<ApiHistoryEntry>, ApiError> {
    Ok(wallet()?
        .history(account, limit as usize)?
        .into_iter()
        .map(|e| {
            let pools = |a: zakura_wallet_facade::PoolAmounts| ApiPoolAmounts {
                orchard: a.orchard,
                ironwood: a.ironwood,
                transparent: a.transparent,
            };
            ApiHistoryEntry {
                txid: e.txid.to_vec(),
                mined_height: e.mined_height,
                received: e.received,
                spent: e.spent,
                is_change_only: e.is_change_only,
                received_by_pool: pools(e.received_by_pool),
                spent_by_pool: pools(e.spent_by_pool),
                paid_to_transparent: e.paid_to_transparent,
            }
        })
        .collect())
}

/// Issues the next unused receive address.
///
/// Two calls return two different addresses: reusing one lets anybody who has
/// seen it link the payments made to it.
pub fn next_address(account: u32) -> Result<String, ApiError> {
    Ok(wallet()?.next_address(account, None)?)
}

/// Starts synchronising, returning immediately.
pub fn start_sync() -> Result<(), ApiError> {
    Ok(wallet()?.start_sync()?)
}

/// Stops synchronising, waiting for the batch in flight to finish.
pub fn stop_sync() -> Result<(), ApiError> {
    wallet()?.stop_sync();
    Ok(())
}

/// Returns how far synchronisation has got.
///
/// A poll rather than a stream. The engine publishes progress on a lossy
/// channel by design, so a reader that falls behind should see the latest value
/// rather than a queue of stale ones, and a poll expresses that directly
/// instead of marshalling a callback back into another language's runtime.
pub fn progress() -> Result<ApiSyncProgress, ApiError> {
    let p = wallet()?.progress();
    Ok(ApiSyncProgress {
        phase: match p.phase {
            zakura_wallet_facade::SyncPhase::Bootstrapping => ApiSyncPhase::Bootstrapping,
            zakura_wallet_facade::SyncPhase::Recovering => ApiSyncPhase::Recovering,
            zakura_wallet_facade::SyncPhase::Tracking => ApiSyncPhase::Tracking,
            zakura_wallet_facade::SyncPhase::Idle => ApiSyncPhase::Idle,
            zakura_wallet_facade::SyncPhase::Stopped => ApiSyncPhase::Stopped,
        },
        fraction: p.fraction,
        tip: p.tip,
        scanned_to: p.scanned_to,
        blocks_remaining: p.blocks_remaining,
        failed: p.failed,
    })
}

/// Returns why the last sync stopped, if it stopped because of a failure.
///
/// Cleared when a new sync starts. The message is for a log or a details pane;
/// `ApiSyncProgress::failed` is what an interface branches on.
pub fn sync_failure() -> Result<Option<String>, ApiError> {
    Ok(wallet()?.sync_failure())
}

/// Works out what a payment would cost, without proving it.
pub fn quote(account: u32, to: String, amount: u64) -> Result<ApiSpendQuote, ApiError> {
    let q = wallet()?.quote(account, &to, amount)?;
    Ok(ApiSpendQuote {
        amount: q.amount,
        fee: q.fee,
        change: q.change,
        inputs: q.inputs as u32,
        crossing: q.crossing,
    })
}

/// Builds, proves, signs and broadcasts a payment.
///
/// Takes seconds. The code generator runs this on a worker rather than on the
/// interface thread, but whatever calls it should already be saying that
/// something is happening.
pub fn send(
    account: u32,
    to: String,
    amount: u64,
    phrase: String,
) -> Result<ApiSendReceipt, ApiError> {
    let wallet = wallet()?;
    let seed = mnemonic::to_seed(&phrase, "")?;
    let receipt = wallet.send(account, &to, amount, &seed)?;
    Ok(ApiSendReceipt {
        txid: receipt.txid.to_vec(),
        server_response: receipt.server_response,
        warning: receipt.warning,
    })
}

/// Closes the wallet, stopping any sync.
pub fn close() -> Result<(), ApiError> {
    let taken = WALLET
        .write()
        .expect("the wallet lock is never poisoned")
        .take();
    if let Some(wallet) = taken {
        wallet.stop_sync();
    }
    Ok(())
}
