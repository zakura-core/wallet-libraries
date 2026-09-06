//! The values that cross the boundary.
//!
//! Deliberately a separate set from the facade's own, even where the shapes
//! match. Everything here is plain data with no methods, no lifetimes and no
//! types from the wallet crates, because the code generator has to be able to
//! mirror it into Dart — and because a type the generator can see is a type
//! that cannot be changed without changing the application.

/// Why something could not be done.
///
/// Carries the facade's stable numeric code alongside the message. The code is
/// what an application branches on; the message is for a log. Returning only a
/// message — which is what the wallet this replaces does — makes control flow
/// depend on wording, and wording changes.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// The stable code. See `zakura_wallet_facade::ErrorCode`.
    pub code: u32,
    /// What happened, for a human reading a log.
    pub message: String,
}

impl From<zakura_wallet_facade::Error> for ApiError {
    fn from(e: zakura_wallet_facade::Error) -> Self {
        Self {
            code: e.code().as_u32(),
            message: e.to_string(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for ApiError {}

/// What an account is worth, in zatoshis.
#[derive(Debug, Clone, Copy)]
pub struct ApiBalance {
    /// Received, unspent, and settled: what can be sent right now.
    pub spendable: u64,
    /// Received and unspent, but not yet settled.
    pub pending: u64,
    /// Committed by a transaction that has not been mined.
    pub spent_unconfirmed: u64,
    /// Value held on transparent addresses.
    ///
    /// Kept apart from `spendable` because it cannot be sent directly:
    /// transparent funds have to be shielded first.
    pub transparent: u64,
}

/// An account the wallet holds.
#[derive(Debug, Clone)]
pub struct ApiAccount {
    /// The wallet-local identifier.
    pub id: u32,
    /// The height below which this account has no history.
    pub birthday: u32,
    /// Whether the wallet can spend, or only watch.
    pub can_spend: bool,
    /// The ZIP 32 account index, for accounts derived from a seed.
    pub hd_account_index: Option<u32>,
}

/// Value, by where in the protocol it sat.
#[derive(Debug, Clone, Copy)]
pub struct ApiPoolAmounts {
    /// Value in the Orchard pool.
    pub orchard: u64,
    /// Value in the Ironwood pool.
    pub ironwood: u64,
    /// Value on transparent addresses, which is to say in public.
    pub transparent: u64,
}

/// One transaction, as it affected the wallet.
#[derive(Debug, Clone)]
pub struct ApiHistoryEntry {
    /// The transaction's identifier, in protocol byte order.
    pub txid: Vec<u8>,
    /// The height it was mined at, or absent while it is unmined.
    pub mined_height: Option<u32>,
    /// What the wallet received.
    pub received: u64,
    /// What the wallet spent.
    pub spent: u64,
    /// Whether everything received was change.
    pub is_change_only: bool,
    /// What the wallet received, by where it landed.
    pub received_by_pool: ApiPoolAmounts,
    /// What the wallet spent, by where it came from.
    pub spent_by_pool: ApiPoolAmounts,
}

/// What the engine is doing.
#[derive(Debug, Clone, Copy)]
pub enum ApiSyncPhase {
    /// Nothing has been scanned yet.
    Bootstrapping,
    /// Working backwards through history.
    Recovering,
    /// Following the chain tip.
    Tracking,
    /// Nothing left to scan right now — which is not the same as finished.
    Idle,
    /// Not running.
    Stopped,
}

/// How far synchronisation has got.
#[derive(Debug, Clone, Copy)]
pub struct ApiSyncProgress {
    /// What the engine is doing.
    pub phase: ApiSyncPhase,
    /// Commitment coverage between 0 and 1, if there is anything to measure.
    pub fraction: Option<f64>,
    /// The highest block the server reported.
    pub tip: Option<u32>,
    /// The highest block the wallet has scanned.
    pub scanned_to: Option<u32>,
    /// How many blocks remain queued.
    pub blocks_remaining: u64,
    /// Whether the last attempt ended in a failure rather than a finish.
    ///
    /// An unreachable server leaves the engine stopped with nothing queued,
    /// which is what having caught up looks like too. Without this an interface
    /// cannot tell them apart, and would say a wallet is up to date when it has
    /// not spoken to a server.
    pub failed: bool,
}

/// What a payment would cost.
#[derive(Debug, Clone, Copy)]
pub struct ApiSpendQuote {
    /// What the recipient receives.
    pub amount: u64,
    /// The fee.
    pub fee: u64,
    /// What comes back to the wallet.
    pub change: u64,
    /// How many notes would be spent, and so how many proofs.
    pub inputs: u32,
    /// Whether this payment leaves the Orchard pool as a ZIP 318 crossing.
    ///
    /// A crossing pays a fixed denomination for a fixed fee, so its numbers are
    /// not negotiable the way an ordinary payment's are.
    pub crossing: bool,
}

/// What came back from broadcasting.
#[derive(Debug, Clone)]
pub struct ApiSendReceipt {
    /// The transaction's identifier.
    pub txid: Vec<u8>,
    /// What the server said. Acceptance means it reached the network, not that
    /// it will be mined.
    pub server_response: String,
    /// Set when the payment was sent but the wallet could not record it.
    ///
    /// Not a failure of the send — the money is gone either way — but the
    /// balance will not account for it until the next scan finds it.
    pub warning: Option<String>,
}
