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
#[derive(Debug, Clone)]
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
    /// Completeness read in the same database snapshot as the amounts.
    pub coverage: ApiTransparentCoverage,
}

/// How far the private transparent ledger has read.
///
/// The interface needs this beside the balance, not instead of it. A
/// transparent balance is true as of a height, and a wallet that has not read
/// as far as the tip is not the same as one that read the whole chain and found
/// nothing — but they show the same number.
#[derive(Debug, Clone)]
pub struct ApiTransparentCoverage {
    /// The last height covered by sealed shards alone.
    ///
    /// Absent when nothing has been read: no transparent service is
    /// configured, or the wallet has not scanned down to the covered range.
    /// Absent is not zero, and must not be presented as though it were.
    pub settled_through: Option<u32>,
    /// The last height covered, including a shard that can still be replaced.
    pub covered_through: Option<u32>,
    /// Spends the ledger could not resolve to an output it holds.
    ///
    /// Non-zero means the balance is too high: an output is still counted that
    /// something has already consumed. The interface must not call the balance
    /// synchronized while this is set, however current the coverage looks.
    pub unresolved_spends: u32,
    /// How many unsealed shard revisions the coverage rests on.
    pub provisional_shards: u32,
    /// Page retrievals the ledger still owes from a sync that stopped short.
    ///
    /// Non-zero means the coverage describes what has been read so far, and
    /// the next sync continues it.
    pub pending_pages: u32,
    /// The height the ledger last accepted as the end of complete coverage.
    pub anchor_height: Option<u32>,
    /// Why the last sync stopped: `complete`, or the reason it stopped short
    /// (`query-budget`, `byte-budget`, `pending-limit`, `overloaded:<shard>`,
    /// `chain-unknown:<height>`, `discovery-unbounded`). Absent before any
    /// sync. The interface may call the transparent balance synchronized only
    /// when this is `complete` and `unresolved_spends` is zero.
    pub completion: Option<String>,
    /// Scripts of the account the private tables cannot index.
    ///
    /// Their history is outside what this path recovers, and nothing else
    /// recovers it. Non-zero means the wallet holds addresses it cannot ask
    /// about, and the interface must say so rather than show their absence
    /// as an empty history.
    pub outside_coverage: u32,
}

/// One transparent output the ledger holds.
#[derive(Debug, Clone)]
pub struct ApiTransparentUtxo {
    /// The address it pays.
    pub address: String,
    /// Its value in zatoshis.
    pub value: u64,
    /// The height it was mined at, where the ledger knows one.
    ///
    /// Absent for an output the ledger only ever saw spent: a recovered spend
    /// carries what it consumed but not the height that was created at.
    pub mined_height: Option<u32>,
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
    /// Value this transaction paid out to transparent addresses.
    ///
    /// Read from the transaction's own bytes. The wallet's side says only that
    /// value left a pool, not whether it went somewhere public.
    pub paid_to_transparent: u64,
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

/// What this native build is.
#[derive(Debug, Clone)]
pub struct ApiBuildInfo {
    /// Whether the build can send. A recovery build cannot, and says so here
    /// rather than only when asked to send.
    pub send_enabled: bool,
    /// The transparent protocol schema this build reads.
    pub transparent_schema: String,
    /// The derived database layout this build writes.
    pub layout_version: u32,
}

/// What a lightwalletd server says it is.
#[derive(Debug, Clone)]
pub struct ApiNetworkIdentity {
    /// `main` or `test`, as the server names its chain.
    pub chain_name: String,
    /// Where Sapling activated on that chain.
    pub sapling_activation_height: u64,
    /// The consensus branch the server is on, in its own encoding.
    pub consensus_branch_id: String,
    /// The latest block the server holds.
    pub block_height: u64,
    /// The server software.
    pub vendor: String,
    /// Its version.
    pub version: String,
}
