//! Shared completion policy for keys that receive swap payouts and refunds. Wallet
//! storage owns canonical-chain validation, receipt attribution, and atomic
//! persistence of this state with scanning. A provider adapter, such as
//! `zakura-near-intents`, normalizes provider responses into [`Observation`].

use zcash_protocol::value::Zatoshis;

/// Seconds a restored wallet keeps scanning a key that discovery found in a provider's
/// recent set, after the publication it was found in, for a payout or refund from a
/// swap in flight at restore. Like [`COMPLETION_LIMIT_SECS`], a
/// wallet convention, not a consensus parameter.
pub const RESTORE_WATCH_SECS: i64 = 24 * 60 * 60;

/// Seconds after the quote deadline, or after registration for a key without
/// operations, after which an incoming key stops scanning whatever the provider reports.
pub const COMPLETION_LIMIT_SECS: i64 = 30 * 24 * 60 * 60;

/// Seconds after a refund operation's deposit deadline after which the wallet stops
/// trial-decrypting with its refund key whatever the provider reports, by the device
/// clock and before scanning any backlog. A later refund is found through the receiver
/// directory instead. Like [`COMPLETION_LIMIT_SECS`], a wallet convention.
pub const REFUND_WATCH_SECS: i64 = 24 * 60 * 60;

/// The route adapter's interpretation of the expected Zcash receipt.
/// Incoming source-chain refunds must not be interpreted as Zcash refunds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptExpectation {
    /// The supported route explicitly establishes that no Zcash receipt is expected.
    None,
    /// A positive receipt is expected. `None` means its amount is unavailable.
    Positive(Option<Zatoshis>),
    /// Receipt details are missing, malformed, or otherwise inconclusive.
    Unknown,
}

/// Provider outcome normalized by direction. It schedules scanning but never
/// establishes ownership, inclusion, or an on-chain amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    /// The provider is waiting for a deposit it has not seen.
    AwaitingDeposit,
    /// The provider has a deposit and the operation is in progress.
    Active,
    /// The provider reports completion with the route's receipt expectation.
    Terminal(ReceiptExpectation),
}

/// A normalized provider observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The direction-specific outcome.
    pub status: OperationStatus,
    /// Whether the provider has seen a deposit.
    pub funded: bool,
}
