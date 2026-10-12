//! Shared completion policy for keys that receive swap payouts and refunds. Wallet
//! storage owns canonical-chain validation, receipt attribution, and atomic
//! persistence of this state with scanning. Provider-specific status parsing
//! belongs to the app, which normalizes responses into [`Observation`].

use zcash_protocol::value::Zatoshis;

/// Seconds a key found only by a restore sweep keeps scanning, for a payout or
/// refund from a swap in flight at restore. Like [`COMPLETION_LIMIT_SECS`], a
/// wallet convention, not a consensus parameter.
pub const RESTORE_WATCH_SECS: i64 = 24 * 60 * 60;

/// Seconds after the quote deadline, or after registration when no deadline is
/// known, after which a key stops scanning whatever the provider reports.
pub const COMPLETION_LIMIT_SECS: i64 = 30 * 24 * 60 * 60;

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

/// A normalized provider observation and the deadline that bounds scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The direction-specific outcome.
    pub status: OperationStatus,
    /// The quote deadline, if the response carried one.
    pub deadline: Option<i64>,
}
