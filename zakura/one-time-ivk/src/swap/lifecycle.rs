//! Provider observations for local quote ownership and receipt obligations.

use zcash_protocol::{TxId, value::Zatoshis};

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

/// Provider outcome normalized by direction. It describes obligations but never
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The direction-specific outcome.
    pub status: OperationStatus,
    /// Whether the provider has seen a deposit.
    pub funded: bool,
    /// Zcash transactions the provider reports as this operation's payouts or refunds.
    /// Only a recovered note in one of these attributes a receipt to the operation. The
    /// wallet still authenticates the note itself.
    pub receipts: Vec<TxId>,
}
