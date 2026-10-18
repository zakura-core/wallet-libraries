//! Transaction facts recovered with owned-script activity; these grant no financial authority.
use zcash_protocol::value::Zatoshis;

pub use zakura_transparent_recovery_types::{TransactionMetadata, WholeTransactionFee};

/// A source-bound observation; the application still chooses and qualifies its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataProvenance {
    /// The qualified source identifier.
    pub source: Vec<u8>,
    /// The exact revision identifier.
    pub revision: Vec<u8>,
    /// The revision's replacement order.
    pub lineage: u64,
}

/// Metadata supported by current, qualified recovery evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionMetadataEvidence {
    /// The agreed transaction assertions.
    pub metadata: TransactionMetadata,
    /// Each retained source/revision that independently contributes this assertion.
    pub provenance: Vec<MetadataProvenance>,
}

/// Aggregate payments preserve local intent and distinguish exact amounts from partial records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregatePayment {
    /// The amount sent outside the selected account is fully accounted for.
    Exact(Zatoshis),
    /// Some external payment records are known; additional payments may be missing.
    Partial(Zatoshis),
    /// Evidence cannot establish an aggregate amount.
    Unknown,
}

/// Recovered account movement; completeness is separate from its known arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountMovement {
    /// Known received value across supported pools, including change.
    pub received: u64,
    /// Known spent value across supported pools.
    pub spent: u64,
    /// Whether every owned effect and input value is established.
    pub complete: bool,
}

impl AccountMovement {
    /// Known received value minus known spent value; partial movement remains partial.
    pub fn net(self) -> i128 {
        i128::from(self.received) - i128::from(self.spent)
    }
}
