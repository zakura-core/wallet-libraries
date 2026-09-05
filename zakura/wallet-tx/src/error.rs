//! Errors from proposing and building a transaction.

use std::fmt;

use zcash_protocol::value::Zatoshis;

/// A failure while proposing or building a transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The wallet does not hold enough spendable value.
    InsufficientFunds {
        /// What was spendable.
        available: Zatoshis,
        /// What the payment alone needed, before the fee.
        required: Zatoshis,
    },

    /// A note's witness could not be produced.
    ///
    /// Usually means the note's shard has not been fully scanned, so the note
    /// is held but not yet spendable. That is a wait, not a failure of the
    /// wallet, and it is why notes carry a stabilisation flag.
    NoWitness {
        /// The position whose witness was wanted.
        position: incrementalmerkletree::Position,
    },

    /// The wallet has no anchor to prove against.
    NoAnchor,

    /// Storage failed.
    Store(zakura_wallet_store::TreeError),

    /// The bundle builder rejected the transaction.
    Build(String),

    /// A payment was asked for from the Orchard pool to somebody else.
    ///
    /// From NU6.3 the Orchard pool prohibits cross-address transfers, so value
    /// leaves it only through a bundle's value balance and into an Ironwood
    /// bundle that makes the payment. An Orchard payment to a third party is
    /// therefore not a thing that can be built directly — it is a pool
    /// crossing, and has to be constructed as one.
    CrossingRequired,

    /// A crossing could not be made canonical.
    ///
    /// A crossing that is nearly the right shape is worse than none: the whole
    /// privacy argument is that every crossing looks like every other, so one
    /// that does not announces itself.
    NotCanonical(String),

    /// No single note can fund a crossing on its own.
    ///
    /// A crossing has exactly two source actions — one spend and its change —
    /// so it spends one note. A wallet whose notes are all too small has to
    /// consolidate first.
    NoSuitableNote {
        /// What one note would have had to cover.
        required: Zatoshis,
    },

    /// Summing values overflowed.
    ValueOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "the wallet holds {} zatoshis of spendable value, and the payment needs {} before fees",
                available.into_u64(),
                required.into_u64()
            ),
            Error::NoWitness { position } => write!(
                f,
                "no witness is available for the note at position {}; \
                 its commitment tree shard may not be fully scanned yet",
                u64::from(*position)
            ),
            Error::NoAnchor => f.write_str(
                "the wallet has no commitment tree checkpoint to anchor a transaction against",
            ),
            Error::Store(e) => write!(f, "{e}"),
            Error::Build(m) => write!(f, "the transaction could not be built: {m}"),
            Error::CrossingRequired => f.write_str(
                "paying somebody else from the Orchard pool requires a pool crossing: \
                 from NU6.3 the Orchard pool permits no cross-address transfers, so the \
                 payment has to be made by an Ironwood bundle funded through the \
                 Orchard bundle's value balance",
            ),
            Error::NotCanonical(m) => write!(f, "the crossing would not be canonical: {m}"),
            Error::NoSuitableNote { required } => write!(
                f,
                "no single Orchard note covers {} zatoshis; a crossing spends exactly one \
                 note, so the wallet needs to consolidate before it can cross",
                required.into_u64()
            ),
            Error::ValueOverflow => f.write_str("the values involved overflowed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<zakura_wallet_store::TreeError> for Error {
    fn from(e: zakura_wallet_store::TreeError) -> Self {
        Error::Store(e)
    }
}

impl From<zakura_wallet_store::Error> for Error {
    fn from(e: zakura_wallet_store::Error) -> Self {
        Error::Store(zakura_wallet_store::TreeError::Store(e))
    }
}
