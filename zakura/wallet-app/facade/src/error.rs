//! One error type, with codes that survive the crossing into another language.
//!
//! The core has six error enums between them, and `zakura_wallet_tx::Error`
//! ends in a `Build(String)` catch-all. None of that survives an FFI boundary
//! usefully: an application needs to branch on what went wrong, and a string it
//! has to pattern-match is a string that breaks the first time a message is
//! reworded. So every failure is flattened here into one enum with a stable
//! numeric code, and the message is for a log rather than for control flow.

use std::fmt;

/// A stable, machine-readable identifier for a failure.
///
/// The numbers are wire format: an application branches on them, so they may be
/// added to but never renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    /// The wallet database could not be opened, read or written.
    Storage = 1,
    /// The wallet's schema version does not match this build's.
    VersionMismatch = 2,
    /// The lightwalletd server could not be reached or misbehaved.
    Source = 3,
    /// The server rejected a broadcast transaction.
    Rejected = 4,
    /// Scanning found a chain that does not join up, and could not recover.
    Unrecoverable = 5,
    /// No account with that identifier exists.
    NoSuchAccount = 6,
    /// The seed does not derive the account it was given.
    ///
    /// Raised when the viewing key derived from a seed does not match the one
    /// stored for the account. It means the wrong seed was supplied, and
    /// proceeding would sign with a key that owns nothing.
    WrongSeed = 7,
    /// The account cannot spend, because the wallet holds only its viewing key.
    WatchOnly = 8,
    /// A seed phrase was not valid.
    BadMnemonic = 9,
    /// An address could not be parsed.
    BadAddress = 10,
    /// An address parsed, but carries no receiver this wallet can pay.
    UnsupportedAddress = 11,
    /// The account does not hold enough spendable value.
    InsufficientFunds = 12,
    /// The wallet has not scanned enough of the chain to build a spend.
    ///
    /// There is no block both pools' trees hold a checkpoint for, so no anchor
    /// exists to prove against. Syncing further resolves it.
    NoAnchor = 13,
    /// The payment would have to cross pools, and this build cannot do it
    /// canonically.
    ///
    /// See [`Error::CrossingUnavailable`].
    CrossingUnavailable = 14,
    /// Building, proving or signing the transaction failed.
    Build = 15,
    /// A sync is already running.
    AlreadySyncing = 16,
    /// The amount cannot leave the Orchard pool in one step.
    NotCanonicalDenomination = 17,
    /// The wallet already holds this account.
    AccountExists = 18,
    /// A unified full viewing key could not be read.
    BadViewingKey = 19,
    /// This wallet was opened to recover only, and cannot send.
    SendDisabled = 20,
    /// The wallet's configuration is one it refuses to run under.
    Configuration = 21,
}

impl ErrorCode {
    /// Returns the code as the integer an application branches on.
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Anything that can go wrong in the wallet.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The wallet database could not be opened, read or written.
    Storage(String),
    /// The wallet's schema version does not match this build's.
    ///
    /// Carries the remedy, which differs by which version disagreed: a cache
    /// rebuild costs a rescan, and is a decision with a visible cost on a
    /// phone, so it is never taken automatically.
    VersionMismatch(String),
    /// The lightwalletd server could not be reached or misbehaved.
    Source(String),
    /// The server rejected a broadcast transaction.
    ///
    /// The transport succeeded and the network refused the transaction, which
    /// is not the same as a failure to send and must not be reported as one.
    Rejected {
        /// The server's own error code.
        code: i32,
        /// What it said.
        message: String,
    },
    /// Scanning found a chain that does not join up, and could not recover.
    Unrecoverable(String),
    /// No account with that identifier exists.
    NoSuchAccount(u32),
    /// The seed does not derive the account it was given.
    WrongSeed,
    /// The account cannot spend, because the wallet holds only its viewing key.
    WatchOnly,
    /// A seed phrase was not valid.
    BadMnemonic(String),
    /// An address could not be parsed.
    BadAddress(String),
    /// An address parsed, but carries no receiver this wallet can pay.
    UnsupportedAddress,
    /// The account does not hold enough spendable value.
    InsufficientFunds {
        /// What is available to spend right now.
        available: u64,
        /// What the payment and its fee would need.
        required: u64,
    },
    /// The wallet has not scanned enough of the chain to build a spend.
    NoAnchor,
    /// The payment would have to cross pools, and this build cannot do it
    /// canonically.
    ///
    /// A payment funded from Orchard is necessarily a ZIP 318 crossing, and a
    /// crossing has a canonical shape it must be indistinguishable within. This
    /// build cannot produce that shape on a wallet that has scanned a chain:
    /// no anchor on the crossing grid is retained or selected. Rather than
    /// assemble a crossing ad hoc — which would work, and would be
    /// identifiable — the wallet refuses.
    CrossingUnavailable,
    /// Building, proving or signing the transaction failed.
    Build(String),
    /// A sync is already running.
    AlreadySyncing,
    /// The amount cannot leave the Orchard pool in one step.
    ///
    /// Value leaves Orchard only as a ZIP 318 crossing, and every crossing
    /// carries one of a fixed set of denominations so that they cannot be told
    /// apart. An arbitrary amount is not one of them. This is a property of the
    /// shape, not a limitation of this wallet: adjusting the amount to the
    /// nearest canonical one would send somebody a different sum than they
    /// asked for, and a crossing that is nearly the right shape stands out from
    /// the ones that are.
    NotCanonicalDenomination(String),
    /// The wallet already holds this account.
    ///
    /// Two accounts sharing an incoming viewing key would see the same notes,
    /// and every balance would be counted twice. Importing a phrase the wallet
    /// already has is a mistake worth naming rather than a second wallet.
    AccountExists,
    /// A unified full viewing key could not be read.
    BadViewingKey(String),
    /// This wallet was opened to recover only, and cannot send.
    ///
    /// Not a temporary state and not a missing key: the wallet was
    /// configured never to build or broadcast a transaction, and no argument
    /// to the send path changes that.
    SendDisabled,
    /// The wallet's configuration is one it refuses to run under.
    ///
    /// Carries what is wrong with it. Raised at open, before any file is
    /// created, so a misconfigured wallet leaves nothing behind.
    Configuration(String),
}

impl Error {
    /// Returns the stable code for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Storage(_) => ErrorCode::Storage,
            Error::VersionMismatch(_) => ErrorCode::VersionMismatch,
            Error::Source(_) => ErrorCode::Source,
            Error::Rejected { .. } => ErrorCode::Rejected,
            Error::Unrecoverable(_) => ErrorCode::Unrecoverable,
            Error::NoSuchAccount(_) => ErrorCode::NoSuchAccount,
            Error::WrongSeed => ErrorCode::WrongSeed,
            Error::WatchOnly => ErrorCode::WatchOnly,
            Error::BadMnemonic(_) => ErrorCode::BadMnemonic,
            Error::BadAddress(_) => ErrorCode::BadAddress,
            Error::UnsupportedAddress => ErrorCode::UnsupportedAddress,
            Error::InsufficientFunds { .. } => ErrorCode::InsufficientFunds,
            Error::NoAnchor => ErrorCode::NoAnchor,
            Error::CrossingUnavailable => ErrorCode::CrossingUnavailable,
            Error::Build(_) => ErrorCode::Build,
            Error::AlreadySyncing => ErrorCode::AlreadySyncing,
            Error::NotCanonicalDenomination(_) => ErrorCode::NotCanonicalDenomination,
            Error::AccountExists => ErrorCode::AccountExists,
            Error::BadViewingKey(_) => ErrorCode::BadViewingKey,
            Error::SendDisabled => ErrorCode::SendDisabled,
            Error::Configuration(_) => ErrorCode::Configuration,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Storage(e) => write!(f, "the wallet database failed: {e}"),
            Error::VersionMismatch(remedy) => {
                write!(f, "the wallet's schema is not this build's: {remedy}")
            }
            Error::Source(e) => write!(f, "the server could not be reached: {e}"),
            Error::Rejected { code, message } => {
                write!(f, "the network refused the transaction ({code}): {message}")
            }
            Error::Unrecoverable(e) => write!(f, "scanning could not recover: {e}"),
            Error::NoSuchAccount(id) => write!(f, "there is no account {id}"),
            Error::WrongSeed => f.write_str("that seed does not derive this account"),
            Error::WatchOnly => f.write_str("this account can see but not spend"),
            Error::BadMnemonic(e) => write!(f, "that is not a valid seed phrase: {e}"),
            Error::BadAddress(e) => write!(f, "that is not a valid address: {e}"),
            Error::UnsupportedAddress => {
                f.write_str("that address has no receiver this wallet can pay")
            }
            Error::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "the payment needs {required} zatoshis and {available} are spendable"
            ),
            Error::NoAnchor => {
                f.write_str("the wallet has not scanned enough of the chain to build a spend")
            }
            Error::CrossingUnavailable => f.write_str(
                "this payment would have to cross pools, which this build cannot do without \
                 making the transaction identifiable",
            ),
            Error::Build(e) => write!(f, "the transaction could not be built: {e}"),
            Error::AlreadySyncing => f.write_str("a sync is already running"),
            Error::NotCanonicalDenomination(why) => {
                write!(f, "that amount cannot be paid from the Orchard pool: {why}")
            }
            Error::AccountExists => f.write_str("this wallet has already been imported"),
            Error::BadViewingKey(e) => write!(f, "that is not a valid viewing key: {e}"),
            Error::SendDisabled => {
                f.write_str("this wallet recovers only; sending is disabled in this build")
            }
            Error::Configuration(why) => write!(f, "the wallet cannot run as configured: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<zakura_wallet_store::Error> for Error {
    fn from(e: zakura_wallet_store::Error) -> Self {
        use zakura_wallet_store::Error as StoreError;
        match e {
            StoreError::VersionMismatch { kind, .. } => {
                Error::VersionMismatch(kind.remedy().to_owned())
            }
            StoreError::NoSuchAccount { id } => Error::NoSuchAccount(id.0),
            // The store has two spellings of the same fact. Mapping only one of
            // them would make an unknown account look like a database failure
            // depending on which method was called.
            StoreError::UnknownAccount(id) => Error::NoSuchAccount(id.0),
            StoreError::AccountExists => Error::AccountExists,
            other => Error::Storage(other.to_string()),
        }
    }
}

impl From<zakura_wallet_store::TreeError> for Error {
    fn from(e: zakura_wallet_store::TreeError) -> Self {
        use zakura_wallet_store::TreeError;
        match e {
            TreeError::Store(e) => e.into(),
            TreeError::Tree(e) => Error::Storage(e.to_string()),
        }
    }
}

impl From<zakura_wallet_sync::Error> for Error {
    fn from(e: zakura_wallet_sync::Error) -> Self {
        use zakura_wallet_sync::Error as SyncError;
        match e {
            SyncError::Store(e) => e.into(),
            SyncError::Source(e) => Error::Source(e.to_string()),
            other @ SyncError::Unrecoverable { .. } => Error::Unrecoverable(other.to_string()),
            other => Error::Source(other.to_string()),
        }
    }
}

impl From<zakura_wallet_lwd::LwdError> for Error {
    fn from(e: zakura_wallet_lwd::LwdError) -> Self {
        Error::Source(e.to_string())
    }
}

impl From<zakura_wallet_tx::Error> for Error {
    fn from(e: zakura_wallet_tx::Error) -> Self {
        use zakura_wallet_tx::Error as TxError;
        match e {
            TxError::NoAnchor => Error::NoAnchor,
            TxError::CrossingRequired => Error::CrossingUnavailable,
            TxError::Store(e) => e.into(),
            TxError::InsufficientFunds {
                available,
                required,
            } => Error::InsufficientFunds {
                available: available.into_u64(),
                required: required.into_u64(),
            },
            other => Error::Build(other.to_string()),
        }
    }
}
