use core::fmt;

use transparent_pq_keys::{Branch, KeyOrigin};

use crate::KeyRange;

/// A pool operation rejected its input or has nothing it may return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The origin belongs to another parameter set, network, or account.
    ForeignKey(KeyOrigin),
    /// The public key is for a different parameter set than the pool.
    PublicKeyParameters(KeyOrigin),
    /// The pool already holds a different public key for this origin.
    ConflictingKey(KeyOrigin),
    /// The entry does not continue its branch at the next missing index.
    NotContiguous(KeyOrigin),
    /// The index is at or beyond the branch's discovery window.
    OutsideWindow(KeyOrigin),
    /// The pool has not provisioned this key.
    UnknownKey(KeyOrigin),
    /// Nothing has been provisioned on this branch yet; replenish first.
    NothingProvisioned(Branch),
    /// The only key left to show has reached the signature warning threshold.
    AddressWithheld(KeyOrigin),
    /// The key has reached the signature warning threshold; signing needs `force`.
    ForceRequired(KeyOrigin),
    /// Saved state breaks the named pool invariant.
    InconsistentState(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignKey(origin) => write!(f, "key {origin:?} belongs to another pool"),
            Self::PublicKeyParameters(origin) => {
                write!(f, "public key for {origin:?} uses another parameter set")
            }
            Self::ConflictingKey(origin) => {
                write!(f, "pool holds a different public key for {origin:?}")
            }
            Self::NotContiguous(origin) => {
                write!(f, "key {origin:?} leaves a gap in its branch")
            }
            Self::OutsideWindow(origin) => {
                write!(f, "key {origin:?} is outside the discovery window")
            }
            Self::UnknownKey(origin) => write!(f, "key {origin:?} is not provisioned"),
            Self::NothingProvisioned(branch) => {
                write!(f, "no {branch:?} keys provisioned; replenish first")
            }
            Self::AddressWithheld(origin) => {
                write!(f, "key {origin:?} reached the signature warning threshold")
            }
            Self::ForceRequired(origin) => {
                write!(
                    f,
                    "key {origin:?} reached the signature warning threshold; force required"
                )
            }
            Self::InconsistentState(invariant) => {
                write!(f, "saved pool state is inconsistent: {invariant}")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Replenishment or restore failed in the key source or the pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError<E> {
    /// The key source failed.
    Source(E),
    /// The key source returned nothing new for this request.
    NoProgress(KeyRange),
    /// The pool rejected the key source's batch.
    Pool(Error),
}

impl<E: fmt::Display> fmt::Display for SourceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "key source failed: {error}"),
            Self::NoProgress(range) => {
                write!(f, "key source returned no new keys for {range:?}")
            }
            Self::Pool(error) => write!(f, "{error}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for SourceError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::NoProgress(_) => None,
            Self::Pool(error) => Some(error),
        }
    }
}
