//! Wallet-level identifiers shared by every layer.

/// A wallet-local account identifier.
///
/// Opaque: detection only compares these and hands them back, and storage
/// assigns them. Making it a newtype rather than a bare integer keeps it from
/// being confused with the other integers in the same signatures — heights,
/// positions, indices — all of which are also just numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(pub u32);

/// Which of an account's two address scopes a note was received on.
///
/// This is not cosmetic. A note received on [`KeyScope::Internal`] is change,
/// which drives balance presentation, which outgoing viewing key can recover a
/// send, and — because change is encrypted under the internal OVK — whether an
/// action can ever become a private-enhancement candidate at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyScope {
    /// An address handed out to other people.
    External,
    /// An address the wallet pays itself, i.e. change.
    Internal,
}

impl KeyScope {
    /// The wire-stable code stored in the database.
    pub fn code(self) -> u8 {
        match self {
            KeyScope::External => 0,
            KeyScope::Internal => 1,
        }
    }

    /// Returns the scope with the given database code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(KeyScope::External),
            1 => Some(KeyScope::Internal),
            _ => None,
        }
    }
}
