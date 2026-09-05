//! The viewing keys detection runs against.
//!
//! Orchard and Ironwood share their key material exactly: one Orchard full
//! viewing key views both pools, and an Ironwood note is spent with the account's
//! Orchard spending key. What separates the pools during trial decryption is the
//! note-encryption domain, not the key. So this module is not generic over the
//! pool — the same [`ScanKeys`] is handed to both pools' decryption passes.

use std::collections::HashMap;

use orchard::keys::{FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, Scope};
use zakura_wallet_core::account::{AccountId, KeyScope};

/// Maps a wallet key scope onto the Orchard scope it selects.
///
/// The two enums are deliberately separate: `KeyScope` is wallet vocabulary
/// with a stored representation, and `orchard::keys::Scope` is protocol
/// vocabulary. Converting here keeps the storage encoding from being pinned to
/// a type this wallet does not own.
fn orchard_scope(scope: KeyScope) -> Scope {
    match scope {
        KeyScope::External => Scope::External,
        KeyScope::Internal => Scope::Internal,
    }
}

/// The set of keys a detection pass trial-decrypts against.
///
/// The incoming viewing keys are held in one flat, prepared vector because that
/// is the shape batch decryption wants: it amortises the scalar multiplications
/// across every output in the batch, and returns the *index* of the key that
/// succeeded. [`ScanKeys::tag`] maps that index back to an account and scope.
#[derive(Clone)]
pub struct ScanKeys {
    ivks: Vec<PreparedIncomingViewingKey>,
    tags: Vec<(AccountId, KeyScope)>,
    fvks: HashMap<AccountId, FullViewingKey>,
}

impl ScanKeys {
    /// Builds a key set covering both scopes of every given account.
    ///
    /// Both scopes are always included: omitting the internal scope would make
    /// the wallet blind to its own change.
    pub fn from_accounts(accounts: impl IntoIterator<Item = (AccountId, FullViewingKey)>) -> Self {
        let mut ivks = Vec::new();
        let mut tags = Vec::new();
        let mut fvks = HashMap::new();

        for (account, fvk) in accounts {
            for scope in [KeyScope::External, KeyScope::Internal] {
                let ivk: IncomingViewingKey = fvk.to_ivk(orchard_scope(scope));
                ivks.push(PreparedIncomingViewingKey::new(&ivk));
                tags.push((account, scope));
            }
            fvks.insert(account, fvk);
        }

        Self { ivks, tags, fvks }
    }

    /// Returns the prepared incoming viewing keys, in batch order.
    pub fn ivks(&self) -> &[PreparedIncomingViewingKey] {
        &self.ivks
    }

    /// Returns the account and scope for the key at `index` in [`Self::ivks`].
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range. Callers pass back an index that batch
    /// decryption produced from [`Self::ivks`], so an out-of-range value is a
    /// bug in this crate rather than bad input.
    pub fn tag(&self, index: usize) -> (AccountId, KeyScope) {
        self.tags[index]
    }

    /// Returns the full viewing key for an account, which is needed to derive
    /// the nullifier of a note received by it.
    pub fn fvk(&self, account: AccountId) -> Option<&FullViewingKey> {
        self.fvks.get(&account)
    }

    /// Returns whether there are no keys to scan with.
    ///
    /// Detection short-circuits trial decryption in this case, but still walks
    /// the blocks: commitments and tree sizes must be recorded even for a
    /// wallet with no accounts, or the trees would fall behind the chain.
    pub fn is_empty(&self) -> bool {
        self.ivks.is_empty()
    }

    /// Returns the accounts covered by this key set.
    pub fn accounts(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.fvks.keys().copied()
    }
}

impl std::fmt::Debug for ScanKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Viewing keys are secret-adjacent: they reveal the whole transaction
        // history of an account. Never print them, even in a debug log.
        f.debug_struct("ScanKeys")
            .field("accounts", &self.fvks.len())
            .field("ivks", &self.ivks.len())
            .finish_non_exhaustive()
    }
}
