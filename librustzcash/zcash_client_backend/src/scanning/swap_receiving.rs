//! Experimental Ironwood receiving keys. Ordinary account keys keep their existing tags.

use std::hash::Hash;

use incrementalmerkletree::Position;
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey},
    note::Nullifier,
    note_encryption::IronwoodDomain,
};
use zakura_swap_receiving::KeyId;
use zip32::Scope;

use super::{ScanningKeyOps, ScanningKeys};

/// Identifies a trial-decryption key without conflating multiple keys of one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceivingKeyTag<AccountId> {
    /// An ordinary account key.
    Account(AccountId, Scope),
    /// An external key derived for one swap sequence index.
    Swap(AccountId, KeyId),
}

/// A derived FVK paired with the identity that must survive note detection.
///
/// This key only scans Ironwood. Change from its spends uses ordinary account keys.
pub struct SwapScanningKey<AccountId> {
    account: AccountId,
    key_id: KeyId,
    fvk: FullViewingKey,
}

impl<AccountId> SwapScanningKey<AccountId> {
    /// Derives the receiving FVK from the owning account's ordinary external FVK.
    pub fn derive(
        account: AccountId,
        key_id: KeyId,
        account_fvk: &FullViewingKey,
    ) -> Result<Self, zakura_swap_receiving::DerivationError> {
        Ok(Self {
            account,
            key_id,
            fvk: key_id.derive(account_fvk)?,
        })
    }
}

impl<AccountId> ScanningKeyOps<IronwoodDomain, AccountId, Nullifier>
    for SwapScanningKey<AccountId>
{
    fn prepare(&self) -> PreparedIncomingViewingKey {
        PreparedIncomingViewingKey::new(&self.fvk.to_ivk(Scope::External))
    }

    fn account_id(&self) -> &AccountId {
        &self.account
    }

    fn key_scope(&self) -> Option<Scope> {
        Some(Scope::External)
    }

    fn swap_key_id(&self) -> Option<KeyId> {
        Some(self.key_id)
    }

    fn nf(&self, note: &orchard::Note, _: Position) -> Option<Nullifier> {
        Some(note.nullifier(&self.fvk))
    }
}

impl<AccountId: Copy + Eq + Hash + Send + Sync + 'static>
    ScanningKeys<AccountId, (AccountId, Scope)>
{
    /// Adds registered swap keys to Ironwood trial decryption, retaining ordinary keys in
    /// every pool. Reload this set when registrations change and schedule missing history.
    pub fn with_swap_receiving_keys(
        self,
        keys: impl IntoIterator<Item = SwapScanningKey<AccountId>>,
    ) -> ScanningKeys<AccountId, ReceivingKeyTag<AccountId>> {
        let tag = |(account, scope)| ReceivingKeyTag::Account(account, scope);
        let mut result = ScanningKeys {
            sapling: self.sapling.into_iter().map(|(k, v)| (tag(k), v)).collect(),
            orchard: self.orchard.into_iter().map(|(k, v)| (tag(k), v)).collect(),
            ironwood: self
                .ironwood
                .into_iter()
                .map(|(k, v)| (tag(k), v))
                .collect(),
        };
        for key in keys {
            result.ironwood.insert(
                ReceivingKeyTag::Swap(key.account, key.key_id),
                Box::new(key),
            );
        }
        result
    }
}
