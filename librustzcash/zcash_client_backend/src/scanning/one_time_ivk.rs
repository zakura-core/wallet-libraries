//! One-time IVKs in trial decryption. Ordinary account keys keep their existing tags.

use std::hash::Hash;

use incrementalmerkletree::Position;
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey},
    note::Nullifier,
    note_encryption::IronwoodDomain,
};
use zakura_one_time_ivk::KeyId;
use zip32::Scope;

use super::{ScanningKeyOps, ScanningKeys};

/// Identifies a trial-decryption key without conflating multiple keys of one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ReceivingKeyTag<AccountId> {
    /// An ordinary account key.
    Account(AccountId, Scope),
    /// A one-time key of the account.
    OneTime(AccountId, KeyId),
}

/// A derived FVK paired with the identity that must survive note detection.
///
/// This key only scans Ironwood. Change from its spends uses ordinary account keys.
pub struct OneTimeScanningKey<AccountId> {
    account: AccountId,
    key_id: KeyId,
    fvk: FullViewingKey,
}

impl<AccountId> OneTimeScanningKey<AccountId> {
    /// The account whose receiving sequence this key belongs to.
    pub fn account_id(&self) -> &AccountId {
        &self.account
    }

    /// The identity to credit when persisting blocks scanned with this key.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The derived viewing key, retaining this key's account and sequence identity.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// Derives the one-time FVK from the owning account's ordinary external FVK.
    pub fn derive(
        account: AccountId,
        key_id: KeyId,
        account_fvk: &FullViewingKey,
    ) -> Result<Self, zakura_one_time_ivk::DerivationError> {
        Ok(Self {
            account,
            key_id,
            fvk: key_id.derive(account_fvk)?,
        })
    }
}

impl<AccountId> ScanningKeyOps<IronwoodDomain, AccountId, Nullifier>
    for OneTimeScanningKey<AccountId>
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

    fn one_time_key_id(&self) -> Option<KeyId> {
        Some(self.key_id)
    }

    fn nf(&self, note: &orchard::Note, _: Position) -> Option<Nullifier> {
        Some(note.nullifier(&self.fvk))
    }
}

impl<AccountId: Copy + Eq + Hash + Send + Sync + 'static>
    ScanningKeys<AccountId, (AccountId, Scope)>
{
    /// Adds one-time keys to Ironwood trial decryption, retaining ordinary keys in
    /// every pool. Reload this set when registrations change and schedule missing history.
    pub(crate) fn with_one_time_ivks(
        self,
        keys: impl IntoIterator<Item = OneTimeScanningKey<AccountId>>,
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
                ReceivingKeyTag::OneTime(key.account, key.key_id),
                Box::new(key),
            );
        }
        result
    }
}
