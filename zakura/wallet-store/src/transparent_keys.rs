//! Deriving the transparent addresses a wallet watches.
//!
//! Pure: keys and an index in, an address out, no database. The path is BIP 44's
//! `m/44'/coin'/account'/scope/index`, where `scope` is the change level — 0 for
//! addresses handed to other people, 1 for the wallet's own change.
//!
//! Derivation is left to `zcash_transparent` rather than reimplemented here,
//! for the same reason unified addresses are left to `zcash_keys`: these are
//! consensus-adjacent formats where a subtle difference is an address nobody
//! can pay, or worse, one somebody else can spend.

use transparent::{
    address::TransparentAddress,
    keys::{AccountPubKey, IncomingViewingKey, NonHardenedChildIndex},
};
use zakura_wallet_core::KeyScope;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Parameters;

use crate::error::Error;

/// One derived transparent address.
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// The address itself.
    pub address: TransparentAddress,
    /// Its encoded form, which is what is stored and shown.
    pub encoded: String,
    /// The `scriptPubKey` paying it, which is what detection matches against.
    pub script: Vec<u8>,
}

/// The viewing keys for one account's transparent addresses.
///
/// Built once per account rather than per index: each scope costs a BIP 32
/// derivation step, and deriving the whole window a step at a time would repeat
/// it for every address.
pub struct TransparentKeys {
    external: Option<transparent::keys::ExternalIvk>,
    internal: Option<transparent::keys::InternalIvk>,
}

impl TransparentKeys {
    /// Derives an account's transparent viewing keys, if it has any.
    ///
    /// An account with no transparent key is not an error: a watch-only
    /// shielded account is a legitimate thing to hold, and it simply has no
    /// transparent addresses to watch.
    pub fn derive(ufvk: &UnifiedFullViewingKey) -> Option<Self> {
        let account: &AccountPubKey = ufvk.transparent()?;
        Some(Self {
            external: account.derive_external_ivk().ok(),
            internal: account.derive_internal_ivk().ok(),
        })
    }

    /// Derives the address at `index` in `scope`.
    pub fn address<P: Parameters>(
        &self,
        params: &P,
        scope: KeyScope,
        index: u32,
    ) -> Result<Option<DerivedAddress>, Error> {
        let index = NonHardenedChildIndex::from_index(index).ok_or_else(|| {
            Error::Corrupt(format!("{index} is not a valid non-hardened child index"))
        })?;

        let address = match scope {
            KeyScope::External => self
                .external
                .as_ref()
                .and_then(|ivk| ivk.derive_address(index).ok()),
            KeyScope::Internal => self
                .internal
                .as_ref()
                .and_then(|ivk| ivk.derive_address(index).ok()),
        };

        Ok(address.map(|address| DerivedAddress {
            encoded: encode(params, &address),
            // Serialised to the same bytes detection compares against: a
            // watch set keyed on one encoding and a chain serving another
            // would simply never match, silently.
            script: zcash_script::script::Code::serialize(&address.script().0),
            address,
        }))
    }
}

/// Encodes a transparent address for storage.
fn encode<P: Parameters>(params: &P, address: &TransparentAddress) -> String {
    zcash_keys::address::Address::from(*address).encode(params)
}
