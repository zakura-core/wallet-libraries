//! Recognising the wallet's scripts inside a transaction it already has.
//!
//! Transparent activity is found by set membership, not by trial decryption: an
//! output is ours if its `scriptPubKey` is one we are watching. There is no
//! tree, no position and no nullifier, which is why transparent is not a
//! [`ShieldedPool`](zakura_wallet_core::ShieldedPool).
//!
//! This is no longer how the wallet *discovers* transparent funds — the private
//! ledger in `zakura-wallet-transparent` is, and it is the only thing that can
//! find an output the wallet was not already looking at. What remains here
//! serves enhancement: a full transaction fetched for shielded reasons carries
//! its transparent bundle, and discarding that side would lose outputs the
//! wallet owns in a transaction it already holds.
//!
//! Spends are not matched here at all. An input is linked to the output it
//! consumes by the spend map in the store, which joins the two whichever order
//! they arrive in; a set of believed-unspent outpoints carried alongside the
//! scripts was a cache of that join, and a cache that could go stale in the
//! direction that overstates a balance.
//!
//! Address discovery — extending the watch set as the gap limit is consumed —
//! is not done here. It needs the wallet's record of which addresses have been
//! used, so it belongs to the stage that owns that record. This module answers
//! only "is this one of the scripts I was given?".

use std::collections::HashMap;

use transparent::{address::Script, bundle::TxOut};

use zakura_wallet_core::AccountId;

/// One of the wallet's addresses, as the watch set knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedAddress {
    /// Whose address it is.
    pub account: AccountId,
    /// The stored row it came from.
    ///
    /// Opaque here: this crate never reads it, it only hands it back so the
    /// store can attribute a received output without re-deriving anything.
    pub address_id: i64,
}

/// The transparent scripts a pass matches against.
///
/// Unlike a shielded note, a transparent output cannot be recognised by trying
/// to decrypt it — the only way to know an output is the wallet's is to have
/// derived its address in advance and to be looking for it. That makes the
/// completeness of this set the whole of transparent detection: an address
/// missing from it is money the wallet will never see.
#[derive(Debug, Clone, Default)]
pub struct TransparentWatch {
    scripts: HashMap<Vec<u8>, WatchedAddress>,
}

impl TransparentWatch {
    /// Builds a watch set from the wallet's addresses.
    ///
    /// Each script is accompanied by the row it came from, so a hit says *which*
    /// address was paid and not merely that one was. Keying on the row rather
    /// than on the account is what lets an external and an internal address be
    /// told apart; keying on the account alone could not.
    pub fn new(scripts: impl IntoIterator<Item = (Script, AccountId, i64)>) -> Self {
        Self {
            scripts: scripts
                .into_iter()
                .map(|(script, account, address_id)| {
                    (
                        script.0.0,
                        WatchedAddress {
                            account,
                            address_id,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Returns the watched scripts, in the shape [`Self::new`] takes.
    ///
    /// Exposed so a caller-supplied watch set can be merged with the wallet's
    /// stored addresses rather than one silently replacing the other.
    pub fn entries(&self) -> impl Iterator<Item = (Script, AccountId, i64)> + '_ {
        self.scripts.iter().map(|(script, watched)| {
            (
                Script(zcash_script::script::Code(script.clone())),
                watched.account,
                watched.address_id,
            )
        })
    }

    /// Returns whether there is nothing to match against.
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Returns the wallet address `txout` pays, if it pays one.
    pub fn watched(&self, txout: &TxOut) -> Option<WatchedAddress> {
        self.scripts.get(&txout.script_pubkey().0.0).copied()
    }

}
