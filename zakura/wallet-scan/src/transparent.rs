//! Transparent detection.
//!
//! Transparent activity is found by set membership, not by trial decryption:
//! an output is ours if its `scriptPubKey` is one we are watching, and an input
//! is ours if it spends an outpoint we already recorded. There is no tree, no
//! position and no nullifier, which is why transparent is not a
//! [`ShieldedPool`](zakura_wallet_core::ShieldedPool).
//!
//! Address discovery — extending the watch set as the gap limit is consumed —
//! is not done here. It needs the wallet's record of which addresses have been
//! used, so it belongs to the stage that owns that record. This module answers
//! only "is this one of the scripts I was given?".

use std::collections::{HashMap, HashSet};

use transparent::{
    address::Script,
    bundle::{OutPoint, TxOut},
};

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

/// The transparent scripts and outpoints a detection pass matches against.
///
/// Unlike a shielded note, a transparent output cannot be recognised by trying
/// to decrypt it — the only way to know an output is the wallet's is to have
/// derived its address in advance and to be looking for it. That makes the
/// completeness of this set the whole of transparent detection: an address
/// missing from it is money the wallet will never see.
#[derive(Debug, Clone, Default)]
pub struct TransparentWatch {
    scripts: HashMap<Vec<u8>, WatchedAddress>,
    utxos: HashSet<OutPoint>,
}

impl TransparentWatch {
    /// Builds a watch set from the wallet's addresses and the outpoints it
    /// believes are currently unspent.
    ///
    /// Each script is accompanied by the row it came from, so a hit says *which*
    /// address was paid and not merely that one was. Keying on the row rather
    /// than on the account is what lets an external and an internal address be
    /// told apart; keying on the account alone could not.
    pub fn new(
        scripts: impl IntoIterator<Item = (Script, AccountId, i64)>,
        utxos: impl IntoIterator<Item = OutPoint>,
    ) -> Self {
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
            utxos: utxos.into_iter().collect(),
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

    /// Returns the outpoints being watched for spends.
    pub fn outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        self.utxos.iter().cloned()
    }

    /// Returns whether there is nothing to match against.
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty() && self.utxos.is_empty()
    }

    /// Returns the wallet address `txout` pays, if it pays one.
    pub fn watched(&self, txout: &TxOut) -> Option<WatchedAddress> {
        self.scripts.get(&txout.script_pubkey().0.0).copied()
    }

    /// Returns whether `outpoint` is one of the wallet's unspent outputs.
    pub fn spends(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains(outpoint)
    }

    /// Records an outpoint created by this batch, so a spend of it later in the
    /// same batch is recognised.
    ///
    /// Without this, a receive and its spend that fall in the same batch would
    /// leave the spend undetected until the next pass.
    pub(crate) fn add_utxo(&mut self, outpoint: OutPoint) {
        self.utxos.insert(outpoint);
    }
}
