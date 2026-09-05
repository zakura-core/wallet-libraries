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

/// The transparent scripts and outpoints a detection pass matches against.
#[derive(Debug, Clone, Default)]
pub struct TransparentWatch {
    scripts: HashMap<Vec<u8>, AccountId>,
    /// The address index each watched script belongs to, so that a hit can say
    /// *which* address was used and not merely that one was.
    indices: HashMap<(AccountId, Vec<u8>), u32>,
    utxos: HashSet<OutPoint>,
}

impl TransparentWatch {
    /// Builds a watch set from the scripts the wallet is watching and the
    /// outpoints it believes are currently unspent.
    pub fn new(
        scripts: impl IntoIterator<Item = (Script, AccountId)>,
        utxos: impl IntoIterator<Item = OutPoint>,
    ) -> Self {
        Self {
            scripts: scripts
                .into_iter()
                .map(|(script, account)| (script.0.0, account))
                .collect(),
            indices: HashMap::new(),
            utxos: utxos.into_iter().collect(),
        }
    }

    /// Builds a watch set that also knows which address index each script is.
    pub fn with_indices(
        scripts: impl IntoIterator<Item = (Script, AccountId, u32)>,
        utxos: impl IntoIterator<Item = OutPoint>,
    ) -> Self {
        let mut watch = Self {
            scripts: HashMap::new(),
            indices: HashMap::new(),
            utxos: utxos.into_iter().collect(),
        };
        for (script, account, index) in scripts {
            watch.scripts.insert(script.0.0.clone(), account);
            watch.indices.insert((account, script.0.0), index);
        }
        watch
    }

    /// Returns the address index the script belongs to, if it is known.
    pub fn index_for(&self, account: AccountId, txout: &TxOut) -> Option<u32> {
        self.indices
            .get(&(account, txout.script_pubkey().0.0.clone()))
            .copied()
    }

    /// Returns whether there is nothing to match against.
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty() && self.utxos.is_empty()
    }

    /// Returns the account watching `txout`'s script, if any.
    pub fn account_for(&self, txout: &TxOut) -> Option<AccountId> {
        self.scripts.get(&txout.script_pubkey().0.0).copied()
    }

    /// Returns the highest watched index for `account`, if any.
    ///
    /// Gap-limit maintenance needs to know how far an account's addresses run,
    /// so it can tell whether enough unused ones remain ahead of the used ones.
    pub fn highest_index(&self, account: AccountId) -> Option<u32> {
        self.indices
            .iter()
            .filter(|((a, _), _)| *a == account)
            .map(|(_, index)| *index)
            .max()
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
