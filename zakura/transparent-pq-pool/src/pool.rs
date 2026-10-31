use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, PublicKey};

use crate::{Error, KeyRange, PublicKeySource, SourceError};

/// 80% of the `2^64` signatures each key is designed for (FIPS 205 section 11).
///
/// Counted from confirmed on-chain signatures only; see the README for what that
/// count cannot see.
pub const SIGNATURE_WARNING_THRESHOLD: u64 = ((1u128 << 64) * 4 / 5) as u64;

/// What the caller saves for one branch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BranchState {
    /// Provisioned public keys; entry `i` is the key at child index `i`.
    pub public_keys: Vec<PublicKey>,
    /// Every index below this has been handed out or seen in use.
    pub issued_end: u64,
    /// The highest index known to have received funds.
    pub highest_used: Option<u32>,
    /// Confirmed on-chain signature totals by index; a missing entry means zero.
    pub confirmed_signatures: BTreeMap<u32, u64>,
}

/// What the caller saves for one account's pool, before showing any issued address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolState {
    /// The parameter set every key in the pool uses.
    pub parameters: ParameterSet,
    /// The derivation network namespace.
    pub network: Network,
    /// The wallet account.
    pub account: u32,
    /// Gap limit on restore and the number of keys kept past the last used one.
    pub window: NonZeroU32,
    /// Receiving keys.
    pub receive: BranchState,
    /// Change keys.
    pub change: BranchState,
}

/// A key handed out by [`AccountPool::issue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The key's recovery metadata.
    pub origin: KeyOrigin,
    /// The key the caller builds its script and address from.
    pub public_key: PublicKey,
    /// False when the pool is empty and this repeats the last handed-out key; the
    /// wallet shows it with a reuse warning.
    pub fresh: bool,
}

/// One account's PQ keys: what is provisioned, handed out, used, and signed.
///
/// Every operation keeps provisioned and issued indices below the branch's discovery
/// end, `(highest_used + 1, or 0) + window`, which is how far restore searches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPool(PoolState);

impl AccountPool {
    /// An empty pool; replenish each branch before issuing from it.
    pub fn new(
        parameters: ParameterSet,
        network: Network,
        account: u32,
        window: NonZeroU32,
    ) -> Self {
        Self(PoolState {
            parameters,
            network,
            account,
            window,
            receive: BranchState::default(),
            change: BranchState::default(),
        })
    }

    /// Resumes from saved state, rejecting state that breaks a pool invariant.
    pub fn from_state(state: PoolState) -> Result<Self, Error> {
        for branch in [&state.receive, &state.change] {
            if branch
                .public_keys
                .iter()
                .any(|key| key.parameters() != state.parameters)
            {
                return Err(Error::InconsistentState("public key parameter set"));
            }
            let provisioned = branch.public_keys.len() as u64;
            if provisioned > discovery_end(branch.highest_used, state.window) {
                return Err(Error::InconsistentState("keys provisioned past the window"));
            }
            if branch.issued_end > provisioned {
                return Err(Error::InconsistentState("issued past the provisioned keys"));
            }
            if branch
                .highest_used
                .is_some_and(|used| u64::from(used) >= branch.issued_end)
            {
                return Err(Error::InconsistentState("used key not marked issued"));
            }
            if branch
                .confirmed_signatures
                .keys()
                .any(|&index| branch.highest_used.is_none_or(|used| index > used))
            {
                return Err(Error::InconsistentState("signatures on an unused key"));
            }
        }
        Ok(Self(state))
    }

    /// The state to save. Save it after every change and before showing an address.
    pub fn state(&self) -> &PoolState {
        &self.0
    }

    /// Every provisioned key on the branch, in index order, for chain tracking.
    pub fn public_keys(&self, branch: Branch) -> impl Iterator<Item = (KeyOrigin, PublicKey)> + '_ {
        self.branch(branch)
            .public_keys
            .iter()
            .enumerate()
            .map(move |(index, key)| (self.origin(branch, index as u32), *key))
    }

    /// Hands out the lowest unissued provisioned key, or repeats the last one.
    ///
    /// Repeating is marked not fresh and never steps past the window. A repeated key
    /// at the signature warning threshold is withheld instead.
    pub fn issue(&mut self, branch: Branch) -> Result<Issued, Error> {
        let state = self.branch(branch);
        let (index, fresh) = if state.issued_end < state.public_keys.len() as u64 {
            (state.issued_end, true)
        } else {
            let last = state
                .issued_end
                .checked_sub(1)
                .ok_or(Error::NothingProvisioned(branch))?;
            (last, false)
        };
        let index = index as u32;
        let origin = self.origin(branch, index);
        let public_key = state.public_keys[index as usize];
        if !fresh {
            // A fresh key has no signatures: signing implies use, and use implies issued.
            if self.signatures(branch, index) >= SIGNATURE_WARNING_THRESHOLD {
                return Err(Error::AddressWithheld(origin));
            }
        } else {
            self.branch_mut(branch).issued_end += 1;
        }
        Ok(Issued {
            origin,
            public_key,
            fresh,
        })
    }

    /// The keys still missing below the branch's discovery end, if any.
    pub fn replenish_request(&self, branch: Branch) -> Option<KeyRange> {
        let state = self.branch(branch);
        let provisioned = state.public_keys.len() as u64;
        let end = discovery_end(state.highest_used, self.0.window);
        // Used keys are provisioned, so the gap never exceeds the window.
        let missing = NonZeroU32::new((end.saturating_sub(provisioned)) as u32)?;
        Some(KeyRange::new(
            self.origin(branch, provisioned as u32),
            missing,
        ))
    }

    /// Adds signer-produced keys, all or none.
    ///
    /// Entries must continue their branch at its next missing index and stay below its
    /// discovery end. Entries the pool already holds with the same key change nothing,
    /// so a retried batch is harmless. The pool trusts that each key matches its
    /// origin; it does not rederive or authenticate it.
    pub fn apply_batch(&mut self, batch: &[(KeyOrigin, PublicKey)]) -> Result<(), Error> {
        let mut next = self.clone();
        let window = next.0.window;
        for &(origin, public_key) in batch {
            next.check_owned(origin)?;
            if public_key.parameters() != next.0.parameters {
                return Err(Error::PublicKeyParameters(origin));
            }
            let state = next.branch_mut(origin.branch());
            let index = u64::from(origin.index());
            let provisioned = state.public_keys.len() as u64;
            if index < provisioned {
                if state.public_keys[index as usize] != public_key {
                    return Err(Error::ConflictingKey(origin));
                }
                continue;
            }
            if index >= discovery_end(state.highest_used, window) {
                return Err(Error::OutsideWindow(origin));
            }
            if index > provisioned {
                return Err(Error::NotContiguous(origin));
            }
            state.public_keys.push(public_key);
        }
        *self = next;
        Ok(())
    }

    /// Fills the branch up to its discovery end from `source`.
    ///
    /// Asks again while the source returns partial batches. Keys added before a
    /// failure stay; calling again resumes.
    pub fn replenish<S: PublicKeySource>(
        &mut self,
        branch: Branch,
        source: &mut S,
    ) -> Result<(), SourceError<S::Error>> {
        while let Some(range) = self.replenish_request(branch) {
            let batch = source.public_keys(range).map_err(SourceError::Source)?;
            self.apply_batch(&batch).map_err(SourceError::Pool)?;
            if self.replenish_request(branch) == Some(range) {
                return Err(SourceError::NoProgress(range));
            }
        }
        Ok(())
    }

    /// Records that a provisioned key has received funds.
    ///
    /// Moves the discovery end forward, which may create a replenishment request. A key
    /// used elsewhere also counts as handed out here. Never moves anything back.
    pub fn record_received(&mut self, origin: KeyOrigin) -> Result<(), Error> {
        self.check_provisioned(origin)?;
        let index = origin.index();
        let state = self.branch_mut(origin.branch());
        state.highest_used = Some(state.highest_used.map_or(index, |used| used.max(index)));
        state.issued_end = state.issued_end.max(u64::from(index) + 1);
        Ok(())
    }

    /// Sets the key's confirmed on-chain signature total, as recomputed from history.
    ///
    /// A nonzero total also records the key as used.
    pub fn set_confirmed_signatures(&mut self, origin: KeyOrigin, total: u64) -> Result<(), Error> {
        self.check_provisioned(origin)?;
        if total == 0 {
            self.branch_mut(origin.branch())
                .confirmed_signatures
                .remove(&origin.index());
            return Ok(());
        }
        self.record_received(origin)?;
        self.branch_mut(origin.branch())
            .confirmed_signatures
            .insert(origin.index(), total);
        Ok(())
    }

    /// Whether the key may sign: at the warning threshold every signature needs `force`.
    pub fn signing_permission(&self, origin: KeyOrigin, force: bool) -> Result<(), Error> {
        self.check_provisioned(origin)?;
        if !force && self.signatures(origin.branch(), origin.index()) >= SIGNATURE_WARNING_THRESHOLD
        {
            return Err(Error::ForceRequired(origin));
        }
        Ok(())
    }

    /// Rebuilds an account's pool from its signer and a check of which keys were paid.
    ///
    /// For each branch, provisions up to the discovery end, checks every new key, and
    /// repeats until `window` consecutive keys past the last used one are unused.
    /// `is_used` gets the public key so the caller can build the script and address and
    /// look them up on chain. Signature totals are supplied afterwards.
    pub fn discover<S: PublicKeySource>(
        parameters: ParameterSet,
        network: Network,
        account: u32,
        window: NonZeroU32,
        source: &mut S,
        mut is_used: impl FnMut(KeyOrigin, &PublicKey) -> bool,
    ) -> Result<Self, SourceError<S::Error>> {
        let mut pool = Self::new(parameters, network, account, window);
        for branch in [Branch::Receive, Branch::Change] {
            let mut checked = 0;
            loop {
                pool.replenish(branch, source)?;
                let used: Vec<KeyOrigin> = pool
                    .public_keys(branch)
                    .skip(checked)
                    .filter(|(origin, key)| is_used(*origin, key))
                    .map(|(origin, _)| origin)
                    .collect();
                let provisioned = pool.branch(branch).public_keys.len();
                if checked == provisioned {
                    break;
                }
                checked = provisioned;
                for origin in used {
                    pool.record_received(origin).map_err(SourceError::Pool)?;
                }
            }
        }
        Ok(pool)
    }

    fn branch(&self, branch: Branch) -> &BranchState {
        match branch {
            Branch::Receive => &self.0.receive,
            Branch::Change => &self.0.change,
        }
    }

    fn branch_mut(&mut self, branch: Branch) -> &mut BranchState {
        match branch {
            Branch::Receive => &mut self.0.receive,
            Branch::Change => &mut self.0.change,
        }
    }

    fn origin(&self, branch: Branch, index: u32) -> KeyOrigin {
        KeyOrigin::new(
            self.0.parameters,
            self.0.network,
            self.0.account,
            branch,
            index,
        )
    }

    fn signatures(&self, branch: Branch, index: u32) -> u64 {
        self.branch(branch)
            .confirmed_signatures
            .get(&index)
            .copied()
            .unwrap_or(0)
    }

    fn check_owned(&self, origin: KeyOrigin) -> Result<(), Error> {
        if origin.parameters() != self.0.parameters
            || origin.network() != self.0.network
            || origin.account() != self.0.account
        {
            return Err(Error::ForeignKey(origin));
        }
        Ok(())
    }

    fn check_provisioned(&self, origin: KeyOrigin) -> Result<(), Error> {
        self.check_owned(origin)?;
        if u64::from(origin.index()) >= self.branch(origin.branch()).public_keys.len() as u64 {
            return Err(Error::UnknownKey(origin));
        }
        Ok(())
    }
}

/// How far restore searches: `window` keys past the highest used one, within `u32`.
fn discovery_end(highest_used: Option<u32>, window: NonZeroU32) -> u64 {
    let next = highest_used.map_or(0, |used| u64::from(used) + 1);
    (next + u64::from(window.get())).min(1 << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_end_stops_at_the_last_child_index() {
        let window = NonZeroU32::new(5).unwrap();
        assert_eq!(discovery_end(None, window), 5);
        assert_eq!(discovery_end(Some(9), window), 15);
        assert_eq!(discovery_end(Some(u32::MAX - 2), window), 1 << 32);
        assert_eq!(discovery_end(Some(u32::MAX), NonZeroU32::MAX), 1 << 32);
    }
}
