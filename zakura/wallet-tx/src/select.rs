//! Choosing which notes to spend.

use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zcash_protocol::value::Zatoshis;

use crate::{error::Error, fee};

/// A note the wallet holds and could spend.
#[derive(Debug, Clone)]
pub struct SpendableNote {
    /// The pool the note belongs to.
    pub pool: PoolId,
    /// The account that holds it.
    pub account: AccountId,
    /// Which of the account's scopes it arrived on.
    pub scope: KeyScope,
    /// The note itself.
    pub note: orchard::note::Note,
    /// Its position in the pool's commitment tree.
    pub position: incrementalmerkletree::Position,
}

impl SpendableNote {
    /// Returns the note's value.
    pub fn value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("a note the wallet stored has a representable value")
    }
}

/// What a proposed transaction will do.
#[derive(Debug, Clone)]
pub struct Proposal {
    /// The notes to spend.
    pub inputs: Vec<SpendableNote>,
    /// The pool the payment is made in.
    pub output_pool: PoolId,
    /// How much the recipient receives.
    pub amount: Zatoshis,
    /// What comes back to the wallet, if anything.
    ///
    /// Change is always paid to the account's internal address, which is what
    /// makes it recognisable as change on a later scan regardless of the order
    /// blocks arrive in.
    pub change: Option<Zatoshis>,
    /// The fee.
    pub fee: Zatoshis,
}

impl Proposal {
    /// Returns how many actions each pool's bundle will carry.
    ///
    /// An Orchard-family action carries one spend and one output, so a bundle
    /// needs as many actions as it has of whichever there are more, and at
    /// least the two a transactional bundle is padded to.
    pub fn action_counts(&self) -> (usize, usize) {
        let mut counts = (0usize, 0usize);
        for input in &self.inputs {
            match input.pool {
                PoolId::Orchard => counts.0 += 1,
                PoolId::Ironwood => counts.1 += 1,
            }
        }

        // The payment, and the change if there is one.
        let outputs = 1 + usize::from(self.change.is_some());
        match self.output_pool {
            PoolId::Orchard => counts.0 = counts.0.max(outputs),
            PoolId::Ironwood => counts.1 = counts.1.max(outputs),
        }

        // A bundle that exists at all is padded to two actions.
        (
            if counts.0 > 0 { counts.0.max(2) } else { 0 },
            if counts.1 > 0 { counts.1.max(2) } else { 0 },
        )
    }

    /// Returns the total value being spent.
    pub fn input_value(&self) -> Zatoshis {
        self.inputs
            .iter()
            .try_fold(Zatoshis::ZERO, |acc, n| acc + n.value())
            .expect("the selected inputs were summed during selection")
    }

    /// Returns whether the proposal balances: inputs equal outputs plus fee.
    ///
    /// Checked rather than assumed, because a transaction that does not balance
    /// is rejected by consensus after the expensive part — proving — is done.
    pub fn balances(&self) -> bool {
        let out = self.change.unwrap_or(Zatoshis::ZERO);
        (self.amount + out).and_then(|o| o + self.fee) == Some(self.input_value())
    }
}

/// Chooses notes to cover `amount` plus the fee it implies.
///
/// Largest notes first. That keeps the input count — and so the fee, and the
/// number of proofs — down, at the cost of fragmenting the wallet's largest
/// notes first. A wallet that cared about note-size distribution would choose
/// differently; this one optimises for the thing the user waits on.
///
/// The fee depends on how many inputs are chosen and the number of inputs
/// depends on the fee, so the two are settled together: each time a note is
/// added the fee is recomputed and the target moves.
pub fn select(
    mut available: Vec<SpendableNote>,
    output_pool: PoolId,
    amount: Zatoshis,
    change_scope: KeyScope,
) -> Result<Proposal, Error> {
    let _ = change_scope;
    available.sort_by_key(|n| std::cmp::Reverse(n.value().into_u64()));

    let mut inputs: Vec<SpendableNote> = Vec::new();
    let mut total = Zatoshis::ZERO;

    for note in available {
        // Would what we already hold cover the payment and the fee it implies?
        if let Some(proposal) = settle(&inputs, output_pool, amount, total) {
            return Ok(proposal);
        }

        total = (total + note.value()).ok_or(Error::ValueOverflow)?;
        inputs.push(note);
    }

    settle(&inputs, output_pool, amount, total).ok_or(Error::InsufficientFunds {
        available: total,
        required: amount,
    })
}

/// Returns a balanced proposal from these inputs, if they cover it.
fn settle(
    inputs: &[SpendableNote],
    output_pool: PoolId,
    amount: Zatoshis,
    total: Zatoshis,
) -> Option<Proposal> {
    if inputs.is_empty() {
        return None;
    }

    // Try with change first, then without. Dropping the change output removes
    // an action, which can lower the fee, so the two cases are genuinely
    // different rather than one being a special case of the other.
    for with_change in [true, false] {
        let candidate = Proposal {
            inputs: inputs.to_vec(),
            output_pool,
            amount,
            change: with_change.then_some(Zatoshis::ZERO),
            fee: Zatoshis::ZERO,
        };
        let (orchard, ironwood) = candidate.action_counts();
        let fee = fee::required(orchard, ironwood);

        let Some(spent) = amount + fee else { continue };
        if total < spent {
            continue;
        }
        let change = (total - spent).expect("total is at least the amount spent");

        // A change output worth nothing is not an output: it would cost an
        // action and hand the wallet a zero-value note to trip over later.
        let keep_change = change > Zatoshis::ZERO;
        if keep_change != with_change {
            continue;
        }

        let proposal = Proposal {
            inputs: inputs.to_vec(),
            output_pool,
            amount,
            change: keep_change.then_some(change),
            fee,
        };
        debug_assert!(proposal.balances(), "settle produced an unbalanced proposal");
        return Some(proposal);
    }

    None
}
