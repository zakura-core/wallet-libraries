//! Choosing which notes to spend.

use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use transparent::address::TransparentAddress;
use zakura_wallet_store::SpendableUtxo;
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
    /// Transparent outputs being spent, if any.
    ///
    /// Empty for an ordinary shielded payment. Spending transparent funds is
    /// never implicit: it links addresses in public, so a caller has to ask.
    pub transparent_inputs: Vec<SpendableUtxo>,
    /// A transparent address being paid, if the payment is to one.
    pub transparent_payment: Option<(TransparentAddress, Zatoshis)>,
}

impl Proposal {
    /// Returns the transparent size this proposal was costed at.
    ///
    /// The builder must charge exactly this, or a transaction whose inputs
    /// cross a ZIP 317 byte boundary is proposed at one fee and built expecting
    /// another.
    pub fn transparent_sizes(&self) -> crate::fee::TransparentSizes {
        crate::fee::TransparentSizes::p2pkh(
            self.transparent_inputs.len(),
            usize::from(self.transparent_payment.is_some()),
        )
    }

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

        // The payment, and the change if there is one. A payment made to a
        // transparent address is not a shielded output, so it does not need an
        // action — but the change still does.
        let outputs = usize::from(self.transparent_payment.is_none())
            + usize::from(self.change.is_some());
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
        // Both sides count transparent value. Omitting it — which this did —
        // makes every shielding transaction look unbalanced, because all of its
        // value comes in transparently and leaves as a shielded note.
        let transparent_in = self
            .transparent_inputs
            .iter()
            .try_fold(Zatoshis::ZERO, |acc, u| acc + u.txout.value());
        let transparent_out = self
            .transparent_payment
            .as_ref()
            .map_or(Some(Zatoshis::ZERO), |(_, v)| Some(*v));

        let (Some(transparent_in), Some(transparent_out)) = (transparent_in, transparent_out)
        else {
            return false;
        };

        let inputs = self.input_value() + transparent_in;
        let outputs = (self.amount + self.change.unwrap_or(Zatoshis::ZERO))
            .and_then(|o| o + transparent_out)
            .and_then(|o| o + self.fee);

        inputs.is_some() && inputs == outputs
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
///
/// Change always goes to the account's internal address, so there is no scope
/// to choose: an external change address would be indistinguishable from a
/// payment on a later scan, and under descending recovery the funding spend is
/// scanned *after* the change note, so scope is the only signal available at
/// the moment the note is first shown to the user.
///
/// This function builds ordinary same-pool payments only. Funding an Ironwood
/// payment from Orchard notes is a ZIP 318 pool crossing, which has a fixed
/// canonical shape that ordinary selection would not produce; see
/// [`crate::crossing`].
pub fn select(
    available: Vec<SpendableNote>,
    output_pool: PoolId,
    amount: Zatoshis,
) -> Result<Proposal, Error> {
    // Every note has to belong to one account. Selection could filter instead,
    // but a caller that offered two accounts' notes did not mean to, and
    // quietly spending a subset would hide that.
    if let Some(first) = available.first()
        && available.iter().any(|n| n.account != first.account)
    {
        return Err(Error::MixedAccounts);
    }

    // Value leaving one pool to pay somebody in the other is a ZIP 318 pool
    // crossing, whatever route it takes. The guard in `build` — refusing an
    // Orchard bundle that pays a stranger — does not catch this shape, because
    // the Orchard side carries no output at all: it is spend-only with a
    // positive value balance, and the Ironwood side makes the payment. Nothing
    // downstream would notice, and the result is a crossing built with this
    // function's action count and fee rather than the canonical ones. A
    // crossing that is not shaped like every other crossing identifies its
    // sender, which is the one thing crossings exist to prevent.
    let (mut candidates, other_pool): (Vec<_>, Vec<_>) = available
        .into_iter()
        .partition(|n| n.pool == output_pool);
    let other_pool_value = other_pool
        .iter()
        .try_fold(Zatoshis::ZERO, |acc, n| acc + n.value())
        .ok_or(Error::ValueOverflow)?;

    candidates.sort_by_key(|n| std::cmp::Reverse(n.value().into_u64()));

    let mut inputs: Vec<SpendableNote> = Vec::new();
    let mut total = Zatoshis::ZERO;

    for note in candidates {
        // Would what we already hold cover the payment and the fee it implies?
        if let Some(proposal) = settle(&inputs, output_pool, amount, total) {
            return Ok(proposal);
        }

        total = (total + note.value()).ok_or(Error::ValueOverflow)?;
        inputs.push(note);
    }

    if let Some(proposal) = settle(&inputs, output_pool, amount, total) {
        return Ok(proposal);
    }

    // The paying pool cannot cover it. Whether the *wallet* can is a different
    // question with a different answer: topping up from the other pool is a
    // crossing, and saying so is more useful than reporting funds the wallet
    // visibly holds as insufficient.
    if other_pool_value > Zatoshis::ZERO {
        return Err(Error::CrossingRequired);
    }
    Err(Error::InsufficientFunds {
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
            // A shielded payment has no transparent parts.
            transparent_inputs: Vec::new(),
            transparent_payment: None,
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
            transparent_inputs: Vec::new(),
            transparent_payment: None,
        };
        debug_assert!(proposal.balances(), "settle produced an unbalanced proposal");
        return Some(proposal);
    }

    None
}


/// Plans a payment to a transparent address.
///
/// Refuses to fund one from Orchard, and that refusal is the point rather than
/// a limitation. An Orchard bundle paying a transparent address would be
/// spend-only with a positive value balance feeding a transparent output — a
/// visible exit from the Orchard pool that no ordinary transaction resembles,
/// and one that marks its sender out precisely when they were trying not to
/// stand out. Value leaves through Ironwood, so a wallet holding only Orchard
/// notes must cross first and pay afterwards.
pub fn plan_transparent_payment(
    available: Vec<SpendableNote>,
    recipient: TransparentAddress,
    amount: Zatoshis,
) -> Result<Proposal, Error> {
    if available.iter().any(|n| n.pool == PoolId::Orchard) {
        return Err(Error::CrossingRequired);
    }

    let mut chosen: Vec<SpendableNote> = Vec::new();
    let mut total = Zatoshis::ZERO;
    let mut sorted = available;
    sorted.sort_by_key(|n| std::cmp::Reverse(n.value().into_u64()));

    for note in sorted {
        total = (total + note.value()).ok_or(Error::Build("input value overflows".into()))?;
        chosen.push(note);

        // Costed through `action_counts` rather than by hand, and with change
        // then without, exactly as the shielded path does. An ad-hoc count here
        // was one action too high, which is a fee the user pays for nothing and
        // a number the builder would not agree with.
        for with_change in [true, false] {
            let candidate = Proposal {
                inputs: chosen.clone(),
                output_pool: PoolId::Ironwood,
                amount: Zatoshis::ZERO,
                change: with_change.then_some(Zatoshis::ZERO),
                fee: Zatoshis::ZERO,
                transparent_inputs: Vec::new(),
                transparent_payment: Some((recipient, amount)),
            };
            let (orchard, ironwood) = candidate.action_counts();
            let fee = crate::fee::required_with(candidate.transparent_sizes(), orchard, ironwood);

            let Some(spent) = amount + fee else { continue };
            if total < spent {
                continue;
            }
            let change = (total - spent).expect("total covers what is spent");

            // A change output worth nothing is not an output.
            let keep_change = change > Zatoshis::ZERO;
            if keep_change != with_change {
                continue;
            }

            return Ok(Proposal {
                inputs: chosen,
                output_pool: PoolId::Ironwood,
                amount: Zatoshis::ZERO,
                change: keep_change.then_some(change),
                fee,
                transparent_inputs: Vec::new(),
                transparent_payment: Some((recipient, amount)),
            });
        }
    }

    Err(Error::InsufficientFunds {
        available: total,
        required: amount,
    })
}
