//! Moving transparent funds into the shielded pool.
//!
//! Shielding is not an ordinary payment with a transparent input. It has no
//! recipient at all: every zatoshi that is not the fee becomes a note the
//! wallet pays itself, which is what makes the whole balance shielded rather
//! than most of it.
//!
//! Two choices here are about privacy rather than mechanics, and both cost
//! something.
//!
//! The destination is **Ironwood, not Orchard**. Orchard bundles are built with
//! cross-address transfers disabled, so value shielded into Orchard could only
//! leave through a ZIP 318 crossing — shielding there would produce funds that
//! need a second, conspicuous transaction before they can be spent. Ironwood is
//! the pool value can leave.
//!
//! It shields **one address at a time** by default. Sweeping several addresses
//! into a single transaction proves, publicly and for ever, that one person
//! held all of them. That is a permanent disclosure in exchange for one fewer
//! transaction, and it is not a trade the wallet makes on somebody's behalf.

use zakura_wallet_store::{SpendableUtxo, TransparentSpendPolicy};
use zcash_protocol::value::Zatoshis;

use crate::{
    error::Error,
    fee::{self, TransparentSizes},
    select::Proposal,
};

/// The share of a block this wallet is willing to fill with one shielding
/// transaction.
///
/// A wallet with hundreds of small outputs would otherwise propose a
/// transaction too large to be mined, which fails only after the fee has been
/// computed and the proving done.
const BLOCK_SPACE_PERCENT: usize = 10;

/// The consensus limit on a block, in bytes.
const MAX_BLOCK_BYTES: usize = 2_000_000;

/// The most transparent inputs one shielding transaction will take.
pub fn max_inputs() -> usize {
    (MAX_BLOCK_BYTES * BLOCK_SPACE_PERCENT / 100) / fee::P2PKH_STANDARD_INPUT_SIZE
}

/// Plans a transaction shielding `utxos` into Ironwood.
///
/// The whole net value becomes change — a note paid to the wallet's own
/// internal address — because there is no external recipient. That is what
/// distinguishes a shielding transaction from a payment that happens to be
/// funded transparently.
pub fn plan_shielding(mut utxos: Vec<SpendableUtxo>) -> Result<Proposal, Error> {
    if utxos.is_empty() {
        return Err(Error::InsufficientFunds {
            available: Zatoshis::ZERO,
            required: Zatoshis::ZERO,
        });
    }

    utxos.truncate(max_inputs());

    let total = utxos
        .iter()
        .try_fold(Zatoshis::ZERO, |acc, u| acc + u.txout.value())
        .ok_or(Error::Build("the outputs to shield overflow".into()))?;

    // One Ironwood output, padded to the two actions any bundle carries.
    let sizes = TransparentSizes::p2pkh(utxos.len(), 0);
    let fee = fee::required_with(sizes, 0, 2);

    let change = (total - fee).ok_or(Error::InsufficientFunds {
        available: total,
        required: fee,
    })?;

    if change.is_zero() {
        // Shielding everything into nothing is not a transaction worth making:
        // it pays the fee and produces no note.
        return Err(Error::InsufficientFunds {
            available: total,
            required: (fee + Zatoshis::const_from_u64(1)).expect("a fee plus one fits"),
        });
    }

    Ok(Proposal {
        inputs: Vec::new(),
        output_pool: zakura_wallet_core::pool::PoolId::Ironwood,
        // No recipient: the entire remainder comes back as change.
        amount: Zatoshis::ZERO,
        change: Some(change),
        fee,
        transparent_inputs: utxos,
        transparent_payment: None,
    })
}

/// The policy a shielding proposal should use by default.
///
/// One address, for the reason in this module's documentation. A caller that
/// genuinely wants to link its addresses has to say so.
pub fn default_policy(address_id: i64) -> TransparentSpendPolicy {
    TransparentSpendPolicy::OneAddress(address_id)
}
