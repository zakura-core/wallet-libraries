//! Making a payment, from an amount and an address to broadcast bytes.
//!
//! Seven ordered steps across three crates, two parameters the core makes the
//! caller derive, and one that must not be offered as a choice at all. Written
//! once here, it is a unit test; written in the application, it would need a
//! device to exercise.
//!
//! # Why this refuses Orchard-funded payments
//!
//! From NU6.3 the Orchard pool prohibits cross-address transfers, so paying
//! somebody else out of Orchard is necessarily a ZIP 318 crossing. A crossing
//! has a canonical shape — action counts, expiry, anchor grid, fee — that it has
//! to be indistinguishable within, and producing that shape needs an anchor on
//! the 144-block grid. This build retains no grid anchors and selects none, so
//! `crossing::plan` cannot succeed on a wallet that has scanned a chain.
//!
//! The trap is that the ad-hoc path still *works*. Handing selection a set of
//! Orchard notes and an Ironwood output pool produces a transaction that
//! balances, proves and would be accepted: an Orchard bundle that is spend-only
//! with a positive value balance, and an Ironwood bundle carrying the output.
//! That is a pool crossing with selection's fee and action counts rather than
//! the canonical ones — which is to say, a crossing that identifies itself.
//! Nothing in the core refuses it today.
//!
//! So this module constrains the inputs rather than trusting the output pool:
//! it selects from Ironwood notes only, and refuses anything else with
//! [`Error::CrossingUnavailable`] rather than silently building the wrong
//! shape.

use zakura_wallet_core::pool::PoolId;
use zakura_wallet_store::WalletDb;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Parameters},
    value::Zatoshis,
};
use zeroize::Zeroizing;

use crate::{Wallet, error::Error, keys};

/// How many blocks a transaction stays valid for after the chain tip.
///
/// The same figure the reference wallet uses. Long enough to survive a slow
/// relay, short enough that an abandoned transaction stops holding its inputs
/// hostage.
const EXPIRY_DELTA: u32 = 40;

/// Returns the height a transaction should expire at, and the height whose
/// consensus rules it is built for.
///
/// Both come from the chain tip rather than from the anchor. The anchor is the
/// most recent block both commitment trees hold a checkpoint for, which during
/// recovery can sit a long way below the tip — and a transaction expiring forty
/// blocks after a height the chain passed an hour ago is born expired. The
/// branch identifier has the same problem in a worse form: taken from a stale
/// height it can name the rules of a network upgrade the chain has already
/// left, and consensus rejects it.
///
/// The anchor is still the floor, because a tip below it would mean the wallet
/// had scanned past what the server admits to having.
fn expiry_height(tip: Option<BlockHeight>, anchor: BlockHeight) -> BlockHeight {
    std::cmp::max(tip.unwrap_or(anchor), anchor) + EXPIRY_DELTA
}

/// What a payment would cost, worked out before anything is proved.
///
/// Proving takes seconds, so the fee and the change are settled first and shown
/// for confirmation. The numbers are exact rather than estimated: they come
/// from the same selection the send will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendQuote {
    /// What the recipient receives.
    pub amount: u64,
    /// The fee, in zatoshis.
    pub fee: u64,
    /// What comes back to the wallet, if anything.
    pub change: u64,
    /// How many notes would be spent.
    ///
    /// Each one is a proof, so this is also roughly how long the send will take.
    pub inputs: usize,
}

impl SpendQuote {
    /// Returns what leaves the wallet in total.
    pub fn total(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }
}

/// What came back from broadcasting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    /// The transaction's identifier.
    pub txid: [u8; 32],
    /// The raw transaction, as it went on the wire.
    pub raw: Vec<u8>,
    /// What the server said when it accepted it.
    ///
    /// Acceptance means the transaction reached the network, not that it will
    /// be mined.
    pub server_response: String,
}

impl Wallet {
    /// Works out what a payment would cost, without proving it.
    pub fn quote(&self, account: u32, to: &str, amount: u64) -> Result<SpendQuote, Error> {
        // Parsed for its errors, not its value: selection does not need the
        // recipient, but somebody quoting a payment to an address this wallet
        // cannot pay should learn that now rather than after the fee is shown.
        crate::address::parse(&self.params, to)?;
        let amount = Zatoshis::from_u64(amount)
            .map_err(|_| Error::Build("that is not a valid amount".to_owned()))?;

        self.with_writer_pausing_sync(|db| {
            let (proposal, _) = plan(db, &self.params, Self::account_id(account), amount)?;
            Ok(SpendQuote {
                amount: proposal.amount.into_u64(),
                fee: proposal.fee.into_u64(),
                change: proposal.change.map_or(0, |c| c.into_u64()),
                inputs: proposal.inputs.len(),
            })
        })
    }

    /// Builds, proves, signs and broadcasts a payment.
    ///
    /// Blocks for as long as proving takes — seconds, and more on a phone — so
    /// it belongs on a worker rather than on whatever thread draws the
    /// interface.
    ///
    /// The seed is needed because the wallet stores only viewing keys. It is
    /// used to derive the account's spending key, checked against the stored
    /// viewing key, and dropped.
    pub fn send(
        &self,
        account: u32,
        to: &str,
        amount: u64,
        seed: &Zeroizing<Vec<u8>>,
    ) -> Result<SendReceipt, Error> {
        let recipient = crate::address::parse(&self.params, to)?;
        let amount = Zatoshis::from_u64(amount)
            .map_err(|_| Error::Build("that is not a valid amount".to_owned()))?;
        let account = Self::account_id(account);
        let params = self.params;

        let (raw, txid) = self.with_writer_pausing_sync(|db| {
            let (proposal, witnesses) = plan(db, &params, account, amount)?;
            let spend_keys = keys::spending_keys(db, &params, account, seed)?;

            let anchors = zakura_wallet_tx::anchors(db)?;
            let expiry = expiry_height(db.chain_tip()?, anchors.height);
            // The rules the transaction will be judged by are the ones in force
            // where it will be mined, not where its anchor was taken.
            let branch_id = BranchId::for_height(&params, expiry);

            let request = zakura_wallet_tx::SpendRequest {
                proposal: &proposal,
                witnesses: &witnesses,
                keys: &spend_keys,
                recipient,
                anchors: &anchors,
            };

            let tx = zakura_wallet_tx::payment(
                &request,
                branch_id,
                expiry,
                zakura_wallet_tx::circuit::proving_key(),
                rand::rng(),
            )?;

            // Verifying locally is the only way to learn that a witness was
            // taken at the wrong position before consensus does, and consensus
            // says so months later by rejecting a proof.
            zakura_wallet_tx::verify_proofs(&tx, zakura_wallet_tx::circuit::verifying_key())?;

            let raw = zakura_wallet_tx::transaction::to_bytes(&tx)?;
            Ok((raw, *tx.txid().as_ref()))
        })?;

        let response = self.broadcast(&raw)?;

        Ok(SendReceipt {
            txid,
            raw,
            server_response: response,
        })
    }

    fn broadcast(&self, raw: &[u8]) -> Result<String, Error> {
        let url = self.config.lightwalletd_url.clone();
        let bytes = raw.to_vec();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Source(format!("could not start a runtime: {e}")))?;

        runtime.block_on(async move {
            let source = zakura_wallet_lwd::LightwalletdSource::connect(&url).await?;
            Ok(source.send(bytes).await?)
        })
    }
}

/// Chooses the notes to spend, and refuses the shapes this build cannot make
/// canonically.
///
/// Selection is restricted to Ironwood before it runs, rather than after: see
/// the module documentation for why handing it a mixed set and asking for an
/// Ironwood output would produce a non-canonical crossing rather than an error.
fn plan<P: Parameters>(
    db: &mut WalletDb,
    params: &P,
    account: zakura_wallet_core::AccountId,
    amount: Zatoshis,
) -> Result<
    (
        zakura_wallet_tx::Proposal,
        Vec<(zakura_wallet_tx::SpendableNote, orchard::tree::MerklePath)>,
    ),
    Error,
> {
    let stored = db
        .account(params, account)?
        .ok_or(Error::NoSuchAccount(account.0))?;
    let fvk = stored.orchard_fvk()?.clone();

    let anchors = zakura_wallet_tx::anchors(db)?;
    let available = zakura_wallet_tx::spendable_notes(db, account, &fvk, &anchors, true)?;

    let (ironwood, orchard): (Vec<_>, Vec<_>) = available
        .into_iter()
        .partition(|(note, _)| note.pool == PoolId::Ironwood);

    let proposal = match zakura_wallet_tx::select(
        ironwood.iter().map(|(note, _)| note.clone()).collect(),
        PoolId::Ironwood,
        amount,
    ) {
        Ok(proposal) => proposal,
        // The wallet may well hold enough — just in the pool this build cannot
        // spend from. Saying "not enough funds" when the funds are visible in
        // the balance would be the most confusing answer available, so the
        // unavailable crossing is named instead.
        Err(zakura_wallet_tx::Error::InsufficientFunds { .. }) if !orchard.is_empty() => {
            return Err(Error::CrossingUnavailable);
        }
        Err(e) => return Err(e.into()),
    };

    // Keep only the witnesses the proposal actually uses, in its order.
    let chosen = proposal
        .inputs
        .iter()
        .map(|input| {
            ironwood
                .iter()
                .find(|(note, _)| note.position == input.position && note.pool == input.pool)
                .cloned()
                .ok_or_else(|| Error::Build("a selected note lost its witness".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((proposal, chosen))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    /// The defect this exists for: during recovery the anchor can sit far below
    /// the tip, and an expiry measured from it names a height the chain passed
    /// long ago.
    #[test]
    fn expiry_follows_the_tip_not_a_lagging_anchor() {
        assert_eq!(expiry_height(Some(h(2_000_000)), h(1_000_000)), h(2_000_040));
    }

    #[test]
    fn expiry_falls_back_to_the_anchor_when_no_tip_is_known() {
        assert_eq!(expiry_height(None, h(1_000_000)), h(1_000_040));
    }

    /// A tip below the anchor would mean the wallet had scanned past what the
    /// server admits to; the anchor is the floor either way.
    #[test]
    fn the_anchor_is_the_floor() {
        assert_eq!(expiry_height(Some(h(900_000)), h(1_000_000)), h(1_000_040));
    }
}
