//! Making a payment, from an amount and an address to broadcast bytes.
//!
//! Seven ordered steps across three crates, two parameters the core makes the
//! caller derive, and one that must not be offered as a choice at all. Written
//! once here, it is a unit test; written in the application, it would need a
//! device to exercise.
//!
//! # Paying out of the Orchard pool
//!
//! From NU6.3 the Orchard pool prohibits cross-address transfers, so paying
//! somebody else out of Orchard is necessarily a ZIP 318 crossing. A crossing
//! has a canonical shape — one source note, fixed action counts, a fixed fee, a
//! set denomination, and an anchor on a grid every wallet's crossings share —
//! and the whole point of that shape is that one crossing cannot be told from
//! another.
//!
//! So an Orchard-funded payment is routed through [`crossing`] when the amount
//! is a canonical denomination, and refused when it is not. Refusing is the
//! answer rather than adjusting: sending a different sum than somebody asked
//! for is worse than not sending, and a crossing carrying an unusual amount
//! announces itself.
//!
//! The trap this module exists to avoid is the ad-hoc path. Handing ordinary
//! selection a set of Orchard notes and an Ironwood output pool produces a
//! transaction that balances, proves and would be accepted: an Orchard bundle
//! spend-only with a positive value balance, and an Ironwood bundle carrying
//! the output. That is a pool crossing with selection's fee and action counts
//! rather than the canonical ones — a crossing that identifies itself — and
//! nothing in the core refuses it. [`route`] therefore chooses by where the
//! money is rather than by what the output pool is set to, and the crossing
//! path goes through `crossing::transaction`, which reads the shape back off
//! the bytes it produced and refuses a non-conforming result.
//!
//! [`crossing`]: zakura_wallet_tx::crossing

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
    /// Whether this payment leaves the Orchard pool as a ZIP 318 crossing.
    ///
    /// Worth surfacing: a crossing pays a fixed denomination and carries a
    /// fixed fee, so the numbers are not negotiable the way an ordinary
    /// payment's are.
    pub crossing: bool,
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
            match route(db, &self.params, Self::account_id(account), amount)? {
                Route::Ironwood { proposal, .. } => Ok(SpendQuote {
                    amount: proposal.amount.into_u64(),
                    fee: proposal.fee.into_u64(),
                    change: proposal.change.map_or(0, |c| c.into_u64()),
                    inputs: proposal.inputs.len(),
                    crossing: false,
                }),
                // A crossing spends exactly one note and its fee is fixed by
                // the canonical shape rather than by how many actions it
                // happens to carry.
                Route::Crossing { plan, .. } => Ok(SpendQuote {
                    amount: plan.denomination.into_u64(),
                    fee: plan.fee.into_u64(),
                    change: plan.change.into_u64(),
                    inputs: 1,
                    crossing: true,
                }),
            }
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

        let (raw, txid, fee, expiry) = self.with_writer_pausing_sync(|db| {
            let spend_keys = keys::spending_keys(db, &params, account, seed)?;
            let chosen = route(db, &params, account, amount)?;

            let tx = match &chosen {
                Route::Ironwood {
                    proposal,
                    witnesses,
                    anchors,
                } => {
                    let expiry = expiry_height(db.chain_tip()?, anchors.height);
                    // The rules the transaction will be judged by are the ones
                    // in force where it will be mined, not where its anchor was
                    // taken.
                    let branch_id = BranchId::for_height(&params, expiry);

                    let request = zakura_wallet_tx::SpendRequest {
                        proposal,
                        witnesses,
                        keys: &spend_keys,
                        recipient,
                        anchors,
                    };
                    zakura_wallet_tx::payment(
                        &request,
                        branch_id,
                        expiry,
                        zakura_wallet_tx::circuit::proving_key(),
                        rand::rng(),
                    )?
                }
                Route::Crossing {
                    plan,
                    witness,
                    anchors,
                } => {
                    // The expiry belongs to the plan, not to us: an ordinary
                    // one would single this transaction out from the crossings
                    // it is meant to be indistinguishable from. `transaction`
                    // reads the shape off the bytes it produced and refuses a
                    // non-conforming result, so a wrong crossing cannot be
                    // returned here — only paid for.
                    let branch_id = BranchId::for_height(&params, plan.expiry);
                    zakura_wallet_tx::crossing::transaction(
                        &zakura_wallet_tx::crossing::CrossingRequest {
                            plan,
                            witness,
                            keys: &spend_keys,
                            recipient,
                            anchors,
                        },
                        branch_id,
                        zakura_wallet_tx::circuit::proving_key(),
                        rand::rng(),
                    )?
                }
            };

            // Verifying locally is the only way to learn that a witness was
            // taken at the wrong position before consensus does, and consensus
            // says so months later by rejecting a proof.
            zakura_wallet_tx::verify_proofs(&tx, zakura_wallet_tx::circuit::verifying_key())?;

            let (fee, expiry) = match &chosen {
                Route::Ironwood {
                    proposal, anchors, ..
                } => (
                    proposal.fee,
                    expiry_height(db.chain_tip()?, anchors.height),
                ),
                Route::Crossing { plan, .. } => (plan.fee, plan.expiry),
            };

            let raw = zakura_wallet_tx::transaction::to_bytes(&tx)?;
            Ok((raw, tx.txid(), fee, expiry))
        })?;

        // Broadcast before recording. A transaction the network refused is not
        // one the wallet spent: writing first would leave the balance short of
        // money it still has, with nothing to correct it.
        let response = self.broadcast(&raw)?;

        // Now record it. Until this exists, the notes the payment spent still
        // look unspent, because a spend is only observed when the transaction
        // is scanned back off the chain — so between broadcasting and the next
        // scan the wallet would say the money is still there, and a second
        // payment could be built from the same notes.
        self.record_sent(account, to, &raw, txid, fee, expiry)?;

        Ok(SendReceipt {
            txid: *txid.as_ref(),
            raw,
            server_response: response,
        })
    }

    /// Records a transaction this wallet just broadcast.
    ///
    /// Decrypting the wallet's own transaction is how its outputs and spends
    /// are learned, and it is the same path a transaction found on the chain
    /// takes — so what is stored here is the shape the scanner would have
    /// stored anyway, and the two cannot disagree when the transaction is
    /// finally mined.
    ///
    /// A failure here is deliberately not fatal to the send. The payment has
    /// already reached the network and telling somebody it failed would be
    /// false; the next scan finds it regardless, so the cost of not recording
    /// it is a stale balance until then.
    fn record_sent(
        &self,
        account: zakura_wallet_core::AccountId,
        to: &str,
        raw: &[u8],
        txid: zcash_protocol::TxId,
        fee: Zatoshis,
        expiry: BlockHeight,
    ) -> Result<(), Error> {
        let params = self.params;

        let recorded = self.with_writer_pausing_sync(|db| {
            let stored = db
                .account(&params, account)?
                .ok_or(Error::NoSuchAccount(account.0))?;
            let scan_keys =
                zakura_wallet_scan::ScanKeys::from_accounts([(account, stored.orchard_fvk()?.clone())]);

            let target = db.chain_tip()?.unwrap_or(expiry);
            let enhanced = zakura_wallet_scan::enhance::decrypt_transaction(
                &params, &scan_keys, txid, target, raw,
            )
            .map_err(|e| Error::Build(e.to_string()))?;

            let created = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);

            db.store_sent_transaction(&params, &enhanced, fee, target, created, Some(to))?;
            Ok(())
        });

        if let Err(e) = recorded {
            // Recorded where a sync failure is recorded rather than raised: the
            // payment was sent, and saying otherwise would be a lie about
            // something irreversible.
            *self.failure.lock().expect("the failure lock is never poisoned") =
                Some(format!("the payment was sent but not recorded: {e}"));
        }
        Ok(())
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
/// How a payment can be made, given where the account's money is.
pub(crate) enum Route {
    /// An ordinary Ironwood-funded payment.
    Ironwood {
        proposal: zakura_wallet_tx::Proposal,
        witnesses: Vec<(zakura_wallet_tx::SpendableNote, orchard::tree::MerklePath)>,
        anchors: zakura_wallet_tx::Anchors,
    },
    /// A ZIP 318 crossing, paying the recipient out of the Orchard pool.
    ///
    /// Only available for a canonical denomination, and only against an anchor
    /// on the grid every wallet's crossings share. Both are conditions of the
    /// shape rather than of this implementation: a crossing that is nearly
    /// right is worse than none, because it stands out from the ones that are.
    Crossing {
        plan: zakura_wallet_tx::crossing::CrossingPlan,
        witness: orchard::tree::MerklePath,
        anchors: zakura_wallet_tx::Anchors,
    },
}

/// Chooses how to pay `amount`, or explains why it cannot be paid.
///
/// Ironwood first, because an Ironwood-funded payment needs no crossing and can
/// carry any amount. Orchard only as a crossing, because from NU6.3 the Orchard
/// pool prohibits cross-address transfers outright — value leaves it through a
/// bundle's value balance and no other way.
fn route<P: Parameters>(
    db: &mut WalletDb,
    params: &P,
    account: zakura_wallet_core::AccountId,
    amount: Zatoshis,
) -> Result<Route, Error> {
    let stored = db
        .account(params, account)?
        .ok_or(Error::NoSuchAccount(account.0))?;
    let fvk = stored.orchard_fvk()?.clone();

    let anchors = zakura_wallet_tx::anchors(db)?;
    let available = zakura_wallet_tx::spendable_notes(db, account, &fvk, &anchors, true)?;

    let (ironwood, orchard): (Vec<_>, Vec<_>) = available
        .into_iter()
        .partition(|(note, _)| note.pool == PoolId::Ironwood);

    let shortfall = match zakura_wallet_tx::select(
        ironwood.iter().map(|(note, _)| note.clone()).collect(),
        PoolId::Ironwood,
        amount,
    ) {
        Ok(proposal) => {
            // Keep only the witnesses the proposal uses, in its order.
            let witnesses = proposal
                .inputs
                .iter()
                .map(|input| {
                    ironwood
                        .iter()
                        .find(|(note, _)| {
                            note.position == input.position && note.pool == input.pool
                        })
                        .cloned()
                        .ok_or_else(|| Error::Build("a selected note lost its witness".to_owned()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            return Ok(Route::Ironwood {
                proposal,
                witnesses,
                anchors,
            });
        }
        Err(e @ zakura_wallet_tx::Error::InsufficientFunds { .. }) => e,
        Err(e) => return Err(e.into()),
    };

    // Nothing in Orchard either: the wallet is simply short, and saying so is
    // the right answer.
    if orchard.is_empty() {
        return Err(shortfall.into());
    }

    plan_crossing(db, account, &fvk, amount)
}

/// Plans a crossing paying `amount` out of the Orchard pool.
///
/// Uses the grid anchors rather than the most recent common one: a crossing
/// anchored anywhere else announces which wallet built it.
fn plan_crossing(
    db: &mut WalletDb,
    account: zakura_wallet_core::AccountId,
    fvk: &orchard::keys::FullViewingKey,
    amount: Zatoshis,
) -> Result<Route, Error> {
    let anchors = match zakura_wallet_tx::crossing_anchors(db) {
        Ok(anchors) => anchors,
        // No boundary of the shared grid has been reached and retained yet.
        // Scanning further resolves it; there is nothing the caller can do now.
        Err(zakura_wallet_tx::Error::NoAnchor) => return Err(Error::NoAnchor),
        Err(e) => return Err(e.into()),
    };

    let target = db.chain_tip()?.unwrap_or(anchors.height) + 1;
    let available = zakura_wallet_tx::spendable_notes(db, account, fvk, &anchors, true)?;

    let plan = zakura_wallet_tx::crossing::plan(
        &available,
        amount,
        &anchors,
        target,
        &zakura_wallet_tx::crossing::CrossingParams,
    )
    .map_err(|e| match e {
        // The amount is the problem, not the wallet. Every crossing carries one
        // of a fixed set of denominations precisely so that they cannot be told
        // apart, so an arbitrary amount cannot leave Orchard in one step.
        zakura_wallet_tx::Error::NotCanonical(why) => Error::NotCanonicalDenomination(why),
        other => Error::from(other),
    })?;

    let witness = available
        .iter()
        .find(|(note, _)| note.position == plan.source.position)
        .map(|(_, path)| path.clone())
        .ok_or_else(|| Error::Build("the planned note lost its witness".to_owned()))?;

    Ok(Route::Crossing {
        plan,
        witness,
        anchors,
    })
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
