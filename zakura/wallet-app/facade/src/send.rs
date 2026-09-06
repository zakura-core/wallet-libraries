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

/// How many blocks a transaction stays valid for after the height it is built
/// against.
///
/// The same figure the reference wallet uses. Long enough to survive a slow
/// relay, short enough that an abandoned transaction stops holding its inputs
/// hostage.
const EXPIRY_DELTA: u32 = 40;

/// Returns the height a transaction built now expects to be mined at.
///
/// This is what selects the consensus rules it is built for, and what its
/// expiry is measured from. It comes from the chain tip rather than from the
/// anchor: the anchor is the most recent block both commitment trees hold a
/// checkpoint for, which during recovery can sit a long way below the tip, and
/// rules taken from a stale height can be the rules of an upgrade the chain has
/// already left.
///
/// The anchor is the floor, because a tip below it would mean the wallet had
/// scanned past what the server admits to having.
fn target_height(tip: Option<BlockHeight>, anchor: BlockHeight) -> BlockHeight {
    std::cmp::max(tip.unwrap_or(anchor), anchor) + 1
}

/// Returns the height past which a transaction aimed at `target` is no longer
/// valid.
///
/// Deliberately not the height the branch is chosen from. A transaction is
/// mined near the tip and expires forty blocks later, so choosing rules from
/// the expiry would build for an upgrade that may not have activated by the
/// time it is actually mined.
fn expiry_height(target: BlockHeight) -> BlockHeight {
    target + EXPIRY_DELTA
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

/// A transaction that has been built but not yet broadcast.
///
/// Carries the height it was built against, so that recording it later reads it
/// back under the same rules it was written under.
struct Built {
    raw: Vec<u8>,
    txid: zcash_protocol::TxId,
    fee: Zatoshis,
    target: BlockHeight,
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
    /// Set when the payment was sent but the wallet could not record it.
    ///
    /// The money is gone either way, so this is not a failure of the send. It
    /// means the balance and history will not account for it until the next
    /// scan finds it, which is worth saying rather than leaving somebody to
    /// notice a figure that looks wrong.
    pub warning: Option<String>,
}

impl Wallet {
    /// Works out what a payment would cost, without proving it.
    pub fn quote(&self, account: u32, to: &str, amount: u64) -> Result<SpendQuote, Error> {
        if amount == 0 {
            return Err(Error::Build(
                "a payment has to be for more than nothing".to_owned(),
            ));
        }
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
        if amount == 0 {
            return Err(Error::Build(
                "a payment has to be for more than nothing".to_owned(),
            ));
        }
        let recipient = crate::address::parse(&self.params, to)?;
        let amount = Zatoshis::from_u64(amount)
            .map_err(|_| Error::Build("that is not a valid amount".to_owned()))?;
        let account = Self::account_id(account);
        let params = self.params;

        let built = self.with_writer_pausing_sync(|db| {
            let spend_keys = keys::spending_keys(db, &params, account, seed)?;
            let chosen = route(db, &params, account, amount)?;

            // One authoritative height for the whole transaction. It decides
            // which consensus rules it is built for, what it expires at, and
            // which rules it is parsed back under when it is recorded — and
            // those three disagreeing is precisely the bug that is invisible
            // until an upgrade boundary falls between them.
            let target = match &chosen {
                Route::Ironwood { target, .. } | Route::Crossing { target, .. } => *target,
            };
            let branch_id = BranchId::for_height(&params, target);

            let (tx, fee) = match &chosen {
                Route::Ironwood {
                    proposal,
                    witnesses,
                    anchors,
                    ..
                } => {
                    let expiry = expiry_height(target);
                    let request = zakura_wallet_tx::SpendRequest {
                        proposal,
                        witnesses,
                        keys: &spend_keys,
                        recipient,
                        anchors,
                    };
                    let tx = zakura_wallet_tx::payment(
                        &request,
                        branch_id,
                        expiry,
                        zakura_wallet_tx::circuit::proving_key(),
                        rand::rng(),
                    )?;
                    (tx, proposal.fee)
                }
                Route::Crossing {
                    plan,
                    witness,
                    anchors,
                    ..
                } => {
                    // The expiry belongs to the plan, not to us: an ordinary
                    // one would single this transaction out from the crossings
                    // it is meant to be indistinguishable from. `transaction`
                    // reads the shape back off the bytes it produced and
                    // refuses a non-conforming result, so a wrong crossing
                    // cannot be returned here — only paid for.
                    let tx = zakura_wallet_tx::crossing::transaction(
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
                    )?;
                    (tx, plan.fee)
                }
            };

            // Verifying locally is the only way to learn that a witness was
            // taken at the wrong position before consensus does, and consensus
            // says so months later by rejecting a proof.
            zakura_wallet_tx::verify_proofs(&tx, zakura_wallet_tx::circuit::verifying_key())?;

            let raw = zakura_wallet_tx::transaction::to_bytes(&tx)?;
            Ok(Built {
                raw,
                txid: tx.txid(),
                fee,
                target,
            })
        })?;

        // Record before broadcasting, not after. The two failure modes are not
        // symmetric.
        //
        // Recording first and then failing to broadcast leaves the wallet
        // holding a spend of notes that are in fact still unspent. That
        // corrects itself: the transaction is never mined, a server eventually
        // says it does not have it, and once its expiry height has passed the
        // notes are released. This wallet did not always have that, and the
        // earlier ordering here was chosen when it did not.
        //
        // Broadcasting first and then failing to record leaves a live
        // transaction the wallet knows nothing about, spending notes it still
        // believes are free. Nothing corrects that: the next payment is built
        // from the same notes, and one of the two is refused. A crash between
        // the two calls is exactly this case, and returns no warning to
        // anybody.
        self.record_sent(account, to, &built)?;

        let response = self.broadcast(&built.raw)?;

        Ok(SendReceipt {
            txid: *built.txid.as_ref(),
            raw: built.raw,
            server_response: response,
            warning: None,
        })
    }

    /// Records a transaction this wallet just broadcast.
    ///
    /// Decrypting the wallet's own transaction is how its outputs and spends
    /// are learned, and it is the same path a transaction found on the chain
    /// takes — so what is stored is the shape the scanner would have stored
    /// anyway, and the two cannot disagree when it is finally mined.
    ///
    /// Parsed at the height it was built for. A transaction is read under the
    /// consensus rules of a height, and reading it under different ones than it
    /// was written under is only harmless while no upgrade falls between them.
    fn record_sent(
        &self,
        account: zakura_wallet_core::AccountId,
        to: &str,
        built: &Built,
    ) -> Result<(), Error> {
        let params = self.params;

        self.with_writer_pausing_sync(|db| {
            let stored = db
                .account(&params, account)?
                .ok_or(Error::NoSuchAccount(account.0))?;
            let scan_keys = zakura_wallet_scan::ScanKeys::from_accounts([(
                account,
                stored.orchard_fvk()?.clone(),
            )]);

            // The wallet's own transparent side matters here as much as the
            // shielded one: a transaction that spends the wallet's UTXOs must
            // mark them spent at broadcast, not when a later scan happens to
            // notice, or the balance offers funds that are already committed.
            let watch = zakura_wallet_sync::merge_watch(
                &zakura_wallet_scan::TransparentWatch::default(),
                db.transparent_watch()?,
            );

            let enhanced = zakura_wallet_scan::enhance::decrypt_transaction(
                &params,
                &scan_keys,
                &watch,
                built.txid,
                built.target,
                &built.raw,
            )
            .map_err(|e| Error::Build(e.to_string()))?;

            let created = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);

            db.store_sent_transaction(
                &params,
                &enhanced,
                built.fee,
                built.target,
                created,
                Some(to),
            )?;
            Ok(())
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
/// How a payment can be made, given where the account's money is.
pub(crate) enum Route {
    /// An ordinary Ironwood-funded payment.
    Ironwood {
        proposal: zakura_wallet_tx::Proposal,
        witnesses: Vec<(zakura_wallet_tx::SpendableNote, orchard::tree::MerklePath)>,
        anchors: zakura_wallet_tx::Anchors,
        /// Where it expects to be mined, and so which rules it is built for.
        target: BlockHeight,
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
        /// The height the plan was made against, which is the same one its
        /// rules and its conformance were judged at.
        target: BlockHeight,
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

            let target = target_height(db.chain_tip()?, anchors.height);
            return Ok(Route::Ironwood {
                proposal,
                witnesses,
                anchors,
                target,
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

    let target = target_height(db.chain_tip()?, anchors.height);
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
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    /// During recovery the anchor can sit far below the tip, and heights
    /// measured from it name a block the chain passed long ago.
    #[test]
    fn the_target_follows_the_tip_not_a_lagging_anchor() {
        assert_eq!(target_height(Some(h(2_000_000)), h(1_000_000)), h(2_000_001));
    }

    #[test]
    fn the_target_falls_back_to_the_anchor_when_no_tip_is_known() {
        assert_eq!(target_height(None, h(1_000_000)), h(1_000_001));
    }

    /// A tip below the anchor would mean the wallet had scanned past what the
    /// server admits to; the anchor is the floor either way.
    #[test]
    fn the_anchor_is_the_floor() {
        assert_eq!(target_height(Some(h(900_000)), h(1_000_000)), h(1_000_001));
    }

    /// The defect this split exists for. A transaction is mined near the tip
    /// and expires forty blocks later, so the rules it is built under must come
    /// from where it will be mined — not from its expiry, which is far enough
    /// ahead that an upgrade can activate in between. Building for rules that
    /// are not yet in force produces a transaction consensus rejects, and the
    /// two heights being the same number is exactly what hides it.
    #[test]
    fn the_expiry_is_well_past_the_target_it_is_measured_from() {
        let target = target_height(Some(h(2_000_000)), h(1_999_000));
        let expiry = expiry_height(target);

        assert_eq!(target, h(2_000_001));
        assert_eq!(expiry, h(2_000_041));
        assert!(
            u32::from(expiry) - u32::from(target) == EXPIRY_DELTA,
            "the gap between them is where an upgrade can hide"
        );
    }
}
