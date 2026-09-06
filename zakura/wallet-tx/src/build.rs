//! Building and proving the bundles a proposal describes.
//!
//! A transaction carries at most one bundle per Orchard-family pool, and each
//! is proved against its own tree at a *shared* anchor height. Proving is the
//! expensive step — seconds, not milliseconds — so it runs once, against a plan
//! already known to balance.

use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags},
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    tree::MerklePath,
    value::NoteValue,
};
use rand::{CryptoRng, Rng};
use zakura_wallet_core::pool::PoolId;
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::{Anchors, Error, Proposal, SpendableNote, transaction::UnprovenBundles};

/// Returns whether `fvk` owns `address`.
fn owns(fvk: &FullViewingKey, address: &orchard::Address) -> bool {
    fvk.scope_for_address(address).is_some()
}

/// The key material a spend needs.
///
/// A viewing key alone cannot spend: the bundle's spend authorisation
/// signatures require the spending key. Holding them together makes it
/// impossible to reach the builder with only half of what it needs.
pub struct Keys {
    /// The account's spending key.
    pub sk: SpendingKey,
    /// The full viewing key derived from it.
    pub fvk: FullViewingKey,
}

impl Keys {
    /// Derives both from a spending key.
    pub fn from_spending_key(sk: SpendingKey) -> Self {
        let fvk = FullViewingKey::from(&sk);
        Self { sk, fvk }
    }
}

/// Verifies every proof a transaction carries.
///
/// This is what proves the wallet's witnesses are right. A witness taken at the
/// wrong position, or against a tree that has drifted from the chain's,
/// produces a proof that does not verify — and verifying locally is the only
/// way to learn that before consensus does.
pub fn verify_proofs(
    tx: &zcash_primitives::transaction::Transaction,
    vk: &VerifyingKey,
) -> Result<(), Error> {
    for (pool, bundle) in [
        (PoolId::Orchard, tx.orchard_bundle()),
        (PoolId::Ironwood, tx.ironwood_bundle()),
    ] {
        if let Some(bundle) = bundle {
            bundle
                .verify_proof(vk)
                .map_err(|e| Error::Build(format!("the {pool:?} proof did not verify: {e:?}")))?;
        }
    }
    Ok(())
}

/// Returns how many actions each of a transaction's bundles carries.
pub fn action_counts(tx: &zcash_primitives::transaction::Transaction) -> (usize, usize) {
    (
        tx.orchard_bundle().map_or(0, |b| b.actions().len()),
        tx.ironwood_bundle().map_or(0, |b| b.actions().len()),
    )
}

/// Everything needed to build the bundles a proposal describes.
///
/// Gathered into one value because the parts are not independently meaningful:
/// witnesses belong to the proposal's inputs, the anchors are the ones those
/// witnesses were taken against, and the sighash is the transaction all of them
/// are going into.
pub struct SpendRequest<'a> {
    /// The plan: which notes, what payment, what fee.
    pub proposal: &'a Proposal,
    /// The spendable notes with their authentication paths.
    pub witnesses: &'a [(SpendableNote, MerklePath)],
    /// The account's keys.
    pub keys: &'a Keys,
    /// Who is being paid.
    pub recipient: orchard::Address,
    /// The anchors the witnesses were taken against.
    pub anchors: &'a Anchors,
}

/// Builds the bundles a proposal describes, unproven and unsigned.
///
/// Proving and signing happen during assembly, because the signatures commit to
/// the transaction's signature hash and that does not exist until the bundles
/// have been assembled into one.
pub fn bundles<R: Rng + CryptoRng>(
    request: &SpendRequest<'_>,
    // Taken by value and reborrowed, rather than cloned: a cryptographic RNG
    // that could be cloned would let two bundles be built from the same
    // randomness.
    mut rng: R,
) -> Result<UnprovenBundles, Error> {
    let SpendRequest {
        proposal,
        witnesses,
        keys,
        recipient,
        anchors,
    } = *request;
    if !proposal.balances() {
        return Err(Error::Build(
            "the proposal does not balance; building it would produce a transaction \
             consensus rejects after the proving is already paid for"
                .into(),
        ));
    }

    // A proposal whose inputs and output straddle the pools is a pool crossing,
    // and this function cannot build one canonically. It would produce an
    // Orchard bundle that is spend-only with a positive value balance and an
    // Ironwood bundle carrying the payment — structurally a crossing, but with
    // the wrong action counts, fee, expiry and anchor, and so distinguishable
    // from every crossing built properly.
    //
    // `select` refuses this too. It is repeated here because a `Proposal` is a
    // plain struct a caller can build by hand, and the guard below — which only
    // fires when the *Orchard bundle itself* pays a stranger — never sees this
    // shape.
    if proposal
        .inputs
        .iter()
        .any(|input| input.pool != proposal.output_pool)
    {
        return Err(Error::CrossingRequired);
    }

    // A ZIP 318 crossing never carries a transparent bundle, and one that did
    // would be classified as nonconforming — which is worse than not crossing
    // at all, because it is a transaction announcing that it tried.
    if !proposal.transparent_inputs.is_empty() && proposal.output_pool == PoolId::Orchard {
        return Err(Error::CrossingRequired);
    }

    let mut built = UnprovenBundles::default();

    for pool in PoolId::ALL {
        let spends: Vec<_> = witnesses
            .iter()
            .filter(|(note, _)| {
                note.pool == pool
                    && proposal
                        .inputs
                        .iter()
                        .any(|i| i.pool == pool && i.position == note.position)
            })
            .collect();

        let pays_here = proposal.output_pool == pool;
        if spends.is_empty() && !pays_here {
            continue;
        }

        // The bundle version fixes both the anchor's tree and the note
        // plaintext version its outputs carry, so the two cannot drift apart.
        //
        // The flags differ, and consensus requires them to. From NU6.3 the
        // Orchard pool prohibits cross-address transfers, so a bundle that
        // claimed to permit them is unrepresentable; Ironwood is the pool where
        // they are allowed, and that permission is what a pool crossing needs.
        let (version, anchor, flags) = match pool {
            PoolId::Orchard => (
                BundleVersion::orchard_v3(),
                anchors.orchard,
                Flags::CROSS_ADDRESS_DISABLED,
            ),
            PoolId::Ironwood => (
                BundleVersion::ironwood_v3(),
                anchors.ironwood,
                Flags::ENABLED,
            ),
        };

        let mut builder = Builder::new(
            BundleType::Transactional {
                bundle_required: false,
                pad_to_minimum: None,
            },
            version,
            flags,
            anchor,
        )
        .map_err(|e| Error::Build(format!("{pool:?} builder: {e:?}")))?;

        for (note, path) in &spends {
            builder
                .add_spend(keys.fvk.clone(), note.note, path.clone())
                .map_err(|e| Error::Build(format!("{pool:?} spend: {e:?}")))?;
        }

        if pays_here {
            // Paying a third party from the Orchard pool is not a policy this
            // wallet chooses: from NU6.3 the Orchard pool prohibits
            // cross-address transfers outright, and the builder refuses. Value
            // leaves Orchard only through a bundle's value balance, into an
            // Ironwood bundle that makes the payment — which is to say, an
            // Orchard payment is *necessarily* a pool crossing. Saying so here
            // is better than surfacing `CrossAddressDisabled` from three layers
            // down.
            if pool == PoolId::Orchard && !owns(&keys.fvk, &recipient) {
                return Err(Error::CrossingRequired);
            }

            // In a bundle with cross-address disabled every retained output is
            // an owned one, and the builder needs to pair it with a fabricated
            // zero-valued spend at the same address. `add_output` refuses
            // outright there, whether or not the recipient is ours, so the
            // owned path is the only one available.
            if flags.cross_address_enabled() {
                builder
                    .add_output(
                        Some(keys.fvk.to_ovk(Scope::External)),
                        recipient,
                        NoteValue::from_raw(proposal.amount.into_u64()),
                        crate::NO_MEMO,
                    )
                    .map_err(|e| Error::Build(format!("{pool:?} payment: {e:?}")))?;
            } else {
                builder
                    .add_change_output(
                        keys.fvk.clone(),
                        Some(keys.fvk.to_ovk(Scope::External)),
                        recipient,
                        NoteValue::from_raw(proposal.amount.into_u64()),
                        crate::NO_MEMO,
                    )
                    .map_err(|e| Error::Build(format!("{pool:?} payment: {e:?}")))?;
            }

            if let Some(change) = proposal.change {
                // Change goes to the account's internal address. That is what
                // makes it recognisable as change on a later scan whatever
                // order blocks arrive in — the scan-order argument that the
                // differential test documents.
                //
                // `add_change_output` rather than `add_output`: in a bundle
                // that disables cross-address transfers it is the only way to
                // retain value, because the builder has to pair the output with
                // a fabricated zero-valued spend at the same address. In a
                // bundle that permits them it behaves the same as an ordinary
                // owned output, so change handling stays uniform.
                builder
                    .add_change_output(
                        keys.fvk.clone(),
                        Some(keys.fvk.to_ovk(Scope::Internal)),
                        keys.fvk.address_at(0u32, Scope::Internal),
                        NoteValue::from_raw(change.into_u64()),
                        crate::NO_MEMO,
                    )
                    .map_err(|e| Error::Build(format!("{pool:?} change: {e:?}")))?;
            }
        }

        let Some((bundle, _meta)) = builder
            .build::<i64>(&mut rng)
            .map_err(|e| Error::Build(format!("{pool:?} build: {e:?}")))?
        else {
            continue;
        };

        match pool {
            PoolId::Orchard => built.orchard = Some(bundle),
            PoolId::Ironwood => built.ironwood = Some(bundle),
        }
    }

    Ok(built)
}

/// Builds, proves and signs the transaction a proposal describes.
pub fn transaction<R: Rng + CryptoRng>(
    request: &SpendRequest<'_>,
    branch_id: BranchId,
    expiry: BlockHeight,
    proving_key: &ProvingKey,
    mut rng: R,
) -> Result<zcash_primitives::transaction::Transaction, Error> {
    let unproven = bundles(request, &mut rng)?;
    crate::transaction::assemble(
        unproven,
        branch_id,
        expiry,
        request.keys,
        proving_key,
        &mut rng,
    )
}


/// Builds the transparent half of a transaction, with the keys to sign it.
///
/// Returns `None` when there is nothing transparent to build, which is the
/// ordinary shielded case.
///
/// The signing set and the builder are populated together and from the same
/// derivation, which is what makes them agree: `add_key` hands back the public
/// key it stored, and that same key goes into the input. Deriving twice — once
/// for each — would let a mistake in one go unnoticed until a signature failed
/// to verify.
pub fn transparent_bundle(
    proposal: &crate::select::Proposal,
    transparent_key: Option<&transparent::keys::AccountPrivKey>,
) -> Result<
    Option<(
        transparent::bundle::Bundle<transparent::builder::Unauthorized>,
        transparent::builder::TransparentSigningSet,
    )>,
    Error,
> {
    if proposal.transparent_inputs.is_empty() && proposal.transparent_payment.is_none() {
        return Ok(None);
    }

    let mut builder = transparent::builder::TransparentBuilder::empty();
    let mut signing = transparent::builder::TransparentSigningSet::new();

    for utxo in &proposal.transparent_inputs {
        let key = transparent_key.ok_or_else(|| {
            Error::Build("a transparent input needs a transparent spending key".into())
        })?;
        let index = transparent::keys::NonHardenedChildIndex::from_index(utxo.index)
            .ok_or_else(|| Error::Build(format!("{} is not a valid address index", utxo.index)))?;
        let scope = match utxo.scope {
            zakura_wallet_core::KeyScope::External => {
                transparent::keys::TransparentKeyScope::EXTERNAL
            }
            zakura_wallet_core::KeyScope::Internal => {
                transparent::keys::TransparentKeyScope::INTERNAL
            }
        };

        let sk = key
            .derive_secret_key(scope, index)
            .map_err(|e| Error::Build(format!("deriving a transparent key: {e:?}")))?;
        let pubkey = signing.add_key(sk);

        // Checks up front that this key can actually spend this output, by
        // comparing its hash against the script being spent. A derivation
        // mistake fails here rather than at consensus.
        builder
            .add_p2pkh_input(pubkey, utxo.outpoint.clone(), utxo.txout.clone())
            .map_err(|e| Error::Build(format!("adding a transparent input: {e:?}")))?;
    }

    if let Some((address, value)) = &proposal.transparent_payment {
        builder
            .add_output(address, *value)
            .map_err(|e| Error::Build(format!("adding a transparent output: {e:?}")))?;
    }

    let bundle = builder
        .build()
        .ok_or_else(|| Error::Build("the transparent bundle is empty".into()))?;

    // The fee was computed from the proposal's own view of its transparent
    // size. If the bundle disagrees, the transaction is about to be built at a
    // fee it does not owe — which fails as unbalanced only after proving.
    let built = crate::fee::TransparentSizes::p2pkh(
        bundle.vin.len(),
        bundle.vout.len(),
    );
    if built != proposal.transparent_sizes() {
        return Err(Error::Build(
            "the built transparent bundle is a different size than the fee assumed".into(),
        ));
    }

    Ok(Some((bundle, signing)))
}
