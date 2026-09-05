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
                        [0u8; 512],
                    )
                    .map_err(|e| Error::Build(format!("{pool:?} payment: {e:?}")))?;
            } else {
                builder
                    .add_change_output(
                        keys.fvk.clone(),
                        Some(keys.fvk.to_ovk(Scope::External)),
                        recipient,
                        NoteValue::from_raw(proposal.amount.into_u64()),
                        [0u8; 512],
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
                        [0u8; 512],
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
