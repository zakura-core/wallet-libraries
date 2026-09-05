//! Assembling bundles into a signed transaction.
//!
//! The order here is forced by the protocol and is worth stating, because it is
//! not the obvious one: the spend authorisation signatures commit to the
//! transaction's signature hash, and the signature hash is computed from the
//! transaction — so the transaction has to be assembled *before* it can be
//! signed. What makes that possible is that a v6 signature hash does not commit
//! to the bundle proofs, so the sequence is:
//!
//! 1. build each bundle, unproven and unsigned;
//! 2. assemble them into a transaction;
//! 3. take its signature hash;
//! 4. prove and sign each bundle against that hash;
//! 5. reassemble, now authorised.
//!
//! A wallet that signed first would produce signatures over nothing, and the
//! failure would appear as a rejected transaction rather than as a mistake.

use orchard::{
    builder::{InProgress, Unauthorized as OrchardUnauthorized, Unproven},
    bundle::{Authorized as OrchardAuthorized, Bundle},
    circuit::ProvingKey,
    keys::SpendAuthorizingKey,
};
use rand::{CryptoRng, Rng};
use zcash_primitives::transaction::{
    Authorized, Transaction, TransactionData, TxVersion, Unauthorized,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::ZatBalance,
};

use crate::{Error, Keys};

/// A bundle that has been built but neither proved nor signed.
pub type UnprovenBundle = Bundle<InProgress<Unproven, OrchardUnauthorized>, i64>;

/// The bundles a transaction will carry, before proving.
#[derive(Default)]
pub struct UnprovenBundles {
    /// The Orchard bundle, if any.
    pub orchard: Option<UnprovenBundle>,
    /// The Ironwood bundle, if any.
    pub ironwood: Option<UnprovenBundle>,
}

/// Assembles, proves and signs a transaction carrying `bundles`.
///
/// `expiry` is the height beyond which the transaction is no longer valid.
/// For a pool crossing it must be the canonical expiry: an ordinary one would
/// single the transaction out from the crossings it is meant to be
/// indistinguishable from.
pub fn assemble<R: Rng + CryptoRng>(
    bundles: UnprovenBundles,
    branch_id: BranchId,
    expiry: BlockHeight,
    keys: &Keys,
    proving_key: &ProvingKey,
    mut rng: R,
) -> Result<Transaction, Error> {
    if bundles.orchard.is_none() && bundles.ironwood.is_none() {
        return Err(Error::Build("a transaction with no bundles".into()));
    }

    // Value balances move from the builder's `i64` to the protocol's checked
    // type here rather than earlier, so that an out-of-range balance is caught
    // once, at the boundary, instead of being re-checked at every step.
    let to_balance = |bundle: UnprovenBundle| -> Result<Bundle<_, ZatBalance>, Error> {
        bundle.try_map_value_balance::<_, (), _>(|v| {
            ZatBalance::from_i64(v).map_err(|_| ())
        })
        .map_err(|()| Error::Build("a bundle's value balance is out of range".into()))
    };

    let orchard = bundles.orchard.map(to_balance).transpose()?;
    let ironwood = bundles.ironwood.map(to_balance).transpose()?;

    // Ironwood exists only in v6 transactions, and both pools' bundles are
    // carried by the same one, so the version is not a choice.
    let unauthed: TransactionData<Unauthorized> = TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry,
        None,
        None,
        orchard.clone(),
        ironwood.clone(),
    );
    debug_assert_eq!(unauthed.version(), TxVersion::V6);

    let txid_parts = unauthed.digest(TxIdDigester);
    let sighash = signature_hash(&unauthed, &SignableInput::Shielded, &txid_parts);
    let sighash: [u8; 32] = *sighash.as_ref();

    let ask = SpendAuthorizingKey::from(&keys.sk);
    let authorize = |bundle: Option<Bundle<_, ZatBalance>>,
                     rng: &mut R,
                     what: &str|
     -> Result<Option<Bundle<OrchardAuthorized, ZatBalance>>, Error> {
        bundle
            .map(|b| {
                b.create_proof(proving_key, &mut *rng)
                    .map_err(|e| Error::Build(format!("{what} proving: {e:?}")))?
                    .apply_signatures(&mut *rng, sighash, std::slice::from_ref(&ask))
                    .map_err(|e| Error::Build(format!("{what} signing: {e:?}")))
            })
            .transpose()
    };

    let orchard = authorize(orchard, &mut rng, "the Orchard bundle")?;
    let ironwood = authorize(ironwood, &mut rng, "the Ironwood bundle")?;

    let authorized: TransactionData<Authorized> =
        TransactionData::from_parts_v6(branch_id, 0, expiry, None, None, orchard, ironwood);

    authorized
        .freeze()
        .map_err(|e| Error::Build(format!("the transaction could not be serialised: {e}")))
}

/// Returns a transaction's bytes, as they would go on the wire.
pub fn to_bytes(tx: &Transaction) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| Error::Build(format!("the transaction could not be written: {e}")))?;
    Ok(bytes)
}
