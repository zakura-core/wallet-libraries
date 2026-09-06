//! Pool crossings: moving value from Orchard to Ironwood.
//!
//! From NU6.3 the Orchard pool prohibits cross-address transfers, so value
//! leaves it only through a bundle's value balance and into an Ironwood bundle
//! that makes the payment. An Orchard-funded payment to anyone else is
//! therefore a *crossing*, and consensus leaves no other path.
//!
//! [ZIP 318] fixes what a crossing looks like, and the shape is the whole
//! point: every crossing must look like every other one, so that a wallet
//! quietly migrating its own funds and a wallet paying somebody are
//! indistinguishable. That means a crossing is not "a transaction that happens
//! to cross" but a transaction of one exact form:
//!
//! - exactly [`CROSSING_SOURCE_ACTIONS`] Orchard actions — one spend and one
//!   change output, or a padding dummy where the note covers the crossing
//!   exactly;
//! - exactly [`CROSSING_DESTINATION_ACTIONS`] Ironwood action, carrying the
//!   whole payment;
//! - a value on the canonical one-two-five denomination series;
//! - an expiry on the canonical window, and an anchor on the shared grid;
//! - the canonical fee, and no other bundles at all.
//!
//! Every one of those is a way to stand out by getting it wrong, which is why
//! this module builds the shape rather than leaving it to a caller.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use orchard::tree::MerklePath;
use zcash_protocol::{
    consensus::BlockHeight,
    value::Zatoshis,
    zip318::{
        AnchorBucketInterval, CROSSING_DESTINATION_ACTIONS, CROSSING_SOURCE_ACTIONS,
        PoolMigrationConstants, Zip318Classification, Zip318Evidence, Zip318TxKind, classify,
    },
};

use crate::{Anchors, Error, SpendableNote, fee};

/// The ZIP 318 parameters this wallet uses.
///
/// The trait's own documentation is emphatic that the network types must not be
/// implementors: a wallet retains its anchor checkpoints on one grid, and a
/// transfer anchored to a boundary it did not retain cannot be proved. So the
/// wallet owns the constants, and everything that needs them takes them from
/// here rather than deriving a second, silently different answer.
#[derive(Clone, Copy, Debug, Default)]
pub struct CrossingParams;

impl PoolMigrationConstants for CrossingParams {}

/// The fee a canonical crossing pays.
///
/// Fixed by the shape rather than by the transaction's contents: two Orchard
/// actions and one Ironwood action, whatever the wallet actually holds.
pub fn canonical_fee() -> Zatoshis {
    fee::required(CROSSING_SOURCE_ACTIONS, CROSSING_DESTINATION_ACTIONS)
}

/// A crossing, planned but not yet built.
#[derive(Debug, Clone)]
pub struct CrossingPlan {
    /// The single Orchard note funding it.
    ///
    /// One note, not several: the source side has exactly two actions, and a
    /// second spend would need a third. A wallet whose notes are all too small
    /// must first consolidate, which is what ZIP 318 preparation transactions
    /// are for.
    pub source: SpendableNote,
    /// The value crossing, on the canonical denomination series.
    pub denomination: Zatoshis,
    /// What stays behind in the Orchard pool.
    pub change: Zatoshis,
    /// The fee.
    pub fee: Zatoshis,
    /// The height the transaction expires at.
    pub expiry: BlockHeight,
    /// The height the transaction was planned against.
    ///
    /// Kept because the canonical expiry is derived from it and the derivation
    /// has no inverse: checking the built transaction's expiry needs the height
    /// it was computed from, not the expiry itself.
    pub target_height: BlockHeight,
}

impl CrossingPlan {
    /// Returns whether the plan balances.
    ///
    /// The two bundles' value balances must be equal and opposite up to the
    /// fee: the Orchard bundle gives up the denomination plus the fee, and the
    /// Ironwood bundle takes the denomination.
    pub fn balances(&self) -> bool {
        (self.denomination + self.change)
            .and_then(|v| v + self.fee)
            .is_some_and(|total| total == self.source.value())
    }

    /// Returns the value balance each bundle will declare.
    ///
    /// Positive leaves a pool, negative enters it.
    pub fn value_balances(&self) -> (i64, i64) {
        let leaving = self.denomination.into_u64() as i64 + self.fee.into_u64() as i64;
        (leaving, -(self.denomination.into_u64() as i64))
    }
}

/// Plans a crossing of `denomination` from the wallet's Orchard notes.
///
/// Fails rather than adjusting when the request cannot be made canonical: a
/// crossing that is nearly the right shape is worse than none, because it
/// stands out from the ones that are.
pub fn plan(
    available: &[(SpendableNote, MerklePath)],
    denomination: Zatoshis,
    anchors: &Anchors,
    target_height: BlockHeight,
    constants: &impl PoolMigrationConstants,
) -> Result<CrossingPlan, Error> {
    if !constants.is_canonical_denomination(denomination) {
        return Err(Error::NotCanonical(format!(
            "{} zatoshis is not a canonical denomination; a crossing carrying it \
             would be distinguishable from every other crossing",
            denomination.into_u64()
        )));
    }

    // The anchor must sit on the grid every wallet's crossings share. Off it,
    // the transaction announces which wallet built it.
    if !constants
        .anchor_bucket_interval()
        .is_boundary(anchors.height)
    {
        return Err(Error::NotCanonical(format!(
            "the anchor at height {} is not on the {}-block grid crossings share",
            anchors.height,
            constants.anchor_bucket_interval().block_count()
        )));
    }

    let fee = canonical_fee();
    let needed = (denomination + fee).ok_or(Error::ValueOverflow)?;

    // Exactly one note, and it has to cover the whole crossing on its own.
    let source = available
        .iter()
        .map(|(note, _)| note)
        .filter(|note| note.pool == zakura_wallet_core::pool::PoolId::Orchard)
        .filter(|note| note.value() >= needed)
        // The smallest note that suffices, so the largest are left intact for
        // the crossings that need them.
        .min_by_key(|note| note.value().into_u64())
        .ok_or(Error::NoSuitableNote {
            required: needed,
        })?
        .clone();

    let change = (source.value() - needed).expect("the note was checked to cover this");

    let plan = CrossingPlan {
        source,
        denomination,
        change,
        fee,
        expiry: constants.canonical_expiry(target_height),
        target_height,
    };
    debug_assert!(plan.balances(), "a planned crossing must balance");
    Ok(plan)
}

/// Returns the evidence a classifier needs about a crossing this wallet built.
///
/// Assembled from the plan rather than from the finished transaction, so that
/// the shape can be checked *before* the expensive part. A wallet that only
/// discovers its transaction is non-conforming after proving has already paid
/// for the proof and, worse, is holding something it should not send.
pub fn evidence(plan: &CrossingPlan, anchors: &Anchors, target_height: BlockHeight) -> Zip318Evidence {
    let constants = CrossingParams;
    Zip318Evidence::default()
        .with_source_actions(Some(CROSSING_SOURCE_ACTIONS))
        .with_destination_actions(Some(CROSSING_DESTINATION_ACTIONS))
        // A crossing carries no transparent, Sapling or other bundle. Anything
        // else is a different transaction wearing a crossing's clothes.
        .with_other_bundles_present(Some(false))
        .with_source_is_send_to_self(Some(true))
        .with_sole_destination_value(Some(plan.denomination))
        .with_expiry_is_canonical(Some(
            constants.is_canonical_expiry(plan.expiry, target_height),
        ))
        .with_anchor_on_grid(Some(
            constants.anchor_bucket_interval().is_boundary(anchors.height),
        ))
        .with_fee_is_canonical(Some(plan.fee == canonical_fee()))
}

/// Returns the evidence a classifier needs about a crossing that has been
/// *built*, read off the transaction itself.
///
/// [`evidence`] answers the shape clauses from constants, because at plan time
/// there is nothing else to answer them from. That makes it a restatement of
/// what [`plan`] already refused on, and it cannot observe a defect introduced
/// between planning and building — a bundle padded to the wrong width, a
/// transparent bundle that crept in, a fee that does not match the shape.
///
/// This reads them from the assembled transaction instead. Six of the eight
/// clauses become measurements of the bytes that will actually be broadcast:
/// both action counts, whether any other bundle is present, the expiry, the
/// denomination (from the destination bundle's value balance) and the fee (from
/// the two balances summed). Only the anchor's position on the grid is not
/// recoverable from the transaction alone, since the anchor is a root rather
/// than a height, so it is carried from the anchors the bundles were proved
/// against.
pub fn evidence_from_transaction(
    tx: &zcash_primitives::transaction::Transaction,
    anchors: &Anchors,
    target_height: BlockHeight,
) -> Zip318Evidence {
    let constants = CrossingParams;

    let source_actions = tx.orchard_bundle().map_or(0, |b| b.actions().len());
    let destination_actions = tx.ironwood_bundle().map_or(0, |b| b.actions().len());

    // No ZIP 318 transaction carries a transparent or Sapling bundle, so either
    // is a refutation on its own.
    let other_bundles_present = tx
        .transparent_bundle()
        .is_some_and(|b| !b.vin.is_empty() || !b.vout.is_empty())
        || tx
            .sapling_bundle()
            .is_some_and(|b| !b.shielded_spends().is_empty() || !b.shielded_outputs().is_empty());

    // The two bundles are joined by their value balances: the source gives up
    // the denomination plus the fee, the destination takes the denomination, and
    // what is left over is what the transaction pays.
    let source_balance = tx.orchard_bundle().map_or(0i64, |b| (*b.value_balance()).into());
    let destination_balance = tx.ironwood_bundle().map_or(0i64, |b| (*b.value_balance()).into());
    let denomination = u64::try_from(-destination_balance)
        .ok()
        .and_then(|v| Zatoshis::from_u64(v).ok());
    let fee = u64::try_from(source_balance + destination_balance)
        .ok()
        .and_then(|v| Zatoshis::from_u64(v).ok());

    Zip318Evidence::default()
        .with_source_actions(Some(source_actions))
        .with_destination_actions(Some(destination_actions))
        .with_other_bundles_present(Some(other_bundles_present))
        // The wallet built the source side to pay itself, and unlike an
        // observer it knows that rather than inferring it.
        .with_source_is_send_to_self(Some(true))
        .with_sole_destination_value(denomination)
        .with_expiry_is_canonical(Some(
            constants.is_canonical_expiry(tx.expiry_height(), target_height),
        ))
        .with_anchor_on_grid(Some(
            constants.anchor_bucket_interval().is_boundary(anchors.height),
        ))
        .with_fee_is_canonical(Some(fee == Some(canonical_fee())))
}

/// Returns how a ZIP 318 classifier will read a crossing this wallet built.
///
/// The wallet classifies its own transaction with the same function the network
/// will. That is the only way to know the shape is right: a wallet that decides
/// for itself what conformance means will drift from the definition, and the
/// drift is invisible until somebody's transaction stands out.
pub fn classification(
    plan: &CrossingPlan,
    anchors: &Anchors,
    target_height: BlockHeight,
) -> Zip318Classification {
    classify(&evidence(plan, anchors, target_height), &CrossingParams)
}

/// Returns whether a crossing will be indistinguishable from every other one.
///
/// This is the *pre-build* check, answered from the plan. It is worth running
/// before proving, which is the expensive part, but it can only confirm that
/// the plan asked for the right shape. [`built_conforms`] is what confirms the
/// wallet produced it.
pub fn conforms(plan: &CrossingPlan, anchors: &Anchors, target_height: BlockHeight) -> bool {
    classification(plan, anchors, target_height)
        == Zip318Classification::Conforms(Zip318TxKind::Transfer)
}

/// Returns whether a crossing the wallet has built is indistinguishable from
/// every other one.
///
/// Unlike [`conforms`], this reads the transaction rather than the plan, so it
/// can fail where the plan was right and the construction was not.
pub fn built_conforms(
    tx: &zcash_primitives::transaction::Transaction,
    anchors: &Anchors,
    target_height: BlockHeight,
) -> bool {
    classify(
        &evidence_from_transaction(tx, anchors, target_height),
        &CrossingParams,
    ) == Zip318Classification::Conforms(Zip318TxKind::Transfer)
}

/// Returns the anchor grid crossings are proved against.
pub fn anchor_grid() -> AnchorBucketInterval {
    CrossingParams.anchor_bucket_interval()
}

/// Everything needed to build a crossing.
///
/// Gathered into one value because the parts belong together: the witness is
/// the planned note's, the anchors are the ones it was taken against, and the
/// sighash is the transaction all of it goes into.
pub struct CrossingRequest<'a> {
    /// The planned crossing.
    pub plan: &'a CrossingPlan,
    /// The authentication path for the note the plan spends.
    pub witness: &'a MerklePath,
    /// The account's keys.
    pub keys: &'a crate::Keys,
    /// Who is being paid.
    pub recipient: orchard::Address,
    /// The anchors the two bundles are proved against.
    pub anchors: &'a Anchors,
}

/// Builds the two bundles a crossing is made of, unproven and unsigned.
///
/// The Orchard bundle spends one note and keeps the remainder; the Ironwood
/// bundle creates the payment. Neither is a transaction on its own: they are
/// joined by their value balances, which must be equal and opposite up to the
/// fee, and that is checked here rather than left for consensus to discover.
pub fn bundles<R: rand::Rng + rand::CryptoRng>(
    request: &CrossingRequest<'_>,
    mut rng: R,
) -> Result<crate::transaction::UnprovenBundles, Error> {
    let CrossingRequest {
        plan,
        witness,
        keys,
        recipient,
        anchors,
    } = request;
    use orchard::{
        builder::{Builder, BundleType},
        bundle::{BundleVersion, Flags},
        keys::Scope,
        value::NoteValue,
    };

    if !plan.balances() {
        return Err(Error::Build(
            "the crossing does not balance; the two bundles' value balances would not \
             sum to the fee"
                .into(),
        ));
    }

    // The source side: exactly two actions. One carries the real spend, the
    // other the change output — or a padding dummy where the note covers the
    // crossing exactly. Padding to two is what makes those two cases look the
    // same.
    let source_type = BundleType::Transactional {
        bundle_required: true,
        pad_to_minimum: Some(
            u8::try_from(CROSSING_SOURCE_ACTIONS).expect("two fits in a u8"),
        ),
    };
    let mut source = Builder::new(
        source_type,
        BundleVersion::orchard_v3(),
        Flags::CROSS_ADDRESS_DISABLED,
        anchors.orchard,
    )
    .map_err(|e| Error::Build(format!("crossing source builder: {e:?}")))?;

    source
        .add_spend(keys.fvk.clone(), plan.source.note, (*witness).clone())
        .map_err(|e| Error::Build(format!("crossing source spend: {e:?}")))?;

    if plan.change > Zatoshis::ZERO {
        source
            .add_change_output(
                keys.fvk.clone(),
                Some(keys.fvk.to_ovk(Scope::Internal)),
                keys.fvk.address_at(0u32, Scope::Internal),
                NoteValue::from_raw(plan.change.into_u64()),
                crate::NO_MEMO,
            )
            .map_err(|e| Error::Build(format!("crossing source change: {e:?}")))?;
    }

    // The destination side: exactly one action, unpadded. The default two-action
    // minimum exists to hide a transaction's shape, and a crossing's shape is
    // already public — the per-pool value balances reveal it — so padding here
    // would only make this crossing differ from the others.
    let destination_type = BundleType::Transactional {
        bundle_required: true,
        pad_to_minimum: Some(
            u8::try_from(CROSSING_DESTINATION_ACTIONS).expect("one fits in a u8"),
        ),
    };
    let mut destination = Builder::new(
        destination_type,
        BundleVersion::ironwood_v3(),
        Flags::ENABLED,
        anchors.ironwood,
    )
    .map_err(|e| Error::Build(format!("crossing destination builder: {e:?}")))?;

    destination
        .add_output(
            Some(keys.fvk.to_ovk(Scope::External)),
            *recipient,
            NoteValue::from_raw(plan.denomination.into_u64()),
            crate::NO_MEMO,
        )
        .map_err(|e| Error::Build(format!("crossing payment: {e:?}")))?;

    let finish = |builder: Builder, rng: &mut R, what: &str| {
        builder
            .build::<i64>(&mut *rng)
            .map_err(|e| Error::Build(format!("{what} build: {e:?}")))?
            .map(|(bundle, _)| bundle)
            .ok_or_else(|| Error::Build(format!("{what} produced no bundle")))
    };

    let orchard = finish(source, &mut rng, "crossing source")?;
    let ironwood = finish(destination, &mut rng, "crossing destination")?;

    // The bundles are only a crossing if their value balances join. Checking
    // here means a mistake surfaces as an error rather than as a transaction
    // the network rejects after the proving is already paid for.
    let (expected_source, expected_destination) = plan.value_balances();
    if *orchard.value_balance() != expected_source {
        return Err(Error::Build(format!(
            "the source bundle's value balance is {}, not the {expected_source} the plan requires",
            orchard.value_balance()
        )));
    }
    if *ironwood.value_balance() != expected_destination {
        return Err(Error::Build(format!(
            "the destination bundle's value balance is {}, not the {expected_destination} \
             the plan requires",
            ironwood.value_balance()
        )));
    }

    Ok(crate::transaction::UnprovenBundles {
        orchard: Some(orchard),
        ironwood: Some(ironwood),
    })
}

/// Builds, proves and signs the transaction a crossing is carried by.
///
/// The expiry comes from the plan rather than the caller: an ordinary expiry
/// would single the transaction out from the crossings it is meant to be
/// indistinguishable from, and letting a caller choose it would make that a
/// mistake somebody can make.
pub fn transaction<R: rand::Rng + rand::CryptoRng>(
    request: &CrossingRequest<'_>,
    branch_id: zcash_protocol::consensus::BranchId,
    proving_key: &orchard::circuit::ProvingKey,
    mut rng: R,
) -> Result<zcash_primitives::transaction::Transaction, Error> {
    let unproven = bundles(request, &mut rng)?;
    let tx = crate::transaction::assemble(
        unproven,
        branch_id,
        request.plan.expiry,
        request.keys,
        proving_key,
        &mut rng,
    )?;

    // The check that means something: read the shape off the bytes that would
    // be broadcast, not off the plan they were meant to follow. A crossing that
    // is nearly the right shape is worse than none — it stands out from the
    // ones that are — so a non-conforming result is refused rather than
    // returned with a warning. Refusing here costs a proof already paid for,
    // which is unfortunate and still much cheaper than sending it.
    let target_height = request.plan.target_height;
    if !built_conforms(&tx, request.anchors, target_height) {
        return Err(Error::NotCanonical(format!(
            "the built crossing does not conform: {:?}",
            classify(
                &evidence_from_transaction(&tx, request.anchors, target_height),
                &CrossingParams,
            )
        )));
    }

    Ok(tx)
}

/// A note-preparation transaction: consolidating small notes into one that can
/// fund a crossing.
///
/// A crossing spends exactly one note, so a wallet whose Orchard notes are all
/// too small cannot cross at all until it has one that is big enough. [ZIP 318]
/// gives that consolidation its own canonical shape — an Orchard-only
/// send-to-self padded to exactly [`PREP_TX_ACTIONS`] actions — for the same
/// reason crossings have one: a preparation transaction that looked like an
/// ordinary consolidation would mark its wallet as one that is about to cross.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
#[derive(Debug, Clone)]
pub struct PreparationPlan {
    /// The notes being consolidated.
    pub inputs: Vec<SpendableNote>,
    /// What the consolidated note will be worth.
    pub output: Zatoshis,
    /// The fee.
    pub fee: Zatoshis,
    /// The height the transaction expires at.
    pub expiry: BlockHeight,
    /// The height the transaction was planned against.
    ///
    /// Kept because the canonical expiry is derived from it and the derivation
    /// has no inverse: checking the built transaction's expiry needs the height
    /// it was computed from, not the expiry itself.
    pub target_height: BlockHeight,
}

impl PreparationPlan {
    /// Returns whether the plan balances.
    pub fn balances(&self) -> bool {
        (self.output + self.fee)
            .is_some_and(|spent| Some(spent) == self.input_value())
    }

    fn input_value(&self) -> Option<Zatoshis> {
        self.inputs
            .iter()
            .try_fold(Zatoshis::ZERO, |acc, n| acc + n.value())
    }
}

/// The fee a preparation transaction pays.
///
/// Fixed by the shape: every preparation transaction is padded to the same
/// action count, so they all cost the same whatever the wallet actually holds.
pub fn preparation_fee(constants: &impl PoolMigrationConstants) -> Zatoshis {
    fee::required(constants.preparation_tx_actions(), 0)
}

/// Plans a preparation transaction that will yield a note able to fund a
/// crossing of `denomination`.
///
/// Returns [`Error::NoSuitableNote`] when even consolidating everything the
/// wallet holds would not be enough — which is a different problem, and one no
/// transaction can solve.
pub fn plan_preparation(
    available: &[(SpendableNote, MerklePath)],
    denomination: Zatoshis,
    target_height: BlockHeight,
    constants: &impl PoolMigrationConstants,
) -> Result<PreparationPlan, Error> {
    if !constants.is_canonical_denomination(denomination) {
        return Err(Error::NotCanonical(format!(
            "{} zatoshis is not a canonical denomination, so no crossing could carry it",
            denomination.into_u64()
        )));
    }

    let prep_fee = preparation_fee(constants);
    let crossing_fee = canonical_fee();
    // The consolidated note has to cover the crossing *and* its fee, and the
    // consolidation itself has to be paid for out of the same notes.
    let target = (denomination + crossing_fee)
        .and_then(|v| v + prep_fee)
        .ok_or(Error::ValueOverflow)?;

    // Largest first: fewer inputs is a cheaper transaction and fewer proofs,
    // and the padding means the action count does not change either way.
    let mut candidates: Vec<_> = available
        .iter()
        .map(|(note, _)| note.clone())
        .filter(|note| note.pool == zakura_wallet_core::pool::PoolId::Orchard)
        .collect();
    candidates.sort_by_key(|note| std::cmp::Reverse(note.value().into_u64()));

    // A preparation transaction is padded to a fixed action count, so it can
    // spend at most that many notes; one more would change the shape.
    let limit = constants.preparation_tx_actions();

    let mut inputs = Vec::new();
    let mut total = Zatoshis::ZERO;
    for note in candidates.into_iter().take(limit) {
        total = (total + note.value()).ok_or(Error::ValueOverflow)?;
        inputs.push(note);
        if total >= target {
            break;
        }
    }

    if total < target {
        return Err(Error::NoSuitableNote { required: target });
    }

    let output = (total - prep_fee).expect("the total was checked to exceed the fee");
    let plan = PreparationPlan {
        inputs,
        output,
        fee: prep_fee,
        expiry: constants.canonical_expiry(target_height),
        target_height,
    };
    debug_assert!(plan.balances(), "a planned preparation must balance");
    Ok(plan)
}

/// Returns how a ZIP 318 classifier will read a preparation transaction this
/// wallet built.
pub fn preparation_classification(
    plan: &PreparationPlan,
    anchors: &Anchors,
    target_height: BlockHeight,
) -> Zip318Classification {
    let constants = CrossingParams;
    let evidence = Zip318Evidence::default()
        .with_source_actions(Some(constants.preparation_tx_actions()))
        // A preparation transaction crosses nothing: it restructures notes
        // within the source pool, so the destination bundle is absent.
        .with_destination_actions(Some(0))
        .with_other_bundles_present(Some(false))
        .with_source_is_send_to_self(Some(true))
        .with_expiry_is_canonical(Some(
            constants.is_canonical_expiry(plan.expiry, target_height),
        ))
        .with_anchor_on_grid(Some(
            constants.anchor_bucket_interval().is_boundary(anchors.height),
        ))
        .with_fee_is_canonical(Some(plan.fee == preparation_fee(&constants)));

    classify(&evidence, &constants)
}

/// Returns whether a preparation transaction will be indistinguishable from
/// every other one.
pub fn preparation_conforms(
    plan: &PreparationPlan,
    anchors: &Anchors,
    target_height: BlockHeight,
) -> bool {
    preparation_classification(plan, anchors, target_height)
        == Zip318Classification::Conforms(Zip318TxKind::Preparation)
}
