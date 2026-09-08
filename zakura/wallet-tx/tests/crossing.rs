//! Tests for ZIP 318 pool crossings.
//!
//! A crossing's privacy argument is that every crossing looks like every other
//! one, so a wallet quietly migrating its own funds and a wallet paying
//! somebody cannot be told apart. That makes the *shape* the thing under test,
//! and the wallet checks its own transactions with the same classifier the
//! network uses — deciding for itself what conformance means is how an
//! implementation drifts from the definition without noticing.

use assert_matches::assert_matches;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use rand::SeedableRng;
use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zakura_wallet_scan::{
    NullifierSnapshot, ScanKeys, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_tx::{
    Anchors, Error, Keys, SpendRequest, action_counts, anchors, crossing, crossing_anchors,
    payment, select, spendable_notes,
    testing::{proving_key, verifying_key},
    verify_proofs,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
    zip318::{Zip318Classification, Zip318TxKind},
};

const ALICE: AccountId = AccountId(1);

/// One ZEC, which is on the canonical one-two-five denomination series.
const ONE_ZEC: Zatoshis = Zatoshis::const_from_u64(100_000_000);

fn rng() -> rand::rngs::ChaCha20Rng {
    rand::rngs::ChaCha20Rng::seed_from_u64(3)
}

fn alice_keys() -> Keys {
    for seed in 0u8..=255 {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes([seed; 32])) {
            return Keys::from_spending_key(sk);
        }
    }
    panic!("some 32-byte value is a valid spending key")
}

fn stranger() -> orchard::Address {
    FullViewingKey::from(
        &Option::<SpendingKey>::from(SpendingKey::from_bytes([42u8; 32]))
            .expect("a valid spending key"),
    )
    .address_at(0u32, Scope::External)
}

/// Builds a wallet whose Orchard notes are worth `values`, scanned so that its
/// anchor lands on the grid crossings are proved against.
///
/// The grid matters: an anchor off it announces which wallet built the
/// transaction, so the scan is arranged to end on a boundary.
fn wallet_on_the_grid(values: &[u64], fvk: &FullViewingKey) -> (WalletDb, BlockHeight) {
    let grid = crossing::anchor_grid();

    // Start low enough that a grid boundary lands above the notes.
    let start = u32::from(grid.boundary_at_or_above(BlockHeight::from_u32(
        IRONWOOD_ACTIVATION + 10,
    )));
    let boundary = u32::from(grid.boundary_at_or_above(BlockHeight::from_u32(start + 5)));

    let mut db = test_db().unwrap();
    db.set_birthday(BlockHeight::from_u32(start)).unwrap();

    let mut chain = ChainBuilder::new(start);
    chain.block(|b| {
        b.tx(|t| {
            for value in values {
                t.receive(PoolId::Orchard, fvk, KeyScope::External, *value);
            }
            // An Ironwood action, so that pool's tree is non-empty and has a
            // checkpoint at the same heights: a crossing anchors both.
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    // Scan up to and including the boundary, so both trees hold a checkpoint
    // there.
    chain.empty_blocks((boundary - start) as usize);

    let keys = ScanKeys::from_accounts([(ALICE, fvk.clone())]);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("the chain scans cleanly");
    db.put_batch(&test_params(), &batch).expect("the batch applies");

    (db, BlockHeight::from_u32(boundary))
}

/// Returns anchors pinned to the grid boundary a crossing must use.
fn grid_anchors(db: &mut WalletDb, boundary: BlockHeight) -> Anchors {
    let anchors = anchors(db).expect("both trees have a shared anchor");
    assert_eq!(
        anchors.height, boundary,
        "the wallet's most recent shared anchor should be the grid boundary"
    );
    anchors
}

// ------------------------------------------------------------- the shape

#[test]
fn a_planned_crossing_conforms() {
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[150_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    let target = boundary + 1;

    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        target,
        &crossing::CrossingParams,
    )
    .expect("one ZEC is canonical and the note covers it");

    assert!(plan.balances());
    assert_eq!(plan.denomination, ONE_ZEC);
    assert_eq!(plan.fee, crossing::canonical_fee());

    // The wallet reads its own transaction with the classifier the network
    // uses, rather than deciding for itself what conformance means.
    assert_eq!(
        crossing::classification(&plan, &anchors, target),
        Zip318Classification::Conforms(Zip318TxKind::Transfer)
    );
    assert!(crossing::conforms(&plan, &anchors, target));
}

#[test]
fn the_canonical_fee_is_fixed_by_the_shape_not_the_contents() {
    // Two source actions and one destination action, whatever the wallet holds.
    // A fee that varied with the wallet would separate crossings from each
    // other, which is the one thing the shape exists to prevent.
    assert_eq!(
        crossing::canonical_fee(),
        zakura_wallet_tx::fee::required(2, 1)
    );
    assert_eq!(crossing::canonical_fee().into_u64(), 15_000);
}

#[test]
fn the_value_balances_join_the_two_bundles() {
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[150_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap();

    let (source, destination) = plan.value_balances();
    assert_eq!(source, 100_015_000, "the denomination plus the fee leaves Orchard");
    assert_eq!(destination, -100_000_000, "the denomination enters Ironwood");
    assert_eq!(
        source + destination,
        plan.fee.into_u64() as i64,
        "what the transaction gives up overall is exactly the fee"
    );
}

// ------------------------------------------------------- refusing to bend

#[test]
fn a_non_canonical_denomination_is_refused() {
    // Not adjusted to the nearest canonical value: silently sending a different
    // amount than asked is worse than refusing, and a crossing that is nearly
    // the right shape stands out from the ones that are.
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[150_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let err = crossing::plan(
        &available,
        Zatoshis::const_from_u64(123_456_789),
        &anchors,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap_err();

    assert_matches!(err, Error::NotCanonical(_));
    assert!(err.to_string().contains("canonical denomination"), "{err}");
}

#[test]
fn an_anchor_off_the_grid_is_refused() {
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[150_000_000], &keys.fvk);
    let mut anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    // One block off the boundary is enough to single the transaction out.
    anchors.height = boundary + 1;
    assert!(!crossing::anchor_grid().is_boundary(anchors.height));

    let err = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap_err();

    assert_matches!(err, Error::NotCanonical(_));
    assert!(err.to_string().contains("grid"), "{err}");
}

#[test]
fn a_wallet_whose_notes_are_all_too_small_must_consolidate_first() {
    // A crossing has two source actions, so it spends exactly one note. Three
    // notes that together cover the denomination still cannot fund one.
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[40_000_000, 40_000_000, 40_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    assert_eq!(available.len(), 3);

    let err = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap_err();

    assert_matches!(err, Error::NoSuitableNote { .. });
    assert!(err.to_string().contains("consolidate"), "{err}");
}

#[test]
fn the_smallest_sufficient_note_is_chosen() {
    // The opposite of ordinary selection: a crossing needs one note that
    // covers it, so taking the smallest such note leaves the larger ones intact
    // for the crossings that will need them.
    let keys = alice_keys();
    let (mut db, boundary) =
        wallet_on_the_grid(&[500_000_000, 110_000_000, 300_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap();

    assert_eq!(plan.source.value().into_u64(), 110_000_000);
}

// ------------------------------------------------------------ the bundles

#[test]
fn a_crossing_builds_proves_and_verifies() {
    // The whole thing: two bundles, joined by their value balances, both proved
    // and both verified. A witness taken at the wrong position, or a value
    // balance that does not join, fails here rather than at the network.
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[150_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    let target = boundary + 1;

    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        target,
        &crossing::CrossingParams,
    )
    .unwrap();
    assert!(crossing::conforms(&plan, &anchors, target));

    let witness = available
        .iter()
        .find(|(note, _)| note.position == plan.source.position)
        .map(|(_, path)| path.clone())
        .expect("the planned note is one of the available ones");

    let built = crossing::transaction(
        &crossing::CrossingRequest {
            plan: &plan,
            witness: &witness,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        proving_key(),
        rng(),
    )
    .expect("a canonical crossing builds");

    verify_proofs(&built, verifying_key()).expect("both proofs verify");

    // And it has the shape the classifier was told it would.
    let (source_actions, destination_actions) = action_counts(&built);
    assert_eq!(source_actions, 2, "a crossing has two source actions");
    assert_eq!(
        destination_actions, 1,
        "a crossing has one destination action, unpadded"
    );
}

#[test]
fn a_crossing_that_consumes_its_note_exactly_still_has_two_source_actions() {
    // With no change, the source bundle has one real spend and a padding dummy.
    // Padding to two is what stops the action count revealing whether the note
    // was consumed exactly — which would separate those crossings from the rest.
    let keys = alice_keys();
    let exact = ONE_ZEC.into_u64() + crossing::canonical_fee().into_u64();
    let (mut db, boundary) = wallet_on_the_grid(&[exact], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap();
    assert_eq!(plan.change, Zatoshis::ZERO, "the note is consumed exactly");

    let witness = available[0].1.clone();
    let built = crossing::transaction(
        &crossing::CrossingRequest {
            plan: &plan,
            witness: &witness,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        proving_key(),
        rng(),
    )
    .expect("a crossing with no change builds");

    verify_proofs(&built, verifying_key()).expect("both proofs verify");
    assert_eq!(
        action_counts(&built),
        (2, 1),
        "the shape is the same whether or not there is change"
    );
}

#[test]
fn the_classifier_refuses_shapes_that_are_not_crossings() {
    // Guards against `conforms` being a function that says yes to everything.
    // Each of these is one deviation from the canonical shape, and each must be
    // caught — because each is a way for a real transaction to stand out.
    use zcash_protocol::zip318::{Zip318Evidence, classify};

    let canonical = Zip318Evidence::default()
        .with_source_actions(Some(2))
        .with_destination_actions(Some(1))
        .with_other_bundles_present(Some(false))
        .with_source_is_send_to_self(Some(true))
        .with_sole_destination_value(Some(ONE_ZEC))
        .with_expiry_is_canonical(Some(true))
        .with_anchor_on_grid(Some(true))
        .with_fee_is_canonical(Some(true));

    assert_eq!(
        classify(&canonical, &crossing::CrossingParams),
        Zip318Classification::Conforms(Zip318TxKind::Transfer),
        "the shape this wallet builds must be the conforming one"
    );

    let deviations = [
        (
            "a third source action",
            canonical.with_source_actions(Some(3)),
        ),
        (
            "a second destination action",
            canonical.with_destination_actions(Some(2)),
        ),
        (
            "a transparent or Sapling bundle alongside",
            canonical.with_other_bundles_present(Some(true)),
        ),
        (
            "an ordinary expiry instead of the canonical window",
            canonical.with_expiry_is_canonical(Some(false)),
        ),
        (
            "an anchor off the shared grid",
            canonical.with_anchor_on_grid(Some(false)),
        ),
        (
            "a fee that is not the canonical one",
            canonical.with_fee_is_canonical(Some(false)),
        ),
        (
            "a value off the denomination series",
            canonical
                .with_sole_destination_value(Some(Zatoshis::const_from_u64(123_456_789))),
        ),
    ];

    for (what, evidence) in deviations {
        assert_eq!(
            classify(&evidence, &crossing::CrossingParams),
            Zip318Classification::Nonconforming,
            "{what} should not conform"
        );
    }
}

#[test]
fn missing_evidence_is_not_a_refusal() {
    // `Unknown` is not a third answer alongside conforming and not: it is "no
    // label yet". Rendering it as "not a migration" would make rows relabel
    // themselves as evidence arrives.
    use zcash_protocol::zip318::{Zip318Evidence, classify};

    let nothing_known = Zip318Evidence::default();
    assert_eq!(
        classify(&nothing_known, &crossing::CrossingParams),
        Zip318Classification::Unknown
    );
}

// ------------------------------------------------------------ preparation

#[test]
fn a_wallet_of_small_notes_can_prepare_one_that_crosses() {
    // The answer to `NoSuitableNote`. A crossing spends exactly one note, so a
    // wallet whose notes are all too small consolidates first — and that
    // consolidation has its own canonical shape, because one that looked like
    // an ordinary consolidation would mark its wallet as about to cross.
    let keys = alice_keys();
    let (mut db, boundary) =
        wallet_on_the_grid(&[40_000_000, 40_000_000, 40_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    let target = boundary + 1;

    // No single note can fund the crossing.
    assert_matches!(
        crossing::plan(&available, ONE_ZEC, &anchors, target, &crossing::CrossingParams)
            .unwrap_err(),
        Error::NoSuitableNote { .. }
    );

    let prep = crossing::plan_preparation(
        &available,
        ONE_ZEC,
        target,
        &crossing::CrossingParams,
    )
    .expect("three notes of 0.4 ZEC consolidate into one that crosses");

    assert!(prep.balances());
    assert_eq!(prep.inputs.len(), 3, "all three are needed");
    assert_eq!(prep.fee, crossing::preparation_fee(&crossing::CrossingParams));

    // And what comes out covers the crossing and its fee.
    assert!(
        prep.output >= (ONE_ZEC + crossing::canonical_fee()).unwrap(),
        "the consolidated note must be able to fund the crossing it was made for"
    );

    assert!(crossing::preparation_conforms(&prep, &anchors, target));
    assert_eq!(
        crossing::preparation_classification(&prep, &anchors, target),
        Zip318Classification::Conforms(Zip318TxKind::Preparation)
    );
}

#[test]
fn a_preparation_costs_the_same_whatever_the_wallet_holds() {
    // Every preparation transaction is padded to the same action count, so a
    // fee that varied with the wallet would separate them from each other.
    use zcash_protocol::zip318::PoolMigrationConstants;

    let params = crossing::CrossingParams;
    assert_eq!(
        crossing::preparation_fee(&params),
        zakura_wallet_tx::fee::required(params.preparation_tx_actions(), 0)
    );
    assert_eq!(params.preparation_tx_actions(), 16);
    assert_eq!(crossing::preparation_fee(&params).into_u64(), 80_000);
}

#[test]
fn a_wallet_that_cannot_afford_the_crossing_at_all_is_told_so() {
    // Consolidation cannot create value. This is a different problem from
    // "no single note is big enough", and no transaction solves it.
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[1_000, 2_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let err = crossing::plan_preparation(
        &available,
        ONE_ZEC,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap_err();

    assert_matches!(err, Error::NoSuitableNote { .. });
}

#[test]
fn a_preparation_spends_no_more_notes_than_its_shape_allows() {
    // The transaction is padded to a fixed action count, so it can spend at
    // most that many notes; one more would change the shape and single it out.
    use zcash_protocol::zip318::PoolMigrationConstants;

    let keys = alice_keys();
    let many: Vec<u64> = std::iter::repeat_n(30_000_000u64, 20).collect();
    let (mut db, boundary) = wallet_on_the_grid(&many, &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    assert_eq!(available.len(), 20);

    let prep = crossing::plan_preparation(
        &available,
        ONE_ZEC,
        boundary + 1,
        &crossing::CrossingParams,
    )
    .unwrap();

    assert!(
        prep.inputs.len() <= crossing::CrossingParams.preparation_tx_actions(),
        "spent {} notes, which exceeds the shape",
        prep.inputs.len()
    );
    // Largest first, so four notes of 0.3 ZEC suffice for a 1 ZEC crossing.
    assert_eq!(prep.inputs.len(), 4);
}

#[test]
fn the_built_check_catches_what_the_plan_check_cannot() {
    // The plan-derived evidence answers the shape clauses from constants, so it
    // restates what `plan` already refused on and cannot see a defect
    // introduced between planning and building. This is the pair of facts that
    // shows the built check is doing separate work: the same plan conforms, and
    // an ordinary payment built from it does not.
    let keys = alice_keys();
    let (mut db, boundary) = wallet_on_the_grid(&[150_000_000], &keys.fvk);
    let anchors = grid_anchors(&mut db, boundary);
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    let target = boundary + 1;

    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &anchors,
        target,
        &crossing::CrossingParams,
    )
    .unwrap();

    // The plan is canonical, and says so.
    assert!(
        crossing::conforms(&plan, &anchors, target),
        "the plan asks for the right shape"
    );

    let witness = available
        .iter()
        .find(|(note, _)| note.position == plan.source.position)
        .map(|(_, path)| path.clone())
        .expect("the planned note is one of the available ones");

    // Built properly, the transaction conforms when read off its own bytes.
    let built = crossing::transaction(
        &crossing::CrossingRequest {
            plan: &plan,
            witness: &witness,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        proving_key(),
        rng(),
    )
    .expect("a canonical crossing builds");
    assert!(
        crossing::built_conforms(&built, &anchors, target),
        "a crossing built from a canonical plan conforms when read off its bytes"
    );

    // Now the part the plan-derived check is blind to: a transaction built from
    // the *same wallet and anchors* that is not a crossing at all. The plan
    // still says "two source actions, one destination action, no other
    // bundles"; the bytes say otherwise.
    let ordinary = {
        let notes: Vec<_> = available.iter().map(|(n, _)| n.clone()).collect();
        let proposal = select(notes, PoolId::Orchard, Zatoshis::const_from_u64(1_000_000))
            .expect("an Orchard send-to-self is an ordinary payment");
        payment(
            &SpendRequest {
                proposal: &proposal,
                witnesses: &available,
                keys: &keys,
                // Our own address: an Orchard bundle may not pay a stranger.
                recipient: keys.fvk.address_at(0u32, Scope::External),
                anchors: &anchors,
            },
            BranchId::Nu6_3,
            plan.expiry,
            proving_key(),
            rng(),
        )
        .expect("an ordinary Orchard payment builds")
    };

    assert!(
        !crossing::built_conforms(&ordinary, &anchors, target),
        "an ordinary payment is not a crossing, and reading its bytes must say so"
    );
}

#[test]
fn a_crossing_anchors_on_the_grid_from_a_wallet_that_stopped_anywhere() {
    // The other tests contrive a chain that ends exactly on a grid boundary, so
    // the most recent shared checkpoint happens to be one. A real wallet stops
    // wherever the tip is, and `anchors` then returns a height off the grid that
    // `plan` must refuse. `crossing_anchors` is what finds the boundary
    // underneath it — and it can only do so because the apply stage retained
    // that boundary against pruning as it passed.
    let keys = alice_keys();
    let grid = crossing::anchor_grid();

    let start = u32::from(grid.boundary_at_or_above(BlockHeight::from_u32(
        IRONWOOD_ACTIVATION + 10,
    )));
    let boundary = u32::from(grid.boundary_at_or_above(BlockHeight::from_u32(start + 5)));
    // Stop part way past the boundary, which is where a wallet actually is.
    let stop = boundary + 37;
    assert!(!grid.is_boundary(BlockHeight::from_u32(stop)));

    let mut db = test_db().unwrap();
    db.set_birthday(BlockHeight::from_u32(start)).unwrap();

    let mut chain = ChainBuilder::new(start);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Orchard, &keys.fvk, KeyScope::External, 150_000_000);
            t.decoy(PoolId::Ironwood, 1);
        });
    });
    chain.empty_blocks((stop - start) as usize);

    let scan_keys = ScanKeys::from_accounts([(ALICE, keys.fvk.clone())]);
    let batch = detect_batch(
        &test_params(),
        &scan_keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("the chain scans cleanly");
    db.put_batch(&test_params(), &batch).expect("the batch applies");

    // The ordinary anchor is off the grid, so planning against it is refused.
    let ordinary = anchors(&mut db).expect("both trees have a shared anchor");
    assert_eq!(ordinary.height, BlockHeight::from_u32(stop));
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &ordinary, false).unwrap();
    assert_matches!(
        crossing::plan(
            &available,
            ONE_ZEC,
            &ordinary,
            ordinary.height + 1,
            &crossing::CrossingParams,
        ),
        Err(Error::NotCanonical(_)),
        "the most recent shared checkpoint is not on the grid"
    );

    // The grid anchor is, and it is the retained boundary the batch crossed.
    let grid_anchor = crossing_anchors(&mut db).expect("a retained boundary is available");
    assert_eq!(grid_anchor.height, BlockHeight::from_u32(boundary));
    assert!(grid.is_boundary(grid_anchor.height));

    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &grid_anchor, false).unwrap();
    let plan = crossing::plan(
        &available,
        ONE_ZEC,
        &grid_anchor,
        grid_anchor.height + 1,
        &crossing::CrossingParams,
    )
    .expect("a crossing plans against the retained grid boundary");
    assert!(crossing::conforms(&plan, &grid_anchor, grid_anchor.height + 1));
}
