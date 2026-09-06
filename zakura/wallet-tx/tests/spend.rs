//! Tests for the spend path.
//!
//! The one that matters is `a_spend_of_a_scanned_note_proves_and_verifies`. It
//! takes a note the scanner found, builds a real bundle spending it, proves it,
//! and verifies the proof. A witness taken at the wrong position, or against a
//! tree that has drifted from the chain's, produces a proof that does not
//! verify — so this is the check that the whole commitment-tree design, from
//! detection through storage to witness generation, is actually right.
//!
//! Proving is slow. These tests are `--release`-friendly and there are few of
//! them on purpose.

use assert_matches::assert_matches;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use rand::SeedableRng;
use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zakura_wallet_scan::{
    NullifierSnapshot, ScanKeys, TransparentWatch, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_tx::{
    Error, Keys, SpendRequest, action_counts, anchors, fee, payment, select, spendable_notes,
    testing::{proving_key, verifying_key},
    verify_proofs,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};

const ALICE: AccountId = AccountId(1);
const START: u32 = IRONWOOD_ACTIVATION + 10;

fn h(n: u32) -> BlockHeight {
    BlockHeight::from_u32(n)
}

/// A deterministic cryptographic RNG.
///
/// Bundle construction requires a `CryptoRng` and rightly refuses a
/// non-cryptographic one, so this is seeded ChaCha rather than a cheaper
/// generator.
fn rng() -> rand::rngs::ChaCha20Rng {
    rand::rngs::ChaCha20Rng::seed_from_u64(7)
}

/// The spending key the tests fund, and the viewing key derived from it.
fn alice_keys() -> Keys {
    for seed in 0u8..=255 {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes([seed; 32])) {
            return Keys::from_spending_key(sk);
        }
    }
    panic!("some 32-byte value is a valid spending key")
}

/// Builds a wallet holding `count` notes of `value` in `pool`, scanned from a
/// synthetic chain and buried deep enough to be spendable.
fn funded_wallet(pool: PoolId, count: usize, value: u64, fvk: &FullViewingKey) -> WalletDb {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            for i in 0..count {
                t.receive(pool, fvk, KeyScope::External, value + i as u64);
            }
        });
    });
    // Bury the notes: a note whose shard is not fully scanned and confirmed has
    // no witness a reorg cannot invalidate, and is deliberately not spendable.
    chain.empty_blocks(2);

    let keys = ScanKeys::from_accounts([(ALICE, fvk.clone())]);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("the chain scans cleanly");
    db.put_batch(&test_params(), &batch).expect("the batch applies");

    db
}

// ------------------------------------------------------------- selection

#[test]
fn selection_covers_the_payment_and_its_fee() {
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 3, 100_000, &keys.fvk);
    let anchors = anchors(&mut db).expect("the trees have a shared anchor");
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    assert_eq!(available.len(), 3);

    let proposal = select(
        available.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(150_000),
    )
    .expect("three notes of 100_000 cover a payment of 150_000");

    assert!(proposal.balances(), "inputs must equal outputs plus fee");
    assert_eq!(proposal.amount.into_u64(), 150_000);
    assert!(proposal.change.is_some(), "the excess comes back as change");
    assert_eq!(proposal.fee, fee::required(0, proposal.action_counts().1));
}

#[test]
fn selection_prefers_the_fewest_notes() {
    // Largest first, because each extra input is another action, another
    // proof, and a larger fee.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 4, 100_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let proposal = select(
        available.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(50_000),
    )
    .unwrap();

    assert_eq!(proposal.inputs.len(), 1, "one note is enough");
    assert_eq!(
        proposal.inputs[0].value().into_u64(),
        100_003,
        "and it should be the largest"
    );
}

#[test]
fn a_payment_larger_than_the_wallet_is_refused() {
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 2, 10_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let err = select(
        available.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(1_000_000),
    )
    .unwrap_err();

    assert_matches!(err, Error::InsufficientFunds { .. });
    assert!(err.to_string().contains("1000000"), "{err}");
}

#[test]
fn an_exact_payment_produces_no_change_output() {
    // A change output worth nothing is not an output: it costs an action and
    // hands the wallet a zero-value note to trip over later.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 1, 100_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    // One note of 100_000, a two-action bundle, so a 10_000 fee.
    let proposal = select(
        available.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(90_000),
    )
    .unwrap();

    assert_eq!(proposal.change, None);
    assert_eq!(proposal.fee.into_u64(), 10_000);
    assert!(proposal.balances());
}

#[test]
fn notes_without_stable_witnesses_are_withheld() {
    // The default is to refuse: a note whose shard is not buried has no witness
    // a reorg cannot invalidate, and a proof against an anchor the chain
    // abandons is worthless.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 2, 100_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();

    let strict = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, true).unwrap();
    let relaxed = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    assert!(relaxed.len() > strict.len(), "the notes exist but are not yet stable");
    assert!(strict.is_empty());
}

// ------------------------------------------------------------- the proof

/// An address belonging to somebody else.
fn stranger() -> orchard::Address {
    FullViewingKey::from(
        &Option::<SpendingKey>::from(SpendingKey::from_bytes([42u8; 32]))
            .expect("a valid spending key"),
    )
    .address_at(0u32, Scope::External)
}

#[test]
fn an_ironwood_payment_proves_and_verifies() {
    // The check the whole design rests on. If a witness was taken at the wrong
    // position, or against a tree that drifted from the chain's, the proof does
    // not verify — and verifying locally is the only way to learn that before
    // consensus does.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 2, 500_000, &keys.fvk);
    let anchors = anchors(&mut db).expect("both trees have a shared anchor");
    let witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    assert_eq!(witnesses.len(), 2);

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();

    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .expect("an Ironwood payment builds");

    verify_proofs(&built, verifying_key()).expect("the proof verifies");

    let (orchard_actions, ironwood_actions) = action_counts(&built);
    assert_eq!(orchard_actions, 0, "no Orchard bundle was asked for");
    assert_eq!(
        ironwood_actions,
        proposal.action_counts().1,
        "the built bundle should carry the action count the fee was based on"
    );
}

#[test]
fn an_orchard_payment_to_a_stranger_requires_a_crossing() {
    // This is consensus, not policy. From NU6.3 the Orchard pool prohibits
    // cross-address transfers, so value leaves it only through a bundle's value
    // balance and into an Ironwood bundle that makes the payment. The
    // indistinguishability the design treats as non-negotiable is therefore
    // structural: there is no Orchard payment path to accidentally take.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Orchard, 2, 500_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Orchard,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();

    let err = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .unwrap_err();

    assert_matches!(err, Error::CrossingRequired);
    assert!(err.to_string().contains("crossing"), "{err}");
}

#[test]
fn an_orchard_spend_that_keeps_its_value_proves_and_verifies() {
    // What an Orchard bundle *can* do: spend its own notes and retain the
    // remainder. Retaining requires `add_change_output`, because in a bundle
    // with cross-address disabled the builder has to pair the output with a
    // fabricated zero-valued spend at the same address.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Orchard, 2, 500_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Orchard,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();

    // Paying an address the wallet owns is not a cross-address transfer.
    let own = keys.fvk.address_at(7u32, Scope::External);

    let built = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: own,
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    )
    .expect("an Orchard send-to-self builds");

    verify_proofs(&built, verifying_key()).expect("the proof verifies");
    assert_eq!(action_counts(&built).1, 0, "no Ironwood bundle");
    assert!(action_counts(&built).0 >= 2, "a bundle is padded to two actions");
}

#[test]
fn an_unbalanced_proposal_is_refused_before_proving() {
    // Proving takes seconds. A transaction that cannot balance is rejected by
    // consensus anyway, so refusing it first is the difference between a fast
    // error and a slow one.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 1, 500_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let mut proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(100_000),
    )
    .unwrap();
    // Quietly take the fee away, so inputs no longer equal outputs plus fee.
    proposal.fee = Zatoshis::ZERO;
    assert!(!proposal.balances());

    // Force the proving key to exist first: building it takes seconds, and
    // measuring that would say nothing about whether proving was skipped.
    let pk = proving_key();

    let began = std::time::Instant::now();
    let err = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: keys.fvk.address_at(0u32, Scope::External),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        pk,
        rng(),
    )
    .unwrap_err();

    assert_matches!(err, Error::Build(_));
    assert!(err.to_string().contains("balance"), "{err}");
    assert!(
        began.elapsed() < std::time::Duration::from_secs(1),
        "it should have failed before proving"
    );
}

#[test]
fn a_wallet_with_no_notes_has_no_anchor_to_spend_against() {
    let mut db = test_db().unwrap();
    db.set_birthday(h(START)).unwrap();
    assert_matches!(anchors(&mut db).unwrap_err(), Error::NoAnchor);
}

#[test]
fn a_witness_from_the_wrong_position_does_not_verify() {
    // Guards against the whole suite passing vacuously. If verification
    // accepted anything, none of the proofs above would mean what they claim,
    // and the commitment-tree design would be untested. Swapping two notes'
    // witnesses gives each a path that is valid for the tree but wrong for the
    // note, which is exactly the shape of an off-by-one position bug.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 2, 500_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let mut witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    assert_eq!(witnesses.len(), 2);

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();

    // Give each note the other's authentication path.
    let (first, second) = witnesses.split_at_mut(1);
    std::mem::swap(&mut first[0].1, &mut second[0].1);

    let outcome = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + 100,
        proving_key(),
        rng(),
    );

    match outcome {
        // The builder checks each spend's witness against the bundle anchor, so
        // it usually rejects before proving. Either way, what must not happen
        // is a bundle that builds *and* verifies.
        Err(_) => {}
        Ok(built) => assert!(
            verify_proofs(&built, verifying_key()).is_err(),
            "a bundle built from mismatched witnesses must not verify"
        ),
    }
}

#[test]
fn orchard_notes_cannot_quietly_fund_an_ironwood_payment() {
    // The shape the `CrossingRequired` guard in `build` does not see: the
    // Orchard bundle carries no output at all, so it never reaches the
    // "paying a stranger from Orchard" branch. It is spend-only with a positive
    // value balance, and the Ironwood bundle makes the payment — structurally a
    // pool crossing, but with ordinary selection's action count, fee, expiry and
    // anchor rather than the canonical ones. A crossing that is not shaped like
    // every other crossing identifies its sender.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Orchard, 3, 100_000, &keys.fvk);
    let anchors = anchors(&mut db).expect("the trees have a shared anchor");
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();
    assert!(
        available.iter().all(|(n, _)| n.pool == PoolId::Orchard),
        "the wallet holds only Orchard notes, which is the situation under test"
    );

    let err = select(
        available.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(50_000),
    )
    .expect_err("funding an Ironwood payment from Orchard notes is a pool crossing");

    assert_matches!(err, Error::CrossingRequired);
}

#[test]
fn a_hand_built_mixed_pool_proposal_is_refused_before_proving() {
    // `select` refuses the shape, but `Proposal` is a plain struct a caller can
    // fill in directly, so the builder has to refuse it too. Proving first and
    // discovering the shape afterwards would pay for the expensive part and
    // leave the wallet holding something it must not send.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Orchard, 2, 200_000, &keys.fvk);
    let anchors = anchors(&mut db).expect("the trees have a shared anchor");
    let witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let inputs: Vec<_> = witnesses.iter().map(|(n, _)| n.clone()).collect();
    let input_value = inputs
        .iter()
        .try_fold(Zatoshis::ZERO, |acc, n| acc + n.value())
        .unwrap();
    let fee = fee::required(2, 2);
    let amount = (input_value - fee).unwrap();

    // Orchard inputs, an Ironwood payment: balanced, and still a crossing.
    let proposal = zakura_wallet_tx::Proposal {
        inputs,
        output_pool: PoolId::Ironwood,
        amount,
        change: None,
        fee,
        transparent_inputs: Vec::new(),
        transparent_payment: None,
    };
    assert!(proposal.balances(), "the proposal balances, so only its shape is wrong");

    let err = zakura_wallet_tx::bundles(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: keys.fvk.address_at(0u32, Scope::External),
            anchors: &anchors,
        },
        rng(),
    )
    // `.err()` rather than `expect_err`: the success type holds bundles that
    // deliberately do not implement `Debug`, since printing one would dump key
    // material into a test log.
    .err()
    .expect("a mixed-pool proposal is a crossing and must be refused");

    assert_matches!(err, Error::CrossingRequired);
}

#[test]
fn notes_from_two_accounts_are_not_spent_together() {
    // Spending them in one transaction publishes that one wallet holds both,
    // which is the linkage separate accounts exist to prevent.
    let keys = alice_keys();
    let mut db = funded_wallet(PoolId::Ironwood, 2, 100_000, &keys.fvk);
    let anchors = anchors(&mut db).expect("the trees have a shared anchor");
    let available = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let mut mixed: Vec<_> = available.iter().map(|(n, _)| n.clone()).collect();
    mixed[1].account = AccountId(2);

    let err = select(mixed, PoolId::Ironwood, Zatoshis::const_from_u64(50_000))
        .expect_err("notes from two accounts must not be spent together");

    assert_matches!(err, Error::MixedAccounts);
}
