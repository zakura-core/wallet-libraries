//! Building transactions that carry transparent parts.
//!
//! The test that matters is `a_shielding_transaction_signs_every_input`. A
//! transparent input is signed with a sighash computed *for that input*, over a
//! transaction that already contains the transparent bundle — so the ordering
//! inside assembly is load-bearing, and getting it wrong produces signatures
//! that are well-formed and invalid.

use orchard::keys::{Scope, SpendingKey};
use rand::SeedableRng;
use transparent::keys::{AccountPrivKey, NonHardenedChildIndex, TransparentKeyScope};
use zakura_wallet_core::{KeyScope, pool::PoolId};
use zakura_wallet_store::SpendableUtxo;
use zakura_wallet_tx::{Error, Keys, fee, plan_shielding, transparent_bundle};
use zcash_protocol::value::Zatoshis;

#[path = "common/mod.rs"]
mod common;

fn keys_from(seed: u8) -> Keys {
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([seed; 32]))
        .expect("this seed is a valid spending key");
    Keys::from_spending_key(sk)
}

fn transparent_key() -> AccountPrivKey {
    AccountPrivKey::from_seed(
        &zcash_protocol::consensus::MAIN_NETWORK,
        &[7u8; 32],
        zip32::AccountId::try_from(0).unwrap(),
    )
    .expect("the seed derives a transparent account key")
}

/// A UTXO the wallet can spend, at `index` in the external scope.
fn utxo(key: &AccountPrivKey, index: u32, value: u64) -> SpendableUtxo {
    let pubkey = key
        .to_account_pubkey()
        .derive_address_pubkey(
            TransparentKeyScope::EXTERNAL,
            NonHardenedChildIndex::from_index(index).unwrap(),
        )
        .expect("the address pubkey derives");
    let address = transparent::address::TransparentAddress::from_pubkey(&pubkey);

    SpendableUtxo {
        scope: KeyScope::External,
        index,
        address_id: i64::from(index) + 1,
        outpoint: transparent::bundle::OutPoint::new([index as u8; 32], 0),
        txout: transparent::bundle::TxOut::new(
            Zatoshis::const_from_u64(value),
            address.script().into(),
        ),
    }
}

#[test]
fn shielding_sends_everything_to_ironwood_as_change() {
    // A shielding transaction has no recipient: the whole net value becomes a
    // note the wallet pays itself. If any of it went to an external address it
    // would be a payment, not a shielding.
    let key = transparent_key();
    let proposal = plan_shielding(vec![utxo(&key, 0, 500_000), utxo(&key, 1, 300_000)])
        .expect("two outputs shield");

    assert_eq!(proposal.output_pool, PoolId::Ironwood);
    assert_eq!(proposal.amount, Zatoshis::ZERO, "there is no recipient");
    assert!(proposal.transparent_payment.is_none());
    assert_eq!(proposal.transparent_inputs.len(), 2);

    // Two transparent inputs plus the two actions any Ironwood bundle carries.
    assert_eq!(
        proposal.fee,
        fee::required_with(fee::TransparentSizes::p2pkh(2, 0), 0, 2)
    );
    assert_eq!(
        proposal.change,
        Some(Zatoshis::const_from_u64(800_000 - proposal.fee.into_u64())),
        "everything that is not the fee comes back as change"
    );
}

#[test]
fn shielding_dust_is_refused_rather_than_built() {
    // A transaction that pays its fee and produces nothing is not worth making,
    // and building one would quietly consume the funds it was meant to rescue.
    let key = transparent_key();
    let err = plan_shielding(vec![utxo(&key, 0, 1_000)])
        .expect_err("an output smaller than the fee cannot be shielded");
    assert!(matches!(err, Error::InsufficientFunds { .. }));
}

#[test]
fn a_shielding_transaction_signs_every_input() {
    let key = transparent_key();
    let proposal = plan_shielding(vec![utxo(&key, 0, 500_000), utxo(&key, 1, 300_000)]).unwrap();

    let (bundle, signing) = transparent_bundle(&proposal, Some(&key))
        .expect("the bundle builds")
        .expect("a shielding proposal has a transparent bundle");

    assert_eq!(bundle.vin.len(), 2, "both outputs are being spent");
    assert!(bundle.vout.is_empty(), "shielding creates no transparent output");

    // The signing set holds a key per input, and it is the same key the input
    // was added with — `add_p2pkh_input` refuses a pubkey whose hash does not
    // match the script being spent, so reaching here at all is the check.
    let authorized = match bundle.apply_signatures(|_| [7u8; 32], &signing) {
        Ok(authorized) => authorized,
        Err(e) => panic!("every input should have its key: {e:?}"),
    };
    assert_eq!(authorized.vin.len(), 2);
}

#[test]
fn a_transparent_input_without_its_key_is_refused() {
    // Watch-only accounts can hold transparent addresses and see their funds.
    // Failing at build time says so; failing at signing time would waste the
    // proving first.
    let key = transparent_key();
    let proposal = plan_shielding(vec![utxo(&key, 0, 500_000)]).unwrap();
    match transparent_bundle(&proposal, None) {
        Err(Error::Build(_)) => {}
        Ok(_) => panic!("a transparent input without its key must not build"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

#[test]
fn the_builder_and_the_fee_agree_on_transparent_size() {
    // The 150-versus-149 trap. ZIP 317 charges a standard size for a P2PKH
    // input rather than its true serialised length, and the proposal and the
    // builder must use the same one — otherwise a transaction with enough
    // inputs to cross a `ceil(bytes / 150)` boundary is costed at one fee and
    // built expecting another, and fails as unbalanced after proving.
    let key = transparent_key();
    for count in 1..6u32 {
        let utxos: Vec<_> = (0..count).map(|i| utxo(&key, i, 500_000)).collect();
        let proposal = plan_shielding(utxos).unwrap();

        let (bundle, _) = transparent_bundle(&proposal, Some(&key)).unwrap().unwrap();
        assert_eq!(
            fee::TransparentSizes::p2pkh(bundle.vin.len(), bundle.vout.len()),
            proposal.transparent_sizes(),
            "the built bundle must be the size the fee was computed from"
        );

        // And the fee is what ZIP 317 says for that size.
        assert_eq!(
            proposal.fee,
            fee::required_with(fee::TransparentSizes::p2pkh(count as usize, 0), 0, 2),
        );
    }
}

#[test]
fn a_crossing_may_not_carry_a_transparent_bundle() {
    // No ZIP 318 transaction has one, so a crossing that did would be
    // classified as nonconforming — worse than not crossing, because it is a
    // transaction announcing that it tried to.
    let key = transparent_key();
    let mut proposal = plan_shielding(vec![utxo(&key, 0, 500_000)]).unwrap();
    proposal.output_pool = PoolId::Orchard;

    let alice = keys_from(1);
    let err = zakura_wallet_tx::bundles(
        &zakura_wallet_tx::SpendRequest {
            proposal: &proposal,
            witnesses: &[],
            keys: &alice,
            recipient: alice.fvk.address_at(0u32, Scope::External),
            anchors: &zakura_wallet_tx::Anchors {
                height: zcash_protocol::consensus::BlockHeight::from_u32(100),
                orchard: orchard::Anchor::empty_tree(),
                ironwood: orchard::Anchor::empty_tree(),
            },
        },
        rand::rngs::ChaCha20Rng::seed_from_u64(1),
    )
    ;
    match err {
        Err(Error::CrossingRequired) => {}
        Ok(_) => panic!("Orchard funded from transparent inputs must not build"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

/// A recipient transparent address, derived from the test key.
fn t_recipient(key: &AccountPrivKey) -> transparent::address::TransparentAddress {
    transparent::address::TransparentAddress::from_pubkey(
        &key.to_account_pubkey()
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(9).unwrap(),
            )
            .unwrap(),
    )
}

/// Real spendable notes in `pool`, from a scanned synthetic chain.
fn notes(pool: PoolId, alice: &Keys) -> Vec<zakura_wallet_tx::SpendableNote> {
    let mut db = common::funded_wallet(pool, 2, 500_000, &alice.fvk);
    let anchors = zakura_wallet_tx::anchors(&mut db).unwrap();
    zakura_wallet_tx::spendable_notes(&mut db, common::ALICE, &alice.fvk, &anchors, false)
        .unwrap()
        .into_iter()
        .map(|(note, _)| note)
        .collect()
}

#[test]
fn paying_a_transparent_address_costs_what_the_builder_will_charge() {
    // The fee has to come from the same place the action count does. An earlier
    // version counted actions by hand here and came out one too high, which is
    // a fee somebody pays for nothing and a number the builder disagrees with.
    let key = transparent_key();
    let alice = keys_from(1);

    let proposal = zakura_wallet_tx::plan_transparent_payment(
        notes(PoolId::Ironwood, &alice),
        t_recipient(&key),
        Zatoshis::const_from_u64(100_000),
    )
    .expect("the wallet's notes cover the payment");

    // The payment leaves transparently, so it is not a shielded output; only
    // the change is. The fee must be the one those actions imply.
    let (orchard, ironwood) = proposal.action_counts();
    assert_eq!(orchard, 0, "nothing Orchard is involved");
    assert_eq!(
        proposal.fee,
        fee::required_with(fee::TransparentSizes::p2pkh(0, 1), orchard, ironwood),
        "the fee must be the one implied by the actions the builder will make"
    );
    assert!(proposal.balances(), "inputs equal outputs plus the fee");
    assert_eq!(
        proposal.transparent_payment.unwrap().1,
        Zatoshis::const_from_u64(100_000)
    );
}

#[test]
fn an_orchard_funded_payment_to_a_transparent_address_is_refused() {
    // It would be a spend-only Orchard bundle with a positive value balance
    // feeding a transparent output: a visible exit from the pool that no
    // ordinary transaction resembles, marking its sender out precisely when
    // they were trying not to stand out.
    let key = transparent_key();
    let alice = keys_from(1);

    match zakura_wallet_tx::plan_transparent_payment(
        notes(PoolId::Orchard, &alice),
        t_recipient(&key),
        Zatoshis::const_from_u64(100_000),
    ) {
        Err(Error::CrossingRequired) => {}
        Ok(_) => panic!("Orchard must not fund a transparent payment directly"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}
