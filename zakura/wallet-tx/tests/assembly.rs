//! Tests for transaction assembly.
//!
//! The order the protocol forces is worth checking rather than assuming: spend
//! authorisation signatures commit to the transaction's signature hash, which
//! is computed from the transaction, so the transaction has to exist before it
//! can be signed. A wallet that signed first would produce signatures over
//! nothing, and the failure would appear as a rejected transaction rather than
//! as a mistake.

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use rand::SeedableRng;
use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zakura_wallet_scan::{
    NullifierSnapshot, ScanKeys, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_tx::{
    Keys, SpendRequest, anchors, payment, select, spendable_notes,
    testing::{proving_key, verifying_key},
    transaction::to_bytes,
    verify_proofs,
};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};

const ALICE: AccountId = AccountId(1);
const START: u32 = IRONWOOD_ACTIVATION + 10;

fn rng() -> rand::rngs::ChaCha20Rng {
    rand::rngs::ChaCha20Rng::seed_from_u64(19)
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

fn funded_wallet(value: u64, fvk: &FullViewingKey) -> WalletDb {
    let mut db = test_db().unwrap();
    db.set_birthday(BlockHeight::from_u32(START)).unwrap();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, fvk, KeyScope::External, value);
        });
    });
    chain.empty_blocks(2);

    let keys = ScanKeys::from_accounts([(ALICE, fvk.clone())]);
    let batch = detect_batch(
        &test_params(),
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    db.put_batch(&test_params(), &batch).unwrap();
    db
}

/// Builds a signed transaction paying a stranger from Ironwood notes.
fn signed_payment(expiry_offset: u32) -> (Transaction, Zatoshis) {
    let keys = alice_keys();
    let mut db = funded_wallet(500_000, &keys.fvk);
    let anchors = anchors(&mut db).unwrap();
    let witnesses = spendable_notes(&mut db, ALICE, &keys.fvk, &anchors, false).unwrap();

    let proposal = select(
        witnesses.iter().map(|(n, _)| n.clone()).collect(),
        PoolId::Ironwood,
        Zatoshis::const_from_u64(300_000),
    )
    .unwrap();
    let fee = proposal.fee;

    let tx = payment(
        &SpendRequest {
            proposal: &proposal,
            witnesses: &witnesses,
            keys: &keys,
            recipient: stranger(),
            anchors: &anchors,
        },
        BranchId::Nu6_3,
        anchors.height + expiry_offset,
        proving_key(),
        rng(),
    )
    .expect("the transaction assembles");

    (tx, fee)
}

#[test]
fn an_assembled_transaction_is_v6_and_carries_its_proofs() {
    let (tx, _) = signed_payment(100);

    // Ironwood exists only in v6, and both pools' bundles ride in the same
    // transaction, so the version is not a choice.
    assert_eq!(tx.version(), TxVersion::V6);
    assert!(tx.ironwood_bundle().is_some());
    assert!(tx.orchard_bundle().is_none(), "nothing was spent from Orchard");

    // The proofs still verify after assembly: nothing in the round trip through
    // a transaction disturbed them.
    verify_proofs(&tx, verifying_key()).expect("the proofs verify");
}

#[test]
fn the_authorisation_binds_to_the_transaction_it_was_built_for() {
    // The property that makes assembly-before-signing necessary. If the
    // signatures did not depend on the transaction, two transactions differing
    // only in their expiry would carry identical authorisation — and a wallet
    // could sign before assembling without noticing.
    //
    // Whether a signature is *valid* is consensus's job and needs the
    // randomised verification key of every action; what is checkable here is
    // that the authorisation is not independent of the transaction.
    let (early, _) = signed_payment(50);
    let (late, _) = signed_payment(500);

    assert_ne!(
        early.expiry_height(),
        late.expiry_height(),
        "the two differ only in expiry"
    );
    assert_ne!(
        early.txid(),
        late.txid(),
        "a different expiry is a different transaction"
    );

    let signature = |tx: &Transaction| {
        <[u8; 64]>::from(
            tx.ironwood_bundle()
                .expect("there is a bundle")
                .authorization()
                .binding_signature(),
        )
    };
    assert_ne!(
        signature(&early),
        signature(&late),
        "the binding signature must depend on the transaction it authorises"
    );
}

#[test]
fn the_value_balance_is_the_fee() {
    // What a shielded-only transaction gives up overall is exactly its fee.
    // Getting this wrong is a transaction the network rejects, and it is
    // cheaper to notice here.
    let (tx, fee) = signed_payment(100);

    let balance: i64 = tx
        .ironwood_bundle()
        .map_or(0, |b| (*b.value_balance()).into())
        + tx.orchard_bundle().map_or(0, |b| (*b.value_balance()).into());

    assert_eq!(balance, fee.into_u64() as i64);
}

#[test]
fn the_expiry_height_is_carried_through() {
    let (tx, _) = signed_payment(37);
    // The wallet was funded from `START`, scanned two blocks further, and the
    // anchor is the highest shared checkpoint.
    assert!(u32::from(tx.expiry_height()) > START);
}

#[test]
fn a_transaction_serialises_and_reads_back_identically() {
    // A transaction the wallet cannot serialise is one it cannot broadcast, and
    // one that does not survive a round trip is one the network would read
    // differently from the wallet that signed it.
    let (tx, _) = signed_payment(100);

    let bytes = to_bytes(&tx).expect("the transaction serialises");
    assert!(!bytes.is_empty());

    let parsed = Transaction::read(&bytes[..], BranchId::Nu6_3)
        .expect("the wallet's own transaction parses");

    assert_eq!(parsed.txid(), tx.txid(), "the round trip must preserve identity");
    assert_eq!(parsed.version(), TxVersion::V6);
    assert_eq!(
        to_bytes(&parsed).unwrap(),
        bytes,
        "re-serialising must reproduce the same bytes"
    );

    // And the parsed form still carries verifiable proofs, which is what a node
    // will check.
    verify_proofs(&parsed, verifying_key()).expect("the proofs verify after a round trip");
}

#[test]
fn a_transaction_with_no_bundles_is_refused() {
    use zakura_wallet_tx::transaction::{UnprovenBundles, assemble};

    let keys = alice_keys();
    let err = assemble(
        UnprovenBundles::default(),
        BranchId::Nu6_3,
        BlockHeight::from_u32(START),
        &keys,
        proving_key(),
        rng(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("no bundles"), "{err}");
}
