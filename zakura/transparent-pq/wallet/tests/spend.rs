use std::num::NonZeroU32;

use transparent::address::TransparentAddress;
use transparent::bundle::{OutPoint, TxOut};
use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, PublicKey, WalletSeed};
use transparent_pq_pool::{AccountPool, KeyRange};
use transparent_pq_wallet::{
    AddressError, Payment, PqDestination, PqSigner, PqUtxo, Recipient, SeedSigner, SeedSignerError,
    SigningRequest, SigningResponse, SpendError, VerifyError, build_spend, max_payment,
    pq_receiver, pq_recipient, quote_spend, verify_inputs, with_pq_receiver,
};
use zcash_address::unified::PqScheme;
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;

const SEED: [u8; 32] = [0x5a; 32];

fn seed() -> WalletSeed {
    WalletSeed::from_bytes(&SEED).unwrap()
}

/// Regtest with every upgrade through NU6 active from height 1.
fn network() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: one,
        sapling: one,
        blossom: one,
        heartwood: one,
        canopy: one,
        nu5: one,
        nu6: one,
        nu6_1: None,
        nu6_2: None,
        nu6_3: None,
        nu7: None,
    }
}

fn target() -> BlockHeight {
    BlockHeight::from_u32(200)
}

/// The height the PQ rules start applying at, well below the target.
fn activation() -> BlockHeight {
    BlockHeight::from_u32(100)
}

fn origin(parameters: ParameterSet, account: u32, branch: Branch, index: u32) -> KeyOrigin {
    KeyOrigin::new(parameters, Network::Regtest, account, branch, index)
}

fn utxo(seed: &WalletSeed, origin: KeyOrigin, value: u64, tag: u8) -> PqUtxo {
    PqUtxo {
        outpoint: OutPoint::new([tag; 32], 0),
        value: Zatoshis::const_from_u64(value),
        origin,
        public_key: seed.derive_key(origin).public_key(),
    }
}

fn pool(parameters: ParameterSet) -> AccountPool {
    let mut pool = AccountPool::new(parameters, Network::Regtest, 0, NonZeroU32::new(2).unwrap());
    let mut source = seed();
    pool.replenish(Branch::Receive, &mut source).unwrap();
    pool.replenish(Branch::Change, &mut source).unwrap();
    pool
}

fn legacy_recipient() -> Recipient {
    Recipient::Transparent(TransparentAddress::ScriptHash([9; 20]))
}

fn payment(value: u64) -> Payment {
    Payment {
        recipient: legacy_recipient(),
        value: Zatoshis::const_from_u64(value),
    }
}

/// An Orchard receiver, so a Unified Address carrying a PQ receiver can be encoded: a PQ
/// receiver is transparent and may not stand alone.
fn orchard_address() -> orchard::Address {
    let key = orchard::keys::SpendingKey::from_bytes([0x2c; 32]).unwrap();
    orchard::keys::FullViewingKey::from(&key).address_at(0u32, orchard::keys::Scope::External)
}

fn unified_address() -> UnifiedAddress {
    UnifiedAddress::from_receivers(Some(orchard_address()), None)
        .expect("an Orchard receiver is enough for a Unified Address")
}

/// ZIP 317's conventional fee, re-derived from the specification rather than from this
/// crate's fee code: one logical action per 150 bytes of transparent inputs or outputs,
/// whichever is larger, with two actions granted free.
fn conventional_fee(input_bytes: usize, output_bytes: usize) -> u64 {
    const MARGINAL_FEE: u64 = 5_000;
    const GRACE_ACTIONS: u64 = 2;
    let actions = |bytes: usize| (bytes as u64).div_ceil(150);
    MARGINAL_FEE * GRACE_ACTIONS.max(actions(input_bytes).max(actions(output_bytes)))
}

/// The serialized sizes of a transaction's transparent inputs and outputs.
fn transparent_sizes(transaction: &zcash_primitives::transaction::Transaction) -> (usize, usize) {
    let bundle = transaction.transparent_bundle().unwrap();
    let inputs = bundle
        .vin
        .iter()
        .map(|input| 36 + input.script_sig().serialized_size() + 4)
        .sum();
    let outputs = bundle
        .vout
        .iter()
        .map(|output| 8 + output.script_pubkey().serialized_size())
        .sum();
    (inputs, outputs)
}

#[test]
fn outputs_commit_to_the_canonical_single_key_body() {
    for (parameters, scheme_opcode, key_push, body_bytes) in [
        (ParameterSet::Sha2_128f, 0x51, 0x20, 34),
        (ParameterSet::Sha2_192s, 0x52, 0x30, 50),
    ] {
        let key = seed().derive_key(origin(parameters, 0, Branch::Receive, 0));
        let destination = PqDestination::single_signer(&key.public_key());

        // The body is one key and one signature check, with the key pushed directly.
        let body = destination.body();
        assert_eq!(body.len(), body_bytes);
        assert_eq!(body[0], key_push);
        assert_eq!(&body[1..body.len() - 1], key.public_key().as_bytes());
        assert_eq!(body[body.len() - 1], 0xac);

        // The commitment is SHA-256 of exactly those bytes, with no prefix or header.
        assert_eq!(
            destination.commitment(),
            &transparent::pq::single_key::commitment(
                match parameters {
                    ParameterSet::Sha2_128f => transparent::pq::ParameterSet::Sha2_128f,
                    ParameterSet::Sha2_192s => transparent::pq::ParameterSet::Sha2_192s,
                },
                key.public_key().as_bytes(),
            )
            .unwrap()
        );

        // The output is thirty-five bytes: format 0, the scheme, and one push of 32.
        let script = destination.script_pubkey();
        let bytes = &script.0.0;
        assert_eq!(bytes.len(), 35);
        assert_eq!(&bytes[..3], &[0x00, scheme_opcode, 0x20]);
        assert_eq!(&bytes[3..], destination.commitment());
    }
}

#[test]
fn a_spend_verifies_pays_conventional_fee_and_sends_change_to_the_next_key() {
    let seed = seed();
    let mut change_pool = pool(ParameterSet::Sha2_128f);
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        10_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();

    verify_inputs(network().network_type(), &spend.transaction, &spend.spent).unwrap();
    let change = spend.change.expect("change is far above dust");
    assert!(change.fresh);
    assert_eq!(
        change.origin,
        origin(ParameterSet::Sha2_128f, 0, Branch::Change, 0)
    );
    let outputs = &spend.transaction.transparent_bundle().unwrap().vout;
    assert_eq!(outputs.len(), 2);
    let change_script = PqDestination::single_signer(&change.public_key).script_pubkey();
    assert_eq!(outputs[1].script_pubkey(), &change_script);
    let total_out: u64 = outputs.iter().map(|o| u64::from(o.value())).sum();
    assert_eq!(total_out + u64::from(spend.fee), 10_000_000);
    // One ~17 KB input dominates the action count; the two outputs are 76 bytes together.
    let (input_bytes, output_bytes) = transparent_sizes(&spend.transaction);
    assert_eq!(
        u64::from(spend.fee),
        conventional_fee(input_bytes, output_bytes)
    );
    assert_eq!(u64::from(spend.fee), 115 * 5_000);
    // Change rotation leaves the receiving index alone.
    assert_eq!(change_pool.state().receive.issued_end, 0);
}

#[test]
fn a_changed_output_or_signature_fails_verification() {
    let seed = seed();
    let mut change_pool = pool(ParameterSet::Sha2_128f);
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        10_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();

    // The signatures commit to the spent amounts.
    let mut wrong_amount = spend.spent.clone();
    wrong_amount[0] = TxOut::new(
        Zatoshis::const_from_u64(10_000_001),
        wrong_amount[0].script_pubkey().clone(),
    );
    assert_eq!(
        verify_inputs(network().network_type(), &spend.transaction, &wrong_amount),
        Err(VerifyError::Invalid(0))
    );

    // Flip one signature byte in the serialized transaction.
    let mut bytes = Vec::new();
    spend.transaction.write(&mut bytes).unwrap();
    let position = bytes
        .windows(3)
        .position(|w| w == [0x4d, 0xc1, 0x42]) // PUSHDATA2 of 17,089 bytes
        .expect("signature push");
    bytes[position + 100] ^= 1;
    let tampered = zcash_primitives::transaction::Transaction::read(
        &bytes[..],
        spend.transaction.consensus_branch_id(),
    )
    .unwrap();
    assert_eq!(
        verify_inputs(network().network_type(), &tampered, &spend.spent),
        Err(VerifyError::Invalid(0))
    );
}

#[test]
fn mixed_parameter_sets_and_accounts_spend_together() {
    let seed = seed();
    let mut change_pool = pool(ParameterSet::Sha2_192s);
    let inputs = [
        utxo(
            &seed,
            origin(ParameterSet::Sha2_128f, 0, Branch::Change, 3),
            3_000_000,
            1,
        ),
        utxo(
            &seed,
            origin(ParameterSet::Sha2_192s, 1, Branch::Receive, 0),
            4_000_000,
            2,
        ),
    ];
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &inputs,
        &[payment(2_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();
    verify_inputs(network().network_type(), &spend.transaction, &spend.spent).unwrap();
    assert_eq!(
        spend.change.unwrap().origin.parameters(),
        ParameterSet::Sha2_192s
    );
}

#[test]
fn dust_change_goes_to_the_fee_and_shortfalls_are_reported() {
    let seed = seed();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        1_000_000,
        1,
    );
    // Fee without change: 115 actions (the input dominates the output count).
    let exact_fee = 115 * 5_000;
    let mut change_pool = pool(ParameterSet::Sha2_128f);
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        std::slice::from_ref(&input),
        &[payment(1_000_000 - exact_fee - 50)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();
    assert!(spend.change.is_none());
    assert_eq!(u64::from(spend.fee), exact_fee + 50);
    assert_eq!(change_pool.state().change.issued_end, 0);

    let short = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000 - exact_fee + 1)],
        &mut pool(ParameterSet::Sha2_128f),
        &mut SeedSigner::new(self::seed()),
    );
    assert!(matches!(short, Err(SpendError::InsufficientFunds { .. })));
}

#[test]
fn the_quote_matches_the_built_spend_and_max_leaves_no_change() {
    let seed = seed();
    let inputs = [
        utxo(
            &seed,
            origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
            2_000_000,
            1,
        ),
        utxo(
            &seed,
            origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 1),
            900_000,
            2,
        ),
    ];
    let values: Vec<Zatoshis> = inputs.iter().map(|input| input.value).collect();
    let quote_for = |value| {
        quote_spend(
            &network(),
            target(),
            ParameterSet::Sha2_128f,
            &values,
            &[payment(value)],
        )
    };
    let build = |value| {
        build_spend(
            &network(),
            target(),
            activation(),
            &inputs,
            &[payment(value)],
            &mut pool(ParameterSet::Sha2_128f),
            &mut SeedSigner::new(self::seed()),
        )
        .unwrap()
    };

    // With change, and with a remainder too small for change.
    let max = max_payment(
        &network(),
        target(),
        ParameterSet::Sha2_128f,
        &values,
        &legacy_recipient(),
    )
    .unwrap();
    for value in [500_000, u64::from(max) - 50] {
        let quote = quote_for(value).unwrap();
        let spend = build(value);
        assert_eq!(quote.fee, spend.fee);
        assert_eq!(
            quote.change,
            spend
                .change
                .map(|_| spend.transaction.transparent_bundle().unwrap().vout[1].value())
        );
    }
    assert!(quote_for(u64::from(max) - 50).unwrap().change.is_none());

    let all = quote_for(u64::from(max)).unwrap();
    assert_eq!(all.change, None);
    assert_eq!(u64::from(all.fee) + u64::from(max), 2_900_000);
    assert!(matches!(
        quote_for(u64::from(max) + 1),
        Err(SpendError::InsufficientFunds { .. })
    ));
}

#[test]
fn signing_refills_the_pool_in_the_same_call() {
    let seed = seed();
    let mut change_pool = pool(ParameterSet::Sha2_128f);
    // A payment received at index 1 widens the receiving window by two keys.
    change_pool
        .record_received(origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 1))
        .unwrap();
    let missing = change_pool.replenish_request(Branch::Receive).unwrap();
    assert_eq!(missing.count().get(), 2);

    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 1),
        5_000_000,
        1,
    );
    build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();
    assert_eq!(change_pool.replenish_request(Branch::Receive), None);
    assert_eq!(change_pool.state().receive.public_keys.len(), 4);
    assert_eq!(
        change_pool.state().receive.public_keys[3],
        seed.derive_key(origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 3))
            .public_key()
    );
}

#[test]
fn change_keys_are_derived_before_signing_when_none_is_left() {
    let seed = seed();
    // Receiving keys are derived but no change key is yet.
    let mut change_pool = AccountPool::new(
        ParameterSet::Sha2_128f,
        Network::Regtest,
        0,
        NonZeroU32::new(2).unwrap(),
    );
    change_pool
        .replenish(Branch::Receive, &mut self::seed())
        .unwrap();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        5_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();
    verify_inputs(network().network_type(), &spend.transaction, &spend.spent).unwrap();
    let change = spend.change.unwrap();
    assert!(change.fresh);
    assert_eq!(
        change.origin,
        origin(ParameterSet::Sha2_128f, 0, Branch::Change, 0)
    );
    assert_eq!(change_pool.state().change.public_keys.len(), 2);
}

#[test]
fn change_steps_past_a_used_up_window_instead_of_reusing_a_key() {
    let seed = seed();
    // Two spends whose change has not confirmed use up a window of two.
    let mut change_pool = pool(ParameterSet::Sha2_128f);
    change_pool.issue(Branch::Change).unwrap();
    change_pool.issue(Branch::Change).unwrap();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        5_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();
    verify_inputs(network().network_type(), &spend.transaction, &spend.spent).unwrap();
    let change = spend.change.unwrap();
    assert!(change.fresh);
    assert_eq!(
        change.origin,
        origin(ParameterSet::Sha2_128f, 0, Branch::Change, 2)
    );
    // The signing call already brought the next change key.
    assert_eq!(change_pool.state().change.public_keys.len(), 4);
}

/// Signs normally but derives no keys outside a signing call.
struct NoKeys(SeedSigner);

impl PqSigner for NoKeys {
    type Error = SeedSignerError;

    fn sign(&mut self, request: &SigningRequest<'_>) -> Result<SigningResponse, Self::Error> {
        self.0.sign(request)
    }

    fn public_keys(&mut self, _: &[KeyRange]) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
        Ok(Vec::new())
    }
}

#[test]
fn a_spend_fails_rather_than_reuse_change_when_no_key_is_derived() {
    let seed = seed();
    let mut change_pool = pool(ParameterSet::Sha2_128f);
    change_pool.issue(Branch::Change).unwrap();
    change_pool.issue(Branch::Change).unwrap();
    let before = change_pool.clone();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        5_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut NoKeys(SeedSigner::new(self::seed())),
    );
    assert!(matches!(spend, Err(SpendError::ChangeKeyNotDerived)));
    assert_eq!(change_pool, before);
}

/// Passes requests to the seed signer after changing what the wallet claims.
struct Tampering<F> {
    inner: SeedSigner,
    change: F,
}

impl<F: FnMut(&mut Vec<(usize, KeyOrigin)>, &mut Vec<KeyOrigin>)> PqSigner for Tampering<F> {
    type Error = SeedSignerError;

    fn sign(&mut self, request: &SigningRequest<'_>) -> Result<SigningResponse, Self::Error> {
        let mut change = request.change.clone();
        let mut input_keys = request.input_keys.clone();
        (self.change)(&mut change, &mut input_keys);
        self.inner.sign(&SigningRequest {
            transaction: request.transaction,
            input_keys,
            change,
            replenish: request.replenish.clone(),
        })
    }

    fn public_keys(
        &mut self,
        ranges: &[KeyRange],
    ) -> Result<Vec<(KeyOrigin, PublicKey)>, Self::Error> {
        self.inner.public_keys(ranges)
    }
}

#[test]
fn the_seed_signer_refuses_foreign_change_and_inputs() {
    let seed = seed();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        5_000_000,
        1,
    );
    let attempt = |tamper: fn(&mut Vec<(usize, KeyOrigin)>, &mut Vec<KeyOrigin>)| {
        build_spend(
            &network(),
            target(),
            activation(),
            std::slice::from_ref(&input),
            &[payment(1_000_000)],
            &mut pool(ParameterSet::Sha2_128f),
            &mut Tampering {
                inner: SeedSigner::new(self::seed()),
                change: tamper,
            },
        )
    };
    // The payment output is not the wallet's change.
    assert!(matches!(
        attempt(|change, _| change[0].0 = 0),
        Err(SpendError::Signer(SeedSignerError::ForeignChange(0)))
    ));
    assert!(matches!(
        attempt(|change, _| change[0].0 = 7),
        Err(SpendError::Signer(SeedSignerError::MissingOutput(7)))
    ));
    // A key that does not control the input.
    assert!(matches!(
        attempt(|_, keys| keys[0] = origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 5)),
        Err(SpendError::Signer(SeedSignerError::ForeignInput(0)))
    ));
}

#[test]
fn the_network_used_in_tests_activates_nu5_at_the_target() {
    assert!(network().is_nu_active(NetworkUpgrade::Nu5, target()));
}

#[test]
fn an_address_publishes_the_commitment_and_a_sender_rebuilds_the_output() {
    // The chain the recovery promise rests on: one seed reaches one output script, with
    // nothing kept beside the seed. Every step is checked, and the last bytes are the ones
    // a payer writes from the address alone.
    for (parameters, scheme) in [
        (ParameterSet::Sha2_128f, PqScheme::Sha2_128f),
        (ParameterSet::Sha2_192s, PqScheme::Sha2_192s),
    ] {
        let key = seed().derive_key(origin(parameters, 0, Branch::Receive, 0));
        let public_key = key.public_key();
        let destination = PqDestination::single_signer(&public_key);

        // What the receiver publishes: the scheme its key fixes, and the bare commitment.
        let (published_scheme, commitment) = pq_receiver(&public_key);
        assert_eq!(published_scheme, scheme);
        assert_eq!(&commitment, destination.commitment());

        // The receiver rides in the Unified Address the wallet already hands out.
        let address = with_pq_receiver(unified_address(), &public_key);
        assert!(address.has_pq_transparent());
        let encoded = address.encode(&network());

        // What a sender does with it, from the encoded address alone.
        let decoded = match Address::decode(&network(), &encoded) {
            Some(Address::Unified(address)) => address,
            other => panic!("a Unified Address decodes as one, got {other:?}"),
        };
        let recipient = pq_recipient(&decoded).unwrap();
        assert_eq!(
            recipient,
            Recipient::Pq {
                parameters,
                commitment,
            }
        );
        assert_eq!(recipient.script(), destination.script_pubkey());
    }
}

#[test]
fn an_address_carries_one_pq_receiver_beside_its_others() {
    let key = |index| {
        seed()
            .derive_key(origin(ParameterSet::Sha2_128f, 0, Branch::Receive, index))
            .public_key()
    };

    // Attaching a second PQ receiver replaces the first: a wallet publishes one, because
    // every receiver it publishes is one it must still be able to sign for.
    let address = with_pq_receiver(with_pq_receiver(unified_address(), &key(0)), &key(1));
    assert_eq!(
        pq_recipient(&address).unwrap(),
        Recipient::Pq {
            parameters: ParameterSet::Sha2_128f,
            commitment: pq_receiver(&key(1)).1,
        }
    );

    // An address with no PQ receiver is an error, never a quiet fallback to a weaker one.
    assert_eq!(
        pq_recipient(&unified_address()),
        Err(AddressError::NoPqReceiver)
    );
}

#[test]
fn a_payment_to_a_pq_receiver_creates_that_receivers_output() {
    let seed = seed();
    let recipient_key = seed.derive_key(origin(ParameterSet::Sha2_192s, 7, Branch::Receive, 0));
    let address = with_pq_receiver(unified_address(), &recipient_key.public_key());
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        10_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[Payment {
            recipient: pq_recipient(&address).unwrap(),
            value: Zatoshis::const_from_u64(1_000_000),
        }],
        &mut pool(ParameterSet::Sha2_128f),
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();

    verify_inputs(network().network_type(), &spend.transaction, &spend.spent).unwrap();
    let outputs = &spend.transaction.transparent_bundle().unwrap().vout;
    // The payment is the recipient's own output, scheme and all, and the change is the
    // wallet's own PQ output under its own parameter set.
    assert_eq!(
        outputs[0].script_pubkey(),
        &PqDestination::single_signer(&recipient_key.public_key()).script_pubkey()
    );
    assert_eq!(outputs[0].script_pubkey().0.0[1], 0x52);
    assert_eq!(outputs[1].script_pubkey().0.0[1], 0x51);
}

#[test]
fn a_spend_below_the_activation_height_is_refused() {
    // Before the rules are in force a PQ output is claimable by an empty scriptSig, so
    // the wallet refuses to create one rather than hand out an unprotected address.
    let seed = seed();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        10_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        target() + 1,
        &[input],
        &[payment(1_000_000)],
        &mut pool(ParameterSet::Sha2_128f),
        &mut SeedSigner::new(self::seed()),
    );
    assert!(matches!(
        spend,
        Err(SpendError::NotActivated {
            target_height,
            activation,
        }) if target_height == target() && activation == target() + 1
    ));
}

#[test]
fn a_non_minimal_push_of_the_body_fails_verification() {
    // The body hashes to the commitment either way, but a PQ spend's pushes must be the
    // shortest encoding of their length, so the longer form is rejected before execution.
    let seed = seed();
    let input = utxo(
        &seed,
        origin(ParameterSet::Sha2_128f, 0, Branch::Receive, 0),
        10_000_000,
        1,
    );
    let spend = build_spend(
        &network(),
        target(),
        activation(),
        &[input],
        &[payment(1_000_000)],
        &mut pool(ParameterSet::Sha2_128f),
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();

    let bundle = spend.transaction.transparent_bundle().unwrap();
    let script_sig = &bundle.vin[0].script_sig().0.0;
    // The body is the last push: a direct push of 34 bytes.
    let body_start = script_sig.len() - 35;
    assert_eq!(script_sig[body_start], 0x22);
    let mut tampered = script_sig[..body_start].to_vec();
    tampered.push(0x4c);
    tampered.push(0x22);
    tampered.extend_from_slice(&script_sig[body_start + 1..]);

    let mut bytes = Vec::new();
    spend.transaction.write(&mut bytes).unwrap();
    let position = bytes
        .windows(script_sig.len())
        .position(|window| window == script_sig.as_slice())
        .expect("the scriptSig appears in the serialized transaction");
    let mut replaced = bytes[..position].to_vec();
    replaced.extend_from_slice(&tampered);
    replaced.extend_from_slice(&bytes[position + script_sig.len()..]);
    // The scriptSig grew by one byte, so fix its length prefix before reading it back.
    let prefix = position - 3;
    assert_eq!(
        u16::from_le_bytes([replaced[prefix + 1], replaced[prefix + 2]]) as usize,
        script_sig.len()
    );
    let grown = (script_sig.len() + 1) as u16;
    replaced[prefix + 1..prefix + 3].copy_from_slice(&grown.to_le_bytes());

    let transaction = zcash_primitives::transaction::Transaction::read(
        &replaced[..],
        spend.transaction.consensus_branch_id(),
    )
    .unwrap();
    assert_eq!(
        verify_inputs(network().network_type(), &transaction, &spend.spent),
        Err(VerifyError::Invalid(0))
    );
}
