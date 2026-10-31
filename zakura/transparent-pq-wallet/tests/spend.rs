use std::num::NonZeroU32;

use transparent::address::TransparentAddress;
use transparent::bundle::{OutPoint, TxOut};
use transparent_pq_keys::{Branch, KeyOrigin, Network, ParameterSet, WalletSeed};
use transparent_pq_pool::AccountPool;
use transparent_pq_wallet::{
    Payment, PqScript, PqSigner, PqUtxo, SeedSigner, SeedSignerError, SigningRequest,
    SigningResponse, SpendError, VerifyError, build_spend, verify_inputs,
};
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

fn payment(value: u64) -> Payment {
    Payment {
        address: TransparentAddress::ScriptHash([9; 20]),
        value: Zatoshis::const_from_u64(value),
    }
}

#[test]
fn addresses_are_p2sh_over_the_pq_header_and_key() {
    for (parameters, version, key_push) in [
        (ParameterSet::Sha2_128f, 1, 0x20),
        (ParameterSet::Sha2_192s, 2, 0x30),
    ] {
        let key = seed().derive_key(origin(parameters, 0, Branch::Receive, 0));
        let script = PqScript::single_signer(&key.public_key());
        let redeem = script.redeem_script();
        assert_eq!(&redeem[..6], &[0x50, 0x02, b'P', b'Q', 0x01, version]);
        assert_eq!(redeem[6], key_push);
        assert_eq!(&redeem[7..redeem.len() - 1], key.public_key().as_bytes());
        assert_eq!(redeem[redeem.len() - 1], 0xac);
        assert!(matches!(
            script.address(),
            TransparentAddress::ScriptHash(_)
        ));
        // Regtest and testnet share the "t2" P2SH prefix.
        assert!(script.encode(Network::Regtest).starts_with("t2"));
        assert!(script.encode(Network::Mainnet).starts_with("t3"));
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
        &[input],
        &[payment(1_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();

    verify_inputs(&spend.transaction, &spend.spent).unwrap();
    let change = spend.change.expect("change is far above dust");
    assert!(change.fresh);
    assert_eq!(
        change.origin,
        origin(ParameterSet::Sha2_128f, 0, Branch::Change, 0)
    );
    let outputs = &spend.transaction.transparent_bundle().unwrap().vout;
    assert_eq!(outputs.len(), 2);
    let change_script = PqScript::single_signer(&change.public_key).script_pubkey();
    assert_eq!(outputs[1].script_pubkey(), &change_script);
    let total_out: u64 = outputs.iter().map(|o| u64::from(o.value())).sum();
    assert_eq!(total_out + u64::from(spend.fee), 10_000_000);
    // One ~17 KB input is 115 ZIP 317 logical actions at 5000 zatoshis each.
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
        verify_inputs(&spend.transaction, &wrong_amount),
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
        verify_inputs(&tampered, &spend.spent),
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
        &inputs,
        &[payment(2_000_000)],
        &mut change_pool,
        &mut SeedSigner::new(self::seed()),
    )
    .unwrap();
    verify_inputs(&spend.transaction, &spend.spent).unwrap();
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
        &[input.clone()],
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
        &[input],
        &[payment(1_000_000 - exact_fee + 1)],
        &mut pool(ParameterSet::Sha2_128f),
        &mut SeedSigner::new(self::seed()),
    );
    assert!(matches!(short, Err(SpendError::InsufficientFunds { .. })));
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
            &[input.clone()],
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
