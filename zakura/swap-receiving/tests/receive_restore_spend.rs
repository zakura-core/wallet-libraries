//! Protocol-level POC. This uses a local commitment tree, not a chain or wallet DB.
//! Signing uses a bundle commitment as a test message, not a transaction sighash.

use incrementalmerkletree::{Hashable, Marking, Position, Retention};
use orchard::{
    builder::{Builder, BundleType, SpendError},
    bundle::{BundleVersion, Flags, TxVersion},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    tree::MerkleHashOrchard,
    value::NoteValue,
};
use rand::rng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zakura_swap_receiving::{Purpose, RefundMemo, derive_full_viewing_key};
use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

#[test]
fn receive_restore_and_spend_both_purposes_with_ordinary_change() {
    let mut rng = rng();
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let public_ovk = OutgoingViewingKey::from([0; 32]);
    // Public deterministic fixture, never a live wallet seed.
    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let account = FullViewingKey::from(&sk);
    let internal = account.address_at(0u32, Scope::Internal);
    let deposit = ZcashAddress::from_transparent_p2pkh(NetworkType::Regtest, [7; 20]).to_string();
    let memo = RefundMemo::new(NetworkType::Regtest, 7, &deposit)
        .unwrap()
        .encode();

    // Only a proven bundle and fixture output indices survive this scope. Recovery below
    // must reconstruct the swap FVKs instead of retaining them from issuance.
    let (received, positions) = {
        let refund = derive_full_viewing_key(&account, Purpose::Refund, 7).unwrap();
        let incoming = derive_full_viewing_key(&account, Purpose::Receive, 0).unwrap();
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::ironwood_v3(),
            Flags::SPENDS_DISABLED,
            MerkleHashOrchard::empty_root(32.into()).into(),
        )
        .unwrap();
        // Zero-value recovery notes must decrypt even when no positive change exists.
        builder
            .add_output(
                Some(account.to_ovk(Scope::Internal)),
                internal,
                NoteValue::ZERO,
                memo,
            )
            .unwrap();
        for (fvk, value, ovk) in [
            (&account, 10_000, None),
            (&refund, 20_000, Some(public_ovk.clone())),
            (&incoming, 30_000, Some(public_ovk.clone())),
        ] {
            builder
                .add_output(
                    ovk,
                    fvk.address_at(0u32, Scope::External),
                    NoteValue::from_raw(value),
                    [0; 512],
                )
                .unwrap();
        }
        let (bundle, metadata) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let positions: Vec<_> = (0..4)
            .map(|i| metadata.output_action_index(i).unwrap())
            .collect();
        let sighash = bundle.commitment(TxVersion::V6).unwrap().into();
        let bundle = bundle
            .create_proof(&pk, &mut rng)
            .unwrap()
            .apply_signatures(&mut rng, sighash, &[])
            .unwrap();
        (bundle, positions)
    };

    received.verify_proof(&vk).unwrap();
    assert!(
        received
            .recover_output_with_ovk(positions[0], &public_ovk)
            .is_none()
    );
    for position in &positions[2..] {
        assert!(
            received
                .recover_output_with_ovk(*position, &public_ovk)
                .is_some()
        );
    }

    let (marker, _, recovered_memo) = received
        .decrypt_output_with_key(positions[0], &account.to_ivk(Scope::Internal))
        .unwrap();
    assert_eq!(marker.value(), NoteValue::ZERO);
    let record = RefundMemo::decode(NetworkType::Regtest, &recovered_memo)
        .unwrap()
        .unwrap();
    assert_eq!(record.deposit_address(), deposit);
    let refund = derive_full_viewing_key(&account, Purpose::Refund, record.index()).unwrap();
    // The incoming index is enumerated by lookahead, not read from a refund memo.
    let incoming = derive_full_viewing_key(&account, Purpose::Receive, 0).unwrap();

    for position in &positions[2..] {
        for scope in [Scope::External, Scope::Internal] {
            assert!(
                received
                    .decrypt_output_with_key(*position, &account.to_ivk(scope))
                    .is_none()
            );
        }
    }
    assert!(
        received
            .decrypt_output_with_key(positions[2], &incoming.to_ivk(Scope::External))
            .is_none()
    );
    assert!(
        received
            .decrypt_output_with_key(positions[3], &refund.to_ivk(Scope::External))
            .is_none()
    );

    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
        ShardTree::new(MemoryShardStore::empty(), 100);
    for (i, action) in received.actions().iter().enumerate() {
        let retention = if i + 1 == received.actions().len() {
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            }
        } else {
            Retention::Marked
        };
        tree.append(MerkleHashOrchard::from_cmx(action.cmx()), retention)
            .unwrap();
    }
    let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
    let mut spend = Builder::new(
        BundleType::DEFAULT,
        BundleVersion::ironwood_v3(),
        BundleVersion::ironwood_v3().default_flags(),
        root.into(),
    )
    .unwrap();
    for (fvk, position) in [&account, &refund, &incoming]
        .into_iter()
        .zip(&positions[1..])
    {
        let (note, _, _) = received
            .decrypt_output_with_key(*position, &fvk.to_ivk(Scope::External))
            .unwrap();
        let path = tree
            .witness_at_checkpoint_id(Position::from(*position as u64), &0)
            .unwrap()
            .unwrap();
        assert_eq!(
            path.root(MerkleHashOrchard::from_cmx(&note.commitment().into())),
            root
        );
        if *position != positions[1] {
            // Sharing spending authority does not make the account IVK own
            // this recipient. Input reconstruction must retain the derived FVK.
            assert_eq!(
                spend.add_spend(account.clone(), note, path.clone().into()),
                Err(SpendError::FvkMismatch)
            );
        }
        spend.add_spend(fvk.clone(), note, path.into()).unwrap();
    }
    // Change uses the ordinary internal key even when swap notes fund the spend.
    spend
        .add_output(
            Some(account.to_ovk(Scope::Internal)),
            internal,
            NoteValue::from_raw(60_000),
            [0; 512],
        )
        .unwrap();
    let (unsigned, metadata) = spend.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash: [u8; 32] = unsigned.commitment(TxVersion::V6).unwrap().into();
    let signed = unsigned
        .create_proof(&pk, &mut rng)
        .unwrap()
        .apply_signatures(&mut rng, sighash, &[SpendAuthorizingKey::from(&sk)])
        .unwrap();
    signed.verify_proof(&vk).unwrap();
    for action in signed.actions() {
        action
            .rk()
            .verify(&sighash, action.authorization())
            .unwrap();
    }
    signed
        .binding_validating_key()
        .verify(&sighash, signed.authorization().binding_signature())
        .unwrap();
    let (change, _, _) = signed
        .decrypt_output_with_key(
            metadata.output_action_index(0).unwrap(),
            &account.to_ivk(Scope::Internal),
        )
        .unwrap();
    assert_eq!(change.value(), NoteValue::from_raw(60_000));
}
