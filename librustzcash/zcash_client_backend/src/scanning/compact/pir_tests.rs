//! Tests for the Ironwood Enhance PIR candidates produced by compact block scanning.

use std::convert::Infallible;

use incrementalmerkletree::Position;
use orchard::{
    keys::Scope,
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    value::NoteValue,
};
use pasta_curves::{
    group::ff::{Field, PrimeField},
    pallas,
};
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_note_encryption::Domain;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Network};
use zip32::AccountId;

use super::scan_block_with_runners;
use crate::{
    data_api::BlockMetadata,
    proto::compact_formats::{ChainMetadata, CompactBlock, CompactOrchardAction, CompactTx},
    scanning::{Nullifiers, ScanningKeys},
};

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

fn outgoing_candidates<A>(
    tx: &crate::wallet::WalletTx<A>,
) -> &[crate::wallet::IronwoodEnhanceCandidate<A>] {
    match tx.ironwood_enhancement_plan() {
        crate::wallet::IronwoodEnhancementPlan::Eligible { outgoing } => outgoing,
        crate::wallet::IronwoodEnhancementPlan::Ineligible => &[],
    }
}

#[test]
fn pir_candidate_rejects_every_explicit_non_ironwood_field() {
    use crate::proto::compact_formats::CompactTx;
    let empty = CompactTx::default();
    assert!(!super::is_ironwood_pir_candidate(&empty));
    let pure = CompactTx {
        ironwood_actions: vec![Default::default()],
        ..empty
    };
    assert!(super::is_ironwood_pir_candidate(&pure));
    for field in 0..5 {
        let mut mixed = pure.clone();
        match field {
            0 => mixed.vin.push(Default::default()),
            1 => mixed.vout.push(Default::default()),
            2 => mixed.spends.push(Default::default()),
            3 => mixed.outputs.push(Default::default()),
            4 => mixed.actions.push(Default::default()),
            _ => unreachable!(),
        }
        assert!(!super::is_ironwood_pir_candidate(&mixed), "field {field}");
    }
}

#[test]
fn owned_ironwood_spend_captures_every_action_for_outgoing_recovery() {
    let network = Network::TestNetwork;
    let account = AccountId::try_from(12).unwrap();
    let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
    let mut rng = OsRng;
    let owned_nullifier =
        orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
    let other_nullifier =
        orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
    let cmx_0 = pallas::Base::random(&mut rng).to_repr();
    let cmx_1 = pallas::Base::random(&mut rng).to_repr();
    let actions = [(owned_nullifier, cmx_0), (other_nullifier, cmx_1)].map(|(nullifier, cmx)| {
        CompactOrchardAction {
            nullifier: nullifier.to_bytes().to_vec(),
            cmx: cmx.to_vec(),
            ephemeral_key: vec![0; 32],
            ciphertext: vec![0; 52],
        }
    });
    let mut tx = CompactTx {
        txid: vec![7; 32],
        ..Default::default()
    };
    tx.ironwood_actions.extend(actions);
    let mut mixed_tx = tx.clone();
    mixed_tx.actions.push(mixed_tx.ironwood_actions[0].clone());
    let mut block = CompactBlock {
        hash: vec![1; 32],
        prev_hash: vec![0; 32],
        height: 1,
        ..Default::default()
    };
    block.vtx.push(tx);
    block.chain_metadata = Some(ChainMetadata {
        sapling_commitment_tree_size: 0,
        orchard_commitment_tree_size: 0,
        ironwood_commitment_tree_size: 7,
    });
    let nullifiers = Nullifiers::new(vec![], vec![], vec![(account, owned_nullifier)]);

    let scanned = scan_block_with_runners::<_, _, _, (), (), ()>(
        &network,
        block,
        &scanning_keys,
        &nullifiers,
        Some(&BlockMetadata::from_parts(
            BlockHeight::from(0),
            BlockHash([0; 32]),
            Some(0),
            Some(0),
            Some(5),
        )),
        None,
    )
    .unwrap();

    let tx = &scanned.transactions()[0];
    assert_eq!(tx.ironwood_spends().len(), 1);
    assert_eq!(outgoing_candidates(tx).len(), 2);
    for (index, candidate) in outgoing_candidates(tx).iter().enumerate() {
        assert_eq!(candidate.position(), Position::from(5 + index as u64));
        assert_eq!(candidate.output_index(), index);
        assert_eq!(candidate.funding_accounts(), &[account]);
        assert_eq!(candidate.ephemeral_key(), &[0; 32]);
        assert_eq!(candidate.compact_ciphertext(), &[0; 52]);
    }
    assert_eq!(
        outgoing_candidates(tx)[0].nullifier(),
        &owned_nullifier.to_bytes()
    );
    assert_eq!(outgoing_candidates(tx)[0].cmx(), &cmx_0);
    assert_eq!(
        outgoing_candidates(tx)[1].nullifier(),
        &other_nullifier.to_bytes()
    );
    assert_eq!(outgoing_candidates(tx)[1].cmx(), &cmx_1);
    assert!(matches!(
        tx.ironwood_enhancement_plan(),
        crate::wallet::IronwoodEnhancementPlan::Eligible { .. }
    ));

    let mut mixed_block = CompactBlock {
        hash: vec![2; 32],
        prev_hash: vec![0; 32],
        height: 1,
        ..Default::default()
    };
    mixed_block.vtx.push(mixed_tx);
    mixed_block.chain_metadata = Some(ChainMetadata {
        sapling_commitment_tree_size: 0,
        orchard_commitment_tree_size: 1,
        ironwood_commitment_tree_size: 7,
    });
    let mixed_scanned = scan_block_with_runners::<_, _, _, (), (), ()>(
        &network,
        mixed_block,
        &scanning_keys,
        &nullifiers,
        Some(&BlockMetadata::from_parts(
            BlockHeight::from(0),
            BlockHash([0; 32]),
            Some(0),
            Some(0),
            Some(5),
        )),
        None,
    )
    .unwrap();
    let mixed_tx = &mixed_scanned.transactions()[0];
    assert!(!matches!(
        mixed_tx.ironwood_enhancement_plan(),
        crate::wallet::IronwoodEnhancementPlan::Eligible { .. }
    ));
    assert!(
        outgoing_candidates(mixed_tx).is_empty(),
        "mixed-pool transactions must remain on standard txid enhancement"
    );
}

/// A wallet-owned Ironwood output — in particular change, which is found because
/// `ScanningKeys` covers the internal scope — is served by the incoming memo queue. It must
/// not also be emitted as an outgoing candidate: change is encrypted under the internal OVK
/// while outgoing recovery holds only the external one, so such an entry could never be
/// resolved and would keep its transaction protected, and so un-enhanced, forever.
#[test]
fn wallet_owned_ironwood_outputs_are_not_outgoing_candidates() {
    let network = Network::TestNetwork;
    let account = AccountId::try_from(0).unwrap();
    let usk = UnifiedSpendingKey::from_seed(&network, &[0; 32], account).unwrap();
    let ufvk = usk.to_unified_full_viewing_key();
    let fvk = ufvk.orchard().expect("Orchard key is present").clone();
    let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);
    let mut rng = OsRng;

    // Action 0 spends a note the wallet owns and pays change back to the wallet's own
    // internal address, so the scanner decrypts it as a received note.
    let owned_nf =
        orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
    let rho = Rho::from_bytes(&owned_nf.to_bytes()).unwrap();
    let rseed = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(rseed) = Option::from(RandomSeed::from_bytes(bytes, &rho)) {
            break rseed;
        }
    };
    let change = Note::from_parts(
        fvk.address_at(0u32, Scope::Internal),
        NoteValue::from_raw(1000),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    // Change carries the internal OVK, exactly as the builder writes it.
    let encryptor =
        IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::Internal)), change, [0; 512]);
    let change_action = CompactOrchardAction {
        nullifier: owned_nf.to_bytes().to_vec(),
        cmx: ExtractedNoteCommitment::from(change.commitment())
            .to_bytes()
            .to_vec(),
        ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0.to_vec(),
        ciphertext: encryptor.encrypt_note_plaintext()[..52].to_vec(),
    };

    // Action 1 pays someone else, so the wallet cannot decrypt it and it stays a candidate.
    let other_nf =
        orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
    let external_cmx = pallas::Base::random(&mut rng).to_repr();
    let external_action = CompactOrchardAction {
        nullifier: other_nf.to_bytes().to_vec(),
        cmx: external_cmx.to_vec(),
        ephemeral_key: vec![0; 32],
        ciphertext: vec![0; 52],
    };

    let mut tx = CompactTx {
        txid: vec![3; 32],
        ..Default::default()
    };
    tx.ironwood_actions.push(change_action);
    tx.ironwood_actions.push(external_action);
    let mut block = CompactBlock {
        hash: vec![1; 32],
        prev_hash: vec![0; 32],
        height: 1,
        ..Default::default()
    };
    block.vtx.push(tx);
    block.chain_metadata = Some(ChainMetadata {
        sapling_commitment_tree_size: 0,
        orchard_commitment_tree_size: 0,
        ironwood_commitment_tree_size: 2,
    });

    let scanned = scan_block_with_runners::<_, _, _, (), (), ()>(
        &network,
        block,
        &scanning_keys,
        &Nullifiers::new(vec![], vec![], vec![(account, owned_nf)]),
        Some(&BlockMetadata::from_parts(
            BlockHeight::from(0),
            BlockHash([0; 32]),
            Some(0),
            Some(0),
            Some(0),
        )),
        None,
    )
    .unwrap();

    let tx = &scanned.transactions()[0];
    assert!(matches!(
        tx.ironwood_enhancement_plan(),
        crate::wallet::IronwoodEnhancementPlan::Eligible { .. }
    ));
    assert_eq!(
        tx.ironwood_outputs().len(),
        1,
        "the change output should be received by the wallet"
    );
    assert_eq!(tx.ironwood_outputs()[0].index(), 0);
    // Dropping the outgoing candidate also drops the `sent_notes` row that would have been
    // written for this output, and with it `flag_previously_received_change`. That repair is
    // only needed for notes scanned before their transaction's spends were linkable — which
    // an Enhance PIR candidate never is, since it exists only when the wallet already
    // recognised the spend. So `is_change` has to be right here, at scan time.
    assert!(
        tx.ironwood_outputs()[0].is_change(),
        "change must be flagged during scanning, with no later repair to rely on"
    );

    let candidates = outgoing_candidates(tx);
    assert_eq!(
        candidates.len(),
        1,
        "only the output the wallet cannot decrypt needs outgoing recovery"
    );
    assert_eq!(candidates[0].output_index(), 1);
    assert_eq!(candidates[0].nullifier(), &other_nf.to_bytes());
}
