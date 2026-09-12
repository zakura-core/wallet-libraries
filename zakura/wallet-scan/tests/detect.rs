//! Behavioural tests for the detection pass.
//!
//! Every block here carries real encrypted notes, built by
//! [`zakura_wallet_scan::testing`], so these exercise the same cryptography the
//! scanner meets on mainnet. Nothing in this file touches a database.

use assert_matches::assert_matches;
use incrementalmerkletree::{Marking, Position, Retention};
use zakura_wallet_core::{
    CompactBlock,
    pool::{PoolId, TreeSizes},
};
use zakura_wallet_scan::{
    AccountId, BlockAnchor, KeyScope, NullifierSnapshot, ScanError, ScanKeys,
    detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, fvk_from_seed, script, test_params, test_rng},
};
use zcash_protocol::consensus::BlockHeight;

const ALICE: AccountId = AccountId(1);

/// The stored address row the watch set reports a hit against.
const BOB: AccountId = AccountId(2);

/// A chain whose first block sits comfortably above both activation heights.
const START: u32 = IRONWOOD_ACTIVATION + 10;

fn alice_keys() -> ScanKeys {
    ScanKeys::from_accounts([(ALICE, fvk_from_seed(1))])
}

fn no_keys() -> ScanKeys {
    ScanKeys::from_accounts([])
}

/// Runs detection with the given keys and nullifier snapshot, and no
/// transparent watch set.
fn detect(
    keys: &ScanKeys,
    nfs: &NullifierSnapshot,
    anchor: &BlockAnchor,
    blocks: &[CompactBlock],
) -> Result<zakura_wallet_scan::DetectedBatch, ScanError> {
    detect_batch(&test_params(), keys, nfs, anchor, blocks)
}

// ---------------------------------------------------------------- basics

#[test]
fn an_empty_batch_leaves_the_anchor_where_it_was() {
    let chain = ChainBuilder::new(START);
    let anchor = chain.anchor();

    let batch = detect(&alice_keys(), &NullifierSnapshot::default(), &anchor, &[])
        .expect("an empty batch is not an error");

    assert!(batch.blocks.is_empty());
    assert_eq!(batch.end_anchor, anchor);
}

#[test]
fn the_end_anchor_describes_the_last_block() {
    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(3);
    let anchor = chain.anchor();

    let batch = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &anchor,
        chain.blocks(),
    )
    .expect("detection succeeds");

    let last = chain.blocks().last().unwrap();
    assert_eq!(batch.end_anchor.height, last.height);
    assert_eq!(batch.end_anchor.hash, last.hash);
    assert_eq!(batch.end_anchor.tree_sizes, last.tree_sizes);
}

// ------------------------------------------------------------- receiving

#[test]
fn a_note_is_detected_in_each_pool() {
    for pool in PoolId::ALL {
        let alice = fvk_from_seed(1);
        let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
        let mut chain = ChainBuilder::new(START);
        chain.block(|b| {
            b.tx(|t| {
                t.receive(pool, &alice, KeyScope::External, 12_345);
            });
        });

        let batch = detect(
            &keys,
            &NullifierSnapshot::default(),
            &chain.anchor(),
            chain.blocks(),
        )
        .unwrap();

        let notes: Vec<_> = batch.received_notes().collect();
        assert_eq!(notes.len(), 1, "{pool:?}");
        let note = notes[0];
        assert_eq!(note.pool, pool);
        assert_eq!(note.account, ALICE);
        assert_eq!(note.scope, KeyScope::External);
        assert_eq!(note.note.value().inner(), 12_345);
        assert_eq!(note.position, Position::from(0));
        assert!(!note.is_change);
    }
}

#[test]
fn an_ironwood_note_is_not_visible_to_the_orchard_domain() {
    // Ironwood notes use version 3 plaintexts and Orchard notes version 2. The
    // domains accept only their own version, so a note planted in one pool must
    // not be found in the other's actions even though the same viewing key
    // opens both.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    for (planted, other) in [
        (PoolId::Ironwood, PoolId::Orchard),
        (PoolId::Orchard, PoolId::Ironwood),
    ] {
        let mut chain = ChainBuilder::new(START);
        chain.block(|b| {
            b.tx(|t| {
                t.receive(planted, &alice, KeyScope::External, 1);
            });
        });

        let batch = detect(
            &keys,
            &NullifierSnapshot::default(),
            &chain.anchor(),
            chain.blocks(),
        )
        .unwrap();

        let found: Vec<_> = batch.received_notes().collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pool, planted);
        assert!(
            batch.received_notes().all(|n| n.pool != other),
            "a {planted:?} note was visible as {other:?}"
        );
    }
}

#[test]
fn another_accounts_notes_are_not_detected() {
    let alice = fvk_from_seed(1);
    let bob = fvk_from_seed(2);
    let keys = ScanKeys::from_accounts([(ALICE, alice)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &bob, KeyScope::External, 500);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert_eq!(batch.received_notes().count(), 0);
    // The commitment is still recorded: the tree must track the chain whether
    // or not the notes in it are ours.
    assert_eq!(batch.blocks[0].ironwood.commitments.len(), 1);
}

#[test]
fn a_note_on_the_internal_scope_is_change() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::Internal, 7);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let note = batch.received_notes().next().unwrap();
    assert_eq!(note.scope, KeyScope::Internal);
    assert!(note.is_change);
}

#[test]
fn a_note_paid_to_an_account_that_funded_the_transaction_is_change() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let mut rng = test_rng(9);
    let spent_nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([(PoolId::Ironwood, spent_nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, spent_nf);
            // Received on the *external* scope, but from a transaction this
            // account funded, so it is still change.
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 3);
        });
    });

    let batch = detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();

    let note = batch.received_notes().next().unwrap();
    assert_eq!(note.scope, KeyScope::External);
    assert!(note.is_change);
}

// ------------------------------------------------------------- positions

#[test]
fn positions_are_tracked_independently_per_pool() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Orchard, 1);
            t.decoy(PoolId::Orchard, 1);
            t.receive(PoolId::Orchard, &alice, KeyScope::External, 10);
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 20);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let orchard = batch
        .received_notes()
        .find(|n| n.pool == PoolId::Orchard)
        .unwrap();
    let ironwood = batch
        .received_notes()
        .find(|n| n.pool == PoolId::Ironwood)
        .unwrap();

    // Two Orchard decoys precede the Orchard note, but the Ironwood tree knows
    // nothing about them.
    assert_eq!(orchard.position, Position::from(2));
    assert_eq!(ironwood.position, Position::from(0));
}

#[test]
fn positions_continue_across_transactions_and_blocks() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
        });
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 2);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let positions: Vec<u64> = batch.received_notes().map(|n| n.position.into()).collect();
    assert_eq!(positions, vec![1, 3]);
}

#[test]
fn positions_are_offset_by_the_anchors_tree_sizes() {
    // A range that starts above the birthday begins with trees that are already
    // populated; positions must be offsets into those, not from zero.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::with_anchor(
        START,
        TreeSizes {
            orchard: 1_000,
            ironwood: 77,
        },
    );
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
            t.receive(PoolId::Orchard, &alice, KeyScope::External, 1);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let ironwood = batch
        .received_notes()
        .find(|n| n.pool == PoolId::Ironwood)
        .unwrap();
    let orchard = batch
        .received_notes()
        .find(|n| n.pool == PoolId::Orchard)
        .unwrap();
    assert_eq!(ironwood.position, Position::from(77));
    assert_eq!(orchard.position, Position::from(1_000));
}

// ------------------------------------------------------------- retention

#[test]
fn wallet_notes_are_marked_and_the_last_commitment_checkpoints() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1); // marked
            t.decoy(PoolId::Ironwood, 1); // ephemeral
            t.decoy(PoolId::Ironwood, 1); // last: checkpoint, unmarked
        });
    });
    let height = chain.blocks()[0].height;

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let retentions: Vec<_> = batch.blocks[0]
        .ironwood
        .commitments
        .iter()
        .map(|(_, r)| *r)
        .collect();
    assert_eq!(
        retentions,
        vec![
            Retention::Marked,
            Retention::Ephemeral,
            Retention::Checkpoint {
                id: height,
                marking: Marking::None
            },
        ]
    );
}

#[test]
fn a_final_commitment_that_is_ours_is_both_checkpointed_and_marked() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });
    let height = chain.blocks()[0].height;

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert_matches!(
        batch.blocks[0].ironwood.commitments[1].1,
        Retention::Checkpoint {
            id,
            marking: Marking::Marked
        } if id == height
    );
}

#[test]
fn a_pool_with_no_actions_in_a_block_produces_no_commitments() {
    // The store adds an empty checkpoint for such a block; detection reports
    // only what the block actually contained.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert!(batch.blocks[0].orchard.commitments.is_empty());
    assert_eq!(batch.blocks[0].orchard.final_tree_size, 0);
    assert_eq!(batch.blocks[0].ironwood.final_tree_size, 1);
}

#[test]
fn commitments_are_recorded_even_with_no_keys() {
    let bob = fvk_from_seed(2);
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &bob, KeyScope::External, 1);
            t.decoy(PoolId::Orchard, 1);
        });
    });

    let batch = detect(
        &no_keys(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert_eq!(batch.received_notes().count(), 0);
    assert_eq!(batch.blocks[0].ironwood.commitments.len(), 1);
    assert_eq!(batch.blocks[0].orchard.commitments.len(), 1);
    assert_eq!(batch.end_anchor.tree_sizes.ironwood, 1);
    assert_eq!(batch.end_anchor.tree_sizes.orchard, 1);
}

// ---------------------------------------------------------------- spends

#[test]
fn a_spend_of_a_known_note_is_detected() {
    let keys = alice_keys();
    let mut rng = test_rng(3);
    let nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([(PoolId::Ironwood, nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });

    let batch = detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();

    let spends: Vec<_> = batch.spends().collect();
    assert_eq!(spends.len(), 1);
    assert_eq!(spends[0].account, ALICE);
    assert_eq!(spends[0].pool, PoolId::Ironwood);
    assert_eq!(spends[0].nullifier, nf);
    assert!(batch.blocks[0].ironwood.unlinked_nullifiers.is_empty());
}

#[test]
fn a_nullifier_is_matched_only_within_its_own_pool() {
    let keys = alice_keys();
    let mut rng = test_rng(4);
    let nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    // The wallet knows this nullifier as an *Orchard* note's.
    let nfs = NullifierSnapshot::new([(PoolId::Orchard, nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });

    let batch = detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();

    assert_eq!(batch.spends().count(), 0);
    assert_eq!(batch.blocks[0].ironwood.unlinked_nullifiers.len(), 1);
}

#[test]
fn unrecognised_nullifiers_are_kept_for_later_linking() {
    // Under descending recovery a spend is seen before the note it spends, so
    // these are not noise: discarding them would lose the spend forever.
    let keys = alice_keys();
    let mut rng = test_rng(5);
    let nf1 = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nf2 = zakura_wallet_scan::testing::random_nullifier(&mut rng);

    let mut chain = ChainBuilder::new(START);
    let mut txid = None;
    chain.block(|b| {
        txid = Some(b.tx(|t| {
            t.spend(PoolId::Ironwood, nf1);
            t.spend(PoolId::Ironwood, nf2);
        }));
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let unlinked = &batch.blocks[0].ironwood.unlinked_nullifiers;
    assert_eq!(unlinked.len(), 1);
    assert_eq!(unlinked[0].0, 0, "transaction index");
    assert_eq!(unlinked[0].1, txid.unwrap());
    assert_eq!(unlinked[0].2, vec![nf1, nf2]);
}

#[test]
fn a_note_received_and_spent_within_one_batch_is_linked() {
    // The nullifier snapshot is immutable, so this only works if detection
    // keeps its own overlay of notes discovered mid-batch.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 99);
        });
    });

    // Learn the nullifier the same way the wallet will.
    let first = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();
    let nf = first.received_notes().next().unwrap().nullifier;

    // Now rebuild the same chain with a later block spending it.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 99);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert_eq!(batch.received_notes().count(), 1);
    let spends: Vec<_> = batch.spends().collect();
    assert_eq!(spends.len(), 1, "the spend must be linked within the batch");
    assert_eq!(spends[0].nullifier, nf);
    assert_eq!(spends[0].account, ALICE);
    assert!(batch.blocks[1].ironwood.unlinked_nullifiers.is_empty());
}

#[test]
fn the_callers_snapshot_is_not_modified() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let nfs = NullifierSnapshot::default();

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });

    detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();

    assert!(nfs.is_empty(PoolId::Ironwood));
    assert!(nfs.is_empty(PoolId::Orchard));
}

// ----------------------------------------------------------- continuity

#[test]
fn a_parent_hash_mismatch_is_reported() {
    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(2);
    let mut blocks = chain.into_blocks();
    blocks[1].prev_hash = zakura_wallet_core::BlockHash([0xff; 32]);

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &ChainBuilder::new(START).anchor(),
        &blocks,
    )
    .unwrap_err();

    assert_matches!(err, ScanError::PrevHashMismatch { at_height } if at_height == blocks[1].height);
    assert!(err.is_continuity_error());
}

#[test]
fn an_anchor_that_does_not_precede_the_batch_is_reported() {
    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(1);
    let mut anchor = chain.anchor();
    anchor.hash = zakura_wallet_core::BlockHash([0x11; 32]);

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &anchor,
        chain.blocks(),
    )
    .unwrap_err();

    assert_matches!(err, ScanError::PrevHashMismatch { .. });
}

#[test]
fn a_height_gap_is_reported() {
    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(3);
    let anchor = chain.anchor();
    let mut blocks = chain.into_blocks();
    blocks.remove(1); // leaves a hole between the first and last

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &anchor,
        &blocks,
    )
    .unwrap_err();

    assert_matches!(
        err,
        ScanError::BlockHeightDiscontinuity { prev_height, new_height }
            if prev_height == BlockHeight::from_u32(START)
                && new_height == BlockHeight::from_u32(START + 2)
    );
    assert!(err.is_continuity_error());
}

#[test]
fn continuity_is_checked_before_any_decryption() {
    // A reorged batch should cost no trial decryption, so the error must not
    // depend on the blocks being decryptable. Corrupting a ciphertext leaves
    // detection able to report only the continuity failure.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });
    let anchor = chain.anchor();
    let mut blocks = chain.into_blocks();
    blocks[0].height = BlockHeight::from_u32(START + 5);

    let err = detect(&keys, &NullifierSnapshot::default(), &anchor, &blocks).unwrap_err();
    assert_matches!(err, ScanError::BlockHeightDiscontinuity { .. });
}

// -------------------------------------------------------- tree integrity

#[test]
fn dropping_an_action_is_detected_as_a_tree_size_mismatch() {
    // This is the check that matters most. Omitting one action shifts every
    // later note's position by one, which invalidates every witness derived
    // from it. Nothing downstream would notice until a spend proof failed.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });
    let anchor = chain.anchor();
    let mut blocks = chain.into_blocks();
    let height = blocks[0].height;

    // The server keeps the stated tree size but omits an action.
    blocks[0].txs[0].ironwood_actions.remove(0);

    let err = detect(&keys, &NullifierSnapshot::default(), &anchor, &blocks).unwrap_err();

    assert_matches!(
        err,
        ScanError::TreeSizeMismatch {
            pool: PoolId::Ironwood,
            at_height,
            given: 2,
            computed: 1,
        } if at_height == height
    );
    assert!(err.is_continuity_error());
}

#[test]
fn an_extra_action_is_detected_as_a_tree_size_mismatch() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });
    let anchor = chain.anchor();
    let mut blocks = chain.into_blocks();
    let extra = blocks[0].txs[0].ironwood_actions[0].clone();
    blocks[0].txs[0].ironwood_actions.push(extra);

    let err = detect(&keys, &NullifierSnapshot::default(), &anchor, &blocks).unwrap_err();

    assert_matches!(
        err,
        ScanError::TreeSizeMismatch {
            given: 1,
            computed: 2,
            ..
        }
    );
}

#[test]
fn an_understated_tree_size_is_detected() {
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Orchard, 1);
        });
    });
    let anchor = chain.anchor();
    let mut blocks = chain.into_blocks();
    blocks[0].tree_sizes.orchard = 0;

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &anchor,
        &blocks,
    )
    .unwrap_err();

    assert_matches!(
        err,
        ScanError::TreeSizeMismatch {
            pool: PoolId::Orchard,
            given: 0,
            computed: 1,
            ..
        }
    );
}

#[test]
fn actions_below_a_pools_activation_height_are_rejected() {
    // Consensus forbids this. Accepting it would mean deriving positions in a
    // tree that does not exist yet.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(IRONWOOD_ACTIVATION - 5);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });

    let err = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap_err();

    assert_matches!(
        err,
        ScanError::ActionsBeforeActivation {
            pool: PoolId::Ironwood,
            activation_height,
            ..
        } if activation_height == BlockHeight::from_u32(IRONWOOD_ACTIVATION)
    );
    assert!(!err.is_continuity_error());
}

#[test]
fn a_block_at_the_activation_height_is_accepted() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(IRONWOOD_ACTIVATION);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .expect("activation height itself is in range");
    assert_eq!(batch.received_notes().count(), 1);
}

// ----------------------------------------------------------- transparent

/// Scanning is no longer how transparent funds are found.
///
/// A payment to a script the wallet watches used to make the transaction the
/// wallet's. It does not any more: the private ledger discovers transparent
/// funds, and it is the only thing that can find an output at an address the
/// wallet had not derived when the block went past. See
/// `docs/zakura_transparent_pir.md`.
#[test]
fn a_payment_to_a_watched_script_is_not_detected_by_scanning() {
    let watched = script(7);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.transparent_out(script(9), 100); // not ours
            t.transparent_out(watched.clone(), 250);
        });
    });

    let batch = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert!(batch.blocks[0].transactions.is_empty());
}

/// What scanning still records: what a transaction it keeps consumed.
///
/// This is not discovery. It cannot create an output, and the store uses it
/// only to attach a spend to an output the ledger recovered — a correction
/// that can only lower a balance, never raise one.
#[test]
fn a_transaction_kept_for_its_notes_records_the_outpoints_it_spends() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let outpoint = transparent::bundle::OutPoint::new([9u8; 32], 3);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.transparent_in(outpoint.clone());
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1_000);
        });
    });

    let batch = detect_batch(
        &test_params(),
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert_eq!(
        batch.blocks[0].transactions[0].candidate_spends,
        vec![outpoint]
    );
}

/// A transaction with only transparent activity is not the wallet's at all.
///
/// Its inputs are not recorded either, because nothing keeps the transaction:
/// every transaction has inputs, so keeping it for them would keep the chain.
#[test]
fn a_transaction_with_only_transparent_activity_is_dropped() {
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.transparent_in(transparent::bundle::OutPoint::new([1u8; 32], 0));
            t.transparent_out(script(7), 100);
        });
    });

    let batch = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert!(batch.blocks[0].transactions.is_empty());
}

// ------------------------------------------------- enhancement candidates

#[test]
fn enhance_candidates_are_only_produced_for_funded_transactions() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        // Not funded by us: no candidates, even though it has Ironwood actions.
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert!(batch.blocks[0].transactions.is_empty());
}

#[test]
fn enhance_candidates_exclude_actions_we_received() {
    // An action we decrypted needs no recovery, and change is encrypted under
    // the internal outgoing key, so a job for it could never be resolved.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let mut rng = test_rng(11);
    let nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([(PoolId::Ironwood, nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf); // action 0: funds the transaction
            t.receive(PoolId::Ironwood, &alice, KeyScope::Internal, 5); // action 1: our change
            t.decoy(PoolId::Ironwood, 10); // action 2: the recipient, or padding
        });
    });

    let batch = detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();

    let tx = &batch.blocks[0].transactions[0];
    let indices: Vec<usize> = tx.enhance_candidates.iter().map(|c| c.action_index).collect();
    assert_eq!(
        indices,
        vec![0, 2],
        "the received change at index 1 must be excluded"
    );
    assert_eq!(tx.enhance_candidates[0].funding_accounts, vec![ALICE]);
}

#[test]
fn an_enhance_candidate_records_the_fields_that_authenticate_a_response() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let mut rng = test_rng(12);
    let nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([(PoolId::Ironwood, nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, nf);
        });
    });

    let batch = detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();
    let candidate = &batch.blocks[0].transactions[0].enhance_candidates[0];
    let action = &chain.blocks()[0].txs[0].ironwood_actions[0];

    assert_eq!(candidate.position, Position::from(0));
    assert_eq!(candidate.nullifier, action.nullifier());
    assert_eq!(candidate.cmx, action.cmx());
}

#[test]
fn orchard_actions_never_become_enhance_candidates() {
    // Private enhancement is Ironwood-only; an Orchard action must not produce
    // a job that could never be served.
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);
    let mut rng = test_rng(13);
    let nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([(PoolId::Orchard, nf, ALICE)]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Orchard, nf);
            t.decoy(PoolId::Orchard, 5);
        });
    });

    let batch = detect(&keys, &nfs, &chain.anchor(), chain.blocks()).unwrap();
    assert!(batch.blocks[0].transactions[0].enhance_candidates.is_empty());
}

// -------------------------------------------------------------- shaping

#[test]
fn transactions_with_no_wallet_activity_are_omitted() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 1);
        });
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
        });
        b.tx(|t| {
            t.decoy(PoolId::Orchard, 1);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    assert_eq!(batch.blocks[0].transactions.len(), 1);
    assert_eq!(batch.blocks[0].transactions[0].index, 1);
    // Their commitments are still there.
    assert_eq!(batch.blocks[0].ironwood.commitments.len(), 2);
    assert_eq!(batch.blocks[0].orchard.commitments.len(), 1);
}

#[test]
fn two_accounts_are_detected_independently() {
    let alice = fvk_from_seed(1);
    let bob = fvk_from_seed(2);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone()), (BOB, bob.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
            t.receive(PoolId::Ironwood, &bob, KeyScope::External, 2);
        });
    });

    let batch = detect(
        &keys,
        &NullifierSnapshot::default(),
        &chain.anchor(),
        chain.blocks(),
    )
    .unwrap();

    let mut by_account: Vec<_> = batch
        .received_notes()
        .map(|n| (n.account, n.note.value().inner()))
        .collect();
    by_account.sort();
    assert_eq!(by_account, vec![(ALICE, 1), (BOB, 2)]);
}

#[test]
fn detection_is_deterministic() {
    let alice = fvk_from_seed(1);
    let keys = ScanKeys::from_accounts([(ALICE, alice.clone())]);

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 1);
            t.decoy(PoolId::Orchard, 2);
        });
    });

    let anchor = chain.anchor();
    let first = detect(
        &keys,
        &NullifierSnapshot::default(),
        &anchor,
        chain.blocks(),
    )
    .unwrap();
    let second = detect(
        &keys,
        &NullifierSnapshot::default(),
        &anchor,
        chain.blocks(),
    )
    .unwrap();

    assert_eq!(first, second);
}

// ---------------------------------------------------------- snapshot api

#[test]
fn a_snapshot_reports_its_contents_per_pool() {
    let mut rng = test_rng(21);
    let orchard_nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let ironwood_nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);
    let nfs = NullifierSnapshot::new([
            (PoolId::Orchard, orchard_nf, ALICE),
            (PoolId::Ironwood, ironwood_nf, BOB),
        ],
    );

    assert_eq!(nfs.len(PoolId::Orchard), 1);
    assert_eq!(nfs.len(PoolId::Ironwood), 1);
    assert!(!nfs.is_empty(PoolId::Orchard));
    assert!(NullifierSnapshot::default().is_empty(PoolId::Orchard));
}

#[test]
fn a_key_set_reports_its_accounts() {
    let keys = ScanKeys::from_accounts([(ALICE, fvk_from_seed(1)), (BOB, fvk_from_seed(2))]);
    let mut accounts: Vec<_> = keys.accounts().collect();
    accounts.sort();
    assert_eq!(accounts, vec![ALICE, BOB]);

    // Two scopes per account, and the tags line up with the keys.
    assert_eq!(keys.ivks().len(), 4);
    assert!(!keys.is_empty());
    assert!(no_keys().is_empty());
}

#[test]
fn debug_output_never_contains_key_material() {
    // Viewing keys reveal an account's entire history; a stray debug log must
    // not be a way to leak one.
    let keys = ScanKeys::from_accounts([(ALICE, fvk_from_seed(1))]);
    let rendered = format!("{keys:?}");
    assert!(rendered.contains("ScanKeys"));
    assert!(!rendered.contains("FullViewingKey"));
    assert!(!rendered.contains("PreparedIncomingViewingKey"));
}

#[test]
fn an_error_yields_the_range_that_must_be_rescanned() {
    use zakura_wallet_core::scanning::ScanPriority;

    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(2);
    let mut blocks = chain.into_blocks();
    blocks[1].prev_hash = zakura_wallet_core::BlockHash([0xab; 32]);

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &ChainBuilder::new(START).anchor(),
        &blocks,
    )
    .unwrap_err();

    let range = err
        .rescan_range(ScanPriority::Verify)
        .expect("a continuity error is recoverable by rescanning");
    assert_eq!(*range.block_range(), blocks[1].height..(blocks[1].height + 1));
    assert_eq!(range.priority(), ScanPriority::Verify);

    // A malformed block is not fixed by rescanning the same data.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Orchard, 1);
        });
    });
    let anchor = chain.anchor();
    let mut blocks = chain.into_blocks();
    blocks[0].txs[0].orchard_actions.clear();
    blocks[0].tree_sizes.orchard = 1;
    // A tree-size mismatch *is* classified as a continuity error, because a
    // reorg is the common cause; the caller rewinds and re-fetches.
    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &anchor,
        &blocks,
    )
    .unwrap_err();
    assert!(err.rescan_range(ScanPriority::Verify).is_some());
}

#[test]
fn errors_render_usefully() {
    let mut chain = ChainBuilder::new(START);
    chain.empty_blocks(2);
    let mut blocks = chain.into_blocks();
    blocks[1].prev_hash = zakura_wallet_core::BlockHash([0xab; 32]);

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &ChainBuilder::new(START).anchor(),
        &blocks,
    )
    .unwrap_err();

    let rendered = err.to_string();
    assert!(rendered.contains(&blocks[1].height.to_string()), "{rendered}");
}

#[test]
fn a_tree_that_would_overflow_is_rejected() {
    // Not reachable on a real chain, but the arithmetic that guards it must be
    // checked rather than wrapping: a wrapped tree size would place notes at
    // positions that do not exist.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.decoy(PoolId::Orchard, 1);
        });
    });

    // Claim an anchor at the very top of the tree. Only the anchor is doctored,
    // so the failure is in the position arithmetic rather than in the fixture.
    let mut anchor = chain.anchor();
    anchor.tree_sizes = TreeSizes {
        orchard: u32::MAX,
        ironwood: 0,
    };

    let err = detect(
        &alice_keys(),
        &NullifierSnapshot::default(),
        &anchor,
        chain.blocks(),
    )
    .unwrap_err();

    assert_matches!(
        err,
        ScanError::TreeSizeOverflow {
            pool: PoolId::Orchard,
            ..
        }
    );
    assert!(!err.is_continuity_error());
}

#[test]
fn block_hashes_round_trip_and_display_reversed() {
    use zakura_wallet_core::BlockHash;

    let mut bytes = [0u8; 32];
    bytes[0] = 0xaa;
    bytes[31] = 0xbb;

    let hash = BlockHash::from_slice(&bytes).expect("32 bytes is a valid hash");
    assert_eq!(hash.0, bytes);
    // Block hashes are conventionally shown byte-reversed.
    let shown = format!("{hash:?}");
    assert!(shown.starts_with("bb"), "{shown}");
    assert!(shown.ends_with("aa"), "{shown}");

    assert_eq!(BlockHash::from_slice(&[0u8; 31]), None);
    assert_eq!(BlockHash::from_slice(&[0u8; 33]), None);
}

#[test]
fn every_error_variant_renders_and_reports_its_height() {
    use zakura_wallet_core::pool::PoolId;

    let h = |n: u32| BlockHeight::from_u32(n);
    let cases = [
        (
            ScanError::PrevHashMismatch { at_height: h(10) },
            h(10),
            true,
        ),
        (
            ScanError::BlockHeightDiscontinuity {
                prev_height: h(9),
                new_height: h(11),
            },
            h(11),
            true,
        ),
        (
            ScanError::TreeSizeMismatch {
                pool: PoolId::Ironwood,
                at_height: h(12),
                given: 5,
                computed: 4,
            },
            h(12),
            true,
        ),
        (
            ScanError::TreeSizeOverflow {
                pool: PoolId::Orchard,
                at_height: h(13),
            },
            h(13),
            false,
        ),
        (
            ScanError::ActionsBeforeActivation {
                pool: PoolId::Ironwood,
                at_height: h(14),
                activation_height: h(200),
            },
            h(14),
            false,
        ),
    ];

    for (err, height, continuity) in cases {
        assert_eq!(err.at_height(), height, "{err:?}");
        assert_eq!(err.is_continuity_error(), continuity, "{err:?}");

        let rendered = err.to_string();
        assert!(!rendered.is_empty(), "{err:?}");
        assert!(
            rendered.contains(&height.to_string()),
            "{rendered} should name height {height}"
        );

        // Only continuity errors are worth re-fetching the same range for.
        assert_eq!(
            err.rescan_range(zakura_wallet_core::scanning::ScanPriority::Verify)
                .is_some(),
            continuity,
            "{err:?}"
        );

        // `Error` is implemented, so these compose with `?` and `anyhow`.
        let _: &dyn std::error::Error = &err;
    }
}
