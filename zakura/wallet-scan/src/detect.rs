//! The detection pass.
//!
//! [`detect_batch`] is a pure function: given keys, a nullifier snapshot, an
//! anchor and a slice of blocks, it returns what those blocks contained. It
//! touches no database, performs no I/O, spawns no task that outlives the call,
//! and is deterministic in its inputs.
//!
//! That is the whole point of this crate. Because detection is separable from
//! storage, it can be tested against a synthetic chain with no SQLite in the
//! dependency graph, its output can be compared as a value, and it can be run
//! wherever there are spare cores.

use incrementalmerkletree::{Marking, Retention};
use orchard::{
    note::Nullifier,
    note_encryption::{CompactAction, IronwoodDomain},
};
use zcash_note_encryption::{COMPACT_NOTE_SIZE, ShieldedOutput};
use rayon::prelude::*;
use zakura_wallet_core::{
    AccountId, CompactBlock, CompactTx, Ironwood, KeyScope, Orchard,
    pool::{ShieldedPool, TreeSizes},
};
use zcash_protocol::{TxId, consensus::Parameters};

use zakura_wallet_core::detected::{
    BlockAnchor, DetectedBatch, DetectedBlock, DetectedNote, DetectedSpend,
    DetectedTransparentOutput, DetectedTx, EnhanceCandidate, NullifierSnapshot, PoolCommitments,
};

use crate::{
    error::ScanError, keys::ScanKeys, position::PositionTracker, transparent::TransparentWatch,
};

/// How many compact actions one rayon task trial-decrypts.
///
/// Batch decryption amortises its per-output cost across the slice it is given,
/// so larger chunks decrypt more cheaply while smaller chunks spread across more
/// cores. This value is a compromise: large enough that the amortisation
/// dominates, small enough that a batch of a few thousand actions still uses the
/// whole machine.
const DECRYPT_CHUNK: usize = 512;

/// Where one compact action sits within a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActionLocator {
    block: usize,
    tx: usize,
    action: usize,
}

/// A single action's trial-decryption outcome: the note, and the index of the
/// viewing key that opened it.
type Decryption = Option<(orchard::note::Note, usize)>;

/// The result of trial-decrypting one pool across a whole batch.
///
/// Indexed as `results[block][tx][action]`, mirroring the input shape so the
/// assembly pass can look up an action's outcome without searching.
struct PoolDecryptions {
    results: Vec<Vec<Vec<Decryption>>>,
}

impl PoolDecryptions {
    fn get(&self, block: usize, tx: usize, action: usize) -> Option<&(orchard::note::Note, usize)> {
        self.results[block][tx][action].as_ref()
    }
}

/// Detects this wallet's activity in a contiguous run of compact blocks.
///
/// `blocks` must be contiguous and ascending, and `anchor` must describe the
/// block immediately before the first of them. Both are checked.
///
/// Returns `Ok` with the batch's results, or the first error encountered.
/// Detection is all-or-nothing: a batch that cannot be interpreted end to end
/// yields nothing, because each block's note positions are derived from the one
/// before it, so a failure part way through invalidates everything after it and
/// leaves everything before it unverifiable in isolation.
///
/// An empty `blocks` returns an empty batch anchored where it started.
pub fn detect_batch<P: Parameters>(
    params: &P,
    keys: &ScanKeys,
    watch: &TransparentWatch,
    nullifiers: &NullifierSnapshot,
    anchor: &BlockAnchor,
    blocks: &[CompactBlock],
) -> Result<DetectedBatch, ScanError> {
    // Continuity first: it is nearly free, and it is the check most likely to
    // fail, because it is the one a reorg trips. Doing it before any decryption
    // means a reorged batch costs no trial decryption at all.
    check_continuity(anchor, blocks)?;

    if blocks.is_empty() {
        return Ok(DetectedBatch {
            start_anchor: anchor.clone(),
            blocks: Vec::new(),
            end_anchor: anchor.clone(),
            snapshot_epoch: nullifiers.epoch(),
        });
    }

    let orchard = decrypt_pool::<Orchard>(keys, blocks);
    let ironwood = decrypt_pool::<Ironwood>(keys, blocks);

    // The snapshot is immutable, so mid-batch discoveries go in a local overlay:
    // a note received in one block can be spent in a later block of the same
    // batch, and the spend must still be recognised. The overlay is discarded
    // when the call returns, leaving the caller's snapshot untouched.
    let mut overlay = nullifiers.clone();
    let mut watch = watch.clone();

    let mut prior_sizes = anchor.tree_sizes;
    let mut detected_blocks = Vec::with_capacity(blocks.len());

    for (block_index, block) in blocks.iter().enumerate() {
        let detected = detect_block(
            params,
            keys,
            &mut watch,
            &mut overlay,
            &prior_sizes,
            block,
            block_index,
            &orchard,
            &ironwood,
        )?;
        prior_sizes = detected.tree_sizes;
        detected_blocks.push(detected);
    }

    let last = blocks.last().expect("blocks is non-empty");
    Ok(DetectedBatch {
        start_anchor: anchor.clone(),
        blocks: detected_blocks,
        end_anchor: BlockAnchor {
            height: last.height,
            hash: last.hash,
            tree_sizes: last.tree_sizes,
        },
        snapshot_epoch: nullifiers.epoch(),
    })
}

/// Checks that `blocks` forms an unbroken chain starting just after `anchor`.
fn check_continuity(anchor: &BlockAnchor, blocks: &[CompactBlock]) -> Result<(), ScanError> {
    let mut prev_height = anchor.height;
    let mut prev_hash = anchor.hash;

    for block in blocks {
        if block.height != prev_height + 1 {
            return Err(ScanError::BlockHeightDiscontinuity {
                prev_height,
                new_height: block.height,
            });
        }
        if block.prev_hash != prev_hash {
            return Err(ScanError::PrevHashMismatch {
                at_height: block.height,
            });
        }
        prev_height = block.height;
        prev_hash = block.hash;
    }

    Ok(())
}

/// Trial-decrypts every action of one pool across the batch, in parallel.
fn decrypt_pool<P: ShieldedPool>(keys: &ScanKeys, blocks: &[CompactBlock]) -> PoolDecryptions {
    // The shape of the answer is fixed by the input, so allocate it up front and
    // scatter results into it. A wallet with no keys still needs the shape,
    // because commitments and tree sizes are recorded regardless of ownership.
    let mut results: Vec<Vec<Vec<Decryption>>> = blocks
        .iter()
        .map(|block| {
            block
                .txs
                .iter()
                .map(|tx| vec![None; P::actions(tx).len()])
                .collect()
        })
        .collect();

    if keys.is_empty() {
        return PoolDecryptions { results };
    }

    let mut locators = Vec::new();
    let mut inputs: Vec<(P::Domain, CompactAction)> = Vec::new();
    for (b, block) in blocks.iter().enumerate() {
        for (t, tx) in block.txs.iter().enumerate() {
            for (a, action) in P::actions(tx).iter().enumerate() {
                locators.push(ActionLocator {
                    block: b,
                    tx: t,
                    action: a,
                });
                inputs.push((P::domain_for(action), action.clone()));
            }
        }
    }

    if inputs.is_empty() {
        return PoolDecryptions { results };
    }

    let ivks = keys.ivks();
    let decrypted: Vec<Decryption> = inputs
        .par_chunks(DECRYPT_CHUNK)
        .flat_map_iter(|chunk| P::batch_decrypt(ivks, chunk))
        .collect();

    debug_assert_eq!(decrypted.len(), locators.len());
    for (locator, outcome) in locators.into_iter().zip(decrypted) {
        results[locator.block][locator.tx][locator.action] = outcome;
    }

    PoolDecryptions { results }
}

#[allow(clippy::too_many_arguments)]
fn detect_block<P: Parameters>(
    params: &P,
    keys: &ScanKeys,
    watch: &mut TransparentWatch,
    overlay: &mut NullifierSnapshot,
    prior_sizes: &TreeSizes,
    block: &CompactBlock,
    block_index: usize,
    orchard: &PoolDecryptions,
    ironwood: &PoolDecryptions,
) -> Result<DetectedBlock, ScanError> {
    let mut orchard_tracker = PositionTracker::<Orchard>::start(params, prior_sizes, block)?;
    let mut ironwood_tracker = PositionTracker::<Ironwood>::start(params, prior_sizes, block)?;

    let mut orchard_out = PoolOutput::new(orchard_tracker.final_size());
    let mut ironwood_out = PoolOutput::new(ironwood_tracker.final_size());
    let mut transactions = Vec::new();

    for (tx_index, tx) in block.txs.iter().enumerate() {
        // Spends are resolved before receives, in both pools, because a note is
        // change when the account receiving it also spent in the same
        // transaction — so the set of spending accounts must be complete first.
        let orchard_spends = find_spends::<Orchard>(tx, overlay, &mut orchard_out);
        let ironwood_spends = find_spends::<Ironwood>(tx, overlay, &mut ironwood_out);

        let mut funding_accounts: Vec<AccountId> = orchard_spends
            .iter()
            .chain(ironwood_spends.iter())
            .map(|s| s.account)
            .collect();
        funding_accounts.sort_unstable();
        funding_accounts.dedup();

        let orchard_received = collect_received::<Orchard>(
            keys,
            tx,
            tx_index,
            block_index,
            orchard,
            &orchard_tracker,
            &funding_accounts,
            &mut orchard_out,
            block.height,
        );
        let ironwood_received = collect_received::<Ironwood>(
            keys,
            tx,
            tx_index,
            block_index,
            ironwood,
            &ironwood_tracker,
            &funding_accounts,
            &mut ironwood_out,
            block.height,
        );

        // A note received now can be spent later in this same batch, so its
        // nullifier joins the overlay immediately.
        for note in orchard_received.iter().chain(ironwood_received.iter()) {
            overlay.insert(note.pool, note.nullifier, note.account);
        }

        let enhance_candidates = collect_enhance_candidates(
            tx,
            block_index,
            tx_index,
            ironwood,
            &ironwood_tracker,
            &funding_accounts,
        );

        let (transparent_received, transparent_spends) = detect_transparent(watch, tx);

        let detected = DetectedTx {
            index: tx.index,
            txid: tx.txid,
            received: orchard_received.into_iter().chain(ironwood_received).collect(),
            spends: orchard_spends.into_iter().chain(ironwood_spends).collect(),
            transparent_received,
            transparent_spends,
            enhance_candidates,
        };
        if let Some(detected) = detected.into_option() {
            transactions.push(detected);
        }

        orchard_tracker.advance_over(tx);
        ironwood_tracker.advance_over(tx);
    }

    orchard_tracker.finish(&block.tree_sizes)?;
    ironwood_tracker.finish(&block.tree_sizes)?;

    Ok(DetectedBlock {
        height: block.height,
        hash: block.hash,
        time: block.time,
        tree_sizes: block.tree_sizes,
        transactions,
        orchard: orchard_out.finish(),
        ironwood: ironwood_out.finish(),
    })
}

/// Accumulates one pool's per-block commitment and nullifier output.
struct PoolOutput {
    commitments: Vec<(orchard::note::ExtractedNoteCommitment, Retention<zcash_protocol::consensus::BlockHeight>)>,
    final_tree_size: u32,
    unlinked: Vec<(u64, TxId, Vec<Nullifier>)>,
}

impl PoolOutput {
    fn new(final_tree_size: u32) -> Self {
        Self {
            commitments: Vec::new(),
            final_tree_size,
            unlinked: Vec::new(),
        }
    }

    fn finish(self) -> PoolCommitments {
        PoolCommitments {
            commitments: self.commitments,
            final_tree_size: self.final_tree_size,
            unlinked_nullifiers: self.unlinked,
        }
    }
}

/// Finds spends of the wallet's notes in one pool of one transaction, and
/// records the nullifiers that matched nothing.
///
/// Upstream compares nullifiers in constant time, scanning the wallet's whole
/// nullifier list for every spend. This uses a hash lookup instead, which is
/// O(1) rather than O(notes) and is what makes descending recovery affordable
/// on a wallet with a large note set.
///
/// The deviation is deliberate and its cost should be stated: a hash lookup
/// takes measurably different time on a hit than on a miss, so an adversary who
/// can observe this process's timing could in principle learn whether a block
/// contained one of the wallet's nullifiers. Both inputs are already local —
/// the block is public data and the nullifiers are the wallet's own — so this
/// matters only against an attacker who is already co-resident, and upstream's
/// own comment questions whether the constant-time comparison earns its cost.
/// If that threat is ever in scope, this is the function to change.
fn find_spends<P: ShieldedPool>(
    tx: &CompactTx,
    overlay: &NullifierSnapshot,
    out: &mut PoolOutput,
) -> Vec<DetectedSpend> {
    let mut spends = Vec::new();
    let mut unlinked = Vec::new();

    for (action_index, action) in P::actions(tx).iter().enumerate() {
        let nf = action.nullifier();
        match overlay.get(P::ID, &nf) {
            Some(account) => spends.push(DetectedSpend {
                pool: P::ID,
                account,
                action_index,
                nullifier: nf,
            }),
            // Not one of ours *yet*. Under descending recovery the note this
            // spends may not have been scanned, so the nullifier is kept and
            // linked when the note turns up.
            None => unlinked.push(nf),
        }
    }

    if !unlinked.is_empty() {
        out.unlinked.push((tx.index, tx.txid, unlinked));
    }

    spends
}

/// Collects the wallet's received notes in one pool of one transaction, and
/// appends every one of that pool's commitments to the block's commitment list.
#[allow(clippy::too_many_arguments)]
fn collect_received<P: ShieldedPool>(
    keys: &ScanKeys,
    tx: &CompactTx,
    tx_index: usize,
    block_index: usize,
    decryptions: &PoolDecryptions,
    tracker: &PositionTracker<P>,
    funding_accounts: &[AccountId],
    out: &mut PoolOutput,
    height: zcash_protocol::consensus::BlockHeight,
) -> Vec<DetectedNote> {
    let actions = P::actions(tx);
    let is_final_tx = tracker.contains_final_action(tx);
    let mut received = Vec::new();

    for (action_index, action) in actions.iter().enumerate() {
        let decrypted = decryptions.get(block_index, tx_index, action_index);

        let note = decrypted.map(|(note, ivk_index)| {
            let (account, scope) = keys.tag(*ivk_index);
            // A key set is built from full viewing keys, so the account that
            // decrypted a note always has one; a missing key here would be a
            // construction bug, and silently dropping the note would lose funds.
            let fvk = keys
                .fvk(account)
                .expect("a key that decrypted a note has a full viewing key");
            DetectedNote {
                pool: P::ID,
                account,
                scope,
                action_index,
                position: tracker.note_position(action_index),
                note: *note,
                nullifier: note.nullifier(fvk),
                // Change is a note the wallet paid itself: either it arrived on
                // the internal address, or the receiving account also funded
                // this transaction.
                is_change: scope == KeyScope::Internal || funding_accounts.contains(&account),
            }
        });

        // The final commitment of the block carries that block's checkpoint,
        // which is what a later rewind to this height rolls the tree back to.
        let is_checkpoint = is_final_tx && action_index + 1 == actions.len();
        let retention = match (note.is_some(), is_checkpoint) {
            (marked, true) => Retention::Checkpoint {
                id: height,
                marking: if marked {
                    Marking::Marked
                } else {
                    Marking::None
                },
            },
            // Marked commitments are the ones a witness can later be produced
            // for; without this the note would be unspendable.
            (true, false) => Retention::Marked,
            (false, false) => Retention::Ephemeral,
        };
        out.commitments.push((action.cmx(), retention));

        if let Some(note) = note {
            received.push(note);
        }
    }

    received
}

/// Collects the Ironwood actions of a wallet-funded transaction that the wallet
/// did not itself receive.
///
/// Compact scanning cannot distinguish a padding dummy from a real output, and
/// padding is routine, so every non-received action of a funded transaction is a
/// candidate. Actions the wallet *did* receive are excluded: their data is
/// already known, and change is encrypted under the internal outgoing viewing
/// key, so an outgoing job for it could never be resolved.
fn collect_enhance_candidates(
    tx: &CompactTx,
    block_index: usize,
    tx_index: usize,
    ironwood: &PoolDecryptions,
    tracker: &PositionTracker<Ironwood>,
    funding_accounts: &[AccountId],
) -> Vec<EnhanceCandidate> {
    if funding_accounts.is_empty() {
        return Vec::new();
    }

    Ironwood::actions(tx)
        .iter()
        .enumerate()
        .filter(|(action_index, _)| ironwood.get(block_index, tx_index, *action_index).is_none())
        .map(|(action_index, action)| EnhanceCandidate {
            position: tracker.note_position(action_index),
            action_index,
            nullifier: action.nullifier(),
            cmx: action.cmx(),
            ephemeral_key: ShieldedOutput::<IronwoodDomain, COMPACT_NOTE_SIZE>::ephemeral_key(
                action,
            )
            .0,
            compact_ciphertext: *ShieldedOutput::<IronwoodDomain, COMPACT_NOTE_SIZE>::enc_ciphertext(
                action,
            ),
            funding_accounts: funding_accounts.to_vec(),
        })
        .collect()
}

/// Matches a transaction's transparent inputs and outputs against the watch set.
fn detect_transparent(
    watch: &mut TransparentWatch,
    tx: &CompactTx,
) -> (Vec<DetectedTransparentOutput>, Vec<transparent::bundle::OutPoint>) {
    if watch.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let spends = tx
        .vin
        .iter()
        .filter(|outpoint| watch.spends(outpoint))
        .cloned()
        .collect();

    let mut received = Vec::new();
    for (output_index, txout) in tx.vout.iter().enumerate() {
        if let Some(account) = watch.account_for(txout) {
            let output_index = u32::try_from(output_index)
                .expect("a transaction cannot have more than u32::MAX outputs");
            // Recorded now so that a spend of this output later in the same
            // batch is recognised rather than deferred to the next pass.
            watch.add_utxo(transparent::bundle::OutPoint::new(
                tx.txid.into(),
                output_index,
            ));
            received.push(DetectedTransparentOutput {
                output_index,
                account,
                address_index: watch.index_for(account, txout),
                txout: txout.clone(),
            });
        }
    }

    (received, spends)
}
