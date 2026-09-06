//! Decrypting a full transaction.
//!
//! Scanning works on compact blocks and can only ever answer "did a note
//! arrive, and was one spent". Two questions need the whole transaction:
//!
//! - *What did the memo say?* Compact actions carry the first 52 bytes of the
//!   note ciphertext, which is enough to decrypt the note and not the memo.
//! - *What did I send, and to whom?* That is recovered with the outgoing
//!   viewing key from the outgoing ciphertext, which compact blocks omit
//!   entirely. No amount of rescanning produces it.
//!
//! This module stays true to the crate's rule: bytes and keys in, an owned
//! value out, no database and no network. What it costs the crate is a
//! transaction parser, deliberately without the proving stack.

use orchard::{
    Address,
    keys::{OutgoingViewingKey, Scope},
    note::{Note, Nullifier},
    note_encryption::{DomainVersion, IronwoodVersion, NoteEncryptionDomain, OrchardVersion},
};
use transparent::bundle::OutPoint;
use zakura_wallet_core::{
    DetectedTransparentOutput,
    account::KeyScope,
    enhanced::{DecryptedOutput, EnhancedTx, TransferType},
    pool::PoolId,
};
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, BranchId, Parameters},
};

use crate::{error::EnhanceError, keys::ScanKeys, transparent::TransparentWatch};

/// Decrypts a full transaction against a wallet's keys.
///
/// `expected` is the identifier the wallet asked for, and is checked against
/// the bytes before anything is decrypted. That check is not ceremony: a server
/// asked for transaction A can answer with transaction B, and without it the
/// wallet would graft B's memos and B's recipients onto A's row, in a way
/// nothing downstream could detect.
///
/// `height` selects the consensus branch the transaction is parsed under, and
/// should be where it was mined, or the next chain tip if it is not yet mined.
///
/// `watch` is matched against the transparent bundle. Transparent detection is
/// set membership rather than trial decryption, so the same watch set scanning
/// uses answers the same question here, and answering it is not optional: the
/// wallet reaches transactions through enhancement that scanning never saw, and
/// discarding their transparent side loses outputs the wallet owns.
pub fn decrypt_transaction<P: Parameters>(
    params: &P,
    keys: &ScanKeys,
    watch: &TransparentWatch,
    expected: TxId,
    height: BlockHeight,
    raw: &[u8],
) -> Result<EnhancedTx, EnhanceError> {
    let branch = BranchId::for_height(params, height);
    let tx = Transaction::read(raw, branch).map_err(|e| EnhanceError::Malformed(e.to_string()))?;

    if tx.txid() != expected {
        return Err(EnhanceError::TxIdMismatch {
            requested: expected,
            received: tx.txid(),
        });
    }

    let mut outputs = Vec::new();
    let mut spent_nullifiers = Vec::new();
    let mut shielded_value_balance: i64 = 0;

    // The pairing of bundle to domain version is the one thing here that fails
    // silently if it is wrong: an Orchard bundle read under the Ironwood domain
    // decrypts nothing at all rather than erroring, and the wallet would
    // conclude the transaction was none of its business.
    decrypt_bundle::<OrchardVersion, _>(
        PoolId::Orchard,
        keys,
        tx.orchard_bundle(),
        &mut outputs,
        &mut spent_nullifiers,
        &mut shielded_value_balance,
    );
    decrypt_bundle::<IronwoodVersion, _>(
        PoolId::Ironwood,
        keys,
        tx.ironwood_bundle(),
        &mut outputs,
        &mut spent_nullifiers,
        &mut shielded_value_balance,
    );

    let expiry = tx.expiry_height();
    let (transparent_received, transparent_spends, candidate_spends, is_coinbase) =
        match_transparent(watch, &tx);

    Ok(EnhancedTx {
        txid: tx.txid(),
        expiry_height: Some(expiry),
        outputs,
        spent_nullifiers,
        shielded_value_balance,
        transparent_received,
        transparent_spends,
        candidate_spends,
        is_coinbase,
        raw: raw.to_vec(),
    })
}

/// Matches a transaction's transparent bundle against the wallet's watch set.
///
/// The mirror of `detect::detect_transparent`, over a full bundle rather than a
/// compact one. It differs in two ways, both because a full transaction says
/// more than a compact one: coinbase-ness is read from the bundle rather than
/// inferred from the transaction's index, and there is no need to fold newly
/// created outputs back into the watch set, because a single transaction cannot
/// spend an output it creates.
fn match_transparent(
    watch: &TransparentWatch,
    tx: &Transaction,
) -> (
    Vec<DetectedTransparentOutput>,
    Vec<OutPoint>,
    Vec<OutPoint>,
    bool,
) {
    let Some(bundle) = tx.transparent_bundle() else {
        return (Vec::new(), Vec::new(), Vec::new(), false);
    };

    let is_coinbase = bundle.is_coinbase();

    // A coinbase's single input names no real outpoint, so recording it would
    // put a sentinel into the spend map for every mined block.
    let candidate_spends: Vec<OutPoint> = if is_coinbase {
        Vec::new()
    } else {
        bundle.vin.iter().map(|txin| txin.prevout().clone()).collect()
    };

    let transparent_spends = candidate_spends
        .iter()
        .filter(|outpoint| watch.spends(outpoint))
        .cloned()
        .collect();

    let mut transparent_received = Vec::new();
    for (output_index, txout) in bundle.vout.iter().enumerate() {
        if let Some(address) = watch.watched(txout) {
            let output_index = u32::try_from(output_index)
                .expect("a transaction cannot have more than u32::MAX outputs");
            transparent_received.push(DetectedTransparentOutput {
                output_index,
                account: address.account,
                address_id: address.address_id,
                txout: txout.clone(),
            });
        }
    }

    (
        transparent_received,
        transparent_spends,
        candidate_spends,
        is_coinbase,
    )
}

/// Decrypts one pool's bundle.
///
/// Generic over the note-encryption domain version for the reason the whole
/// wallet is generic over the pool: Ironwood *is* Orchard with a different
/// domain, and the domain is the only thing that varies here.
fn decrypt_bundle<V: DomainVersion, A: orchard::bundle::Authorization>(
    pool: PoolId,
    keys: &ScanKeys,
    bundle: Option<&orchard::Bundle<A, zcash_protocol::value::ZatBalance>>,
    outputs: &mut Vec<DecryptedOutput>,
    spent: &mut Vec<(PoolId, Nullifier)>,
    value_balance: &mut i64,
) {
    let Some(bundle) = bundle else { return };

    *value_balance += i64::from(*bundle.value_balance());

    for (action_index, action) in bundle.actions().iter().enumerate() {
        // Every nullifier is recorded, not just the ones matching a note the
        // wallet holds. Under descending recovery the note a spend refers to
        // may not have been scanned yet, and discarding the nullifier here
        // would lose the only chance to link them.
        spent.push((pool, *action.nullifier()));

        let domain = NoteEncryptionDomain::<V>::for_action(action);
        if let Some(output) = try_action(pool, keys, &domain, action, action_index) {
            outputs.push(output);
        }
    }
}

/// Tries one action against every key the wallet holds.
///
/// The order is the logic. An external incoming viewing key opening the note
/// means somebody paid us; an internal one means it is our own change; and only
/// if neither opens it is the outgoing viewing key tried, which succeeds
/// exactly when we were the sender. Trying the outgoing key first would label
/// the wallet's own receipts as payments it made.
fn try_action<V: DomainVersion, S>(
    pool: PoolId,
    keys: &ScanKeys,
    domain: &NoteEncryptionDomain<V>,
    action: &orchard::Action<S>,
    action_index: usize,
) -> Option<DecryptedOutput> {
    for (index, ivk) in keys.ivks().iter().enumerate() {
        if let Some((note, recipient, memo)) = try_note_decryption(domain, ivk, action) {
            let (account, scope) = keys.tag(index);
            // A key set is built from full viewing keys, so the account that
            // decrypted a note always has one. Derived here rather than left to
            // storage because this is the only place the note and its owning
            // key are both in hand.
            let fvk = keys
                .fvk(account)
                .expect("a key that decrypted a note has a full viewing key");
            return Some(DecryptedOutput {
                pool,
                action_index,
                account,
                note,
                recipient,
                memo,
                transfer_type: match scope {
                    KeyScope::External => TransferType::Incoming,
                    KeyScope::Internal => TransferType::AccountInternal,
                },
                nullifier: Some(note.nullifier(fvk)),
            });
        }
    }

    // Nothing of ours received it, so ask whether we sent it. This is the arm
    // that needs the full transaction: it reads the outgoing ciphertext, which
    // a compact block does not carry.
    for (account, fvk) in keys.outgoing_keys() {
        for scope in [Scope::External, Scope::Internal] {
            let ovk: OutgoingViewingKey = fvk.to_ovk(scope);
            let recovered: Option<(Note, Address, [u8; 512])> = try_output_recovery_with_ovk(
                domain,
                &ovk,
                action,
                action.cv_net(),
                &action.encrypted_note().out_ciphertext,
            );
            if let Some((note, recipient, memo)) = recovered {
                return Some(DecryptedOutput {
                    pool,
                    action_index,
                    account,
                    note,
                    recipient,
                    memo,
                    transfer_type: TransferType::Outgoing,
                    // Recovered with an outgoing key: the wallet sent this note
                    // and cannot derive its nullifier.
                    nullifier: None,
                });
            }
        }
    }

    None
}
