//! Apply discovery only after local chain and spend checks, in one transaction.
use std::borrow::BorrowMut;

use incrementalmerkletree::{Address, Position, Retention};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::{
    data_api::{
        dynamic_ivk::{PaymentApplication, ProviderView, SweepDeferral},
        transparent_ledger::ChainPoint,
    },
    wallet::{WalletOrchardOutput, WalletTx},
};
use zcash_note_encryption::ShieldedOutput as _;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, Parameters},
};

use super::{
    AccountUuid, KeyId, PendingPayment, SpendStatus, corrupt,
    payments::{authenticate, pending_payments, spend_status},
    retention::queue_spend_history,
    sweep,
};
use crate::{WalletDb, error::SqliteClientError, wallet};

/// Implements `DynamicIvkWrite::apply_dynamic_sweep`, one transaction per payment.
#[allow(clippy::type_complexity)]
pub(crate) fn apply_sweep<C: BorrowMut<Connection>, P: Parameters, CL, R>(
    db: &mut WalletDb<C, P, CL, R>,
    account: AccountUuid,
    key: KeyId,
    through: ChainPoint,
    publication: ChainPoint,
    provider: ProviderView,
    mut witness: impl FnMut(u32, [u8; 32]) -> Option<[[u8; 32]; 32]>,
) -> Result<Result<PaymentApplication, SweepDeferral>, SqliteClientError> {
    for candidate in pending_payments(db.conn.borrow(), account, key)? {
        let path = witness(candidate.position, candidate.encrypted_note.commitment())
            .and_then(|siblings| merkle_path(candidate.position, siblings));
        let Some(path) = path else {
            return Ok(Ok(PaymentApplication::AwaitingWitness));
        };
        let applied = db.transactionally(|db| {
            apply_payment(
                db.conn.0,
                db.params,
                account,
                key,
                &candidate,
                through,
                (publication, &path),
            )
        })?;
        match applied {
            Ok(PaymentApplication::Applied | PaymentApplication::BeforeBirthday) => {}
            other => return Ok(other),
        }
    }
    Ok(db
        .transactionally(|db| sweep::finish(db.conn.0, account, key, provider))?
        .map(|()| PaymentApplication::Applied))
}

/// The inclusion path at `position`, if every sibling is a valid hash.
fn merkle_path(position: u32, siblings: [[u8; 32]; 32]) -> Option<MerklePath> {
    let hashes = siblings
        .iter()
        .map(|bytes| Option::from(MerkleHashOrchard::from_bytes(bytes)))
        .collect::<Option<Vec<_>>>()?;
    Some(MerklePath::from_parts(position, hashes.try_into().ok()?))
}

/// Applies queued `candidate` with its inclusion path at an anchor on the wallet's chain,
/// which authenticates the note and position but not its transaction ID or memo, which is
/// not stored (see `wallet::dynamic_ivk`).
pub(super) fn apply_payment<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
    (anchor, path): (ChainPoint, &MerklePath),
) -> Result<Result<PaymentApplication, SweepDeferral>, SqliteClientError> {
    if !pending_payments(conn, account, key)?
        .iter()
        .any(|p| p == candidate)
    {
        return Err(corrupt("dynamic-key payment is not queued or changed"));
    }
    let (key_ref, recovered) = authenticate(conn, params, account, key, candidate)?;
    let dequeue = || {
        conn.execute(
            "DELETE FROM ironwood_dynamic_payment_recovery
             WHERE receiving_key_id = ?1 AND txid = ?2 AND action_index = ?3",
            params![key_ref, candidate.txid.as_ref(), candidate.action_index],
        )
    };
    // Scanning stores a note under the transaction it is found in, which no directory
    // claim overrides (see `adopt_found_note`), so a copy stored under another
    // transaction makes this answer redundant.
    let stored_elsewhere: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE n.nf = ?1 AND (t.txid != ?2 OR n.action_index != ?3))",
        params![
            recovered.nullifier().to_bytes(),
            candidate.txid.as_ref(),
            candidate.action_index
        ],
        |r| r.get(0),
    )?;
    if stored_elsewhere {
        dequeue()?;
        return Ok(Ok(PaymentApplication::Applied));
    }
    if wallet::fully_scanned_height(conn)? != Some(through.height)
        || wallet::chain_tip_height(conn)? != Some(through.height)
    {
        return Ok(Ok(PaymentApplication::AwaitingScan));
    }
    let birthday: u32 = conn.query_row(
        "SELECT birthday_height FROM accounts WHERE uuid = ?1",
        [account.0],
        |r| r.get(0),
    )?;
    // The wallet stores no block before its birthday, so an older note need only precede
    // the birthday block's first action. Otherwise a later note claimed at an early
    // height would be marked paid and dropped.
    let before_birthday = u32::from(candidate.height) < birthday;
    let block = if before_birthday {
        birthday
    } else {
        u32::from(candidate.height)
    };
    let Some((end, count)): Option<(u64, u64)> = conn
        .query_row(
            "SELECT ironwood_commitment_tree_size, ironwood_action_count FROM blocks
             WHERE height = ?1",
            [block],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
    else {
        return Ok(Ok(PaymentApplication::AwaitingScan));
    };
    let position = u64::from(candidate.position);
    let placed = end.checked_sub(count).is_some_and(|start| {
        if before_birthday {
            position < start
        } else {
            start <= position && position < end
        }
    });
    if !placed {
        return reject(conn, key_ref);
    }
    if anchor.height > through.height
        || through.height - anchor.height > crate::PRUNING_DEPTH
        || wallet::get_block_hash(conn, anchor.height)? != Some(anchor.hash)
    {
        return Ok(Ok(PaymentApplication::AwaitingWitness));
    }
    let oldest = u32::from(through.height).saturating_sub(crate::PRUNING_DEPTH);
    let checkpoint: Option<u32> = conn.query_row(
        "SELECT MAX(checkpoint_id) FROM ironwood_tree_checkpoints
         WHERE checkpoint_id BETWEEN ?1 AND ?2",
        params![oldest, u32::from(anchor.height)],
        |r| r.get(0),
    )?;
    let Some(checkpoint) = checkpoint.map(BlockHeight::from) else {
        return Ok(Ok(PaymentApplication::AwaitingWitness));
    };
    let mut tree = crate::ironwood_tree(conn)?;
    let Some(root) = tree.root_at_checkpoint_id(&checkpoint)? else {
        return Ok(Ok(PaymentApplication::AwaitingWitness));
    };
    if !recovered.verify_position(position, path, root.into()) {
        return reject(conn, key_ref);
    }
    if before_birthday {
        conn.execute(
            "UPDATE ironwood_receiving_keys
             SET advances_allocation = 1, used = 1, paid_before_birthday = 1 WHERE id = ?1",
            [key_ref],
        )?;
        dequeue()?;
        return Ok(Ok(PaymentApplication::BeforeBirthday));
    }
    // An unmined transaction is one a rewind or the mempool left: its note may move to a
    // new position, but a transaction holding no such note is not this one.
    let conflict: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid = ?1 AND mined_height IS NOT NULL
             AND (mined_height != ?2 OR tx_index != ?3))
         OR EXISTS(SELECT 1 FROM transactions t WHERE t.txid = ?1 AND t.mined_height IS NULL
             AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n
                 WHERE n.transaction_id = t.id_tx AND n.action_index = ?4
                   AND n.receiving_key_id = ?6))
         OR EXISTS(SELECT 1 FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.txid = ?1 AND n.action_index = ?4 AND (
                 (n.nf IS NULL AND t.mined_height IS NOT NULL) OR n.nf != ?5
                 OR n.receiving_key_id IS NULL OR n.receiving_key_id != ?6
                 OR (t.mined_height IS NOT NULL AND n.commitment_tree_position IS NOT NULL
                     AND n.commitment_tree_position != ?7)))",
        params![
            candidate.txid.as_ref(),
            u32::from(candidate.height),
            candidate.tx_index,
            candidate.action_index,
            recovered.nullifier().to_bytes(),
            key_ref,
            candidate.position
        ],
        |r| r.get(0),
    )?;
    if conflict {
        return reject(conn, key_ref);
    }
    let spent = match spend_status(conn, candidate, recovered.nullifier(), through)? {
        Ok(SpendStatus::Unknown) => {
            // Authenticate inclusion before a directory answer can trigger a replay.
            queue_spend_history(conn, params, account, through.height)?;
            return Ok(Ok(PaymentApplication::AwaitingSpendHistory));
        }
        Ok(spent) => spent,
        Err(deferral) => return Ok(Err(deferral)),
    };
    let anchor_size: u64 = conn.query_row(
        "SELECT ironwood_commitment_tree_size FROM blocks WHERE height = ?1",
        [u32::from(checkpoint)],
        |r| r.get(0),
    )?;
    // Persist only complete sibling subtrees. A partial right subtree includes empty
    // future leaves and must not become a fixed hash for future appends.
    for (level, hash) in path.auth_path().into_iter().enumerate() {
        let address = Address::from_parts((level as u8).into(), (position >> level) ^ 1);
        if u64::from(address.position_range_end()) <= anchor_size {
            tree.insert(address, hash)?;
        }
    }
    tree.batch_insert(
        Position::from(position),
        std::iter::once((
            MerkleHashOrchard::from_cmx(&recovered.note().commitment().into()),
            Retention::Marked,
        )),
    )?;
    let stored_path = tree
        .witness_at_checkpoint_id(Position::from(position), &checkpoint)?
        .ok_or_else(|| corrupt("stored dynamic-key witness missing"))?;
    if !recovered.verify_position(position, &stored_path.into(), root.into()) {
        return Err(corrupt("stored dynamic-key witness changed"));
    }
    let tx = WalletTx::new(
        candidate.txid,
        candidate.tx_index.into(),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    );
    let tx_ref = wallet::put_tx_meta(conn, &tx, candidate.height)?;
    let spent_in = if let SpendStatus::Spent(txid) = spent {
        // The map also records the spend's canonical height and index on a stored row,
        // which may be unmined. A linked spend has no map entry (see `spend_status`).
        let nf = recovered.nullifier().to_bytes();
        let spending = match wallet::query_nullifier_map(conn, ShieldedPool::Ironwood, &nf)? {
            Some(id) => Some(id),
            None => conn
                .query_row(
                    "SELECT id_tx FROM transactions WHERE txid = ?1",
                    [txid.as_ref()],
                    |r| r.get(0).map(crate::TxRef),
                )
                .optional()?,
        };
        Some(spending.ok_or_else(|| corrupt("verified dynamic-key spend lost its transaction"))?)
    } else {
        None
    };
    let encrypted = &candidate.encrypted_note;
    let output = WalletOrchardOutput::from_parts(
        candidate.action_index as usize,
        encrypted.ephemeral_key(),
        (*recovered.note(), orchard::ValuePool::Ironwood),
        false,
        Position::from(position),
        Some(*recovered.nullifier()),
        account,
        Some(zip32::Scope::External),
    )
    .with_dynamic_key_id(Some(key))
    .with_compact_ciphertext(encrypted.enc_ciphertext()[..52].try_into().unwrap());
    wallet::orchard::put_received_note(
        conn,
        params,
        ShieldedPool::Ironwood,
        &output,
        tx_ref,
        Some(candidate.height),
        spent_in,
    )?;
    wallet::enhance_pir::finish_private_receipt(conn, tx_ref)?;
    dequeue()?;
    Ok(Ok(PaymentApplication::Applied))
}

/// Discards key `key_ref`'s queued lookup (see [`PaymentApplication::Rejected`]).
fn reject(
    conn: &Connection,
    key_ref: i64,
) -> Result<Result<PaymentApplication, SweepDeferral>, SqliteClientError> {
    conn.execute(
        "DELETE FROM ironwood_dynamic_payment_recovery WHERE receiving_key_id = ?1",
        [key_ref],
    )?;
    conn.execute(
        "UPDATE ironwood_dynamic_sweeps SET lookup_height = NULL, lookup_hash = NULL,
            done_height = NULL WHERE receiving_key_id = ?1",
        [key_ref],
    )?;
    Ok(Ok(PaymentApplication::Rejected))
}
