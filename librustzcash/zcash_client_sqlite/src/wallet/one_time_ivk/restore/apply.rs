//! Admits a late candidate only after local chain, coverage and spend checks, in one
//! transaction.
use incrementalmerkletree::{Address, Position, Retention};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use rusqlite::{Connection, OptionalExtension, params};
use shardtree::error::ShardTreeError;
use zcash_client_backend::{
    data_api::{
        one_time_ivk::restore::{
            decode_witness_payload, recovery::RecoveredNote, witness_is_final,
        },
        transparent_ledger::ChainPoint,
    },
    wallet::{WalletOrchardOutput, WalletTx},
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, Parameters},
};

use super::{PendingPayment, payments::authenticate};
use crate::wallet::one_time_ivk::{KeyId, corrupt};
use crate::{AccountUuid, error::SqliteClientError, wallet};

/// The handle state that storing a note's transaction routes its enhancement with.
pub(crate) struct Sessions<'a> {
    /// The handle's private Enhance session.
    pub(crate) enhance: &'a wallet::enhance_pir::session::SessionState,
    /// The handle's transparent PIR session.
    pub(crate) tpir: &'a wallet::transparent_ledger::session::SessionState,
}

/// What [`apply_payment`] did with a late candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::wallet::one_time_ivk) enum Admission {
    /// The note, its witness and any spend were stored, or it already was, or it predates
    /// the account's birthday and only marks its key used.
    Admitted,
    /// The scan has not stored its block or reached a usable anchor, or the local tree lacks
    /// material a final path needs yet.
    Waiting,
    /// The scan finished blocks from the payment on without covering them for the account,
    /// so they must be scanned again (see `queue::admit`).
    Uncovered,
    /// Its witness is unusable: malformed, built on a tree off the wallet's chain, too old
    /// or no longer reconstructible locally, or not reaching the accepted root. The payment
    /// stays pending and is read again for a new witness.
    StaleWitness,
    /// The directory's claim failed a check against the wallet's own chain.
    Rejected,
}

/// A stored companion witness payload and the tree it was built at.
pub(in crate::wallet::one_time_ivk) struct WitnessPath<'a> {
    pub(in crate::wallet::one_time_ivk) payload: &'a [u8],
    pub(in crate::wallet::one_time_ivk) context: ChainPoint,
    pub(in crate::wallet::one_time_ivk) tree_size: u64,
}

/// Whether `error` means the local tree lacks or conflicts with material, rather than a
/// storage failure that must abort the transaction.
fn tree_data(error: &ShardTreeError<crate::wallet::commitment_tree::Error>) -> bool {
    !matches!(error, ShardTreeError::Storage(_))
}

/// Admits late `candidate` with its companion witness, which authenticates the note and
/// its position, so its height, but not its transaction ID. It waits until the scan covered
/// every block from the payment through `through`, the highest block the scan stored, for
/// the account: the change rule puts every spend of a one-time note in a transaction the
/// scan recognizes, so the spend journal then holds the note's nullifier if it was spent.
/// No memo is stored (see `wallet::one_time_ivk`).
///
/// A provisional witness is checked at exactly its construction block, which must be on
/// the wallet's chain within the pruning depth. A final witness (its Ironwood shard full)
/// is checked at `through`, its construction block being provenance only. Either way the
/// accepted root is read before returned nodes touch the tree, and the path the tree then
/// reconstructs must reach it, or nothing is kept.
#[allow(clippy::too_many_arguments)]
pub(in crate::wallet::one_time_ivk) fn apply_payment<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    sessions: &Sessions<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
    witness: WitnessPath<'_>,
) -> Result<Admission, SqliteClientError> {
    let (key_ref, recovered) = authenticate(conn, params, account, key, candidate)?;
    let dequeue = || {
        conn.execute(
            "DELETE FROM ironwood_one_time_payment_recovery
             WHERE one_time_key_id = ?1 AND txid = ?2 AND action_index = ?3",
            params![key_ref, candidate.txid.as_ref(), candidate.action_index],
        )
    };
    // The proof authenticates the note but not the transaction label a record claims. An
    // earlier admission of the same note under another label already owns it, and
    // relabeling it could drop that label's spend state, so this answer is redundant.
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
        return Ok(Admission::Admitted);
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
        return Ok(Admission::Waiting);
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
        return Ok(Admission::Rejected);
    }
    let Ok(supplied) = decode_witness_payload(witness.payload, position, witness.tree_size) else {
        return Ok(Admission::StaleWitness);
    };
    let final_path = witness_is_final(position, witness.tree_size);
    let context = witness.context;
    if context.height > through.height {
        return Ok(Admission::Waiting);
    }
    let anchor = if final_path {
        // A final path depends on blocks through its construction block only; a fork
        // there replaces it, but its age does not.
        if wallet::get_block_hash(conn, context.height)?.is_some_and(|h| h != context.hash) {
            return Ok(Admission::StaleWitness);
        }
        through
    } else {
        if through.height - context.height > crate::PRUNING_DEPTH {
            return Ok(Admission::StaleWitness);
        }
        let Some((hash, size)): Option<([u8; 32], u64)> = conn
            .query_row(
                "SELECT hash, ironwood_commitment_tree_size FROM blocks WHERE height = ?1",
                [u32::from(context.height)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        else {
            return Ok(Admission::Waiting);
        };
        if hash != context.hash.0 || size != witness.tree_size {
            return Ok(Admission::StaleWitness);
        }
        context
    };
    // Missing final-path material can arrive with later scanning; a provisional tree that
    // is gone cannot, so its payment is read again.
    let missing = if final_path {
        Admission::Waiting
    } else {
        Admission::StaleWitness
    };
    // Quiet blocks do not create tree checkpoints. An older checkpoint is usable only
    // when it represents exactly the anchor's tree, never a preceding smaller tree.
    let checkpoint: Option<u32> = conn.query_row(
        "SELECT MAX(c.checkpoint_id) FROM ironwood_tree_checkpoints c
         JOIN blocks b ON b.height = ?1
         WHERE c.checkpoint_id <= b.height
           AND COALESCE(c.position + 1, 0) = b.ironwood_commitment_tree_size",
        [u32::from(anchor.height)],
        |r| r.get(0),
    )?;
    let Some(checkpoint) = checkpoint.map(BlockHeight::from) else {
        return Ok(missing);
    };
    let mut tree = crate::ironwood_tree(conn)?;
    let root = match tree.root_at_checkpoint_id(&checkpoint) {
        Ok(Some(root)) => root,
        Ok(None) => return Ok(missing),
        Err(e) if tree_data(&e) => return Ok(missing),
        Err(e) => return Err(e.into()),
    };
    // Supplied siblings come from the payload. The tree supplies the rest at the anchor:
    // empty subtrees, the one straddling the anchor's frontier, and levels above the shard.
    let anchor_size = Position::from(checkpoint_position(conn, checkpoint)?);
    let mut auth_path = Vec::with_capacity(32);
    for level in 0..32u8 {
        let address = Address::from_parts(level.into(), (position >> level) ^ 1);
        let node = match supplied.get(usize::from(level)).copied().flatten() {
            Some(bytes) => {
                match Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes)) {
                    Some(node) => node,
                    None => return Ok(Admission::StaleWitness),
                }
            }
            None => match tree.root(address, anchor_size) {
                Ok(node) => node,
                Err(e) if tree_data(&e) => return Ok(missing),
                Err(e) => return Err(e.into()),
            },
        };
        auth_path.push(node);
    }
    let path = MerklePath::from_parts(
        u32::try_from(position).map_err(|_| corrupt("position beyond the tree"))?,
        auth_path.try_into().expect("32 levels"),
    );
    // A path that misses the root condemns this witness, not the authenticated payment:
    // the candidate stays and is read again for another witness.
    if !recovered.verify_position(position, &path, root.into()) {
        return Ok(Admission::StaleWitness);
    }
    // Like any note before the birthday, it is not tracked; marking its key paid keeps
    // the index from being issued again and moves the recovery bound past it.
    if before_birthday {
        conn.execute(
            "UPDATE ironwood_one_time_keys
             SET used = 1, prebirthday_height = MIN(COALESCE(prebirthday_height, ?2), ?2) WHERE id = ?1",
            params![key_ref, birthday],
        )?;
        dequeue()?;
        return Ok(Admission::Admitted);
    }
    // An unmined transaction is one a rewind or the mempool left: its note may move to a
    // new position, but a rewound one holding no such note is not this one. One with raw
    // bytes may predate the key, so the action check below decides it.
    let conflict: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid = ?1 AND mined_height IS NOT NULL
             AND (mined_height != ?2 OR tx_index != ?3))
         OR EXISTS(SELECT 1 FROM transactions t WHERE t.txid = ?1 AND t.mined_height IS NULL
             AND t.raw IS NULL AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n
                 WHERE n.transaction_id = t.id_tx AND n.action_index = ?4
                   AND n.one_time_key_id = ?6))
         OR EXISTS(SELECT 1 FROM ironwood_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id
             WHERE t.txid = ?1 AND n.action_index = ?4 AND (
                 (n.nf IS NULL AND t.mined_height IS NOT NULL) OR n.nf != ?5
                 OR n.one_time_key_id IS NULL OR n.one_time_key_id != ?6
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
    // A stored raw transaction must hold the claimed action. Without raw bytes only the label
    // is unverified (value, position and nullifier are authenticated); relabeling once raw
    // arrives could drop spend state.
    let contradicted =
        wallet::get_transaction(conn, params, candidate.txid)?.is_some_and(|(_, tx)| {
            let action = tx.ironwood_bundle().and_then(|b| {
                b.actions()
                    .get(usize::try_from(candidate.action_index).ok()?)
            });
            !action.is_some_and(|a| {
                candidate.encrypted_note.matches_compact(
                    a.nullifier().to_bytes(),
                    a.cmx().to_bytes(),
                    a.encrypted_note().epk_bytes,
                    a.encrypted_note().enc_ciphertext[..52].try_into().unwrap(),
                )
            })
        });
    if conflict || contradicted {
        return Ok(Admission::Rejected);
    }
    if !covered(conn, account, candidate.height, through.height)? {
        return Ok(Admission::Uncovered);
    }
    // Tree material the scan stored only as roots, or left without checkpoints, can make
    // insertion fail even though the path reached the accepted root. That condemns the
    // anchor, not the payment, so the insertion is undone and retried at a newer one.
    conn.execute_batch("SAVEPOINT one_time_witness")?;
    let kept = match insert_witness(
        &mut tree, position, &recovered, &supplied, &path, checkpoint, root,
    ) {
        Ok(kept) => kept,
        Err(e) if tree_data(&e) => false,
        Err(e) => return Err(e.into()),
    };
    if !kept {
        conn.execute_batch("ROLLBACK TO one_time_witness; RELEASE one_time_witness")?;
        return Ok(missing);
    }
    conn.execute_batch("RELEASE one_time_witness")?;
    let spent_in: Option<crate::TxRef> = conn
        .query_row(
            "SELECT t.id_tx FROM ironwood_spend_journal_nullifiers n
             JOIN ironwood_spend_journal j USING (block_height, tx_index)
             JOIN transactions t ON t.txid = j.txid
             WHERE n.nf = ?1 AND n.block_height BETWEEN ?2 AND ?3
             LIMIT 1",
            params![
                recovered.nullifier().to_bytes(),
                u32::from(candidate.height),
                u32::from(through.height)
            ],
            |r| r.get(0).map(crate::TxRef),
        )
        .optional()?;
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
    let tx_ref = wallet::put_tx_meta(conn, sessions.tpir, &tx, candidate.height)?;
    let encrypted = candidate.encrypted_note.to_bytes();
    let output = WalletOrchardOutput::from_parts(
        candidate.action_index as usize,
        zcash_note_encryption::EphemeralKeyBytes(encrypted[64..96].try_into().unwrap()),
        (*recovered.note(), orchard::ValuePool::Ironwood),
        false,
        Position::from(position),
        Some(*recovered.nullifier()),
        account,
        Some(zip32::Scope::External),
    )
    .with_one_time_key_id(Some(key))
    .with_compact_ciphertext(encrypted[96..].try_into().unwrap());
    wallet::orchard::put_received_note(
        conn,
        sessions.tpir,
        params,
        ShieldedPool::Ironwood,
        &output,
        tx_ref,
        Some(candidate.height),
        spent_in,
    )?;
    wallet::enhance_pir::finish_private_receipt(conn, sessions.enhance, tx_ref)?;
    dequeue()?;
    Ok(Admission::Admitted)
}

/// Inserts the recovered note as a marked leaf with the payload's supplied siblings, and
/// reports whether the tree's own witness at `checkpoint` then reaches `root`.
///
/// The marked leaf goes in before its siblings, since it keeps its pair from pruning. A
/// sibling inserted first can strip a reference that held the pair unpruned, and the
/// leaf's insertion under the pruned node would then drop that sibling. Only supplied
/// siblings are kept: they are complete at the anchor, so no future append changes them.
fn insert_witness<'a>(
    tree: &mut crate::IronwoodCommitmentTree<&'a rusqlite::Transaction<'a>>,
    position: u64,
    recovered: &RecoveredNote,
    supplied: &[Option<[u8; 32]>],
    path: &MerklePath,
    checkpoint: BlockHeight,
    root: MerkleHashOrchard,
) -> Result<bool, ShardTreeError<crate::wallet::commitment_tree::Error>> {
    tree.batch_insert(
        Position::from(position),
        std::iter::once((
            MerkleHashOrchard::from_cmx(&recovered.note().commitment().into()),
            Retention::Marked,
        )),
    )?;
    for (level, hash) in path.auth_path().into_iter().enumerate() {
        if supplied.get(level).is_some_and(Option::is_some) {
            tree.insert(
                Address::from_parts((level as u8).into(), (position >> level) ^ 1),
                hash,
            )?;
        }
    }
    Ok(tree
        .witness_at_checkpoint_id(Position::from(position), &checkpoint)?
        .is_some_and(|stored| recovered.verify_position(position, &stored.into(), root.into())))
}

/// The tree size at checkpoint `checkpoint`: one past its last leaf, or zero.
fn checkpoint_position(
    conn: &Connection,
    checkpoint: BlockHeight,
) -> Result<u64, SqliteClientError> {
    let position: Option<u64> = conn.query_row(
        "SELECT position FROM ironwood_tree_checkpoints WHERE checkpoint_id = ?1",
        [u32::from(checkpoint)],
        |r| r.get(0),
    )?;
    Ok(position.map_or(0, |p| p + 1))
}

/// Whether the scan covered every block from `from` through `through` for `account`, with
/// its keys while the journal was recording (see `one_time_ivk::journal`).
fn covered(
    conn: &Connection,
    account: AccountUuid,
    from: BlockHeight,
    through: BlockHeight,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_journal_coverage c
             JOIN accounts a ON a.id = c.account_id
             WHERE a.uuid = ?1 AND c.start_height <= ?2 AND c.end_height > ?3)",
        params![account.0, u32::from(from), u32::from(through)],
        |r| r.get(0),
    )?)
}
