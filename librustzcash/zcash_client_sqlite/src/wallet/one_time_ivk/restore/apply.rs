//! Admits a late candidate only after local chain, coverage and spend checks, in one
//! transaction.
use incrementalmerkletree::{Address, Position, Retention};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use rusqlite::{Connection, OptionalExtension, params};
use zcash_client_backend::{
    data_api::{
        scanning::ScanPriority,
        transparent_ledger::{ChainPoint, TransparentLedgerMode},
    },
    wallet::{WalletOrchardOutput, WalletTx},
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, Parameters},
};

use super::{PendingPayment, payments::authenticate};
use crate::wallet::one_time_ivk::{KeyId, corrupt};
use crate::wallet::scanning::priority_code;
use crate::{AccountUuid, error::SqliteClientError, wallet};
use zcash_primitives::block::BlockHash;

/// The handle state that storing a note's transaction routes its enhancement with.
pub(crate) struct Sessions<'a> {
    /// The handle's transparent ledger mode.
    pub(crate) configured: Option<TransparentLedgerMode>,
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
    /// The scan has not stored its block or reached its path's anchor yet.
    Waiting,
    /// The scan finished blocks from the payment on without covering them for the account,
    /// so they must be scanned again (see `discovery::admit`).
    Uncovered,
    /// Its path's anchor is off the wallet's chain or too old to check, so a new path is
    /// needed.
    StaleWitness,
    /// The directory's claim failed a check against the wallet's own chain.
    Rejected,
}

/// The inclusion path at `position`, if every sibling is a valid hash.
pub(in crate::wallet::one_time_ivk) fn merkle_path(
    position: u32,
    siblings: [[u8; 32]; 32],
) -> Option<MerklePath> {
    let hashes = siblings
        .iter()
        .map(|bytes| Option::from(MerkleHashOrchard::from_bytes(bytes)))
        .collect::<Option<Vec<_>>>()?;
    Some(MerklePath::from_parts(position, hashes.try_into().ok()?))
}

/// Admits late `candidate` with its inclusion path at an anchor on the wallet's chain,
/// which authenticates the note and its position, so its height, but not its transaction
/// ID. It waits until the scan covered every block from the payment through `through`, the
/// highest block the scan stored, for the account: the change rule puts every spend of a
/// one-time note in a transaction the scan recognizes, so the spend journal then holds the
/// note's nullifier if it was spent. No memo is stored (see `wallet::one_time_ivk`).
#[allow(clippy::too_many_arguments)]
pub(in crate::wallet::one_time_ivk) fn apply_payment<P: Parameters>(
    conn: &rusqlite::Transaction<'_>,
    sessions: &Sessions<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    candidate: &PendingPayment,
    through: ChainPoint,
    (anchor, path): (ChainPoint, &MerklePath),
) -> Result<Admission, SqliteClientError> {
    let (key_ref, recovered) = authenticate(conn, params, account, key, candidate)?;
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
    if anchor.height > through.height {
        return Ok(Admission::Waiting);
    }
    if through.height - anchor.height > crate::PRUNING_DEPTH
        || wallet::get_block_hash(conn, anchor.height)? != Some(anchor.hash)
    {
        return Ok(Admission::StaleWitness);
    }
    let oldest = u32::from(through.height).saturating_sub(crate::PRUNING_DEPTH);
    let checkpoint: Option<u32> = conn.query_row(
        "SELECT MAX(checkpoint_id) FROM ironwood_tree_checkpoints
         WHERE checkpoint_id BETWEEN ?1 AND ?2",
        params![oldest, u32::from(anchor.height)],
        |r| r.get(0),
    )?;
    let Some(checkpoint) = checkpoint.map(BlockHeight::from) else {
        return Ok(Admission::StaleWitness);
    };
    let mut tree = crate::ironwood_tree(conn)?;
    let Some(root) = tree.root_at_checkpoint_id(&checkpoint)? else {
        return Ok(Admission::StaleWitness);
    };
    if !recovered.verify_position(position, path, root.into()) {
        return Ok(Admission::Rejected);
    }
    // Like any note before the birthday, it is not tracked; marking its key paid keeps
    // the index from being issued again and moves the recovery bound past it.
    if before_birthday {
        conn.execute(
            "UPDATE ironwood_one_time_keys
             SET advances_allocation = 1, used = 1, paid_before_birthday = 1 WHERE id = ?1",
            [key_ref],
        )?;
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
    let anchor_size: u64 = conn.query_row(
        "SELECT ironwood_commitment_tree_size FROM blocks WHERE height = ?1",
        [u32::from(checkpoint)],
        |r| r.get(0),
    )?;
    // The marked leaf goes in before its siblings, since it keeps its pair from pruning.
    // A sibling inserted first can strip a reference that held the pair unpruned, and the
    // leaf's insertion under the pruned node would then drop that sibling.
    tree.batch_insert(
        Position::from(position),
        std::iter::once((
            MerkleHashOrchard::from_cmx(&recovered.note().commitment().into()),
            Retention::Marked,
        )),
    )?;
    // Persist only complete sibling subtrees. A partial right subtree includes empty
    // future leaves and must not become a fixed hash for future appends.
    for (level, hash) in path.auth_path().into_iter().enumerate() {
        let address = Address::from_parts((level as u8).into(), (position >> level) ^ 1);
        if u64::from(address.position_range_end()) <= anchor_size {
            tree.insert(address, hash)?;
        }
    }
    let stored_path = tree
        .witness_at_checkpoint_id(Position::from(position), &checkpoint)?
        .ok_or_else(|| corrupt("stored one-time-key witness missing"))?;
    if !recovered.verify_position(position, &stored_path.into(), root.into()) {
        return Err(corrupt("stored one-time-key witness changed"));
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
    wallet::enhance_pir::finish_private_receipt(
        conn,
        sessions.tpir,
        sessions.configured,
        sessions.enhance,
        tx_ref,
        candidate.txid,
    )?;
    Ok(Admission::Admitted)
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

/// The highest block the scan stored that the scan queue no longer requires.
pub(in crate::wallet::one_time_ivk) fn scanned_tip(
    conn: &Connection,
) -> Result<Option<ChainPoint>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT b.height, b.hash FROM blocks b WHERE EXISTS(SELECT 1 FROM scan_queue q
                 WHERE q.priority = ?1 AND b.height >= q.block_range_start
                   AND b.height < q.block_range_end)
             ORDER BY b.height DESC LIMIT 1",
            [priority_code(&ScanPriority::Scanned)],
            |r| {
                Ok(ChainPoint {
                    height: BlockHeight::from(r.get::<_, u32>(0)?),
                    hash: BlockHash(r.get(1)?),
                })
            },
        )
        .optional()?)
}

/// Queues for a rescan each stretch from `from` through `through` that the scan finished
/// without covering for account `owner`, as blocks scanned before the journal existed are,
/// so a late payment there is not left waiting for good.
pub(in crate::wallet::one_time_ivk) fn rescan_uncovered(
    conn: &rusqlite::Transaction<'_>,
    owner: i64,
    from: BlockHeight,
    through: ChainPoint,
) -> Result<(), SqliteClientError> {
    let covered: Vec<(u32, u32)> = conn
        .prepare(
            "SELECT start_height, end_height FROM ironwood_journal_coverage
             WHERE account_id = ?1 AND end_height > ?2 AND start_height <= ?3
             ORDER BY start_height",
        )?
        .query_map(
            params![owner, u32::from(from), u32::from(through.height)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<Result<_, _>>()?;
    let end = u32::from(through.height) + 1;
    let mut gaps = vec![];
    let mut next = u32::from(from);
    for (start, stop) in covered {
        if start > next {
            gaps.push(next..start.min(end));
        }
        next = next.max(stop);
    }
    if next < end {
        gaps.push(next..end);
    }
    for gap in gaps {
        // Only a stretch the scan finished; one still queued is covered when it is scanned.
        let finished: bool = conn.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM scan_queue
             WHERE priority != ?3 AND block_range_start < ?2 AND block_range_end > ?1)",
            params![gap.start, gap.end, priority_code(&ScanPriority::Scanned)],
            |r| r.get(0),
        )?;
        if finished {
            crate::wallet::one_time_ivk::queue_rescan(
                conn,
                BlockHeight::from(gap.start)..BlockHeight::from(gap.end),
            )?;
        }
    }
    Ok(())
}
