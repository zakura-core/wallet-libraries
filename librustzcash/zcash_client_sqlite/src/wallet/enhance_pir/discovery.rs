//! Durable rediscovery after an Ironwood spend becomes linkable retroactively.

use std::collections::{HashMap, HashSet};

use orchard::note_encryption::CompactAction;
use rusqlite::{Connection, OptionalExtension, Transaction, named_params};
use zcash_client_backend::{
    data_api::enhance_pir::{
        IronwoodEnhanceDiscoveryFailure, IronwoodEnhanceDiscoveryFailureReason,
        IronwoodEnhanceDiscoveryRequest, IronwoodEnhanceDiscoveryResult, is_ironwood_pir_candidate,
    },
    proto::compact_formats::{CompactBlock, CompactTx},
    wallet::IronwoodEnhanceCandidate,
};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::{AccountUuid, TxRef, error::SqliteClientError};

use super::{
    LWD_REQUIRED, TxQueryType, outgoing_position_owned_by_other, queue_transaction,
    retire_enhancement_if_complete,
};

/// Reopens outgoing discovery in the same transaction that persists the spend link.
/// This is mode-independent; Standard exposes the restored request, PrivateIronwood withholds it.
pub(crate) fn queue(conn: &Connection, tx_ref: TxRef) -> Result<(), SqliteClientError> {
    let needs_work: bool = conn.query_row(
        "SELECT raw IS NULL AND mined_height IS NOT NULL FROM transactions WHERE id_tx = :tx",
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )?;
    if !needs_work {
        return Ok(());
    }
    let route: Option<i64> = conn
        .query_row(
            "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = :tx",
            named_params![":tx": tx_ref.0],
            |row| row.get(0),
        )
        .optional()?;
    if route == Some(LWD_REQUIRED) {
        return super::require_lwd(conn, tx_ref);
    }
    conn.execute(
        "INSERT INTO ironwood_enhance_discovery_queue (transaction_id, suspended) VALUES (:tx, :suspended)
         ON CONFLICT(transaction_id) DO UPDATE SET suspended = excluded.suspended",
        named_params![":tx": tx_ref.0, ":suspended": funding(conn, tx_ref)?.is_empty()],
    )?;
    conn.execute(
        "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (:tx, 0)
         ON CONFLICT(transaction_id) DO NOTHING",
        named_params![":tx": tx_ref.0],
    )?;
    conn.execute(
        "INSERT INTO tx_retrieval_queue (txid, query_type)
         SELECT txid, :enhancement FROM transactions WHERE id_tx = :tx
         ON CONFLICT(txid, query_type) DO NOTHING",
        named_params![":tx": tx_ref.0, ":enhancement": TxQueryType::Enhancement.code()],
    )?;
    Ok(())
}

pub(crate) fn requests(
    conn: &Connection,
) -> Result<Vec<IronwoodEnhanceDiscoveryRequest>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT b.height, b.hash FROM ironwood_enhance_discovery_queue q
         JOIN transactions t ON t.id_tx = q.transaction_id
         JOIN blocks b ON b.height = t.mined_height
         LEFT JOIN blocks prior ON prior.height = b.height - 1
         JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
         WHERE t.raw IS NULL AND r.route = 0 AND q.suspended = 0
           AND b.ironwood_commitment_tree_size IS NOT NULL
           AND (b.height = 0 OR prior.ironwood_commitment_tree_size IS NOT NULL)
         ORDER BY b.height",
    )?;
    stmt.query_map([], |row| {
        Ok(IronwoodEnhanceDiscoveryRequest {
            height: BlockHeight::from_u32(row.get(0)?),
            block_hash: BlockHash(row.get(1)?),
        })
    })?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

/// Runs after account-deletion cascades, in the same SQL transaction. Keep the job as
/// incomplete, but remove it from automatic discovery so it cannot poison its block.
pub(super) fn suspend_orphaned(conn: &Transaction<'_>) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE ironwood_enhance_discovery_queue SET suspended = 1
         WHERE NOT EXISTS (
             SELECT 1 FROM ironwood_received_note_spends s
             JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
             WHERE s.transaction_id = ironwood_enhance_discovery_queue.transaction_id
               AND rn.nf IS NOT NULL)",
        [],
    )?;
    Ok(())
}

pub(crate) fn suspended(
    conn: &Connection,
) -> Result<Vec<IronwoodEnhanceDiscoveryFailure>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT t.txid,
                CASE WHEN q.suspended = 1 THEN 0 ELSE 1 END AS reason
         FROM ironwood_enhance_discovery_queue q
         JOIN transactions t ON t.id_tx = q.transaction_id
         LEFT JOIN blocks b ON b.height = t.mined_height
         LEFT JOIN blocks prior ON prior.height = t.mined_height - 1
         JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
         WHERE t.raw IS NULL AND t.mined_height IS NOT NULL AND r.route = 0
           AND (
               q.suspended = 1
               OR b.ironwood_commitment_tree_size IS NULL
               OR (t.mined_height != 0 AND prior.ironwood_commitment_tree_size IS NULL)
           )
         ORDER BY t.mined_height, t.tx_index, t.txid",
    )?;
    stmt.query_map([], |row| {
        Ok(IronwoodEnhanceDiscoveryFailure {
            txid: TxId::from_bytes(row.get(0)?),
            reason: match row.get::<_, i64>(1)? {
                0 => IronwoodEnhanceDiscoveryFailureReason::NoFundingAccounts,
                1 => IronwoodEnhanceDiscoveryFailureReason::AnchorUnavailable,
                _ => unreachable!("reason is produced by a closed SQL CASE"),
            },
        })
    })?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

/// Unlike the scan-time nullifier set, this includes already-spent funding notes.
pub(super) fn funding(
    conn: &Connection,
    tx_ref: TxRef,
) -> Result<Vec<(AccountUuid, [u8; 32])>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid, rn.nf FROM ironwood_received_note_spends s
         JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
         JOIN accounts a ON a.id = rn.account_id
         WHERE s.transaction_id = :tx AND rn.nf IS NOT NULL",
    )?;
    stmt.query_map(named_params![":tx": tx_ref.0], |row| {
        Ok((AccountUuid(row.get(0)?), row.get(1)?))
    })?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

/// Validates the entire reconstruction before mutating any work, using current funding
/// associations under the caller's SQL transaction (not a pre-network account snapshot).
pub(crate) fn rebuild(
    conn: &Transaction<'_>,
    request: IronwoodEnhanceDiscoveryRequest,
    block: &CompactBlock,
) -> Result<IronwoodEnhanceDiscoveryResult, SqliteClientError> {
    use IronwoodEnhanceDiscoveryFailureReason::{
        ContextMismatch, NoFundingAccounts, TransactionMissing,
    };
    use IronwoodEnhanceDiscoveryResult::{AlreadyResolved, Incomplete, Rebuilt, Rejected};
    let metadata: Option<([u8; 32], Option<u32>)> = conn
        .query_row(
            "SELECT hash, ironwood_commitment_tree_size FROM blocks WHERE height = :height",
            named_params![":height": u32::from(request.height)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((hash, Some(end))) = metadata else {
        return Ok(AlreadyResolved);
    };
    if BlockHash(hash) != request.block_hash {
        return Ok(AlreadyResolved);
    }
    let block_hash = if block.header.is_empty() {
        block.hash.as_slice().try_into().ok().map(BlockHash)
    } else {
        block.header().map(|header| header.hash())
    };
    if block.height != u64::from(u32::from(request.height))
        || block_hash != Some(request.block_hash)
        || block
            .chain_metadata
            .as_ref()
            .is_none_or(|m| m.ironwood_commitment_tree_size != end)
    {
        return Ok(Rejected);
    }
    let mut stmt = conn.prepare_cached(
        "SELECT t.id_tx, t.txid, t.tx_index FROM ironwood_enhance_discovery_queue q
         JOIN transactions t ON t.id_tx = q.transaction_id
         JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
         WHERE t.mined_height = :height AND t.raw IS NULL AND r.route = 0 AND q.suspended = 0
         ORDER BY t.tx_index, t.txid",
    )?;
    let jobs = stmt
        .query_map(named_params![":height": u32::from(request.height)], |row| {
            // A locator is recorded for every queued job, but an absent one is a
            // context mismatch to report per transaction, not a hard read failure.
            Ok((
                TxRef(row.get(0)?),
                row.get::<_, [u8; 32]>(1)?,
                row.get::<_, Option<u64>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if jobs.is_empty() {
        return Ok(AlreadyResolved);
    }

    let count = block.vtx.iter().try_fold(0u32, |sum, tx| {
        sum.checked_add(u32::try_from(tx.ironwood_actions.len()).ok()?)
    });
    let Some(mut position) = count.and_then(|n| end.checked_sub(n)) else {
        return Ok(Rejected);
    };
    // The preceding tree size anchors the action list. A claimed block hash does
    // not prove that the supplied compact action list is complete.
    let expected_start = if u32::from(request.height) == 0 {
        Some(0)
    } else {
        conn.query_row(
            "SELECT ironwood_commitment_tree_size FROM blocks WHERE height = :height",
            named_params![":height": u32::from(request.height) - 1],
            |row| row.get(0),
        )
        .optional()?
        .flatten()
    };
    if expected_start != Some(position) {
        return Ok(Rejected);
    }

    // Validate block-wide ordering before considering any transaction-local failures.
    // The same full block supplies positions for every independently processed job.
    let mut transactions = HashMap::new();
    let mut previous_index = None;
    for compact_tx in &block.vtx {
        if compact_tx.txid.len() != 32
            || transactions
                .insert(compact_tx.txid.as_slice(), (position, compact_tx))
                .is_some()
            || previous_index.is_some_and(|index| index >= compact_tx.index)
        {
            return Ok(Rejected);
        }
        previous_index = Some(compact_tx.index);
        position += u32::try_from(compact_tx.ironwood_actions.len()).expect("checked total");
    }

    let mut plans = vec![];
    let mut unresolved = vec![];
    let mut suspend = vec![];
    for (tx_ref, txid, index) in jobs {
        let funding = funding(conn, tx_ref)?;
        let reason = if funding.is_empty() {
            // Defensive handling for an active orphan, even if deletion cleanup was missed.
            suspend.push(tx_ref);
            Some(NoFundingAccounts)
        } else if let Some((position, compact_tx)) = transactions.get(txid.as_slice()) {
            if let Some(candidates) =
                candidates(conn, tx_ref, index, *position, compact_tx, &funding)?
            {
                plans.push((tx_ref, candidates, is_ironwood_pir_candidate(compact_tx)));
                None
            } else {
                Some(ContextMismatch)
            }
        } else {
            Some(TransactionMissing)
        };
        if let Some(reason) = reason {
            unresolved.push(IronwoodEnhanceDiscoveryFailure {
                txid: TxId::from_bytes(txid),
                reason,
            });
        }
    }

    // Do not allow a bad reconstruction to transfer a globally position-keyed
    // outgoing row from a transaction that was previously queued.
    for (tx_ref, candidates, _) in &plans {
        for candidate in candidates {
            if outgoing_position_owned_by_other(conn, *tx_ref, u64::from(candidate.position()))? {
                return Ok(Rejected);
            }
        }
    }

    // No early return for a bad job: it retains its intent while valid siblings progress.
    // Any SQL error still rolls back all writes in this call, including suspension.
    let rebuilt = plans.len();
    for tx_ref in suspend {
        conn.execute(
            "UPDATE ironwood_enhance_discovery_queue SET suspended = 1 WHERE transaction_id = :tx",
            named_params![":tx": tx_ref.0],
        )?;
    }
    for (tx_ref, candidates, eligible) in plans {
        queue_transaction(conn, tx_ref, &candidates, eligible)?;
        conn.execute(
            "DELETE FROM ironwood_enhance_discovery_queue WHERE transaction_id = :tx",
            named_params![":tx": tx_ref.0],
        )?;
        retire_enhancement_if_complete(conn, tx_ref)?;
    }
    Ok(if unresolved.is_empty() {
        Rebuilt(rebuilt)
    } else {
        Incomplete {
            rebuilt,
            unresolved,
        }
    })
}

/// Returns None for transaction-local context mismatches. Database errors remain errors;
/// neither case is permission to declare the transaction complete or fetch it publicly.
fn candidates(
    conn: &Connection,
    tx_ref: TxRef,
    expected_index: Option<u64>,
    position: u32,
    compact_tx: &CompactTx,
    funding: &[(AccountUuid, [u8; 32])],
) -> Result<Option<Vec<IronwoodEnhanceCandidate<AccountUuid>>>, SqliteClientError> {
    if expected_index != Some(compact_tx.index) {
        return Ok(None);
    }
    let accounts = funding
        .iter()
        .map(|(account, _)| *account)
        .collect::<HashSet<_>>();
    let mut stmt = conn.prepare_cached(
        "SELECT action_index, commitment_tree_position FROM ironwood_received_notes
         WHERE transaction_id = :tx",
    )?;
    let received = stmt
        .query_map(named_params![":tx": tx_ref.0], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Option<u64>>(1)?))
        })?
        .collect::<Result<HashMap<_, _>, _>>()?;
    if received.iter().any(|(index, pos)| {
        *index as usize >= compact_tx.ironwood_actions.len()
            || *pos != Some(u64::from(position) + u64::from(*index))
    }) {
        return Ok(None);
    }
    let mut candidates = vec![];
    let mut nullifiers = HashSet::new();
    for (index, raw) in compact_tx.ironwood_actions.iter().enumerate() {
        let Ok(action) = CompactAction::try_from(raw) else {
            return Ok(None);
        };
        nullifiers.insert(action.nullifier().to_bytes());
        if !received.contains_key(&(index as u32)) {
            candidates.push(IronwoodEnhanceCandidate::from_parts(
                (u64::from(position) + index as u64).into(),
                index,
                action.nullifier().to_bytes(),
                action.cmx().to_bytes(),
                raw.ephemeral_key
                    .as_slice()
                    .try_into()
                    .expect("validated CompactAction"),
                raw.ciphertext
                    .as_slice()
                    .try_into()
                    .expect("validated CompactAction"),
                accounts.iter().copied().collect(),
            ));
        }
    }
    if funding.iter().any(|(_, nf)| !nullifiers.contains(nf)) {
        return Ok(None);
    }
    Ok(Some(candidates))
}
