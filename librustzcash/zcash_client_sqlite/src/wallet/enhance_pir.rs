use incrementalmerkletree::Position;
use orchard::{
    keys::Diversifier,
    note::{Note, RandomSeed, Rho},
    value::NoteValue,
};
use rusqlite::{Connection, OptionalExtension, Transaction, named_params};
use uuid::Uuid;
use zcash_client_backend::data_api::{
    Account as _,
    enhance_pir::{
        EnhancePirRequest, EnhancePirStoreResult, EnhancePirSuspension, EnhancePirWork,
        EnhanceRecord, IronwoodEnhanceDiscoveryFailure, IronwoodEnhanceDiscoveryFailureReason,
        IronwoodEnhanceDiscoveryRequest, IronwoodEnhanceRequestId,
        storage::{
            EnhancePirStorage, IronwoodOutgoingResult, PendingIronwoodMemo,
            PendingIronwoodOutgoing, ValidatedIronwoodEnhancement, validate_and_apply_record,
        },
    },
};
use zcash_client_backend::wallet::{IronwoodEnhancementPlan, Recipient, WalletTx};
use zcash_keys::address::Receiver;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, ShieldedPool, consensus::Parameters};
use zip32::Scope;

use crate::{AccountUuid, error::SqliteClientError};

use super::{TxQueryType, get_account, memo_repr, orchard::parse_note_version};

pub(crate) mod discovery;

// A route is transaction-wide. LwdRequired is sticky, including across rescans.
// PrivateProtected survives completion and rewinds; only an explicit LWD decision or
// transaction deletion with retrieval-intent cleanup ends protection. No row retains
// ordinary enhancement semantics for unclassified and legacy transactions.
const PRIVATE_PROTECTED: i64 = 0;
const LWD_REQUIRED: i64 = 1;

type PendingOutgoingRow = ([u8; 32], u32, [u8; 32], [u8; 32], [u8; 32], [u8; 52]);

const OUTSTANDING_OUTGOING: &str = "
    FROM ironwood_enhance_outgoing_queue q
    JOIN transactions t ON t.id_tx = q.transaction_id
    JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
    WHERE t.raw IS NULL AND t.mined_height IS NOT NULL AND r.route = 0";

fn retire_enhancement_if_complete(
    tx: &Connection,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    tx.execute(
        "DELETE FROM tx_retrieval_queue
         WHERE txid = (SELECT txid FROM transactions WHERE id_tx = :tx)
           AND query_type = :enhancement
           AND EXISTS (SELECT 1 FROM ironwood_enhance_routing
                       WHERE transaction_id = :tx AND route = 0)
           AND NOT EXISTS (
               SELECT 1 FROM ironwood_memo_retrieval_queue q
               JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
               WHERE rn.transaction_id = :tx)
           AND NOT EXISTS (
               SELECT 1 FROM ironwood_enhance_outgoing_queue WHERE transaction_id = :tx)
           AND NOT EXISTS (
               SELECT 1 FROM ironwood_enhance_discovery_queue WHERE transaction_id = :tx)",
        named_params![":tx": tx_ref.0, ":enhancement": TxQueryType::Enhancement.code()],
    )?;
    Ok(())
}

/// Clears private work without removing recovered data or an ordinary request.
pub(crate) fn clear_work(conn: &Connection, tx_ref: crate::TxRef) -> Result<(), SqliteClientError> {
    super::clear_ironwood_enhancement_work(conn, tx_ref)
}

fn require_lwd(conn: &Connection, tx_ref: crate::TxRef) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (:tx, :route)
         ON CONFLICT(transaction_id) DO UPDATE SET route = excluded.route",
        named_params![":tx": tx_ref.0, ":route": LWD_REQUIRED],
    )?;
    clear_work(conn, tx_ref)?;
    // Keep (or restore after earlier partial completion) the normal request.
    conn.execute(
        "INSERT INTO tx_retrieval_queue (txid, query_type)
         SELECT txid, :enhancement FROM transactions WHERE id_tx = :tx AND raw IS NULL
         ON CONFLICT(txid, query_type) DO NOTHING",
        named_params![":tx": tx_ref.0, ":enhancement": TxQueryType::Enhancement.code()],
    )?;
    Ok(())
}

pub(crate) fn is_protected(conn: &Connection, txid: TxId) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_routing r
         JOIN transactions t ON t.id_tx = r.transaction_id WHERE t.txid = :txid AND r.route = 0)",
        named_params![":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}

/// A single statement gives callers a consistent view across the independent queues.
pub(crate) fn work(conn: &Connection) -> Result<Vec<EnhancePirWork>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(&format!(
        "WITH discovery AS (
             SELECT t.txid, t.mined_height AS height, t.tx_index, b.hash,
                    CASE WHEN q.suspended = 1 THEN 0
                         WHEN b.ironwood_commitment_tree_size IS NULL
                           OR (t.mined_height != 0 AND prior.ironwood_commitment_tree_size IS NULL)
                         THEN 1 ELSE NULL END AS reason
             FROM ironwood_enhance_discovery_queue q
             JOIN transactions t ON t.id_tx = q.transaction_id
             LEFT JOIN blocks b ON b.height = t.mined_height
             LEFT JOIN blocks prior ON prior.height = t.mined_height - 1
             JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
             WHERE t.raw IS NULL AND t.mined_height IS NOT NULL AND r.route = 0
         ), queries AS (
             SELECT q.commitment_tree_position AS position, t.txid, rn.action_index AS output_index
             FROM ironwood_memo_retrieval_queue q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN transactions t ON t.id_tx = rn.transaction_id
             JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
             WHERE r.route = 0 AND t.raw IS NULL AND t.mined_height IS NOT NULL
               AND rn.memo IS NULL AND rn.commitment_tree_position = q.commitment_tree_position
             UNION
             SELECT q.commitment_tree_position, t.txid, q.output_index {OUTSTANDING_OUTGOING}
               AND q.not_recoverable = 0
         )
         SELECT DISTINCT 0 AS kind, height AS ordinal, hash AS identity, NULL AS output_index,
                         NULL AS reason, NULL AS tx_index FROM discovery WHERE reason IS NULL
         UNION ALL
         SELECT 1, position, txid, output_index, NULL, NULL FROM queries
         UNION ALL
         SELECT 2, height, txid, NULL, reason, tx_index FROM discovery WHERE reason IS NOT NULL
         UNION ALL
         SELECT 3, q.commitment_tree_position, t.txid, q.output_index, NULL, NULL
           {OUTSTANDING_OUTGOING} AND q.not_recoverable = 1
         ORDER BY kind, ordinal, tx_index, identity, output_index"
    ))?;
    stmt.query_map([], |row| {
        let kind: u8 = row.get(0)?;
        let ordinal: u64 = row.get(1)?;
        let identity: [u8; 32] = row.get(2)?;
        Ok(match kind {
            0 => EnhancePirWork::Rediscover(IronwoodEnhanceDiscoveryRequest {
                height: zcash_protocol::consensus::BlockHeight::from_u32(row.get(1)?),
                block_hash: zcash_primitives::block::BlockHash(identity),
            }),
            1 | 3 => {
                let request = EnhancePirRequest::new(
                    ordinal.into(),
                    IronwoodEnhanceRequestId::new(TxId::from_bytes(identity), row.get(3)?),
                );
                if kind == 1 {
                    EnhancePirWork::Query(request)
                } else {
                    EnhancePirWork::Suspended(EnhancePirSuspension::OutgoingNotRecoverable(request))
                }
            }
            2 => EnhancePirWork::Suspended(EnhancePirSuspension::Discovery(
                IronwoodEnhanceDiscoveryFailure {
                    txid: TxId::from_bytes(identity),
                    reason: match row.get::<_, u8>(4)? {
                        0 => IronwoodEnhanceDiscoveryFailureReason::NoFundingAccounts,
                        1 => IronwoodEnhanceDiscoveryFailureReason::AnchorUnavailable,
                        _ => unreachable!("closed SQL CASE"),
                    },
                },
            )),
            _ => unreachable!("closed SQL UNION"),
        })
    })?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

/// Authentication context and writes share the transaction owned by the public operation.
struct Storage<'a, 'conn, P> {
    tx: &'a Transaction<'conn>,
    params: &'a P,
}

impl<P: Parameters> EnhancePirStorage for Storage<'_, '_, P> {
    type AccountId = AccountUuid;
    type Account = super::Account;
    type Error = SqliteClientError;

    fn get_account(&self, id: AccountUuid) -> Result<Option<Self::Account>, Self::Error> {
        super::get_account(self.tx, self.params, id)
    }

    fn pending_ironwood_memo(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, Self::Error> {
        pending(self.tx, self.params, position)
    }

    fn pending_ironwood_outgoing(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<AccountUuid>>, Self::Error> {
        pending_outgoing(self.tx, position)
    }

    fn apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<AccountUuid>,
    ) -> Result<EnhancePirStoreResult, Self::Error> {
        apply(self.tx, self.params, enhancement)
    }
}

pub(crate) fn apply_record<P: Parameters>(
    tx: &Transaction<'_>,
    params: &P,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
) -> Result<EnhancePirStoreResult, SqliteClientError> {
    validate_and_apply_record(&mut Storage { tx, params }, request, record)
}

pub(crate) fn pending_outgoing(
    conn: &Connection,
    position: Position,
) -> Result<Option<PendingIronwoodOutgoing<AccountUuid>>, SqliteClientError> {
    let action: Option<PendingOutgoingRow> = conn
        .query_row(
            &format!(
                "SELECT t.txid, q.output_index, q.nullifier, q.cmx,
                        q.ephemeral_key, q.compact_ciphertext
                 {OUTSTANDING_OUTGOING}
                   AND q.commitment_tree_position = :position
                   AND q.not_recoverable = 0"
            ),
            named_params![":position": u64::from(position)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((txid, output_index, nullifier, cmx, ephemeral_key, compact_ciphertext)) = action
    else {
        return Ok(None);
    };
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid
         FROM ironwood_enhance_outgoing_accounts oa
         JOIN accounts a ON a.id = oa.account_id
         WHERE oa.commitment_tree_position = :position
         ORDER BY a.uuid",
    )?;
    let account_ids = stmt
        .query_map(named_params![":position": u64::from(position)], |row| {
            row.get::<_, Uuid>(0).map(AccountUuid::from_uuid)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(PendingIronwoodOutgoing {
        request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes(txid), output_index),
        account_ids,
        nullifier,
        cmx,
        ephemeral_key,
        compact_ciphertext,
    }))
}

/// Runs exactly once per scanned wallet transaction, after its notes are stored.
pub(crate) fn queue_scanned(
    conn: &Connection,
    tx_ref: crate::TxRef,
    tx: &WalletTx<AccountUuid>,
) -> Result<(), SqliteClientError> {
    // A wallet-funded mixed transaction may have no received Ironwood note
    // (for example, unshielding with only dummy Ironwood outputs). Its positive
    // LWD decision must still survive a later scan with omitted transparent data.
    if matches!(
        tx.ironwood_enhancement_plan(),
        IronwoodEnhancementPlan::Ineligible
    ) && (!tx.ironwood_spends().is_empty() || !tx.ironwood_outputs().is_empty())
    {
        return require_lwd(conn, tx_ref);
    }
    // Ordinary rescans load only unspent nullifiers. They must not erase outgoing work
    // merely because an already-linked spend is absent from this scan's account set.
    let scanned_accounts = tx
        .ironwood_spends()
        .iter()
        .map(|s| *s.account_id())
        .collect::<std::collections::HashSet<_>>();
    if discovery::funding(conn, tx_ref)?
        .iter()
        .any(|(account, _)| !scanned_accounts.contains(account))
    {
        discovery::queue(conn, tx_ref)?;
    }
    queue_transaction(conn, tx_ref, tx.ironwood_enhancement_plan())
}

fn queue_transaction(
    conn: &Connection,
    tx_ref: crate::TxRef,
    plan: &IronwoodEnhancementPlan<AccountUuid>,
) -> Result<(), SqliteClientError> {
    let (has_raw, mined): (bool, bool) = conn.query_row(
        "SELECT raw IS NOT NULL, mined_height IS NOT NULL FROM transactions WHERE id_tx = :tx",
        named_params![":tx": tx_ref.0],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if has_raw || !mined {
        return clear_work(conn, tx_ref);
    }
    let route: Option<i64> = conn
        .query_row(
            "SELECT route FROM ironwood_enhance_routing WHERE transaction_id = :tx",
            named_params![":tx": tx_ref.0],
            |row| row.get(0),
        )
        .optional()?;
    if route == Some(LWD_REQUIRED) {
        return require_lwd(conn, tx_ref);
    }
    let candidates = match plan {
        IronwoodEnhancementPlan::Eligible { outgoing } => outgoing,
        IronwoodEnhancementPlan::Ineligible => {
            let has_notes: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes WHERE transaction_id = :tx)",
                named_params![":tx": tx_ref.0],
                |row| row.get(0),
            )?;
            if route.is_some() || has_notes {
                require_lwd(conn, tx_ref)?;
            }
            return Ok(());
        }
    };

    // A position identifies one action globally. Rewinds remove obsolete claims
    // before positions can be reused, so another transaction owning one of these
    // positions is an integrity failure, not an upsert target.
    for candidate in candidates {
        if outgoing_position_owned_by_other(conn, tx_ref, u64::from(candidate.position()))? {
            return Err(SqliteClientError::CorruptedData(format!(
                "Ironwood commitment tree position {} is already owned by another transaction",
                u64::from(candidate.position())
            )));
        }
    }

    // Reconcile incoming work only after every note in this transaction exists.
    // Rewinds have already evicted position claims left by a prior chain branch.
    conn.execute(
        "DELETE FROM ironwood_memo_retrieval_queue
         WHERE received_note_id IN (SELECT id FROM ironwood_received_notes WHERE transaction_id = :tx)",
        named_params![":tx": tx_ref.0],
    )?;
    conn.execute(
        "INSERT INTO ironwood_memo_retrieval_queue (received_note_id, commitment_tree_position)
         SELECT id, commitment_tree_position FROM ironwood_received_notes
         WHERE transaction_id = :tx AND memo IS NULL AND note_version = 3
           AND commitment_tree_position IS NOT NULL
         ON CONFLICT(commitment_tree_position) DO UPDATE SET received_note_id = excluded.received_note_id",
        named_params![":tx": tx_ref.0],
    )?;
    // Rebuild the candidates recognized by this scan so newly decrypted received/change
    // actions do not retain outgoing jobs. queue_scanned records a durable discovery
    // obligation first if spent funding was omitted; this list alone cannot prove completion.
    // Reconstruction also retries previously suspended candidates.
    conn.execute(
        "DELETE FROM ironwood_enhance_outgoing_queue WHERE transaction_id = :tx",
        named_params![":tx": tx_ref.0],
    )?;
    for candidate in candidates {
        let position = u64::from(candidate.position());
        // Replayed compact scans must not undo an already recovered sent output.
        let recovered: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sent_notes
             WHERE transaction_id = :tx AND output_pool = :pool AND output_index = :index)",
            named_params![":tx": tx_ref.0, ":pool": super::pool_code(PoolType::Shielded(ShieldedPool::Ironwood)), ":index": candidate.output_index()],
            |row| row.get(0),
        )?;
        if recovered {
            continue;
        }
        let changed = conn.execute(
            "INSERT INTO ironwood_enhance_outgoing_queue (
                 commitment_tree_position, transaction_id, output_index, nullifier, cmx,
                 ephemeral_key, compact_ciphertext
             ) VALUES (
                 :position, :tx, :output_index, :nullifier, :cmx,
                 :ephemeral_key, :compact_ciphertext
             )
             ON CONFLICT(commitment_tree_position) DO UPDATE SET
                 transaction_id = excluded.transaction_id,
                 output_index = excluded.output_index,
                 nullifier = excluded.nullifier,
                 cmx = excluded.cmx,
                 ephemeral_key = excluded.ephemeral_key,
                 compact_ciphertext = excluded.compact_ciphertext,
                 not_recoverable = 0
             WHERE ironwood_enhance_outgoing_queue.transaction_id = excluded.transaction_id",
            named_params![
                ":position": position,
                ":tx": tx_ref.0,
                ":output_index": i64::try_from(candidate.output_index()).expect("output index fits"),
                ":nullifier": candidate.nullifier(),
                ":cmx": candidate.cmx(),
                ":ephemeral_key": candidate.ephemeral_key(),
                ":compact_ciphertext": candidate.compact_ciphertext(),
            ],
        )?;
        if changed != 1 {
            return Err(SqliteClientError::CorruptedData(format!(
                "Ironwood commitment tree position {position} became owned by another transaction"
            )));
        }
        conn.execute(
            "DELETE FROM ironwood_enhance_outgoing_accounts
             WHERE commitment_tree_position = :position",
            named_params![":position": position],
        )?;
        for account in candidate.funding_accounts() {
            conn.execute(
                "INSERT INTO ironwood_enhance_outgoing_accounts (
                     commitment_tree_position, account_id
                 ) SELECT :position, id FROM accounts WHERE uuid = :uuid",
                named_params![
                    ":position": position,
                    ":uuid": account.expose_uuid(),
                ],
            )?;
        }
    }

    let has_work: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_memo_retrieval_queue q
                       JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
                       WHERE rn.transaction_id = :tx)
             OR EXISTS(SELECT 1 FROM ironwood_enhance_outgoing_queue WHERE transaction_id = :tx)",
        named_params![":tx": tx_ref.0],
        |row| row.get(0),
    )?;
    if has_work {
        conn.execute(
            "INSERT INTO ironwood_enhance_routing (transaction_id, route) VALUES (:tx, :route)
             ON CONFLICT(transaction_id) DO NOTHING",
            named_params![":tx": tx_ref.0, ":route": PRIVATE_PROTECTED],
        )?;
    }
    // No route + no work is not proof of completion. A previously completed
    // private transaction, however, must not gain a txid request on replay.
    retire_enhancement_if_complete(conn, tx_ref)
}

pub(super) fn outgoing_position_owned_by_other(
    conn: &Connection,
    tx_ref: crate::TxRef,
    position: u64,
) -> Result<bool, SqliteClientError> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM ironwood_enhance_outgoing_queue
             WHERE commitment_tree_position = :position AND transaction_id != :tx
         )",
        named_params![":position": position, ":tx": tx_ref.0],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub(crate) fn pending<P: zcash_protocol::consensus::Parameters>(
    conn: &Connection,
    params: &P,
    position: Position,
) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, SqliteClientError> {
    #[allow(clippy::type_complexity)]
    let raw: Option<(
        [u8; 32],
        u32,
        Uuid,
        [u8; 11],
        u64,
        [u8; 32],
        [u8; 32],
        i64,
        i64,
    )> = conn
        .query_row(
            "SELECT t.txid, rn.action_index, a.uuid, rn.diversifier, rn.value,
                    rn.rho, rn.rseed, rn.note_version, rn.recipient_key_scope
             FROM ironwood_memo_retrieval_queue q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN transactions t ON t.id_tx = rn.transaction_id
             JOIN accounts a ON a.id = rn.account_id
             JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
             WHERE q.commitment_tree_position = :position
               AND rn.memo IS NULL AND r.route = 0
               AND t.raw IS NULL AND t.mined_height IS NOT NULL
               AND rn.commitment_tree_position = q.commitment_tree_position",
            named_params![":position": u64::from(position)],
            |row| {
                let value = u64::try_from(row.get::<_, i64>(4)?)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, i64::MIN))?;
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    value,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    let Some((txid, output_index, account_uuid, diversifier, value, rho, rseed, version, scope)) =
        raw
    else {
        return Ok(None);
    };
    let account_id = AccountUuid::from_uuid(account_uuid);
    let scope = match scope {
        0 => Scope::External,
        1 => Scope::Internal,
        _ => {
            return Err(SqliteClientError::CorruptedData(
                "Invalid Ironwood note key scope".to_owned(),
            ));
        }
    };
    let account =
        get_account(conn, params, account_id)?.ok_or(SqliteClientError::AccountUnknown)?;
    let diversifier = Diversifier::from_bytes(diversifier);
    let recipient = match scope {
        Scope::External => account
            .uivk()
            .orchard()
            .as_ref()
            .map(|ivk| ivk.address(diversifier)),
        Scope::Internal => account
            .ufvk()
            .and_then(|ufvk| ufvk.orchard())
            .map(|fvk| fvk.to_ivk(Scope::Internal).address(diversifier)),
    }
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Account cannot reconstruct queued Ironwood note".to_owned(),
        )
    })?;
    let rho = Option::from(Rho::from_bytes(&rho)).ok_or_else(|| {
        SqliteClientError::CorruptedData("Invalid queued Ironwood rho".to_owned())
    })?;
    let rseed = Option::from(RandomSeed::from_bytes(rseed, &rho)).ok_or_else(|| {
        SqliteClientError::CorruptedData("Invalid queued Ironwood rseed".to_owned())
    })?;
    let version = parse_note_version(version).ok_or_else(|| {
        SqliteClientError::CorruptedData("Invalid queued Ironwood note version".to_owned())
    })?;
    let note = Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        version,
    ))
    .ok_or_else(|| SqliteClientError::CorruptedData("Invalid queued Ironwood note".to_owned()))?;
    Ok(Some(PendingIronwoodMemo {
        request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes(txid), output_index),
        account_id,
        note,
        scope,
    }))
}

/// The sole mutation boundary for a network response. The caller owns this SQL
/// transaction, so memo writes, outgoing writes, queue changes, and routing roll
/// back together if any operation fails.
pub(crate) fn apply<P: Parameters>(
    tx: &Transaction<'_>,
    params: &P,
    enhancement: ValidatedIronwoodEnhancement<AccountUuid>,
) -> Result<EnhancePirStoreResult, SqliteClientError> {
    let (request, has_transparent, incoming, outgoing) = enhancement.into_parts();
    let id = request.request_id();
    let target: Option<crate::TxRef> = tx
        .query_row(
            "SELECT t.id_tx FROM transactions t
         JOIN ironwood_enhance_routing r ON r.transaction_id = t.id_tx
         WHERE t.txid = :txid AND t.raw IS NULL AND t.mined_height IS NOT NULL AND r.route = 0",
            named_params![":txid": id.txid().as_ref()],
            |row| row.get(0).map(crate::TxRef),
        )
        .optional()?;
    let Some(tx_ref) = target else {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    };
    let memo_id: Option<i64> = tx.query_row(
        "SELECT rn.id FROM ironwood_memo_retrieval_queue q
         JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
         WHERE q.commitment_tree_position = :position AND rn.transaction_id = :tx
           AND rn.action_index = :index AND rn.memo IS NULL
           AND rn.commitment_tree_position = :position",
        named_params![":position": u64::from(request.position()), ":tx": tx_ref.0, ":index": id.output_index()],
        |row| row.get(0),
    ).optional()?;
    let has_outgoing: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_outgoing_queue
         WHERE commitment_tree_position = :position AND transaction_id = :tx
           AND output_index = :index AND not_recoverable = 0)",
        named_params![":position": u64::from(request.position()), ":tx": tx_ref.0, ":index": id.output_index()],
        |row| row.get(0),
    )?;
    let expects_outgoing = !matches!(outgoing, IronwoodOutgoingResult::NotRequested);
    if memo_id.is_some() != incoming.is_some()
        || has_outgoing != expects_outgoing
        || (memo_id.is_none() && !has_outgoing)
    {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    }
    if let IronwoodOutgoingResult::Recovered { from_account, .. } = &outgoing {
        let still_candidate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_enhance_outgoing_accounts oa
             JOIN accounts a ON a.id = oa.account_id
             WHERE oa.commitment_tree_position = :position AND a.uuid = :uuid)",
            named_params![":position": u64::from(request.position()), ":uuid": from_account.expose_uuid()],
            |row| row.get(0),
        )?;
        if !still_candidate {
            return Ok(EnhancePirStoreResult::AlreadyResolved);
        }
    }
    // Crucially, no routing mutation happens before the identity rechecks.
    if has_transparent {
        require_lwd(tx, tx_ref)?;
        return Ok(EnhancePirStoreResult::LwdRequired);
    }
    if let (Some(note_id), Some(memo)) = (memo_id, incoming) {
        tx.execute(
            "UPDATE ironwood_received_notes SET memo = :memo WHERE id = :id",
            named_params![":memo": memo_repr(Some(&memo)), ":id": note_id],
        )?;
        tx.execute(
            "DELETE FROM ironwood_memo_retrieval_queue WHERE received_note_id = :id",
            named_params![":id": note_id],
        )?;
    }
    let result = match outgoing {
        IronwoodOutgoingResult::NotRequested => EnhancePirStoreResult::Stored,
        IronwoodOutgoingResult::NotRecoverable => {
            // Could be a dummy, OVK discard, or corrupt server fields. Suspend
            // retries but retain this row so it cannot masquerade as completion.
            tx.execute(
                "UPDATE ironwood_enhance_outgoing_queue SET not_recoverable = 1
                 WHERE commitment_tree_position = :position",
                named_params![":position": u64::from(request.position())],
            )?;
            EnhancePirStoreResult::NotRecoverable
        }
        IronwoodOutgoingResult::Recovered {
            from_account,
            recipient,
            value,
            memo,
        } => {
            let receiver = Receiver::Orchard(recipient);
            let recipient_address =
                super::select_receiving_address(tx, params, from_account, &receiver)?
                    .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));
            super::put_sent_output(
                tx,
                params,
                from_account,
                tx_ref,
                id.output_index() as usize,
                &Recipient::External {
                    recipient_address,
                    output_pool: PoolType::Shielded(ShieldedPool::Ironwood),
                },
                value,
                Some(&memo),
            )?;
            tx.execute(
                "DELETE FROM ironwood_enhance_outgoing_queue WHERE commitment_tree_position = :position",
                named_params![":position": u64::from(request.position())],
            )?;
            EnhancePirStoreResult::Stored
        }
    };
    retire_enhancement_if_complete(tx, tx_ref)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
