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
        EnhancePirRequest, IronwoodEnhanceRequestId, PendingIronwoodMemo, PendingIronwoodOutgoing,
    },
};
use zcash_client_backend::wallet::{IronwoodEnhanceCandidate, Recipient};
use zcash_keys::address::Receiver;
use zcash_primitives::transaction::TxId;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::{PoolType, ShieldedPool, consensus::Parameters, value::Zatoshis};
use zip32::Scope;

use crate::{AccountUuid, error::SqliteClientError};

use super::{TxQueryType, get_account, memo_repr, orchard::parse_note_version};

type PendingOutgoingRow = ([u8; 32], u32, [u8; 32], [u8; 32], [u8; 32], [u8; 52]);

/// Selects the outgoing queue rows that still stand between a transaction and completion:
/// rows whose transaction has not obtained its full data by some other route.
///
/// Issuing work and retiring the transaction-ID fallback differ by exactly one clause, and
/// both callers state it rather than restating the whole predicate. A `not_recoverable` row
/// is no longer *work* — nothing further can be done with it — but it is emphatically not
/// *completion*, so it must keep blocking retirement; see [`retire_outgoing`] for why that
/// distinction is load-bearing. The two work-issuing queries therefore extend this fragment
/// with `AND q.not_recoverable = 0`, and [`retire_enhancement_if_complete`] does not.
///
/// `t.raw IS NULL` is common to all three: once the wallet holds the full transaction, its
/// outgoing rows can never be applied, so treating them as outstanding would leave the
/// transaction permanently unable to retire.
const OUTSTANDING_OUTGOING: &str = "
    FROM ironwood_enhance_outgoing_queue q
    JOIN transactions t ON t.id_tx = q.transaction_id
    WHERE t.raw IS NULL";

/// Retires a transaction's ordinary transaction-ID enhancement request once Enhance PIR has
/// finished with it.
///
/// Two conditions must hold, and the first is not an optimization. A transaction is retired
/// only if it is *protected* — only if Enhance PIR was made responsible for it by scanning,
/// which happens solely for compact transactions that represent the Ironwood pool and no
/// other. Absence of protection means the transaction is not ours: it may be a mixed-pool
/// transaction whose Sapling, Orchard or transparent data the transaction-ID request is the
/// only way to obtain, and deleting that request would put it permanently out of reach.
/// Reading "not protected" as "complete" would do exactly that.
///
/// The second is that no outstanding position remains, on either queue.
fn retire_enhancement_if_complete(
    tx: &Transaction<'_>,
    tx_ref: crate::TxRef,
) -> Result<(), SqliteClientError> {
    let complete = tx.query_row(
        &format!(
            "SELECT
                 EXISTS (
                     SELECT 1
                     FROM ironwood_enhance_tx_protection p
                     WHERE p.transaction_id = :transaction_id
                 )
                 AND NOT EXISTS (
                     SELECT 1
                     FROM ironwood_memo_retrieval_queue incoming
                     JOIN ironwood_received_notes rn
                       ON rn.id = incoming.received_note_id
                     WHERE rn.transaction_id = :transaction_id
                 )
                 AND NOT EXISTS (
                     SELECT 1 {OUTSTANDING_OUTGOING}
                       AND q.transaction_id = :transaction_id
                 )"
        ),
        named_params![":transaction_id": tx_ref.0],
        |row| row.get::<_, bool>(0),
    )?;

    if complete {
        tx.execute(
            "DELETE FROM tx_retrieval_queue
             WHERE txid = (
                 SELECT txid FROM transactions WHERE id_tx = :transaction_id
             )
               AND query_type = :enhancement_type",
            named_params![
                ":transaction_id": tx_ref.0,
                ":enhancement_type": TxQueryType::Enhancement.code(),
            ],
        )?;
    }

    Ok(())
}

pub(crate) fn requests(conn: &Connection) -> Result<Vec<EnhancePirRequest>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT commitment_tree_position FROM ironwood_memo_retrieval_queue
         UNION
         SELECT q.commitment_tree_position {OUTSTANDING_OUTGOING}
           AND q.not_recoverable = 0
         ORDER BY commitment_tree_position ASC"
    ))?;
    let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
    rows.map(|position| {
        let position = position?;
        let position = u64::try_from(position).map_err(|_| {
            SqliteClientError::CorruptedData(
                "Ironwood memo queue contains an invalid position".to_owned(),
            )
        })?;
        Ok(EnhancePirRequest::from_position(Position::from(position)))
    })
    .collect()
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

pub(crate) fn is_protected(conn: &Connection, txid: TxId) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM ironwood_enhance_tx_protection p
             JOIN transactions t ON t.id_tx = p.transaction_id
             WHERE t.txid = :txid
         )",
        named_params![":txid": &txid.as_ref()[..]],
        |row| row.get(0),
    )?)
}

pub(crate) fn queue_outgoing(
    conn: &Connection,
    tx_ref: crate::TxRef,
    candidates: &[IronwoodEnhanceCandidate<AccountUuid>],
    pir_eligible: bool,
) -> Result<(), SqliteClientError> {
    if !pir_eligible {
        conn.execute(
            "DELETE FROM ironwood_enhance_outgoing_queue
             WHERE transaction_id = :transaction_id",
            named_params![":transaction_id": tx_ref.0],
        )?;
        conn.execute(
            "DELETE FROM ironwood_enhance_tx_protection
             WHERE transaction_id = :transaction_id",
            named_params![":transaction_id": tx_ref.0],
        )?;
        return Ok(());
    }

    for candidate in candidates {
        let position = u64::from(candidate.position());
        conn.execute(
            "INSERT INTO ironwood_enhance_tx_protection (
                 transaction_id, commitment_tree_position
             ) VALUES (:tx, :position)
             ON CONFLICT DO NOTHING",
            named_params![":tx": tx_ref.0, ":position": position],
        )?;
        conn.execute(
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
                 not_recoverable = 0",
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
    Ok(())
}

pub(crate) fn remove_orphaned_outgoing(tx: &Transaction<'_>) -> Result<(), SqliteClientError> {
    tx.execute(
        "DELETE FROM ironwood_enhance_outgoing_queue
         WHERE NOT EXISTS (
             SELECT 1
             FROM ironwood_enhance_outgoing_accounts accounts
             WHERE accounts.commitment_tree_position =
                 ironwood_enhance_outgoing_queue.commitment_tree_position
         )",
        [],
    )?;
    tx.execute(
        "DELETE FROM ironwood_enhance_tx_protection
         WHERE NOT EXISTS (
             SELECT 1
             FROM ironwood_memo_retrieval_queue incoming
             WHERE incoming.commitment_tree_position =
                 ironwood_enhance_tx_protection.commitment_tree_position
         )
           AND NOT EXISTS (
             SELECT 1
             FROM ironwood_enhance_outgoing_queue outgoing
             WHERE outgoing.commitment_tree_position =
                 ironwood_enhance_tx_protection.commitment_tree_position
         )",
        [],
    )?;
    Ok(())
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
             WHERE q.commitment_tree_position = :position
               AND rn.memo IS NULL",
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

pub(crate) fn put(
    tx: &Transaction<'_>,
    position: Position,
    request_id: IronwoodEnhanceRequestId,
    memo: &MemoBytes,
) -> Result<bool, SqliteClientError> {
    let tx_ref = tx
        .query_row(
            "SELECT rn.transaction_id
             FROM ironwood_memo_retrieval_queue q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN transactions t ON t.id_tx = rn.transaction_id
             WHERE q.commitment_tree_position = :position
               AND t.txid = :txid
               AND rn.action_index = :output_index",
            named_params![
                ":position": u64::from(position),
                ":txid": request_id.txid().as_ref(),
                ":output_index": request_id.output_index(),
            ],
            |row| row.get::<_, i64>(0).map(crate::TxRef),
        )
        .optional()?;
    let Some(tx_ref) = tx_ref else {
        return Ok(false);
    };

    let changed = tx.execute(
        "UPDATE ironwood_received_notes
         SET memo = :memo
         WHERE id = (
             SELECT q.received_note_id
             FROM ironwood_memo_retrieval_queue q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN transactions t ON t.id_tx = rn.transaction_id
             WHERE q.commitment_tree_position = :position
               AND t.txid = :txid
               AND rn.action_index = :output_index
         ) AND memo IS NULL",
        named_params![
            ":position": u64::from(position),
            ":txid": request_id.txid().as_ref(),
            ":output_index": request_id.output_index(),
            ":memo": memo_repr(Some(memo)),
        ],
    )?;
    if changed == 1 {
        tx.execute(
            "DELETE FROM ironwood_memo_retrieval_queue
             WHERE commitment_tree_position = :position",
            named_params![":position": u64::from(position)],
        )?;
        retire_enhancement_if_complete(tx, tx_ref)?;
    }
    Ok(changed == 1)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn put_outgoing<P: Parameters>(
    tx: &Transaction<'_>,
    params: &P,
    position: Position,
    request_id: IronwoodEnhanceRequestId,
    from_account: AccountUuid,
    recipient: orchard::Address,
    value: Zatoshis,
    memo: &MemoBytes,
) -> Result<bool, SqliteClientError> {
    let target: Option<(crate::TxRef, usize)> = tx
        .query_row(
            "SELECT q.transaction_id, q.output_index
             FROM ironwood_enhance_outgoing_queue q
             JOIN transactions t ON t.id_tx = q.transaction_id
             WHERE q.commitment_tree_position = :position
               AND t.txid = :txid
               AND q.output_index = :output_index",
            named_params![
                ":position": u64::from(position),
                ":txid": request_id.txid().as_ref(),
                ":output_index": request_id.output_index(),
            ],
            |row| Ok((crate::TxRef(row.get(0)?), row.get(1)?)),
        )
        .optional()?;
    let Some((tx_ref, output_index)) = target else {
        return Ok(false);
    };
    let receiver = Receiver::Orchard(recipient);
    let recipient_address = super::select_receiving_address(tx, params, from_account, &receiver)?
        .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));
    super::put_sent_output(
        tx,
        params,
        from_account,
        tx_ref,
        output_index,
        &Recipient::External {
            recipient_address,
            output_pool: PoolType::Shielded(ShieldedPool::Ironwood),
        },
        value,
        Some(memo),
    )?;
    tx.execute(
        "DELETE FROM ironwood_enhance_outgoing_queue
         WHERE commitment_tree_position = :position",
        named_params![":position": u64::from(position)],
    )?;
    retire_enhancement_if_complete(tx, tx_ref)?;
    Ok(true)
}

/// Marks an outgoing candidate that authenticated against its compact action but carried no
/// outgoing plaintext any candidate funding account could recover.
///
/// The row is **marked, not deleted**, and [`retire_enhancement_if_complete`] is deliberately not
/// called. Both follow from the same point: retiring a transaction's transaction-ID fallback
/// asserts that Enhance PIR *completed* it, and giving up on one of its positions is not
/// completing it. Deleting the row would erase that distinction, because
/// [`retire_enhancement_if_complete`] reads completion off the queues — so the next position of
/// the same transaction to complete legitimately would retire the fallback on this position's
/// behalf. Marking is what keeps the row outstanding: [`OUTSTANDING_OUTGOING`] deliberately does
/// not filter on `not_recoverable`, which is the sole clause separating a row that still blocks
/// retirement from one that is still work.
///
/// That distinction is load-bearing rather than pedantic. Two reasons for non-recovery are
/// benign — a dummy action, or an output the wallet sent under `OvkPolicy::Discard` — but a
/// third is not: of the record's four fields only `ephemeral_key` and the compact ciphertext
/// prefix are bound to the action the wallet scanned, while `cv_net` and `out_ciphertext`, the
/// two recovery actually consumes, are not. A server can pair the genuine on-chain prefix with
/// forged versions of those two and reach this path at will. Were that to retire the fallback,
/// the server could erase a transaction from every retrieval path at once, in either enhancement
/// mode, with nothing the user could do to recover it.
///
/// The marked row keeps the transaction permanently ineligible for retirement, so its
/// transaction-ID request survives. That costs one transaction ID, and only if the user later
/// disables Enhance PIR — the same price every other unfinished transaction already pays. The
/// mark is cleared if a rescan re-queues the position as genuine work.
pub(crate) fn retire_outgoing(
    tx: &Transaction<'_>,
    position: Position,
    request_id: IronwoodEnhanceRequestId,
) -> Result<bool, SqliteClientError> {
    let marked = tx.execute(
        "UPDATE ironwood_enhance_outgoing_queue
         SET not_recoverable = 1
         WHERE commitment_tree_position = :position
           AND output_index = :output_index
           AND not_recoverable = 0
           AND transaction_id = (
               SELECT id_tx FROM transactions WHERE txid = :txid
           )",
        named_params![
            ":position": u64::from(position),
            ":txid": request_id.txid().as_ref(),
            ":output_index": request_id.output_index(),
        ],
    )?;
    Ok(marked == 1)
}

#[cfg(test)]
mod tests {
    use incrementalmerkletree::Position;
    use rusqlite::{Connection, named_params};
    use uuid::Uuid;
    use zcash_client_backend::wallet::IronwoodEnhanceCandidate;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::memo::MemoBytes;

    use crate::{AccountUuid, TxRef};

    #[test]
    fn completion_updates_and_dequeues_atomically() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY,
                 txid BLOB NOT NULL,
                 raw BLOB
             );
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL,
                 memo BLOB
             );
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             CREATE TABLE ironwood_enhance_outgoing_queue (
                 commitment_tree_position INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL
             );
             CREATE TABLE ironwood_enhance_tx_protection (
                 transaction_id INTEGER NOT NULL,
                 commitment_tree_position INTEGER NOT NULL,
                 PRIMARY KEY(transaction_id, commitment_tree_position)
             );
             CREATE TABLE tx_retrieval_queue (
                 txid BLOB NOT NULL,
                 query_type INTEGER NOT NULL,
                 UNIQUE(txid, query_type)
             );
             INSERT INTO transactions (id_tx, txid) VALUES (1, zeroblob(32));
             INSERT INTO ironwood_received_notes VALUES
                 (1, 1, 0, NULL),
                 (2, 1, 1, NULL);
             INSERT INTO ironwood_memo_retrieval_queue VALUES
                 (1, 42),
                 (2, 44);
             INSERT INTO ironwood_enhance_outgoing_queue VALUES (43, 1);
             INSERT INTO ironwood_enhance_tx_protection VALUES
                 (1, 42),
                 (1, 43),
                 (1, 44);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tx_retrieval_queue VALUES (zeroblob(32), :query_type)",
            named_params![":query_type": super::TxQueryType::Enhancement.code()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tx_retrieval_queue VALUES (zeroblob(32), :query_type)",
            named_params![":query_type": super::TxQueryType::Status.code()],
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        let first_id = super::IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0);
        let second_id = super::IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 1);
        assert!(
            !super::put(&tx, 42u64.into(), second_id, &MemoBytes::empty()).unwrap(),
            "a stale identity must not complete the current position"
        );
        assert!(super::put(&tx, 42u64.into(), first_id, &MemoBytes::empty()).unwrap());
        assert_eq!(
            tx.query_row(
                "SELECT memo FROM ironwood_received_notes WHERE id = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap(),
            vec![0xf6]
        );
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM ironwood_memo_retrieval_queue",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
            1
        );
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = :query_type",
                named_params![":query_type": super::TxQueryType::Enhancement.code()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "partial PIR completion retains the standard fallback"
        );

        assert!(!super::put(&tx, 99u64.into(), first_id, &MemoBytes::empty()).unwrap());
        tx.execute(
            "DELETE FROM ironwood_enhance_outgoing_queue
             WHERE commitment_tree_position = 43",
            [],
        )
        .unwrap();
        super::retire_enhancement_if_complete(&tx, TxRef(1)).unwrap();
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = :query_type",
                named_params![":query_type": super::TxQueryType::Enhancement.code()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "another incoming position still needs PIR completion"
        );

        assert!(super::put(&tx, 44u64.into(), second_id, &MemoBytes::empty()).unwrap());
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = :query_type",
                named_params![":query_type": super::TxQueryType::Enhancement.code()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "final PIR completion retires the standard fallback"
        );
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = :query_type",
                named_params![":query_type": super::TxQueryType::Status.code()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "status intent is independent of enhancement completion"
        );
    }

    #[test]
    fn outgoing_candidates_are_position_keyed_and_protect_the_txid() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL, raw BLOB
             );
             CREATE TABLE accounts (id INTEGER PRIMARY KEY, uuid BLOB NOT NULL);
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             CREATE TABLE ironwood_enhance_outgoing_queue (
                 commitment_tree_position INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL REFERENCES transactions(id_tx) ON DELETE CASCADE,
                 output_index INTEGER NOT NULL,
                 nullifier BLOB NOT NULL,
                 cmx BLOB NOT NULL,
                 ephemeral_key BLOB NOT NULL,
                 compact_ciphertext BLOB NOT NULL,
                 not_recoverable INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(transaction_id, output_index)
             );
             CREATE TABLE ironwood_enhance_outgoing_accounts (
                 commitment_tree_position INTEGER NOT NULL REFERENCES ironwood_enhance_outgoing_queue(commitment_tree_position) ON DELETE CASCADE,
                 account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                 PRIMARY KEY(commitment_tree_position, account_id)
             );
             CREATE TABLE ironwood_enhance_tx_protection (
                 transaction_id INTEGER NOT NULL REFERENCES transactions(id_tx) ON DELETE CASCADE,
                 commitment_tree_position INTEGER NOT NULL,
                 PRIMARY KEY(transaction_id, commitment_tree_position)
             );",
        )
        .unwrap();
        let account = AccountUuid::from_uuid(Uuid::from_u128(7));
        let txid = TxId::from_bytes([9; 32]);
        conn.execute(
            "INSERT INTO transactions VALUES (1, ?1, NULL)",
            [txid.as_ref()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO accounts VALUES (1, ?1)",
            [account.expose_uuid()],
        )
        .unwrap();
        let replacement_account = AccountUuid::from_uuid(Uuid::from_u128(8));
        conn.execute(
            "INSERT INTO accounts VALUES (2, ?1)",
            [replacement_account.expose_uuid()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ironwood_memo_retrieval_queue VALUES (99, 42)",
            [],
        )
        .unwrap();
        super::queue_outgoing(
            &conn,
            TxRef(1),
            &[IronwoodEnhanceCandidate::from_parts(
                Position::from(42),
                3,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 52],
                vec![account],
            )],
            true,
        )
        .unwrap();

        let requests = super::requests(&conn).unwrap();
        assert_eq!(requests.len(), 1, "UNION deduplicates the shared position");
        assert_eq!(requests[0].position(), Position::from(42));
        let pending = super::pending_outgoing(&conn, Position::from(42))
            .unwrap()
            .unwrap();
        assert_eq!(pending.account_ids, vec![account]);
        assert_eq!(pending.nullifier, [1; 32]);
        assert_eq!(pending.cmx, [2; 32]);
        assert_eq!(pending.ephemeral_key, [3; 32]);
        assert_eq!(pending.compact_ciphertext, [4; 52]);
        assert!(super::is_protected(&conn, txid).unwrap());

        super::queue_outgoing(
            &conn,
            TxRef(1),
            &[
                IronwoodEnhanceCandidate::from_parts(
                    Position::from(42),
                    4,
                    [3; 32],
                    [4; 32],
                    [5; 32],
                    [6; 52],
                    vec![replacement_account],
                ),
                IronwoodEnhanceCandidate::from_parts(
                    Position::from(7),
                    5,
                    [5; 32],
                    [6; 32],
                    [7; 32],
                    [8; 52],
                    vec![account],
                ),
            ],
            true,
        )
        .unwrap();
        assert_eq!(
            super::requests(&conn)
                .unwrap()
                .iter()
                .map(|request| request.position())
                .collect::<Vec<_>>(),
            vec![Position::from(7), Position::from(42)]
        );
        let replacement = super::pending_outgoing(&conn, Position::from(42))
            .unwrap()
            .unwrap();
        assert_eq!(replacement.account_ids, vec![replacement_account]);
        assert_eq!(replacement.nullifier, [3; 32]);
        assert_eq!(replacement.cmx, [4; 32]);
        assert_eq!(replacement.ephemeral_key, [5; 32]);
        assert_eq!(replacement.compact_ciphertext, [6; 52]);

        let tx = conn.transaction().unwrap();
        assert!(
            !super::retire_outgoing(
                &tx,
                Position::from(42),
                super::IronwoodEnhanceRequestId::new(txid, 3),
            )
            .unwrap()
        );
        assert!(super::retire_outgoing(&tx, Position::from(42), replacement.request_id,).unwrap());
        assert!(
            super::pending_outgoing(&tx, Position::from(42))
                .unwrap()
                .is_none()
        );
        tx.commit().unwrap();

        conn.execute("UPDATE transactions SET raw = X'00' WHERE id_tx = 1", [])
            .unwrap();
        assert_eq!(
            super::requests(&conn)
                .unwrap()
                .iter()
                .map(|request| request.position())
                .collect::<Vec<_>>(),
            vec![Position::from(42)],
            "raw transactions suppress outgoing work but preserve incoming requests"
        );
        assert!(super::is_protected(&conn, txid).unwrap());

        super::queue_outgoing(&conn, TxRef(1), &[], false).unwrap();
        assert!(!super::is_protected(&conn, txid).unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM ironwood_enhance_outgoing_queue",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "mixed-pool eligibility removes outgoing PIR work"
        );
    }

    /// A position that could not be recovered must stop being offered as work without ever being
    /// mistaken for completed work.
    ///
    /// Only `ephemeral_key` and the compact ciphertext prefix bind a record to the action the
    /// wallet scanned; `cv_net` and `out_ciphertext` — the two fields recovery consumes — do not.
    /// A server can pair the genuine prefix with forged versions of those and drive any position
    /// down this path at will, so if non-recovery retired the transaction-ID fallback, that
    /// server could erase a transaction from every retrieval path at once. Marking the row rather
    /// than deleting it is what keeps the two apart: deletion would leave the position
    /// indistinguishable from a completed one, and the next position to complete legitimately
    /// would retire the fallback on its behalf.
    #[test]
    fn non_recoverable_positions_stop_being_work_without_counting_as_complete() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL, raw BLOB
             );
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL,
                 memo BLOB
             );
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             CREATE TABLE ironwood_enhance_outgoing_queue (
                 commitment_tree_position INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 output_index INTEGER NOT NULL,
                 nullifier BLOB NOT NULL,
                 cmx BLOB NOT NULL,
                 ephemeral_key BLOB NOT NULL,
                 compact_ciphertext BLOB NOT NULL,
                 not_recoverable INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE ironwood_enhance_tx_protection (
                 transaction_id INTEGER NOT NULL,
                 commitment_tree_position INTEGER NOT NULL,
                 PRIMARY KEY(transaction_id, commitment_tree_position)
             );
             CREATE TABLE tx_retrieval_queue (
                 txid BLOB NOT NULL,
                 query_type INTEGER NOT NULL,
                 UNIQUE(txid, query_type)
             );
             -- One transaction with a received note at position 7 and an outgoing candidate at
             -- position 42, both protected, with an enhancement request outstanding.
             INSERT INTO transactions VALUES (1, zeroblob(32), NULL);
             INSERT INTO ironwood_received_notes VALUES (1, 1, 0, NULL);
             INSERT INTO ironwood_memo_retrieval_queue VALUES (1, 7);
             INSERT INTO ironwood_enhance_outgoing_queue
                 VALUES (42, 1, 3, zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(52), 0);
             INSERT INTO ironwood_enhance_tx_protection VALUES (1, 7), (1, 42);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tx_retrieval_queue VALUES (zeroblob(32), :query_type)",
            named_params![":query_type": super::TxQueryType::Enhancement.code()],
        )
        .unwrap();

        let txid = TxId::from_bytes([0; 32]);
        let enhancement_requests = |conn: &Connection| {
            conn.query_row(
                "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = :query_type",
                named_params![":query_type": super::TxQueryType::Enhancement.code()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };

        let tx = conn.transaction().unwrap();
        assert_eq!(
            super::requests(&tx).unwrap().len(),
            2,
            "both positions start out as work"
        );

        // A record authenticated against the compact action but held nothing recoverable.
        assert!(
            super::retire_outgoing(
                &tx,
                Position::from(42),
                super::IronwoodEnhanceRequestId::new(txid, 3)
            )
            .unwrap()
        );
        assert!(
            !super::retire_outgoing(
                &tx,
                Position::from(42),
                super::IronwoodEnhanceRequestId::new(txid, 3)
            )
            .unwrap(),
            "retiring an already-marked position reports no change"
        );
        assert_eq!(
            super::requests(&tx)
                .unwrap()
                .into_iter()
                .map(|request| request.position())
                .collect::<Vec<_>>(),
            vec![Position::from(7)],
            "a marked position is no longer offered as work"
        );
        assert!(
            super::pending_outgoing(&tx, Position::from(42))
                .unwrap()
                .is_none(),
            "a marked position cannot be applied again"
        );
        assert_eq!(
            enhancement_requests(&tx),
            1,
            "giving up on a position must not retire the transaction-ID fallback"
        );

        // The remaining position now completes legitimately. The transaction still is not
        // complete, because position 42 was never recovered.
        assert!(
            super::put(
                &tx,
                Position::from(7),
                super::IronwoodEnhanceRequestId::new(txid, 0),
                &MemoBytes::empty(),
            )
            .unwrap()
        );
        assert!(
            super::requests(&tx).unwrap().is_empty(),
            "no work remains to be issued"
        );
        assert_eq!(
            enhancement_requests(&tx),
            1,
            "a transaction with an unrecovered position is never Enhance PIR-complete, so the \
             fallback survives for a user who later disables the setting"
        );
    }

    /// The tables retirement reads, with one transaction holding one received note.
    fn retirement_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL, raw BLOB
             );
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL,
                 memo BLOB
             );
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             CREATE TABLE ironwood_enhance_outgoing_queue (
                 commitment_tree_position INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 output_index INTEGER NOT NULL,
                 nullifier BLOB NOT NULL,
                 cmx BLOB NOT NULL,
                 ephemeral_key BLOB NOT NULL,
                 compact_ciphertext BLOB NOT NULL,
                 not_recoverable INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE ironwood_enhance_tx_protection (
                 transaction_id INTEGER NOT NULL,
                 commitment_tree_position INTEGER NOT NULL,
                 PRIMARY KEY(transaction_id, commitment_tree_position)
             );
             CREATE TABLE tx_retrieval_queue (
                 txid BLOB NOT NULL,
                 query_type INTEGER NOT NULL,
                 UNIQUE(txid, query_type)
             );
             INSERT INTO transactions VALUES (1, zeroblob(32), NULL);
             INSERT INTO ironwood_received_notes VALUES (1, 1, 0, NULL);
             INSERT INTO ironwood_memo_retrieval_queue VALUES (1, 7);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tx_retrieval_queue VALUES (zeroblob(32), :query_type)",
            named_params![":query_type": super::TxQueryType::Enhancement.code()],
        )
        .unwrap();
    }

    fn enhancement_request_count(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM tx_retrieval_queue WHERE query_type = :query_type",
            named_params![":query_type": super::TxQueryType::Enhancement.code()],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// Completing every position of an *unprotected* transaction must not retire its
    /// transaction-ID request.
    ///
    /// Protection is what records that Enhance PIR is responsible for a transaction, and only
    /// scanning can establish it, because eligibility is a property of the compact transaction
    /// rather than of anything the database keeps. A queued position on an unprotected
    /// transaction is exactly the shape a wallet has after the migration backfills the memo
    /// queue: the transaction may be mixed-pool, in which case its transaction-ID request is the
    /// only route to its other pools' data and deleting it would put that data permanently out
    /// of reach.
    #[test]
    fn completion_never_retires_an_unprotected_transaction() {
        let mut conn = Connection::open_in_memory().unwrap();
        retirement_schema(&conn);
        // Deliberately no `ironwood_enhance_tx_protection` row.

        let tx = conn.transaction().unwrap();
        assert!(
            super::put(
                &tx,
                Position::from(7),
                super::IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
                &MemoBytes::empty(),
            )
            .unwrap(),
            "the memo is still stored; only the fallback decision differs"
        );
        assert!(
            super::requests(&tx).unwrap().is_empty(),
            "no work remains to be issued"
        );
        assert_eq!(
            enhancement_request_count(&tx),
            1,
            "an unprotected transaction is not Enhance PIR's to complete, so its \
             transaction-ID request must survive"
        );
    }

    /// An outgoing row whose transaction has since obtained its full data can never be applied,
    /// so it must not keep the transaction from retiring for ever.
    ///
    /// This is the one clause `OUTSTANDING_OUTGOING` shares with work issuance. The other,
    /// `not_recoverable = 0`, is deliberately absent from retirement; see
    /// `non_recoverable_positions_stop_being_work_without_counting_as_complete`.
    #[test]
    fn outgoing_rows_on_a_retrieved_transaction_do_not_block_retirement() {
        let mut conn = Connection::open_in_memory().unwrap();
        retirement_schema(&conn);
        conn.execute_batch(
            "INSERT INTO ironwood_enhance_outgoing_queue
                 VALUES (42, 1, 3, zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(52), 0);
             INSERT INTO ironwood_enhance_tx_protection VALUES (1, 7), (1, 42);
             UPDATE transactions SET raw = X'00' WHERE id_tx = 1;",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        assert!(
            super::requests(&tx)
                .unwrap()
                .into_iter()
                .map(|request| request.position())
                .eq([Position::from(7)]),
            "the outgoing row is no longer work either"
        );
        assert!(
            super::put(
                &tx,
                Position::from(7),
                super::IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
                &MemoBytes::empty(),
            )
            .unwrap()
        );
        assert_eq!(
            enhancement_request_count(&tx),
            0,
            "an unapplicable outgoing row must not leave the transaction permanently \
             unable to retire"
        );
    }

    #[test]
    fn removing_the_last_candidate_account_retires_orphaned_work() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY);
             CREATE TABLE accounts (id INTEGER PRIMARY KEY);
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             CREATE TABLE ironwood_enhance_outgoing_queue (
                 commitment_tree_position INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL REFERENCES transactions(id_tx) ON DELETE CASCADE
             );
             CREATE TABLE ironwood_enhance_outgoing_accounts (
                 commitment_tree_position INTEGER NOT NULL
                     REFERENCES ironwood_enhance_outgoing_queue(commitment_tree_position)
                     ON DELETE CASCADE,
                 account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                 PRIMARY KEY(commitment_tree_position, account_id)
             );
             CREATE TABLE ironwood_enhance_tx_protection (
                 transaction_id INTEGER NOT NULL REFERENCES transactions(id_tx) ON DELETE CASCADE,
                 commitment_tree_position INTEGER NOT NULL,
                 PRIMARY KEY(transaction_id, commitment_tree_position)
             );
             INSERT INTO transactions VALUES (1);
             INSERT INTO accounts VALUES (1);
             INSERT INTO ironwood_enhance_outgoing_queue VALUES (42, 1);
             INSERT INTO ironwood_enhance_outgoing_accounts VALUES (42, 1);
             INSERT INTO ironwood_enhance_tx_protection VALUES (1, 42);",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("DELETE FROM accounts WHERE id = 1", []).unwrap();
        super::remove_orphaned_outgoing(&tx).unwrap();
        assert_eq!(
            tx.query_row(
                "SELECT (
                     SELECT COUNT(*) FROM ironwood_enhance_outgoing_queue
                 ) + (
                     SELECT COUNT(*) FROM ironwood_enhance_tx_protection
                 )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn invalid_queued_scope_is_reported_as_corruption() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB NOT NULL);
             CREATE TABLE accounts (id INTEGER PRIMARY KEY, uuid BLOB NOT NULL);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL,
                 account_id INTEGER NOT NULL,
                 diversifier BLOB NOT NULL,
                 value INTEGER NOT NULL,
                 rho BLOB NOT NULL,
                 rseed BLOB NOT NULL,
                 note_version INTEGER NOT NULL,
                 recipient_key_scope INTEGER NOT NULL,
                 memo BLOB
             );
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             INSERT INTO transactions VALUES (1, zeroblob(32));",
        )
        .unwrap();
        conn.execute("INSERT INTO accounts VALUES (1, ?1)", [Uuid::from_u128(1)])
            .unwrap();
        conn.execute(
            "INSERT INTO ironwood_received_notes
             VALUES (
                 1, 1, 0, 1, zeroblob(11), 1, zeroblob(32), zeroblob(32), 3, 9, NULL
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ironwood_memo_retrieval_queue VALUES (1, 12)",
            [],
        )
        .unwrap();

        assert!(matches!(
            super::pending(
                &conn,
                &zcash_protocol::consensus::Network::TestNetwork,
                Position::from(12)
            ),
            Err(crate::error::SqliteClientError::CorruptedData(message))
                if message == "Invalid Ironwood note key scope"
        ));
    }
}
