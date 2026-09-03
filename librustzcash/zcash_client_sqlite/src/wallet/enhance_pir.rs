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
    enhance_pir::{EnhancePirRequest, PendingIronwoodMemo, PendingIronwoodOutgoing},
};
use zcash_client_backend::wallet::{IronwoodEnhanceCandidate, Recipient};
use zcash_keys::address::Receiver;
use zcash_primitives::transaction::TxId;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::{PoolType, ShieldedPool, consensus::Parameters, value::Zatoshis};
use zip32::Scope;

use crate::{AccountUuid, error::SqliteClientError};

use super::{get_account, memo_repr, orchard::parse_note_version};

pub(crate) fn requests(conn: &Connection) -> Result<Vec<EnhancePirRequest>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT commitment_tree_position FROM ironwood_memo_retrieval_queue
         UNION
         SELECT q.commitment_tree_position
         FROM ironwood_enhance_outgoing_queue q
         JOIN transactions t ON t.id_tx = q.transaction_id
         WHERE t.raw IS NULL
         ORDER BY commitment_tree_position ASC",
    )?;
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
    let action: Option<([u8; 32], [u8; 32])> = conn
        .query_row(
            "SELECT q.nullifier, q.cmx
             FROM ironwood_enhance_outgoing_queue q
             JOIN transactions t ON t.id_tx = q.transaction_id
             WHERE q.commitment_tree_position = :position AND t.raw IS NULL",
            named_params![":position": u64::from(position)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((nullifier, cmx)) = action else {
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
        account_ids,
        nullifier,
        cmx,
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
) -> Result<(), SqliteClientError> {
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
                 commitment_tree_position, transaction_id, output_index, nullifier, cmx
             ) VALUES (:position, :tx, :output_index, :nullifier, :cmx)
             ON CONFLICT(commitment_tree_position) DO UPDATE SET
                 transaction_id = excluded.transaction_id,
                 output_index = excluded.output_index,
                 nullifier = excluded.nullifier,
                 cmx = excluded.cmx",
            named_params![
                ":position": position,
                ":tx": tx_ref.0,
                ":output_index": i64::try_from(candidate.output_index()).expect("output index fits"),
                ":nullifier": candidate.nullifier(),
                ":cmx": candidate.cmx(),
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

pub(crate) fn pending<P: zcash_protocol::consensus::Parameters>(
    conn: &Connection,
    params: &P,
    position: Position,
) -> Result<Option<PendingIronwoodMemo<AccountUuid>>, SqliteClientError> {
    #[allow(clippy::type_complexity)]
    let raw: Option<(Uuid, [u8; 11], u64, [u8; 32], [u8; 32], i64, i64)> = conn
        .query_row(
            "SELECT a.uuid, rn.diversifier, rn.value, rn.rho, rn.rseed,
                    rn.note_version, rn.recipient_key_scope
             FROM ironwood_memo_retrieval_queue q
             JOIN ironwood_received_notes rn ON rn.id = q.received_note_id
             JOIN accounts a ON a.id = rn.account_id
             WHERE q.commitment_tree_position = :position
               AND rn.memo IS NULL",
            named_params![":position": u64::from(position)],
            |row| {
                let value = u64::try_from(row.get::<_, i64>(2)?)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, i64::MIN))?;
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    value,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((account_uuid, diversifier, value, rho, rseed, version, scope)) = raw else {
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
        account_id,
        note,
        scope,
    }))
}

pub(crate) fn put(
    tx: &Transaction<'_>,
    position: Position,
    memo: &MemoBytes,
) -> Result<bool, SqliteClientError> {
    let changed = tx.execute(
        "UPDATE ironwood_received_notes
         SET memo = :memo
         WHERE id = (
             SELECT received_note_id FROM ironwood_memo_retrieval_queue
             WHERE commitment_tree_position = :position
         ) AND memo IS NULL",
        named_params![
            ":position": u64::from(position),
            ":memo": memo_repr(Some(memo)),
        ],
    )?;
    if changed == 1 {
        tx.execute(
            "DELETE FROM ironwood_memo_retrieval_queue
             WHERE commitment_tree_position = :position",
            named_params![":position": u64::from(position)],
        )?;
    }
    Ok(changed == 1)
}

pub(crate) fn put_outgoing<P: Parameters>(
    tx: &Transaction<'_>,
    params: &P,
    position: Position,
    from_account: AccountUuid,
    recipient: orchard::Address,
    value: Zatoshis,
    memo: &MemoBytes,
) -> Result<bool, SqliteClientError> {
    let target: Option<(crate::TxRef, usize)> = tx
        .query_row(
            "SELECT transaction_id, output_index
             FROM ironwood_enhance_outgoing_queue
             WHERE commitment_tree_position = :position",
            named_params![":position": u64::from(position)],
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
    Ok(true)
}

#[cfg(test)]
mod tests {
    use incrementalmerkletree::Position;
    use rusqlite::Connection;
    use uuid::Uuid;
    use zcash_client_backend::wallet::IronwoodEnhanceCandidate;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::memo::MemoBytes;

    use crate::{AccountUuid, TxRef};

    #[test]
    fn completion_updates_and_dequeues_atomically() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE ironwood_received_notes (id INTEGER PRIMARY KEY, memo BLOB);
             CREATE TABLE ironwood_memo_retrieval_queue (
                 received_note_id INTEGER PRIMARY KEY,
                 commitment_tree_position INTEGER NOT NULL UNIQUE
             );
             INSERT INTO ironwood_received_notes VALUES (1, NULL);
             INSERT INTO ironwood_memo_retrieval_queue VALUES (1, 42);",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        assert!(super::put(&tx, 42u64.into(), &MemoBytes::empty()).unwrap());
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
            0
        );
        assert!(!super::put(&tx, 42u64.into(), &MemoBytes::empty()).unwrap());
    }

    #[test]
    fn outgoing_candidates_are_position_keyed_and_protect_the_txid() {
        let conn = Connection::open_in_memory().unwrap();
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
        super::queue_outgoing(
            &conn,
            TxRef(1),
            &[IronwoodEnhanceCandidate::from_parts(
                Position::from(42),
                3,
                [1; 32],
                [2; 32],
                vec![account],
            )],
        )
        .unwrap();

        assert_eq!(
            super::requests(&conn).unwrap()[0].position(),
            Position::from(42)
        );
        let pending = super::pending_outgoing(&conn, Position::from(42))
            .unwrap()
            .unwrap();
        assert_eq!(pending.account_ids, vec![account]);
        assert_eq!(pending.nullifier, [1; 32]);
        assert_eq!(pending.cmx, [2; 32]);
        assert!(super::is_protected(&conn, txid).unwrap());

        conn.execute("UPDATE transactions SET raw = X'00' WHERE id_tx = 1", [])
            .unwrap();
        assert!(super::requests(&conn).unwrap().is_empty());
        assert!(super::is_protected(&conn, txid).unwrap());
    }
}
