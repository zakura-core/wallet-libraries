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
    memo_pir::{MemoPirRequest, PendingIronwoodMemo},
};
use zcash_protocol::memo::MemoBytes;
use zip32::Scope;

use crate::{AccountUuid, error::SqliteClientError};

use super::{get_account, memo_repr, orchard::parse_note_version};

pub(crate) fn requests(conn: &Connection) -> Result<Vec<MemoPirRequest>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT commitment_tree_position
         FROM ironwood_memo_retrieval_queue
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
        Ok(MemoPirRequest::from_position(Position::from(position)))
    })
    .collect()
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

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use zcash_protocol::memo::MemoBytes;

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
}
