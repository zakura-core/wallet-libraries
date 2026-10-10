//! Stored display facts: validation on store, decoding, and removal.

use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension as _, named_params};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    TransparentDetailOutcome, TransparentDisplayFacts, TransparentDisplayOutput,
    TransparentDisplayProvenance, TransparentDisplaySender, TransparentDisplayStore,
    TransparentLedgerMode,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::{TxRef, error::SqliteClientError};

use super::super::{check_transparent_policy_generation, resolve_mode, with_read_snapshot};
use super::codes::{KIND_ABSENT, KIND_NON_STANDARD, KIND_P2PKH, KIND_P2SH};
use super::schedule::{record_outcome, unix};
use super::sql::related_transaction_sql;
use super::validate::validate;

/// The `(kind, hash)` columns of a display address; `None` is a non-standard script.
fn encode_address_columns(address: Option<TransparentAddress>) -> (i64, Option<[u8; 20]>) {
    match address {
        Some(TransparentAddress::PublicKeyHash(hash)) => (KIND_P2PKH, Some(hash)),
        Some(TransparentAddress::ScriptHash(hash)) => (KIND_P2SH, Some(hash)),
        None => (KIND_NON_STANDARD, None),
    }
}

/// The `(kind, hash)` columns of a display sender.
fn encode_sender_columns(sender: TransparentDisplaySender) -> (i64, Option<[u8; 20]>) {
    match sender {
        TransparentDisplaySender::Absent => (KIND_ABSENT, None),
        TransparentDisplaySender::Address(address) => encode_address_columns(Some(address)),
        TransparentDisplaySender::NonStandard => encode_address_columns(None),
    }
}

/// Decodes `(kind, hash)` address columns, of a sender or of an output. An output's columns
/// never hold the absent kind; the caller rejects it.
fn decode_address_columns(
    kind: i64,
    hash: Option<[u8; 20]>,
) -> Result<TransparentDisplaySender, SqliteClientError> {
    match (kind, hash) {
        (KIND_ABSENT, None) => Ok(TransparentDisplaySender::Absent),
        (KIND_P2PKH, Some(hash)) => Ok(TransparentDisplaySender::Address(
            TransparentAddress::PublicKeyHash(hash),
        )),
        (KIND_P2SH, Some(hash)) => Ok(TransparentDisplaySender::Address(
            TransparentAddress::ScriptHash(hash),
        )),
        (KIND_NON_STANDARD, None) => Ok(TransparentDisplaySender::NonStandard),
        _ => Err(SqliteClientError::CorruptedData(
            "invalid display address kind".into(),
        )),
    }
}

/// Deletes the stored display facts of the transactions `filter` selects that contradict the
/// wallet; see [`enqueue`].
pub(super) fn revalidate(
    conn: &Connection,
    filter: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
) -> Result<(), SqliteClientError> {
    let stored: Vec<(i64, Option<u32>, Option<u64>)> = conn
        .prepare_cached(&format!(
            "SELECT t.id_tx, t.tx_index, t.fee FROM transactions t
             JOIN transparent_tx_display d ON d.transaction_id = t.id_tx
             WHERE {filter}"
        ))?
        .query_map(params, |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (id_tx, tx_index, fee) in stored {
        let Some(facts) = stored_facts(conn, id_tx)? else {
            continue;
        };
        if validate(conn, id_tx, tx_index, fee, &facts)?.is_some() {
            conn.execute(
                "DELETE FROM transparent_tx_display WHERE transaction_id = :tx",
                named_params![":tx": id_tx],
            )?;
        }
    }
    Ok(())
}

/// Removes work and display facts once raw bytes are stored: the raw transaction supersedes them.
pub(crate) fn clear(conn: &Connection, tx_ref: TxRef) -> Result<(), SqliteClientError> {
    conn.prepare_cached("DELETE FROM transparent_detail_work WHERE transaction_id = :tx")?
        .execute(named_params![":tx": tx_ref.0])?;
    conn.prepare_cached("DELETE FROM transparent_tx_display WHERE transaction_id = :tx")?
        .execute(named_params![":tx": tx_ref.0])?;
    Ok(())
}

/// Validates and stores display facts; see `TransparentDetailWrite::store_transparent_display`.
pub(crate) fn store(
    conn: &Connection,
    configured: Option<TransparentLedgerMode>,
    facts: TransparentDisplayFacts,
    expected_generation: u64,
    now: SystemTime,
) -> Result<TransparentDisplayStore, SqliteClientError> {
    resolve_mode(conn, configured)?;
    with_read_snapshot(conn, |conn| {
        check_transparent_policy_generation(conn, expected_generation)?;
        let row = conn
            .query_row(
                "SELECT id_tx, raw IS NOT NULL, tx_index, fee FROM transactions WHERE txid = :txid",
                named_params![":txid": facts.txid.as_ref()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<u64>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((id_tx, has_raw, tx_index, fee)) = row else {
            return Ok(TransparentDisplayStore::Superseded);
        };
        if has_raw {
            clear(conn, TxRef(id_tx))?;
            return Ok(TransparentDisplayStore::Superseded);
        }
        // Only a transaction the wallet wants details of, or still relates to, takes facts.
        let wanted: bool = conn.query_row(
            &format!(
                "SELECT EXISTS (SELECT 1 FROM transparent_detail_work WHERE transaction_id = :tx)
                     OR EXISTS (SELECT 1 FROM transactions t WHERE t.id_tx = :tx AND {})",
                related_transaction_sql()
            ),
            named_params![":tx": id_tx],
            |row| row.get(0),
        )?;
        if !wanted {
            return Ok(TransparentDisplayStore::Superseded);
        }
        if let Some(kind) = validate(conn, id_tx, tx_index, fee, &facts)? {
            record_outcome(
                conn,
                &facts.txid,
                facts.provenance.looked_up_height,
                TransparentDetailOutcome::Contradiction,
                Some(facts.provenance.map_sha256),
                now,
            )?;
            return Ok(TransparentDisplayStore::Contradiction(kind));
        }

        let provenance = &facts.provenance;
        let (sender_kind, sender_hash) = encode_sender_columns(facts.sender);
        conn.execute(
            "DELETE FROM transparent_tx_display WHERE transaction_id = :tx",
            named_params![":tx": id_tx],
        )?;
        conn.execute(
            "INSERT INTO transparent_tx_display
             (transaction_id, coinbase, fee_zat, input_count, output_count, shielded,
              sender_kind, sender_hash, multiple_source_scripts,
              shielded_and_transparent_funding, shard_id, revision, map_sha256,
              looked_up_height, stored_at)
             VALUES (:tx, :coinbase, :fee, :inputs, :outputs, :shielded, :sender_kind,
                     :sender_hash, :multiple, :mixed, :shard, :revision, :map, :height, :now)",
            named_params![
                ":tx": id_tx,
                ":coinbase": facts.coinbase,
                ":fee": facts.fee.into_u64() as i64,
                ":inputs": facts.input_count,
                ":outputs": facts.output_count,
                ":shielded": facts.shielded_components,
                ":sender_kind": sender_kind,
                ":sender_hash": sender_hash.as_ref().map(|h| &h[..]),
                ":multiple": facts.multiple_source_scripts,
                ":mixed": facts.shielded_and_transparent_funding,
                ":shard": i64::try_from(provenance.shard_id).map_err(|_| {
                    SqliteClientError::CorruptedData("display shard id does not fit i64".into())
                })?,
                ":revision": provenance.revision,
                ":map": &provenance.map_sha256[..],
                ":height": u32::from(provenance.looked_up_height),
                ":now": unix(now),
            ],
        )?;
        let mut insert = conn.prepare_cached(
            "INSERT INTO transparent_tx_display_outputs
             (transaction_id, output_index, value_zat, address_kind, address_hash)
             VALUES (:tx, :index, :value, :kind, :hash)",
        )?;
        for (output, index) in facts.outputs.iter().zip(0u32..) {
            let (kind, hash) = encode_address_columns(output.address);
            insert.execute(named_params![
                ":tx": id_tx,
                ":index": index,
                ":value": output.value.into_u64() as i64,
                ":kind": kind,
                ":hash": hash.as_ref().map(|h| &h[..]),
            ])?;
        }
        conn.execute(
            "DELETE FROM transparent_detail_work WHERE transaction_id = :tx",
            named_params![":tx": id_tx],
        )?;
        Ok(TransparentDisplayStore::Stored)
    })
}

/// The display facts stored for transaction `id_tx`, if any.
pub(super) fn stored_facts(
    conn: &Connection,
    id_tx: i64,
) -> Result<Option<TransparentDisplayFacts>, SqliteClientError> {
    let corrupt = |what: &str| SqliteClientError::CorruptedData(format!("display {what}"));
    let display = conn
        .query_row(
            "SELECT t.txid, d.coinbase, d.fee_zat, d.input_count, d.output_count, d.shielded,
                    d.sender_kind, d.sender_hash, d.multiple_source_scripts,
                    d.shielded_and_transparent_funding, d.shard_id, d.revision, d.map_sha256,
                    d.looked_up_height
             FROM transparent_tx_display d JOIN transactions t ON t.id_tx = d.transaction_id
             WHERE d.transaction_id = :tx",
            named_params![":tx": id_tx],
            |row| {
                Ok((
                    (
                        row.get::<_, [u8; 32]>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, u32>(4)?,
                        row.get::<_, bool>(5)?,
                    ),
                    (
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<[u8; 20]>>(7)?,
                        row.get::<_, bool>(8)?,
                        row.get::<_, bool>(9)?,
                    ),
                    (
                        row.get::<_, i64>(10)?,
                        row.get::<_, u32>(11)?,
                        row.get::<_, [u8; 32]>(12)?,
                        row.get::<_, u32>(13)?,
                    ),
                ))
            },
        )
        .optional()?;
    let Some((
        (txid, coinbase, fee, input_count, output_count, shielded),
        (sender_kind, sender_hash, multiple_source_scripts, mixed),
        (shard, revision, map, height),
    )) = display
    else {
        return Ok(None);
    };
    let outputs = conn
        .prepare_cached(
            "SELECT output_index, value_zat, address_kind, address_hash
             FROM transparent_tx_display_outputs
             WHERE transaction_id = :tx ORDER BY output_index",
        )?
        .query_map(named_params![":tx": id_tx], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<[u8; 20]>>(3)?,
            ))
        })?
        .zip(0u32..)
        .map(|(row, expected)| {
            let (index, value, kind, hash) = row?;
            if index != expected {
                return Err(corrupt("outputs are not contiguous"));
            }
            let address = match decode_address_columns(kind, hash)? {
                TransparentDisplaySender::Address(address) => Some(address),
                TransparentDisplaySender::NonStandard => None,
                TransparentDisplaySender::Absent => return Err(corrupt("output without a kind")),
            };
            let value =
                Zatoshis::from_u64(value).map_err(|_| corrupt("value exceeds MAX_MONEY"))?;
            Ok(TransparentDisplayOutput { value, address })
        })
        .collect::<Result<Vec<_>, SqliteClientError>>()?;
    let facts = TransparentDisplayFacts {
        txid: TxId::from_bytes(txid),
        coinbase,
        fee: Zatoshis::from_u64(fee).map_err(|_| corrupt("fee exceeds MAX_MONEY"))?,
        input_count,
        output_count,
        shielded_components: shielded,
        sender: decode_address_columns(sender_kind, sender_hash)?,
        outputs,
        multiple_source_scripts,
        shielded_and_transparent_funding: mixed,
        provenance: TransparentDisplayProvenance {
            shard_id: u64::try_from(shard).map_err(|_| corrupt("shard id is negative"))?,
            revision,
            map_sha256: map,
            looked_up_height: BlockHeight::from_u32(height),
        },
    };
    if !facts.is_well_formed() {
        return Err(corrupt("facts are malformed"));
    }
    Ok(Some(facts))
}
