//! The facts a history entry is derived from: the transaction row, the account's recorded
//! amounts and sends, and qualified recovered metadata.

use rusqlite::{OptionalExtension as _, named_params};
use zcash_client_backend::data_api::transparent_ledger::{
    MetadataProvenance, TransactionMetadata, TransactionMetadataEvidence, WholeTransactionFee,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, consensus::BlockHeight, value::Zatoshis};

use crate::{error::SqliteClientError, wallet::encoding::parse_pool_code};

/// Current qualified facts, kept separate from independently stored local-send records.
pub(super) fn metadata_evidence(
    conn: &rusqlite::Connection,
    account: i64,
    txid: &TxId,
) -> Result<Option<TransactionMetadataEvidence>, SqliteClientError> {
    let mut stmt = conn.prepare_cached("SELECT m.fee_state, m.fee_zat, m.input_count, m.shielded,
        r.source, r.revision, r.lineage
        FROM tpir_transaction_metadata m
        JOIN tpir_revisions r ON r.id = m.revision_id
        JOIN tpir_qualified_revisions q ON q.revision_id = r.id
        JOIN tpir_active_accounts a ON a.account_id = m.account_id
        WHERE m.account_id = :account AND m.txid = :txid
        AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources s WHERE s.source = r.source)
        AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_accounts a WHERE a.account_id = m.account_id)
        AND (EXISTS (SELECT 1 FROM tpir_receive_events e JOIN tpir_receive_observations o ON o.receive_id = e.id
            WHERE e.account_id = m.account_id AND e.txid = m.txid AND e.mined_height = m.mined_height
            AND o.revision_id = m.revision_id)
        OR EXISTS (SELECT 1 FROM tpir_spend_events e JOIN tpir_spend_observations o ON o.spend_id = e.id
            WHERE e.account_id = m.account_id AND e.spending_txid = m.txid AND e.mined_height = m.mined_height
            AND o.revision_id = m.revision_id)) ORDER BY r.source, r.lineage")?;
    let mut rows = stmt.query(named_params![":account": account, ":txid": txid.as_ref()])?;
    let mut evidence: Option<TransactionMetadataEvidence> = None;
    while let Some(row) = rows.next()? {
        let fee = match row.get::<_, i64>(0)? {
            0 => WholeTransactionFee::Exact(zatoshis(row.get(1)?)?),
            1 => WholeTransactionFee::Unknown,
            2 => WholeTransactionFee::NotApplicable,
            _ => {
                return Err(SqliteClientError::CorruptedData(
                    "invalid transaction fee state".into(),
                ));
            }
        };
        let metadata = TransactionMetadata {
            fee,
            transparent_input_count: row.get(2)?,
            has_shielded_components: row.get(3)?,
        };
        let provenance = MetadataProvenance {
            source: row.get(4)?,
            revision: row.get(5)?,
            lineage: row.get(6)?,
        };
        if let Some(existing) = &mut evidence {
            if existing.metadata != metadata {
                return Err(SqliteClientError::CorruptedData(
                    "conflicting transaction metadata".into(),
                ));
            }
            existing.provenance.push(provenance);
        } else {
            evidence = Some(TransactionMetadataEvidence {
                metadata,
                provenance: vec![provenance],
            });
        }
    }
    Ok(evidence)
}

pub(super) fn qualified_owned_spend_inputs(
    conn: &rusqlite::Connection,
    account: i64,
    txid: &TxId,
) -> Result<u32, SqliteClientError> {
    Ok(conn.query_row("SELECT COUNT(DISTINCT s.input_index) FROM tpir_spend_events s
        WHERE s.account_id = :account AND s.spending_txid = :txid AND s.mined_height IS NOT NULL
        AND EXISTS (SELECT 1 FROM tpir_spend_observations o JOIN tpir_qualified_revisions q ON q.revision_id = o.revision_id
            JOIN tpir_revisions r ON r.id = o.revision_id WHERE o.spend_id = s.id
            AND NOT EXISTS (SELECT 1 FROM tpir_quarantined_sources qs WHERE qs.source = r.source))",
        named_params![":account": account, ":txid": txid.as_ref()], |row| row.get(0))?)
}

/// The `transactions` row facts a history entry depends on.
pub(super) struct TransactionFacts {
    pub(super) id: i64,
    pub(super) mined_height: Option<BlockHeight>,
    pub(super) has_full_data: bool,
    pub(super) fee: Option<Zatoshis>,
    /// The wallet constructed and stored the transaction, recording every input it spent and
    /// every output it created, with recipients and memos. Deleting the funding account deletes
    /// those outputs, and with them this evidence.
    pub(super) constructed: bool,
    /// The wallet created the transaction, whether or not it stored the construction details. An
    /// outbox records only this evidence; its details live outside the wallet database.
    pub(super) created_locally: bool,
    /// Enhancement found pools beyond Ironwood (transparent data, by the service's flags or the
    /// compact scan) and the full transaction is not stored: its fee, if known, comes from
    /// private metadata and also covers inputs and outputs that are not the account's.
    pub(super) mixed_without_full_data: bool,
    /// Display-only service assertion; NULL means it has not been recovered.
    pub(super) has_transparent_outputs: Option<bool>,
}

pub(super) fn transaction_facts(
    conn: &rusqlite::Connection,
    txid: &TxId,
) -> Result<Option<TransactionFacts>, SqliteClientError> {
    conn.query_row(
        "SELECT id_tx, mined_height, raw IS NOT NULL, fee,
                created IS NOT NULL
                    AND EXISTS (SELECT 1 FROM sent_notes s WHERE s.transaction_id = id_tx),
                created IS NOT NULL OR target_height IS NOT NULL,
                raw IS NULL AND EXISTS (
                    SELECT 1 FROM ironwood_enhance_routing r
                    WHERE r.transaction_id = id_tx AND r.route IN (1, 2)
                ),
                (SELECT has_transparent_outputs FROM ironwood_enhance_routing r
                 WHERE r.transaction_id = id_tx)
         FROM transactions WHERE txid = :txid",
        named_params![":txid": txid.as_ref()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<u32>>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, Option<bool>>(7)?,
            ))
        },
    )
    .optional()?
    .map(
        |(id, mined_height, has_full_data, fee, constructed, created_locally, mixed, outputs)| {
            Ok(TransactionFacts {
                id,
                mined_height: mined_height.map(BlockHeight::from_u32),
                has_full_data,
                fee: fee.map(zatoshis).transpose()?,
                constructed,
                created_locally,
                mixed_without_full_data: mixed,
                has_transparent_outputs: outputs,
            })
        },
    )
    .transpose()
}

pub(super) fn zatoshis(value: i64) -> Result<Zatoshis, SqliteClientError> {
    Zatoshis::from_nonnegative_i64(value)
        .map_err(|_| SqliteClientError::CorruptedData(format!("invalid value {value}")))
}

/// The account's recorded received and spent amounts per pool in the transaction. Empty when the
/// account has no recorded output or spend in it.
pub(super) fn known_amounts(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<Vec<(PoolType, Zatoshis, Zatoshis)>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT pool, SUM(received), SUM(spent) FROM (
             SELECT ro.pool, ro.value AS received, 0 AS spent
             FROM v_received_outputs ro
             WHERE ro.account_id = :account_id AND ro.transaction_id = :transaction_id
             UNION ALL
             SELECT ro.pool, 0, ro.value
             FROM v_received_outputs ro
             JOIN v_received_output_spends ros
                  ON ros.pool = ro.pool AND ros.received_output_id = ro.id_within_pool_table
             WHERE ro.account_id = :account_id AND ros.transaction_id = :transaction_id
         )
         GROUP BY pool",
    )?;
    let mut rows = stmt.query(named_params![
        ":account_id": account_id,
        ":transaction_id": transaction_id,
    ])?;
    let mut amounts = vec![];
    while let Some(row) = rows.next()? {
        amounts.push((
            parse_pool_code(row.get(0)?)?,
            zatoshis(row.get(1)?)?,
            zatoshis(row.get(2)?)?,
        ));
    }
    Ok(amounts)
}

/// The value of the recorded outputs the account sent in the transaction to anyone but itself.
pub(super) fn sent_elsewhere(
    conn: &rusqlite::Connection,
    account_id: i64,
    transaction_id: i64,
) -> Result<u64, SqliteClientError> {
    let value: i64 = conn.query_row(
        "SELECT COALESCE(SUM(s.value), 0) FROM sent_notes s
         WHERE s.from_account_id = :account_id AND s.transaction_id = :transaction_id
         AND NOT EXISTS (
             SELECT 1 FROM v_received_outputs ro
             WHERE ro.account_id = :account_id AND ro.transaction_id = s.transaction_id
             AND ro.pool = s.output_pool AND ro.output_index = s.output_index
         )",
        named_params![":account_id": account_id, ":transaction_id": transaction_id],
        |row| row.get(0),
    )?;
    Ok(zatoshis(value)?.into_u64())
}

/// Whether an active account's ledger records a spend in `txid`. Such a spend makes the account a
/// party to the transaction even before the output it consumes is recovered. A candidate ledger
/// is isolated from history.
#[cfg(feature = "transparent-inputs")]
pub(super) fn has_active_ledger_spend(
    conn: &rusqlite::Connection,
    account_id: i64,
    txid: &TxId,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events s
             JOIN tpir_active_accounts a ON a.account_id = s.account_id
             WHERE s.account_id = :account_id AND s.spending_txid = :txid
         )",
        named_params![":account_id": account_id, ":txid": txid.as_ref()],
        |row| row.get(0),
    )?)
}
