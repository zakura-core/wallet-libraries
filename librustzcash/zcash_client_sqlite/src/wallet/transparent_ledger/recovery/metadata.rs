//! Atomic, source-bound transaction assertions. Absence is never an asserted zero.
use super::*;
use zcash_client_backend::data_api::transparent_ledger::{
    TransactionMetadata, WholeTransactionFee,
};

/// Candidate assertions observed at the event's current placement. History's
/// `metadata_evidence` requires the same observation and additionally qualification;
/// `forget_reattributed_script` deletes metadata whose revision observes no event of the
/// account, at any placement. These remain
/// unqualified diagnostics and never grant financial authority.
pub(super) fn candidate_metadata(
    conn: &rusqlite::Connection,
    account: AccountRef,
    txid: TxId,
    mined_height: BlockHeight,
) -> Result<Option<TransactionMetadata>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT m.fee_state, m.fee_zat, m.input_count, m.shielded
         FROM tpir_transaction_metadata m
         WHERE m.account_id = :account AND m.txid = :txid AND m.mined_height = :height
         AND (EXISTS (SELECT 1 FROM tpir_receive_events e
              JOIN tpir_receive_observations o ON o.receive_id = e.id
              WHERE e.account_id = m.account_id AND e.txid = m.txid
              AND e.mined_height = m.mined_height AND o.revision_id = m.revision_id)
           OR EXISTS (SELECT 1 FROM tpir_spend_events e
              JOIN tpir_spend_observations o ON o.spend_id = e.id
              WHERE e.account_id = m.account_id AND e.spending_txid = m.txid
              AND e.mined_height = m.mined_height AND o.revision_id = m.revision_id))",
    )?;
    let mut rows = stmt.query(named_params![":account": account.0, ":txid": txid.as_ref(),
        ":height": u32::from(mined_height)])?;
    let mut result = None;
    while let Some(row) = rows.next()? {
        let state: i64 = row.get(0)?;
        let value: Option<i64> = row.get(1)?;
        let fee = match (state, value) {
            (0, Some(value)) => {
                WholeTransactionFee::Exact(Zatoshis::from_nonnegative_i64(value).map_err(|_| {
                    SqliteClientError::CorruptedData("invalid candidate transaction fee".into())
                })?)
            }
            (1, None) => WholeTransactionFee::Unknown,
            (2, None) => WholeTransactionFee::NotApplicable,
            _ => {
                return Err(SqliteClientError::CorruptedData(
                    "invalid candidate fee state".into(),
                ));
            }
        };
        let inputs: u32 = row.get(2)?;
        let shielded: i64 = row.get(3)?;
        if !matches!(shielded, 0 | 1) || (fee == WholeTransactionFee::NotApplicable && inputs != 0)
        {
            return Err(SqliteClientError::CorruptedData(
                "invalid candidate transaction metadata".into(),
            ));
        }
        let metadata = TransactionMetadata {
            fee,
            transparent_input_count: inputs,
            has_shielded_components: shielded == 1,
        };
        if result.is_some_and(|prior| prior != metadata) {
            return Err(SqliteClientError::CorruptedData(
                "conflicting candidate transaction metadata".into(),
            ));
        }
        result = Some(metadata);
    }
    Ok(result)
}

/// Records `metadata` asserted by revision `revision` for `txid` at `mined_height`. Nothing is
/// recorded for absent metadata, which asserts nothing.
///
/// Fee states persist as 0 (an exact fee, with its amount), 1 (unknown) and 2 (not applicable).
/// Metadata for the transaction must agree with what any revision already asserted, at the same
/// placement; a disagreement refuses the commit as an integrity failure.
pub(super) fn apply_metadata(
    conn: &rusqlite::Connection,
    account: AccountRef,
    revision: i64,
    txid: TxId,
    mined_height: BlockHeight,
    metadata: Option<TransactionMetadata>,
) -> Result<(), SqliteClientError> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    super::super::require_reader_version(conn, super::super::METADATA_READER_VERSION)?;
    let (fee_state, fee) = match metadata.fee {
        WholeTransactionFee::Exact(value) => (0, Some(value.into_u64() as i64)),
        WholeTransactionFee::Unknown => (1, None),
        WholeTransactionFee::NotApplicable => (2, None),
    };
    let params = named_params![":account": account.0, ":revision": revision, ":txid": txid.as_ref(),
        ":height": u32::from(mined_height), ":fee_state": fee_state, ":fee": fee,
        ":inputs": metadata.transparent_input_count, ":shielded": metadata.has_shielded_components];
    let conflicting: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_transaction_metadata WHERE txid = :txid
         AND (mined_height != :height OR fee_state != :fee_state OR fee_zat IS NOT :fee
              OR input_count != :inputs OR shielded != :shielded))",
        named_params![":txid": txid.as_ref(), ":height": u32::from(mined_height),
            ":fee_state": fee_state, ":fee": fee, ":inputs": metadata.transparent_input_count,
            ":shielded": metadata.has_shielded_components],
        |row| row.get(0),
    )?;
    if conflicting {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::TransactionMetadata(txid),
        )));
    }
    conn.execute(
        "INSERT INTO tpir_transaction_metadata
        (account_id, txid, revision_id, mined_height, fee_state, fee_zat, input_count, shielded)
        VALUES (:account, :txid, :revision, :height, :fee_state, :fee, :inputs, :shielded)
        ON CONFLICT DO NOTHING",
        params,
    )?;
    Ok(())
}
