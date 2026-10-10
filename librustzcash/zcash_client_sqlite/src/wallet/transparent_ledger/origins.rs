//! Projection origins: why each transparent output and spend exists in the wallet's projection.

#[cfg(feature = "transparent-inputs")]
use {
    crate::{TxRef, UtxoId, error::SqliteClientError},
    rusqlite::named_params,
    transparent::bundle::OutPoint,
};

/// A SQL condition admitting an output's existence as current evidence. A ledger-only output
/// whose receive was withdrawn or unplaced is retained to preserve its spend links and locks,
/// but cannot contribute value or authorize an input under either public or private policy.
/// Independent origins retain their existing semantics. Rows missing provenance are left in
/// the counted set so the balance provenance check still reports them as corrupted data.
pub(crate) fn output_observation_condition(output: &str) -> String {
    format!(
        "NOT EXISTS (
             SELECT 1 FROM tpir_output_origins oo WHERE oo.output_id = {output}.id AND oo.origin = 2
         ) OR EXISTS (
             SELECT 1 FROM tpir_output_origins oo WHERE oo.output_id = {output}.id AND oo.origin != 2
         ) OR EXISTS (
             SELECT 1 FROM tpir_receive_events re
             JOIN transactions rt ON rt.txid = re.txid
             WHERE rt.id_tx = {output}.transaction_id AND re.output_index = {output}.output_index
             AND re.account_id = {output}.account_id AND re.mined_height IS NOT NULL
         )"
    )
}

/// Why a transparent output or spend exists in the wallet's projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "transparent-inputs"), allow(dead_code))]
pub(crate) enum ProjectionOrigin {
    /// Written by public discovery, or present before the ledger schema existed.
    LegacyPublic,
    /// Written by local transaction construction.
    LocalConstruction,
    /// Projected from an active account's private ledger.
    LedgerEvent,
}

impl ProjectionOrigin {
    #[cfg_attr(not(feature = "transparent-inputs"), allow(dead_code))]
    fn code(self) -> i64 {
        match self {
            Self::LegacyPublic => 0,
            Self::LocalConstruction => 1,
            Self::LedgerEvent => 2,
        }
    }
}

/// Records `origin` for a transparent output. Idempotent.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn record_output_origin(
    conn: &rusqlite::Connection,
    output: UtxoId,
    origin: ProjectionOrigin,
) -> Result<(), SqliteClientError> {
    conn.prepare_cached(
        "INSERT INTO tpir_output_origins (output_id, origin)
         VALUES (:output_id, :origin)
         ON CONFLICT (output_id, origin) DO NOTHING",
    )?
    .execute(named_params![":output_id": output.0, ":origin": origin.code()])?;
    // Local creation evidence may already exist, recorded by an outbox before the transaction
    // was projected; the record then has a local origin whatever path projected it.
    conn.prepare_cached(
        "INSERT INTO tpir_output_origins (output_id, origin)
         SELECT o.id, 1
         FROM transparent_received_outputs o
         JOIN transactions t ON t.id_tx = o.transaction_id
         WHERE o.id = :output_id
         AND (t.created IS NOT NULL OR t.target_height IS NOT NULL)
         ON CONFLICT (output_id, origin) DO NOTHING",
    )?
    .execute(named_params![":output_id": output.0])?;
    Ok(())
}

/// Records `origin` for the spend of `outpoint` by `spent_in_tx`, whether or not the spent
/// output is known yet. Idempotent.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn record_spend_origin(
    conn: &rusqlite::Connection,
    spent_in_tx: TxRef,
    outpoint: &OutPoint,
    origin: ProjectionOrigin,
) -> Result<(), SqliteClientError> {
    conn.prepare_cached(
        "INSERT INTO tpir_spend_origins (
             spending_transaction_id, prevout_txid, prevout_output_index, origin
         )
         VALUES (:spent_in_tx, :prevout_txid, :prevout_idx, :origin)
         ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index, origin)
         DO NOTHING",
    )?
    .execute(named_params![
        ":spent_in_tx": spent_in_tx.0,
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
        ":origin": origin.code(),
    ])?;
    conn.prepare_cached(
        "INSERT INTO tpir_spend_origins (
             spending_transaction_id, prevout_txid, prevout_output_index, origin
         )
         SELECT id_tx, :prevout_txid, :prevout_idx, 1
         FROM transactions
         WHERE id_tx = :spent_in_tx
         AND (created IS NOT NULL OR target_height IS NOT NULL)
         ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index, origin)
         DO NOTHING",
    )?
    .execute(named_params![
        ":spent_in_tx": spent_in_tx.0,
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
    ])?;
    Ok(())
}

/// Adds local origins to the transparent records already projected for `txid`, when local
/// creation evidence is recorded after projection.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn record_local_origins_for_tx(
    conn: &rusqlite::Connection,
    txid: &[u8],
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO tpir_output_origins (output_id, origin)
         SELECT o.id, 1
         FROM transparent_received_outputs o
         JOIN transactions t ON t.id_tx = o.transaction_id
         WHERE t.txid = :txid
         ON CONFLICT (output_id, origin) DO NOTHING",
        named_params![":txid": txid],
    )?;
    conn.execute(
        "INSERT INTO tpir_spend_origins (
             spending_transaction_id, prevout_txid, prevout_output_index, origin
         )
         SELECT so.spending_transaction_id, so.prevout_txid, so.prevout_output_index, 1
         FROM tpir_spend_origins so
         JOIN transactions t ON t.id_tx = so.spending_transaction_id
         WHERE t.txid = :txid
         ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index, origin)
         DO NOTHING",
        named_params![":txid": txid],
    )?;
    Ok(())
}
