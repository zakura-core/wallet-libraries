use super::*;
use rusqlite::OptionalExtension as _;

/// Clears candidate state above `floor`, the height above which a truncation or rewind may
/// replace blocks. Callers pass the rescan floor, which can lie below the retained checkpoint.
///
/// Placements above the floor are cleared; the events stay and a later commit can place them
/// again. Pages opened for a later target are removed. Coverage anchored above the floor is
/// clipped to it and re-anchored at the floor block: the revision agreed with the old chain at
/// its anchor, and that chain equals the surviving one through `floor`. Without a local hash
/// for the floor block the coverage is deleted rather than given an invented anchor. Candidate
/// windows never shrink.
pub(crate) fn truncate(
    conn: &rusqlite::Connection,
    floor: BlockHeight,
) -> Result<(), SqliteClientError> {
    // A build that cannot interpret the wallet's ledger state cannot rewind it either: it would
    // leave whatever a newer reader maintains anchored on replaced blocks. Refusing fails the
    // whole rewind.
    super::super::durable_policy(conn)?;
    let height = u32::from(floor);
    conn.execute(
        "DELETE FROM tpir_transaction_metadata WHERE mined_height > :height",
        named_params![":height": height],
    )?;
    conn.execute(
        "UPDATE tpir_receive_events SET mined_height = NULL WHERE mined_height > :height",
        named_params![":height": height],
    )?;
    conn.execute(
        "UPDATE tpir_spend_events SET mined_height = NULL WHERE mined_height > :height",
        named_params![":height": height],
    )?;
    conn.execute(
        "DELETE FROM tpir_pending_pages WHERE target_height > :height",
        named_params![":height": height],
    )?;
    let retained_hash: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hash FROM blocks WHERE height = :height",
            named_params![":height": height],
            |row| row.get(0),
        )
        .optional()?;
    match retained_hash {
        Some(hash) => {
            conn.execute(
                "DELETE FROM tpir_coverage
                 WHERE anchor_height > :height AND from_height > :height",
                named_params![":height": height],
            )?;
            conn.execute(
                "UPDATE tpir_coverage
                 SET through_height = MIN(through_height, :height),
                     anchor_height = :height,
                     anchor_hash = :hash
                 WHERE anchor_height > :height",
                named_params![":height": height, ":hash": hash],
            )?;
        }
        None => {
            conn.execute(
                "DELETE FROM tpir_coverage WHERE anchor_height > :height",
                named_params![":height": height],
            )?;
        }
    }
    Ok(())
}

/// Removes pending pages on a policy transition. A page is work started under the policy that
/// authorized it; after a transition it can be neither completed nor resumed.
pub(crate) fn clear_pending_pages(conn: &rusqlite::Connection) -> Result<(), SqliteClientError> {
    conn.execute("DELETE FROM tpir_pending_pages", [])?;
    Ok(())
}

/// Forgets `from_account`'s candidate state for a script that has just been re-attributed to
/// another account. The receiving account starts without coverage for it.
///
/// Runs inside address generation, which migrations also call; it is a no-op before the
/// recovery tables exist.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn forget_reattributed_script(
    conn: &rusqlite::Connection,
    from_account: AccountRef,
    address: &TransparentAddress,
) -> Result<(), SqliteClientError> {
    let has_tables: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tpir_coverage'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_tables {
        return Ok(());
    }
    // Only a build that interprets the wallet's ledger state may change it.
    durable_policy(conn)?;
    let params = named_params![":account_id": from_account.0, ":script": script_bytes(address)];
    conn.execute(
        "DELETE FROM tpir_receive_events WHERE account_id = :account_id AND script = :script",
        params,
    )?;
    conn.execute(
        "DELETE FROM tpir_spend_events
         WHERE account_id = :account_id AND prevout_script = :script",
        params,
    )?;
    conn.execute(
        "DELETE FROM tpir_coverage WHERE account_id = :account_id AND script = :script",
        params,
    )?;
    conn.execute(
        "DELETE FROM tpir_pending_pages WHERE account_id = :account_id AND EXISTS (
            SELECT 1 FROM tpir_pending_page_scripts s WHERE s.page_id = tpir_pending_pages.id AND s.script = :script
        )", params,
    )?;
    // Address generation also runs while older migrations are being applied.
    let has_metadata: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table'
         AND name = 'tpir_transaction_metadata')",
        [],
        |row| row.get(0),
    )?;
    if has_metadata {
        conn.execute(
            "DELETE FROM tpir_transaction_metadata AS m WHERE account_id = :account_id
             AND NOT EXISTS (
                SELECT 1 FROM tpir_receive_events e JOIN tpir_receive_observations o ON o.receive_id = e.id
                WHERE e.account_id = m.account_id AND e.txid = m.txid AND o.revision_id = m.revision_id
             ) AND NOT EXISTS (
                SELECT 1 FROM tpir_spend_events e JOIN tpir_spend_observations o ON o.spend_id = e.id
                WHERE e.account_id = m.account_id AND e.spending_txid = m.txid AND o.revision_id = m.revision_id
             )", named_params![":account_id": from_account.0],
        )?;
    }
    Ok(())
}

/// Removes everything the ledger alone contributed to the wallet, and the recovery state that
/// would project it again. See `TransparentLedgerWrite::forget_transparent_ledger`.
///
/// Requires `Public` on the handle and durably: public discovery rebuilds what this removes.
/// Revision lineage, qualification, quarantine, candidate windows, and shared derivations stay:
/// they constrain what a later return to `PrivateRequired` may accept, and none of them is a
/// wallet fact.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn forget(
    conn: &rusqlite::Connection,
    configured: Option<TransparentLedgerMode>,
) -> Result<
    zcash_client_backend::data_api::transparent_ledger::ForgottenTransparentLedger,
    SqliteClientError,
> {
    use zcash_client_backend::data_api::transparent_ledger::ForgottenTransparentLedger;

    // Resolving the mode also refuses a wallet that requires a newer reader.
    let public = |conn: &rusqlite::Connection| -> Result<(), SqliteClientError> {
        if resolve_mode(conn, configured)?.retains_public_authority() {
            Ok(())
        } else {
            Err(SqliteClientError::PublicTransparentDiscoveryForbidden)
        }
    };
    // Callers forget at every opportunity; a wallet without ledger facts, as
    // every wallet that never recovered privately, is only read. Under
    // `Public` nothing can add facts, so the answer cannot go stale.
    let has_facts = super::super::with_read_snapshot(conn, |conn| {
        public(conn)?;
        Ok(conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM tpir_receive_events)
                 OR EXISTS (SELECT 1 FROM tpir_spend_events)
                 OR EXISTS (SELECT 1 FROM tpir_coverage)
                 OR EXISTS (SELECT 1 FROM tpir_pending_pages)
                 OR EXISTS (SELECT 1 FROM tpir_transaction_metadata)
                 OR EXISTS (SELECT 1 FROM tpir_active_accounts)
                 OR EXISTS (SELECT 1 FROM tpir_output_origins WHERE origin = 2)
                 OR EXISTS (SELECT 1 FROM tpir_spend_origins WHERE origin = 2)",
            [],
            |row| row.get::<_, bool>(0),
        )?)
    })?;
    if !has_facts {
        return Ok(ForgottenTransparentLedger::default());
    }

    super::commit::atomically(conn, |conn| {
        public(conn)?;

        // Every transaction a ledger fact names, collected before those facts are removed.
        let touched: Vec<i64> = conn
            .prepare(
                "SELECT t.id_tx FROM transactions t WHERE t.txid IN (
                     SELECT txid FROM tpir_receive_events
                     UNION SELECT spending_txid FROM tpir_spend_events
                     UNION SELECT txid FROM tpir_transaction_metadata
                 )
                 UNION SELECT spending_transaction_id FROM tpir_spend_origins WHERE origin = 2
                 UNION SELECT o.transaction_id FROM tpir_output_origins oo
                     JOIN transparent_received_outputs o ON o.id = oo.output_id
                     WHERE oo.origin = 2",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;

        // A spend whose only origin is the ledger, for spending transaction `{tx}` and the
        // prevout `{prevout_txid}`:`{prevout_index}`.
        let ledger_only_spend = |tx: &str, prevout_txid: &str, prevout_index: &str| {
            format!(
                "EXISTS (
                     SELECT 1 FROM tpir_spend_origins so
                     WHERE so.spending_transaction_id = {tx}
                     AND so.prevout_txid = {prevout_txid}
                     AND so.prevout_output_index = {prevout_index}
                     AND so.origin = 2
                 ) AND NOT EXISTS (
                     SELECT 1 FROM tpir_spend_origins so
                     WHERE so.spending_transaction_id = {tx}
                     AND so.prevout_txid = {prevout_txid}
                     AND so.prevout_output_index = {prevout_index}
                     AND so.origin != 2
                 )"
            )
        };
        let ledger_only_link = ledger_only_spend("s.transaction_id", "ot.txid", "o.output_index");

        // Outputs that keep another origin and lose a spend: public discovery must look for
        // their real spend again, because a resolved spend stops every later search.
        let requeue: Vec<(String, i64, i64)> = conn
            .prepare(&format!(
                "SELECT DISTINCT o.address, o.transaction_id, o.output_index
                 FROM transparent_received_output_spends s
                 JOIN transparent_received_outputs o ON o.id = s.transparent_received_output_id
                 JOIN transactions ot ON ot.id_tx = o.transaction_id
                 WHERE {ledger_only_link}
                 AND EXISTS (
                     SELECT 1 FROM tpir_output_origins oo
                     WHERE oo.output_id = o.id AND oo.origin != 2
                 )"
            ))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;

        let mut spends = conn.execute(
            &format!(
                "DELETE FROM transparent_received_output_spends
                 WHERE EXISTS (
                     SELECT 1 FROM transparent_received_output_spends s
                     JOIN transparent_received_outputs o
                         ON o.id = s.transparent_received_output_id
                     JOIN transactions ot ON ot.id_tx = o.transaction_id
                     WHERE s.rowid = transparent_received_output_spends.rowid
                     AND {ledger_only_link}
                 )"
            ),
            [],
        )?;
        spends += conn.execute(
            &format!(
                "DELETE FROM transparent_spend_map
                 WHERE {}",
                ledger_only_spend(
                    "transparent_spend_map.spending_transaction_id",
                    "transparent_spend_map.prevout_txid",
                    "transparent_spend_map.prevout_output_index",
                )
            ),
            [],
        )?;
        // Every remaining spend has another origin, which stays its provenance.
        conn.execute("DELETE FROM tpir_spend_origins WHERE origin = 2", [])?;

        // An output with another origin keeps that evidence alone.
        conn.execute(
            "DELETE FROM tpir_output_origins
             WHERE origin = 2 AND EXISTS (
                 SELECT 1 FROM tpir_output_origins other
                 WHERE other.output_id = tpir_output_origins.output_id AND other.origin != 2
             )",
            [],
        )?;

        // Every output left with the ledger origin is ledger-only. Nothing searches for its
        // spend any longer.
        let ledger_only_output = "EXISTS (
             SELECT 1 FROM tpir_output_origins oo WHERE oo.output_id = o.id AND oo.origin = 2
         )";
        conn.execute(
            &format!(
                "DELETE FROM transparent_spend_search_queue
                 WHERE EXISTS (
                     SELECT 1 FROM transparent_received_outputs o
                     WHERE o.transaction_id = transparent_spend_search_queue.transaction_id
                     AND o.output_index = transparent_spend_search_queue.output_index
                     AND {ledger_only_output}
                 )"
            ),
            [],
        )?;
        // Deleting a locked output would discard its reservation, and deleting one that a spend
        // from another origin refers to would cascade that spend. Those stay; without a placed
        // receive, financial queries exclude them.
        let outputs = conn.execute(
            &format!(
                "DELETE FROM transparent_received_outputs
                 WHERE id IN (
                     SELECT o.id FROM transparent_received_outputs o
                     WHERE {ledger_only_output}
                     AND o.lock_owner IS NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM transparent_received_output_spends s
                         WHERE s.transparent_received_output_id = o.id
                     )
                 )"
            ),
            [],
        )?;
        let retained_outputs: usize = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM transparent_received_outputs o WHERE {ledger_only_output}"
            ),
            [],
            |row| row.get::<_, i64>(0),
        )? as usize;

        let mut queue = conn.prepare_cached(
            "INSERT INTO transparent_spend_search_queue (address, transaction_id, output_index)
             VALUES (:address, :transaction_id, :output_index)
             ON CONFLICT (transaction_id, output_index) DO NOTHING",
        )?;
        for (address, transaction_id, output_index) in &requeue {
            queue.execute(named_params![
                ":address": address,
                ":transaction_id": transaction_id,
                ":output_index": output_index,
            ])?;
        }

        // Recovery state. Observations and pending page scripts cascade.
        let mut events = conn.execute("DELETE FROM tpir_receive_events", [])?;
        events += conn.execute("DELETE FROM tpir_spend_events", [])?;
        conn.execute("DELETE FROM tpir_coverage", [])?;
        conn.execute("DELETE FROM tpir_pending_pages", [])?;
        conn.execute("DELETE FROM tpir_transaction_metadata", [])?;
        // Already empty under `Public`; a ledger-only row must never be counted as active.
        conn.execute("DELETE FROM tpir_active_accounts", [])?;

        // Transactions the ledger named that no wallet evidence supports any longer. Their
        // retrieval intents go with them; details work and display facts cascade.
        let mut orphaned = conn.prepare_cached(
            "SELECT txid FROM transactions
             WHERE id_tx = :tx
             AND raw IS NULL AND created IS NULL AND target_height IS NULL
             AND NOT EXISTS (SELECT 1 FROM v_received_outputs WHERE transaction_id = :tx)
             AND NOT EXISTS (SELECT 1 FROM v_received_output_spends WHERE transaction_id = :tx)
             AND NOT EXISTS (
                 SELECT 1 FROM transparent_spend_map WHERE spending_transaction_id = :tx
             )
             AND NOT EXISTS (SELECT 1 FROM sent_notes WHERE transaction_id = :tx)",
        )?;
        let mut delete_intent =
            conn.prepare_cached("DELETE FROM tx_retrieval_queue WHERE txid = :txid")?;
        let mut delete_tx = conn.prepare_cached("DELETE FROM transactions WHERE id_tx = :tx")?;
        let mut transactions = 0;
        for tx in touched {
            let txid: Option<Vec<u8>> = orphaned
                .query_row(named_params![":tx": tx], |row| row.get(0))
                .optional()?;
            if let Some(txid) = txid {
                delete_intent.execute(named_params![":txid": txid])?;
                transactions += delete_tx.execute(named_params![":tx": tx])?;
            }
        }

        if retained_outputs > 0 {
            // A ledger-only row without a placed receive is excluded only by readers that honor
            // withdrawn receives.
            super::super::require_reader_version(conn, super::super::ACTIVATION_READER_VERSION)?;
        }

        Ok(ForgottenTransparentLedger {
            spends,
            outputs,
            retained_outputs,
            transactions,
            events,
        })
    })
}
