//! Removes abandoned feature state from databases already carrying the old migration IDs.
use super::{
    one_time_ivk_discovery, v_transactions_legacy_projection, v_tx_outputs_transparent_addresses,
};
use crate::wallet::init::WalletMigrationError;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

/// Identifies the cutover independently of the earlier published schema.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x2eed2da7_2176_4d72_9461_c9ae27491b0a);
pub(super) struct Migration;

/// `v_transactions` with disputed private receipts left out of what a transaction received.
const VIEW_TRANSACTIONS: &str = "
CREATE VIEW v_transactions AS
WITH
notes AS (
    -- Outputs received in this transaction
    SELECT ro.account_id              AS account_id,
           ro.transaction_id          AS transaction_id,
           ro.pool                    AS pool,
           id_within_pool_table,
           ro.value                   AS value,
           ro.value                   AS received_value,
           0                          AS spent_value,
           0                          AS spent_note_count,
           CASE
                WHEN ro.is_change THEN 1
                ELSE 0
           END AS change_note_count,
           CASE
                WHEN ro.is_change THEN 0
                ELSE 1
           END AS received_count,
           CASE
             WHEN (ro.memo IS NULL OR ro.memo = X'F6')
               THEN 0
             ELSE 1
           END AS memo_present,
           -- The wallet cannot receive transparent outputs in shielding transactions.
           CASE
             WHEN ro.pool = 0
               THEN 1
             ELSE 0
           END AS does_not_match_shielding
    -- A private receipt whose transaction label raw bytes disproved is not received in it.
    FROM (SELECT * FROM v_received_outputs
          WHERE NOT (pool = 4 AND id_within_pool_table IN
              (SELECT note_id FROM ironwood_one_time_disputed_receipts))) ro
    UNION
    -- Outputs spent in this transaction
    SELECT ro.account_id              AS account_id,
           ros.transaction_id         AS transaction_id,
           ro.pool                    AS pool,
           id_within_pool_table,
           -ro.value                  AS value,
           0                          AS received_value,
           ro.value                   AS spent_value,
           1                          AS spent_note_count,
           0                          AS change_note_count,
           0                          AS received_count,
           0                          AS memo_present,
           -- The wallet cannot spend shielded outputs in shielding transactions.
           CASE
             WHEN ro.pool != 0
               THEN 1
             ELSE 0
           END AS does_not_match_shielding
    FROM v_received_outputs ro
    JOIN v_received_output_spends ros
         ON ros.pool = ro.pool
         AND ros.received_output_id = ro.id_within_pool_table
),
-- What each account spent and received in each pool, per transaction. A pool the account
-- received value in but spent nothing from is a pool that value crossed into from
-- elsewhere, which is what `pool_crossings` below is built on.
notes_by_pool AS (
    SELECT account_id, transaction_id, pool,
           SUM(spent_note_count)                   AS spent_note_count,
           SUM(received_count + change_note_count) AS received_note_count,
           SUM(received_value)                     AS received_value
    FROM notes
    GROUP BY account_id, transaction_id, pool
),
-- Obtain a count of the notes that the wallet created in each transaction,
-- not counting change notes.
sent_note_counts AS (
    SELECT sent_notes.from_account_id     AS account_id,
           sent_notes.transaction_id      AS transaction_id,
           COUNT(DISTINCT sent_notes.id)  AS sent_notes,
           SUM(
             CASE
               WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                 THEN 0
               ELSE 1
             END
           ) AS memo_count
    FROM sent_notes
    LEFT JOIN v_received_outputs ro ON sent_notes.id = ro.sent_note_id
    WHERE COALESCE(ro.is_change, 0) = 0
    -- Group by the sending account. A bare `account_id` here would resolve to the joined
    -- `ro.account_id`, splitting one sender's notes into a group per receiving account.
    GROUP BY sent_notes.from_account_id, sent_notes.transaction_id
),
-- Identifies the transactions that are wallet-internal transfers moving an account's own
-- funds between shielded pools, and reports the value that crossed. `crossing_value` is
-- non-NULL exactly for such a transaction, so it carries both the classification and the
-- amount; see the `pool_crossing_value` column below.
pool_crossings AS (
    SELECT notes_by_pool.account_id     AS account_id,
           notes_by_pool.transaction_id AS transaction_id,
           CASE WHEN (
                -- Every note spent and every output received by the wallet is shielded.
                SUM(CASE WHEN notes_by_pool.pool = 0 THEN notes_by_pool.spent_note_count + notes_by_pool.received_note_count ELSE 0 END) = 0
                -- The transaction spends at least one of the account's notes.
                AND SUM(notes_by_pool.spent_note_count) > 0
                -- At least one output was received in a pool the account spent nothing
                -- from, so value crossed between pools.
                AND SUM(CASE WHEN notes_by_pool.spent_note_count = 0 THEN notes_by_pool.received_note_count ELSE 0 END) > 0
                -- We do not know about any external outputs of the transaction.
                AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
           )
           -- The total value received in the pools the account did not spend from. The
           -- condition above guarantees at least one such output, so when this branch is
           -- taken the sum is never NULL.
           THEN SUM(CASE WHEN notes_by_pool.spent_note_count = 0 THEN notes_by_pool.received_value ELSE 0 END)
           END AS crossing_value
    FROM notes_by_pool
    LEFT JOIN sent_note_counts
         ON sent_note_counts.account_id = notes_by_pool.account_id
         AND sent_note_counts.transaction_id = notes_by_pool.transaction_id
    GROUP BY notes_by_pool.account_id, notes_by_pool.transaction_id
),
blocks_max_height AS (
    SELECT MAX(blocks.height) AS max_height FROM blocks
)
SELECT accounts.uuid                AS account_uuid,
       transactions.mined_height    AS mined_height,
       transactions.txid            AS txid,
       transactions.tx_index        AS tx_index,
       COALESCE(transactions.expiry_height, (SELECT history_expiry_height
        FROM ironwood_enhance_routing WHERE transaction_id = transactions.id_tx AND route = 0))
           AS expiry_height,
       transactions.raw             AS raw,
       SUM(notes.value)             AS account_balance_delta,
       SUM(notes.spent_value)       AS total_spent,
       SUM(notes.received_value)    AS total_received,
       transactions.fee             AS fee_paid,
       SUM(notes.change_note_count) > 0  AS has_change,
       MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
       SUM(notes.received_count)         AS received_note_count,
       SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
       blocks.time                       AS block_time,
       (
            transactions.mined_height IS NULL
            AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
       ) AS expired_unmined,
       SUM(notes.spent_note_count) AS spent_note_count,
       (
            -- All of the wallet-spent and wallet-received notes are consistent with a
            -- shielding transaction.
            SUM(notes.does_not_match_shielding) = 0
            -- The transaction contains at least one wallet-spent output.
            AND SUM(notes.spent_note_count) > 0
            -- The transaction contains at least one wallet-received note.
            AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
            -- We do not know about any external outputs of the transaction.
            AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
       ) AS is_shielding,
       -- The value that crossed pools, when this transaction is a wallet-internal transfer
       -- between shielded pools; NULL when it is not such a transfer. A transaction is one
       -- exactly when this column is non-NULL.
       pool_crossings.crossing_value AS pool_crossing_value,
       transactions.trust_status,
       transactions.zip318_kind
FROM notes
JOIN accounts ON accounts.id = notes.account_id
JOIN transactions ON transactions.id_tx = notes.transaction_id
LEFT JOIN blocks_max_height
LEFT JOIN blocks ON blocks.height = transactions.mined_height
LEFT JOIN sent_note_counts
     ON sent_note_counts.account_id = notes.account_id
     AND sent_note_counts.transaction_id = notes.transaction_id
LEFT JOIN pool_crossings
     ON pool_crossings.account_id = notes.account_id
     AND pool_crossings.transaction_id = notes.transaction_id
GROUP BY notes.account_id, notes.transaction_id
";

/// `v_tx_outputs` with disputed private receipts left out of a transaction's outputs.
const VIEW_TX_OUTPUTS: &str = "
CREATE VIEW v_tx_outputs AS
WITH unioned AS (
    -- select all outputs received by the wallet
    SELECT t.id_tx                      AS transaction_id,
           t.txid                       AS txid,
           t.mined_height               AS mined_height,
           IFNULL(t.trust_status, 0)    AS trust_status,
           ro.pool                      AS output_pool,
           ro.output_index              AS output_index,
           from_account.uuid            AS from_account_uuid,
           to_account.uuid              AS to_account_uuid,
           -- for a transparent output, the address at which it was received is
           -- the transparent receiver itself, not a unified address containing it
           CASE ro.pool
                WHEN 0 THEN a.cached_transparent_receiver_address
                ELSE a.address
           END                          AS to_address,
           0                            AS is_sent_row,
           a.diversifier_index_be       AS diversifier_index_be,
           ro.value                     AS value,
           ro.is_change                 AS is_change,
           ro.memo                      AS memo,
           a.key_scope                  AS recipient_key_scope
    -- A private receipt whose transaction label raw bytes disproved is not an output of it.
    FROM (SELECT * FROM v_received_outputs
          WHERE NOT (pool = 4 AND id_within_pool_table IN
              (SELECT note_id FROM ironwood_one_time_disputed_receipts))) ro
    JOIN transactions t
        ON t.id_tx = ro.transaction_id
    LEFT JOIN addresses a ON a.id = ro.address_id
    -- join to the sent_notes table to obtain `from_account_id`
    LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
    -- join on the accounts table to obtain account UUIDs
    LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
    LEFT JOIN accounts to_account ON to_account.id = ro.account_id
    UNION ALL
    -- select all outputs sent by the wallet
    SELECT t.id_tx                      AS transaction_id,
           t.txid                       AS txid,
           t.mined_height               AS mined_height,
           IFNULL(t.trust_status, 0)    AS trust_status,
           sent_notes.output_pool       AS output_pool,
           sent_notes.output_index      AS output_index,
           from_account.uuid            AS from_account_uuid,
           NULL                         AS to_account_uuid,
           sent_notes.to_address        AS to_address,
           1                            AS is_sent_row,
           NULL                         AS diversifier_index_be,
           sent_notes.value             AS value,
           0                            AS is_change,
           sent_notes.memo              AS memo,
           NULL                         AS recipient_key_scope
    FROM sent_notes
    JOIN transactions t
        ON t.id_tx = sent_notes.transaction_id
    LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
    -- join on the accounts table to obtain account UUIDs
    LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
)
-- merge duplicate rows while retaining maximum information
SELECT
    transaction_id,
    MAX(txid)                   AS txid,
    MAX(mined_height)           AS tx_mined_height,
    MIN(trust_status)           AS tx_trust_status,
    output_pool,
    output_index,
    MAX(from_account_uuid)      AS from_account_uuid,
    MAX(to_account_uuid)        AS to_account_uuid,
    -- the recipient address recorded when the wallet created the output is
    -- authoritative; the receiving address is reported only for outputs the
    -- wallet did not create
    COALESCE(
        MAX(CASE WHEN is_sent_row THEN to_address END),
        MAX(CASE WHEN NOT is_sent_row THEN to_address END)
    )                           AS to_address,
    MAX(value)                  AS value,
    MAX(is_change)              AS is_change,
    MAX(memo)                   AS memo,
    MAX(recipient_key_scope)    AS recipient_key_scope
FROM unioned
GROUP BY transaction_id, output_pool, output_index";
impl schemerz::Migration<Uuid> for Migration {
    /// Returns the unique cutover identifier.
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }
    /// Runs after the registry, ordinary note ownership and spend journal exist, and after
    /// the history views it replaces.
    fn dependencies(&self) -> HashSet<Uuid> {
        [
            one_time_ivk_discovery::MIGRATION_ID,
            v_transactions_legacy_projection::MIGRATION_ID,
            v_tx_outputs_transparent_addresses::MIGRATION_ID,
        ]
        .into_iter()
        .collect()
    }
    /// Describes the stored-state change for migration diagnostics.
    fn description(&self) -> &'static str {
        "Replace unlaunched one-time discovery state with the PIR queue."
    }
}
impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;
    /// Existing wallets discard only obsolete progress, then every wallet converges on one schema.
    fn up(&self, tx: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ironwood_one_time_recovery')",
            [], |r| r.get(0))?;
        if !current {
            one_time_ivk_discovery::Migration.up(tx)?;
        }
        tx.execute_batch(
            "ALTER TABLE ironwood_one_time_recovery ADD COLUMN receive_end BLOB NOT NULL
                DEFAULT X'0000000000000000' CHECK (length(receive_end) = 8);
             DROP INDEX IF EXISTS idx_ironwood_one_time_keys_account_receiver;
             ALTER TABLE ironwood_one_time_keys DROP COLUMN registered_at;
             CREATE TABLE ironwood_one_time_operation_receipts (
                operation_id INTEGER NOT NULL REFERENCES ironwood_one_time_operations(id) ON DELETE CASCADE,
                txid BLOB NOT NULL CHECK (length(txid) = 32),
                PRIMARY KEY (operation_id, txid)
             );
             CREATE TABLE ironwood_one_time_disputed_receipts (
                note_id INTEGER PRIMARY KEY REFERENCES ironwood_received_notes(id) ON DELETE CASCADE
             );
             CREATE TABLE ironwood_one_time_unchecked_raw (
                transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id_tx) ON DELETE CASCADE
             );
             DROP VIEW v_transactions;
             DROP VIEW v_tx_outputs;",
        )?;
        tx.execute_batch(VIEW_TRANSACTIONS)?;
        tx.execute_batch(VIEW_TX_OUTPUTS)?;
        Ok(())
    }
    /// Old discovery state cannot be reconstructed from the replacement queue.
    fn down(&self, _: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    /// The terminal migration keeps the normal wallet migration graph valid.
    #[test]
    fn migrate() {
        super::super::tests::test_migrate(&[super::MIGRATION_ID]);
    }
}
