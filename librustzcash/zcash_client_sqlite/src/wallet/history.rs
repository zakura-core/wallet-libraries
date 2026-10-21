//! Account-scoped transaction summaries for activity lists.
//!
//! Summaries use the accounting semantics of `v_transactions` without selecting raw transaction
//! payloads. They are local history metadata, not proof of complete discovery or spendability:
//! combine them with `transaction_history_details` and the ledger authority APIs for those claims.

use rusqlite::{Connection, named_params};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::{AccountUuid, error::SqliteClientError};

/// One account's recorded effects in a transaction, without its raw payload.
///
/// A net movement includes change and fees; it is not a payment amount. Summary fields describe
/// stored wallet evidence and may change as discovery progresses. Unknown timestamps, expiry,
/// and fees remain `None`. Counts and classifications have the same semantics as `v_transactions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSummary {
    /// Database-local transaction identifier, useful for pairing ordered multi-step operations.
    /// Never expose this identifier to users or compare it across restored databases.
    pub transaction_id: i64,
    /// Consensus transaction identifier, in its canonical byte order.
    pub txid: TxId,
    /// Mined height, or `None` while unmined.
    pub mined_height: Option<BlockHeight>,
    /// Transaction's index within its mined block, if known.
    pub tx_index: Option<u32>,
    /// Recorded expiry, including private history metadata's expiry fallback.
    pub expiry_height: Option<BlockHeight>,
    /// Received value minus spent value, in zatoshis, including fees.
    pub account_balance_delta: i64,
    /// Total recorded owned input value, in zatoshis.
    pub total_spent: u64,
    /// Total recorded owned output value, including change, in zatoshis.
    pub total_received: u64,
    /// Whole transaction fee in zatoshis, when recorded. This is not an allocated fee share.
    pub fee: Option<u64>,
    /// Whether any received output was marked as change.
    pub has_change: bool,
    /// Count of recorded sent outputs, excluding marked change.
    pub sent_note_count: u32,
    /// Count of recorded received outputs, excluding marked change.
    pub received_note_count: u32,
    /// Count of non-empty recorded memos.
    pub memo_count: u32,
    /// Mined block's Unix timestamp, if its block is known locally.
    pub block_time: Option<u64>,
    /// Whether an unmined transaction has a recorded expiry at or below the highest local block.
    /// Missing or zero expiry does not establish expiration.
    pub expired_unmined: bool,
    /// Count of recorded owned inputs.
    pub spent_note_count: u32,
    /// Whether the recorded effects meet the view's shielding classification.
    pub is_shielding: bool,
    /// Value crossing between the account's shielded pools, when the view establishes it.
    pub pool_crossing_value: Option<u64>,
    /// Recorded wallet trust marker; `None` when the marker has not been set.
    pub is_trusted: Option<bool>,
    /// Recorded local construction time, in SQLite's stored timestamp format.
    pub created: Option<String>,
    /// Construction time converted to Unix seconds, if parseable.
    pub created_time: Option<i64>,
    /// Whether the transaction spends a recorded version-2 Orchard note of any wallet account.
    /// This preserves the fact used to classify an Orchard-to-Ironwood operation.
    pub has_orchard_spend: bool,
}

pub(crate) fn transaction_summaries(
    conn: &Connection,
    account: AccountUuid,
) -> Result<Vec<TransactionSummary>, SqliteClientError> {
    let account = super::get_account_ref(conn, account)?;
    let mut statement = conn.prepare_cached(SUMMARY_QUERY)?;
    let rows = statement.query_map(named_params! {":account_id": account.0}, read_summary)?;
    rows.collect::<Result<_, _>>().map_err(Into::into)
}

pub(super) fn read_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransactionSummary> {
    Ok(TransactionSummary {
        transaction_id: row.get("transaction_id")?,
        txid: TxId::from_bytes(row.get("txid")?),
        mined_height: row
            .get::<_, Option<u32>>("mined_height")?
            .map(BlockHeight::from_u32),
        tx_index: row.get("tx_index")?,
        expiry_height: row
            .get::<_, Option<u32>>("expiry_height")?
            .map(BlockHeight::from_u32),
        account_balance_delta: row.get("account_balance_delta")?,
        total_spent: row.get("total_spent")?,
        total_received: row.get("total_received")?,
        fee: row.get("fee_paid")?,
        has_change: row.get("has_change")?,
        sent_note_count: row.get("sent_note_count")?,
        received_note_count: row.get("received_note_count")?,
        memo_count: row.get("memo_count")?,
        block_time: row.get("block_time")?,
        expired_unmined: row
            .get::<_, Option<bool>>("expired_unmined")?
            .unwrap_or(false),
        spent_note_count: row.get("spent_note_count")?,
        is_shielding: row.get("is_shielding")?,
        pool_crossing_value: row.get("pool_crossing_value")?,
        is_trusted: row.get("trust_status")?,
        created: row.get("created")?,
        created_time: row.get("created_time")?,
        has_orchard_spend: row.get("has_orchard_spend")?,
    })
}

// The account query and the schema contract expand the same accounting SQL. Only account
// predicates, payload projection, and non-accounting metadata differ. Migration SQL stays frozen.
macro_rules! history_sql {
    ($prefix:literal, $received_filter:literal, $spent_filter:literal,
     $sent_filter:literal, $raw:literal, $metadata:literal) => {
        concat!(
            $prefix,
            r#"WITH
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
              (SELECT note_id FROM ironwood_one_time_disputed_receipts))) ro"#,
            $received_filter,
            r#"
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
         AND ros.received_output_id = ro.id_within_pool_table"#,
            $spent_filter,
            r#"
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
    WHERE COALESCE(ro.is_change, 0) = 0"#,
            $sent_filter,
            r#"
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
"#,
            $raw,
            r#"       SUM(notes.value)             AS account_balance_delta,
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
       transactions.trust_status"#,
            $metadata,
            r#"
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
"#
        )
    };
}

pub(super) const VIEW_TRANSACTIONS: &str = history_sql!(
    "\nCREATE VIEW v_transactions AS\n",
    "",
    "",
    "",
    "       transactions.raw             AS raw,\n",
    ",\n       transactions.zip318_kind"
);

pub(crate) const SUMMARY_QUERY: &str = history_sql!(
    "",
    "\n    WHERE ro.account_id = :account_id",
    "\n    WHERE ro.account_id = :account_id",
    " AND sent_notes.from_account_id = :account_id",
    "",
    ",
       transactions.id_tx AS transaction_id,
       transactions.created,
       CAST(strftime('%s', transactions.created) AS INTEGER) AS created_time,
       EXISTS (
           SELECT 1 FROM orchard_received_note_spends s
           JOIN orchard_received_notes n ON n.id = s.orchard_received_note_id
           WHERE s.transaction_id = transactions.id_tx AND n.note_version = 2
       ) AS has_orchard_spend"
);

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};
    use zcash_client_backend::data_api::{Account as _, testing::TestBuilder};
    use zcash_primitives::block::BlockHash;

    use super::read_summary;
    use crate::{AccountUuid, error::SqliteClientError, testing::db::TestDbFactory};

    fn transaction(conn: &Connection, tag: u8) -> i64 {
        conn.execute(
            "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, 0)",
            [[tag; 32]],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn history_summaries_empty_and_unknown_accounts_in_every_feature_lane() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let db = st.wallet().db();
        assert!(
            db.transaction_history_summaries(st.test_account().unwrap().id())
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            db.transaction_history_summaries(AccountUuid::from_uuid(uuid::Uuid::nil())),
            Err(SqliteClientError::AccountUnknown)
        ));
    }

    #[test]
    fn history_summaries_preserve_pool_crossings_memos_and_private_expiry_without_raw() {
        // Local accounting fixtures under the real migrated schema. No raw transaction or
        // cryptographic note payload is required to summarize partially recovered history.
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let db = st.wallet().db();
        let conn = &db.conn;
        let account = st.test_account().unwrap().id();
        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?1",
                [account.expose_uuid().as_bytes()],
                |r| r.get(0),
            )
            .unwrap();
        let original = transaction(conn, 0xe0);
        let crossing = transaction(conn, 0xe1);
        let ironwood = transaction(conn, 0xe2);
        conn.execute("INSERT INTO sapling_received_notes (transaction_id, output_index, account_id, diversifier, value, rcm, is_change) VALUES (?1, 0, ?2, zeroblob(11), 500000, zeroblob(32), 0)", params![original, account_id]).unwrap();
        let sapling_note = conn.last_insert_rowid();
        conn.execute("INSERT INTO sapling_received_note_spends (sapling_received_note_id, transaction_id) VALUES (?1, ?2)", params![sapling_note, crossing]).unwrap();
        conn.execute("INSERT INTO orchard_received_notes (transaction_id, action_index, account_id, diversifier, value, rho, rseed, is_change, memo, note_version) VALUES (?1, 0, ?2, zeroblob(11), 490000, zeroblob(32), zeroblob(32), 1, X'01', 2)", params![crossing, account_id]).unwrap();
        let orchard_note = conn.last_insert_rowid();
        conn.execute("INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id) VALUES (?1, ?2)", params![orchard_note, ironwood]).unwrap();
        conn.execute("INSERT INTO ironwood_received_notes (transaction_id, action_index, account_id, diversifier, value, rho, rseed, is_change, memo, note_version) VALUES (?1, 0, ?2, zeroblob(11), 480000, zeroblob(32), zeroblob(32), 1, X'F6', 3)", params![ironwood, account_id]).unwrap();
        conn.execute("INSERT INTO ironwood_enhance_routing (transaction_id, route, history_expiry_height) VALUES (?1, 0, 2000000)", [ironwood]).unwrap();
        let actual = db.transaction_history_summaries(account).unwrap();
        let s = actual
            .iter()
            .find(|s| s.transaction_id == crossing)
            .unwrap();
        assert_eq!(
            (s.account_balance_delta, s.total_spent, s.total_received),
            (-10000, 500000, 490000)
        );
        assert_eq!(s.pool_crossing_value, Some(490000));
        assert_eq!(
            (
                s.spent_note_count,
                s.received_note_count,
                s.sent_note_count,
                s.memo_count
            ),
            (1, 0, 0, 1)
        );
        assert!(s.has_change);
        assert!(!s.is_shielding);
        assert!(!s.has_orchard_spend);
        assert_eq!(s.is_trusted, None);
        let i = actual
            .iter()
            .find(|s| s.transaction_id == ironwood)
            .unwrap();
        assert_eq!(i.pool_crossing_value, Some(480000));
        assert!(i.has_orchard_spend);
        assert_eq!(i.expiry_height.map(u32::from), Some(2000000));
        assert!(!i.expired_unmined);
        assert_eq!(i.memo_count, 0);
        assert_eq!(i.fee, None);
        let mut view = conn.prepare("SELECT vt.*, tx.id_tx AS transaction_id, tx.created,
            CAST(strftime('%s', tx.created) AS INTEGER) AS created_time,
            EXISTS (SELECT 1 FROM orchard_received_note_spends s JOIN orchard_received_notes n ON n.id = s.orchard_received_note_id WHERE s.transaction_id = tx.id_tx AND n.note_version = 2) AS has_orchard_spend
            FROM v_transactions vt JOIN transactions tx ON tx.txid = vt.txid WHERE vt.account_uuid = ?1").unwrap();
        let mut expected = view
            .query_map([account.expose_uuid().as_bytes()], read_summary)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut actual = actual;
        expected.sort_by_key(|s| s.transaction_id);
        actual.sort_by_key(|s| s.transaction_id);
        assert_eq!(actual, expected);
    }
}
