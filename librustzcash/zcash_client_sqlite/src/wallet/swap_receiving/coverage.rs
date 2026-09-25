//! Per-key coverage is independent of the wallet's ordinary scan progress.

use std::ops::Range;

use rusqlite::{Connection, OptionalExtension, Transaction, named_params};
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_protocol::consensus::BlockHeight;

use super::{KeyId, purpose_code};
use crate::{AccountUuid, error::SqliteClientError, wallet};

fn key_ref(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
) -> Result<Option<i64>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT k.id FROM ironwood_receiving_keys k JOIN accounts a ON a.id = k.account_id
         WHERE a.uuid = ?1 AND k.purpose = ?2 AND k.derivation_version = 1 AND k.key_index = ?3",
            rusqlite::params![
                account.0,
                purpose_code(key.purpose()),
                &key.index().to_be_bytes()
            ],
            |row| row.get(0),
        )
        .optional()?)
}

pub(super) fn ranges(
    conn: &Connection,
    account: AccountUuid,
    key: KeyId,
) -> Result<Option<Vec<Range<BlockHeight>>>, SqliteClientError> {
    let Some(id) = key_ref(conn, account, key)? else {
        return Ok(None);
    };
    let mut stmt = conn.prepare_cached(
        "SELECT range_start, range_end FROM ironwood_receiving_key_scan_ranges
         WHERE receiving_key_id = ?1 ORDER BY range_start",
    )?;
    Ok(Some(
        stmt.query_map([id], |row| {
            Ok(BlockHeight::from(row.get::<_, u32>(0)?)..BlockHeight::from(row.get::<_, u32>(1)?))
        })?
        .collect::<Result<_, _>>()?,
    ))
}

/// Called only with the key snapshot used to scan the blocks stored in this transaction.
pub(crate) fn record(
    conn: &Transaction<'_>,
    keys: &[(AccountUuid, KeyId)],
    range: Range<BlockHeight>,
) -> Result<(), SqliteClientError> {
    if range.is_empty() {
        return Ok(());
    }
    for &(account, key) in keys {
        let id = key_ref(conn, account, key)?.ok_or_else(|| {
            SqliteClientError::CorruptedData("scanned swap key is no longer registered".into())
        })?;
        // Existing ranges are disjoint and non-adjacent. Merge only touched ranges,
        // preserving holes when the caller scans the tip before older history.
        let (start, end): (u32, u32) = conn.query_row(
            "SELECT MIN(MIN(range_start), :start), MAX(MAX(range_end), :end)
             FROM ironwood_receiving_key_scan_ranges
             WHERE receiving_key_id = :key AND range_start <= :end AND range_end >= :start",
            named_params![":key": id, ":start": u32::from(range.start), ":end": u32::from(range.end)],
            |row| Ok((row.get::<_, Option<u32>>(0)?.unwrap_or(range.start.into()),
                      row.get::<_, Option<u32>>(1)?.unwrap_or(range.end.into()))),
        )?;
        conn.execute(
            "DELETE FROM ironwood_receiving_key_scan_ranges
             WHERE receiving_key_id = ?1 AND range_start <= ?3 AND range_end >= ?2",
            rusqlite::params![id, start, end],
        )?;
        conn.execute(
            "INSERT INTO ironwood_receiving_key_scan_ranges (receiving_key_id, range_start, range_end)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![id, start, end],
        )?;
    }
    Ok(())
}

/// Requeues missing key coverage, including keys registered while a scan was running.
/// This also repairs gaps after scanning with swap support disabled.
pub(crate) fn queue_missing(conn: &Transaction<'_>) -> Result<(), SqliteClientError> {
    let Some(tip) = wallet::chain_tip_height(conn)? else {
        return Ok(());
    };
    let end = u32::from(tip + 1);
    let mut stmt = conn.prepare_cached(
        "SELECT k.id, k.scan_from, r.range_start, r.range_end
         FROM ironwood_receiving_keys k
         LEFT JOIN ironwood_receiving_key_scan_ranges r ON r.receiving_key_id = k.id
         ORDER BY k.id, r.range_start",
    )?;
    let mut rows = stmt.query([])?;
    let mut current = None;
    let mut cursor = end;
    let mut gaps = Vec::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        if current != Some(id) {
            if cursor < end {
                gaps.push(cursor..end);
            }
            current = Some(id);
            cursor = row.get(1)?;
        }
        if let Some(start) = row.get::<_, Option<u32>>(2)? {
            if cursor < start.min(end) {
                gaps.push(cursor..start.min(end));
            }
            cursor = cursor.max(row.get::<_, u32>(3)?);
        }
    }
    if cursor < end {
        gaps.push(cursor..end);
    }
    drop(rows);
    drop(stmt);

    // Many keys need the same blocks. Queue their union once.
    gaps.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<Range<u32>> = Vec::new();
    for gap in gaps {
        if let Some(last) = merged.last_mut().filter(|last| last.end >= gap.start) {
            last.end = last.end.max(gap.end);
        } else {
            merged.push(gap);
        }
    }
    for gap in merged {
        let range = BlockHeight::from(gap.start)..BlockHeight::from(gap.end);
        wallet::scanning::replace_queue_entries::<SqliteClientError>(
            conn,
            &range,
            std::iter::once(ScanRange::from_parts(range.clone(), ScanPriority::Historic)),
            true,
        )?;
    }
    Ok(())
}
