//! An account's recorded coverage, read for authority diagnostics.

use super::*;

/// Merges inclusive `(from, through)` ranges into disjoint, non-adjacent ranges.
fn merge(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = vec![];
    for (from, through) in ranges {
        match merged.last_mut() {
            Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(through),
            _ => merged.push((from, through)),
        }
    }
    merged
}

/// An account's recorded coverage, by output script.
pub(super) struct Coverage {
    /// The checked ranges per script, inclusive, merged into disjoint, non-adjacent ranges.
    pub(super) supported: BTreeMap<Vec<u8>, Vec<(u32, u32)>>,
    /// The ranges a revision declared it cannot index, as recorded: `(script, from, through)`.
    pub(super) unsupported: Vec<(Vec<u8>, u32, u32)>,
}

/// Reads `account_ref`'s recorded coverage.
pub(super) fn read(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<Coverage, SqliteClientError> {
    let mut supported: BTreeMap<Vec<u8>, Vec<(u32, u32)>> = BTreeMap::new();
    let mut unsupported: Vec<(Vec<u8>, u32, u32)> = vec![];
    let mut stmt = conn.prepare_cached(
        "SELECT script, from_height, through_height, supported
         FROM tpir_coverage WHERE account_id = :account_id",
    )?;
    let mut rows = stmt.query(named_params![":account_id": account_ref.0])?;
    while let Some(row) = rows.next()? {
        let (script, from, through): (Vec<u8>, u32, u32) = (row.get(0)?, row.get(1)?, row.get(2)?);
        if row.get::<_, bool>(3)? {
            supported.entry(script).or_default().push((from, through));
        } else {
            unsupported.push((script, from, through));
        }
    }
    let supported: BTreeMap<_, _> = supported
        .into_iter()
        .map(|(script, ranges)| (script, merge(ranges)))
        .collect();

    Ok(Coverage {
        supported,
        unsupported,
    })
}
