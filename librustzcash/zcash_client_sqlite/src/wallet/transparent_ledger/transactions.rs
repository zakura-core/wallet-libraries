//! The SQLite transaction boundaries ledger reads and writes run in.

use crate::error::SqliteClientError;

/// Runs `f` against one SQLite snapshot.
///
/// Public follow-on dispatch reads the resolved mode, the durable generation, and queued work.
/// Those must not be mixed across a concurrent `Public` → `PrivateRequired` transition: a stale
/// public-authority result combined with the new generation would emit newly queued txids as
/// public work. Callers already inside a transaction reuse that snapshot.
pub(crate) fn with_read_snapshot<T, F>(
    conn: &rusqlite::Connection,
    f: F,
) -> Result<T, SqliteClientError>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T, SqliteClientError>,
{
    in_transaction(conn, f)
}

/// Runs `f` in a new deferred transaction, committed when `f` succeeds, or in the caller's
/// transaction when one is open. A deferred transaction takes the write lock at its first
/// write.
pub(super) fn in_transaction<T, F>(
    conn: &rusqlite::Connection,
    f: F,
) -> Result<T, SqliteClientError>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T, SqliteClientError>,
{
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction()?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    } else {
        f(conn)
    }
}

/// Runs `f` atomically: in a new immediate transaction, or under a savepoint inside the
/// caller's transaction. Nothing `f` wrote survives its failure, including a failure to
/// commit or release.
#[cfg(feature = "transparent-inputs")]
pub(super) fn atomically<T>(
    conn: &rusqlite::Connection,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, SqliteClientError>,
) -> Result<T, SqliteClientError> {
    if conn.is_autocommit() {
        // The guard rolls back when dropped, including after a failed commit.
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        return Ok(value);
    }
    conn.execute_batch("SAVEPOINT tpir_commit")?;
    let result = f(conn).and_then(|value| {
        conn.execute_batch("RELEASE tpir_commit")?;
        Ok(value)
    });
    if result.is_err() {
        // Undo everything since the savepoint and remove it, even when releasing it failed. If
        // this cleanup fails too, the error still aborts the caller's enclosing transaction.
        let _ = conn.execute_batch("ROLLBACK TO tpir_commit; RELEASE tpir_commit");
    }
    result
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use super::atomically;
    use crate::error::SqliteClientError;

    #[test]
    fn failed_commit_rolls_back() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // A deferred foreign key violation makes COMMIT itself fail.
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE written (x INTEGER);
             CREATE TABLE parent (id INTEGER PRIMARY KEY);
             CREATE TABLE child (
                 parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED
             );",
        )
        .unwrap();
        let result = atomically(&conn, |conn| {
            conn.execute_batch("INSERT INTO written VALUES (1); INSERT INTO child VALUES (42);")?;
            Ok(())
        });
        assert!(matches!(result, Err(SqliteClientError::DbError(_))));
        assert!(
            conn.is_autocommit(),
            "the failed transaction must not stay open"
        );
        let written: i64 = conn
            .query_row("SELECT COUNT(*) FROM written", [], |row| row.get(0))
            .unwrap();
        assert_eq!(written, 0);
    }
}
