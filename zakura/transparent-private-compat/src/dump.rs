//! SQLite databases as text: their SQL objects and their rows.
//!
//! A frozen database is kept as the SQL that recreates it, never as a file, so
//! a comparison reads what a schema and its rows say rather than how SQLite
//! happened to lay out pages. [`Snapshot`] is what two databases are compared
//! by; [`to_sql`] and [`restore`] carry a database through the repository.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A database's SQL objects and rows, in a stable order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// `PRAGMA user_version`.
    pub user_version: i64,
    /// Every schema object other than SQLite's own: `type name tbl_name: sql`.
    pub objects: Vec<String>,
    /// Every table's rows, each rendered as one line, sorted.
    pub rows: BTreeMap<String, Vec<String>>,
}

impl Snapshot {
    /// Reads `path` without writing to it.
    pub fn of_path(path: &Path) -> Self {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        Self::of(&conn)
    }

    /// Reads the database `conn` holds.
    pub fn of(conn: &Connection) -> Self {
        let user_version = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let objects = schema(conn)
            .into_iter()
            .map(|o| format!("{} {} {}: {}", o.kind, o.name, o.table, o.sql))
            .collect();
        let rows = tables(conn)
            .into_iter()
            .map(|table| {
                let mut lines: Vec<String> = select_all(conn, &table)
                    .into_iter()
                    .map(|row| row.join(", "))
                    .collect();
                lines.sort();
                (table, lines)
            })
            .collect();
        Self {
            user_version,
            objects,
            rows,
        }
    }

    /// What a comparison needs from this snapshot: its user version and SQL
    /// objects as they are, and each table's row count and the SHA-256 of its
    /// sorted rows.
    pub fn digest(&self) -> SnapshotDigest {
        SnapshotDigest {
            user_version: self.user_version,
            objects: self.objects.clone(),
            tables: self
                .rows
                .iter()
                .map(|(table, rows)| {
                    let digest = Sha256::digest(rows.join("\n").as_bytes());
                    (
                        table.clone(),
                        TableDigest {
                            rows: rows.len(),
                            sha256: hex::encode(digest),
                        },
                    )
                })
                .collect(),
        }
    }
}

/// A [`Snapshot`] with each table's rows reduced to their count and digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDigest {
    pub user_version: i64,
    pub objects: Vec<String>,
    pub tables: BTreeMap<String, TableDigest>,
}

/// One table's rows: how many, and the SHA-256 of the sorted rendered rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDigest {
    pub rows: usize,
    pub sha256: String,
}

struct Object {
    kind: String,
    name: String,
    table: String,
    sql: String,
}

/// Schema objects in creation order, SQLite's internal ones left out.
fn schema(conn: &Connection) -> Vec<Object> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' ORDER BY rowid",
        )
        .unwrap();
    statement
        .query_map([], |row| {
            Ok(Object {
                kind: row.get(0)?,
                name: row.get(1)?,
                table: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Ordinary tables, `sqlite_sequence` included when it exists.
fn tables(conn: &Connection) -> Vec<String> {
    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table'
             AND (name NOT LIKE 'sqlite_%' OR name = 'sqlite_sequence')
             AND sql NOT LIKE 'CREATE VIRTUAL TABLE%' ORDER BY name",
        )
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn select_all(conn: &Connection, table: &str) -> Vec<Vec<String>> {
    let mut statement = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            Ok((0..columns)
                .map(|i| render(row.get_ref(i).unwrap()))
                .collect())
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// One value as an SQL literal. Text is written as a cast blob, so no value
/// contains a quote or a separator and every byte survives.
fn render(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(r) => format!("{r:?}"),
        ValueRef::Text(t) => format!("CAST(X'{}' AS TEXT)", hex::encode(t)),
        ValueRef::Blob(b) => format!("X'{}'", hex::encode(b)),
    }
}

/// SQL that recreates the database `conn` holds: its user version, every table
/// with its rows, then every index, view and trigger, in creation order.
pub fn to_sql(conn: &Connection) -> String {
    let mut out = String::new();
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    writeln!(out, "PRAGMA user_version = {user_version};").unwrap();
    let objects = schema(conn);
    for object in objects.iter().filter(|o| o.kind == "table") {
        writeln!(out, "{};", object.sql).unwrap();
    }
    let mut names = tables(conn);
    names.sort();
    for table in names {
        let mut rows = select_all(conn, &table);
        rows.sort();
        for row in rows {
            writeln!(out, "INSERT INTO \"{table}\" VALUES ({});", row.join(", ")).unwrap();
        }
    }
    for object in objects
        .iter()
        .filter(|o| o.kind != "table" && !o.sql.is_empty())
    {
        writeln!(out, "{};", object.sql).unwrap();
    }
    out
}

/// Writes the database `sql` describes to a new file at `path`.
pub fn restore(sql: &str, path: &Path) {
    assert!(!path.exists(), "{} already exists", path.display());
    let conn = Connection::open(path).unwrap();
    // Rows are written table by table, so a reference may precede its row;
    // the frozen database satisfied every constraint when it was read.
    conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    conn.execute_batch(&format!("BEGIN;\n{sql}\nCOMMIT;"))
        .unwrap_or_else(|e| panic!("restore {}: {e}", path.display()));
}
