//! Functions for initializing the various databases.
use crate::BlockDb;

#[cfg(feature = "unstable")]
use {
    super::migrations,
    crate::FsBlockDb,
    crate::{error::MigrationError, migration},
};

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     BlockDb,
///     chain::init::init_cache_database,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let db = BlockDb::for_path(cache_file.path()).unwrap();
/// init_cache_database(&db).unwrap();
/// ```
pub fn init_cache_database(db_cache: &BlockDb) -> Result<(), rusqlite::Error> {
    db_cache.0.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks (
            height INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Sets up the internal structure of the metadata cache database.
///
/// This will automatically apply any available migrations that have not yet been applied to the
/// database as part of its operation.
///
/// # Examples
///
/// ```
/// use tempfile::{tempdir, NamedTempFile};
/// use zcash_client_sqlite::{
///     FsBlockDb,
///     chain::init::init_blockmeta_db,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let blocks_dir = tempdir().unwrap();
/// let mut db = FsBlockDb::for_path(blocks_dir.path()).unwrap();
/// init_blockmeta_db(&mut db).unwrap();
/// ```
#[cfg(feature = "unstable")]
pub fn init_blockmeta_db(db: &mut FsBlockDb) -> Result<(), MigrationError<rusqlite::Error>> {
    migration::initialize(&db.conn).expect("Migrations table setup succeeds.");
    migration::migrate(&mut db.conn, &migrations::blockmeta::all_migrations(), &[])
}
