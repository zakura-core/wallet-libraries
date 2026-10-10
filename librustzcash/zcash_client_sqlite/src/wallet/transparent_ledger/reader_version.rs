//! Reader versions: how new a build must be to interpret the wallet's ledger state.

#[cfg(feature = "transparent-inputs")]
use crate::error::SqliteClientError;

/// The highest `tpir_meta.min_reader_version` this build can interpret. A wallet requiring a
/// newer reader is refused rather than operated on with semantics this build lacks: every
/// ledger read and write fails, and so does a rewind, which would otherwise leave state this
/// build cannot maintain anchored on replaced blocks.
///
/// Version 3 maintains candidate recovery state through rewinds, policy transitions, and
/// account changes; the first candidate commit requires it. Version 5 honors activation,
/// qualification, quarantine, and retained outputs whose receive was withdrawn. Version 4
/// could admit those retained rows under public authority, so activation writes require 5.
/// Version 6 separates observed revisions from trusted replacement; revision writes require 6.
/// Version 7 maintains source-bound transaction facts through withdrawals and rewinds.
/// Version 8 retains shared derivation origins after address materialization.
pub(crate) const TPIR_READER_VERSION: i64 = SHARED_DERIVATION_READER_VERSION;

/// The reader version retained shared derivation origins require.
pub(crate) const SHARED_DERIVATION_READER_VERSION: i64 = 8;

/// Maintains source-bound transaction facts through withdrawals and rewinds.
pub(crate) const METADATA_READER_VERSION: i64 = 7;

/// Separates observed revision identities from trusted wallet-wide supersession.
pub(crate) const REVISION_READER_VERSION: i64 = 6;

/// The reader version candidate recovery state requires.
#[cfg(feature = "transparent-inputs")]
pub(crate) const RECOVERY_READER_VERSION: i64 = 3;

/// The reader version activation, qualification, and quarantine state requires.
pub(crate) const ACTIVATION_READER_VERSION: i64 = 5;

/// Raises `tpir_meta.min_reader_version` to at least `version`, so that builds that cannot
/// interpret the state about to be written fail closed rather than ignore it.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn require_reader_version(
    conn: &rusqlite::Connection,
    version: i64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE tpir_meta
         SET min_reader_version = MAX(min_reader_version, :version)
         WHERE id = 0",
        rusqlite::named_params![":version": version],
    )?;
    Ok(())
}
