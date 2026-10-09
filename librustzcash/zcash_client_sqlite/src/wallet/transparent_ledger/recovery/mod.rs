//! Recovery storage: watched addresses, events, coverage, pending pages, quarantine,
//! qualification, and promotion.
//!
//! A candidate account's writes touch only `tpir_*` recovery tables. They never change the LRZ
//! outputs, spends, locks, addresses, or transactions that balances, input selection,
//! receiving-address allocation, and history read, and the ledger never reads those back as
//! evidence. Promotion and an active account's commits also project events into those tables.
//!
//! Rewinds and policy transitions maintain recovery state in every build, because another
//! build may have written it. A build refuses both when the wallet requires a newer reader.

use rusqlite::named_params;
use zcash_protocol::consensus::BlockHeight;

use crate::error::SqliteClientError;

#[cfg(feature = "transparent-inputs")]
use {
    super::{
        capture_policy_generation, durable_policy, ensure_policy_generation,
        grants_private_authority, projection, resolve_mode,
    },
    crate::{
        AccountRef, AccountUuid,
        wallet::{
            Account, chain_tip_height, encoding::KeyScope, fully_scanned_height, get_account,
            get_block_hash, transparent::get_legacy_transparent_address,
        },
    },
    std::collections::{BTreeMap, BTreeSet},
    transparent::{
        address::TransparentAddress,
        bundle::OutPoint,
        keys::{IncomingViewingKey as _, NonHardenedChildIndex, TransparentKeyScope},
    },
    zcash_client_backend::data_api::{
        Account as _,
        transparent_ledger::{
            AccountLifecycle, AddressRange, CandidateBlocker, CandidateRecovery, ChainPoint,
            CommitOutcome, CommitRejection, IntegrityFailure, InvalidCommit,
            MAX_RECOVERY_IDENTIFIER_LEN, PageRequest, PendingPage, PublicationAnchor, ReceiveEvent,
            RecoveryBlocker, RecoveryRevision, RefusedCommit, SpendEvent, StaleCommit,
            TransparentLedgerCommit, TransparentLedgerMode, TransparentWatchSet, WatchOrigin,
            WatchedAddress,
        },
    },
    zcash_keys::{
        address::Address,
        keys::{
            ReceiverRequirement::{Allow, Require},
            UnifiedAddressRequest,
            transparent::gap_limits::GapLimits,
        },
    },
    zcash_primitives::{block::BlockHash, transaction::TxId},
    zcash_protocol::{consensus, value::Zatoshis},
    zcash_script::script,
};

#[cfg(feature = "transparent-inputs")]
mod commit;
#[cfg(feature = "transparent-inputs")]
mod coverage;
#[cfg(feature = "transparent-inputs")]
mod diagnostics;
#[cfg(feature = "transparent-inputs")]
mod events;
mod lifecycle;
#[cfg(feature = "transparent-inputs")]
mod metadata;
#[cfg(feature = "transparent-inputs")]
mod ownership;
#[cfg(feature = "transparent-inputs")]
mod promotion;
#[cfg(feature = "transparent-inputs")]
mod revisions;
#[cfg(feature = "transparent-inputs")]
mod watch;

#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
pub(crate) use commit::qualify_revision;
#[cfg(feature = "transparent-inputs")]
pub(crate) use commit::{CommitTrust, apply_commit};
#[cfg(feature = "transparent-inputs")]
pub(crate) use diagnostics::candidate_recovery;
#[cfg(feature = "transparent-inputs")]
use diagnostics::{AccountLedger, placed_receives, placed_spends, recovery_status};
#[cfg(feature = "transparent-inputs")]
pub(crate) use diagnostics::{account_ledger, ledger_blockers};
#[cfg(feature = "transparent-inputs")]
pub(crate) use lifecycle::forget_reattributed_script;
pub(crate) use lifecycle::{clear_pending_pages, truncate};
#[cfg(all(feature = "transparent-inputs", feature = "transparent-key-import"))]
pub(crate) use ownership::forget_other_candidates;
#[cfg(feature = "transparent-inputs")]
pub(crate) use promotion::promote;
#[cfg(feature = "transparent-inputs")]
pub(crate) use watch::watch_set;

#[cfg(feature = "transparent-inputs")]
use commit::{account_quarantined, atomically, lifecycle};
#[cfg(feature = "transparent-inputs")]
use events::{apply_receive, apply_spend, open_page, record_range};
#[cfg(feature = "transparent-inputs")]
use watch::{WINDOW_LIMIT, WINDOW_SCOPES, Watch};

#[cfg(feature = "transparent-inputs")]
fn script_bytes(address: &TransparentAddress) -> Vec<u8> {
    transparent::address::Script::from(address.script()).0.0
}

#[cfg(feature = "transparent-inputs")]
fn address_from_script(bytes: Vec<u8>) -> Result<TransparentAddress, SqliteClientError> {
    script::FromChain::parse(&script::Code(bytes))
        .ok()
        .and_then(|script| TransparentAddress::from_script_from_chain(&script))
        .ok_or_else(|| {
            SqliteClientError::CorruptedData("recovery script is not a standard address".into())
        })
}

#[cfg(feature = "transparent-inputs")]
fn reject(rejection: CommitRejection) -> SqliteClientError {
    SqliteClientError::TransparentLedgerCommitRejected(rejection)
}

/// The highest contiguously scanned local block.
#[cfg(feature = "transparent-inputs")]
fn local_target(conn: &rusqlite::Connection) -> Result<Option<ChainPoint>, SqliteClientError> {
    let Some(height) = fully_scanned_height(conn)? else {
        return Ok(None);
    };
    Ok(get_block_hash(conn, height)?.map(|hash| ChainPoint { height, hash }))
}

#[cfg(feature = "transparent-inputs")]
fn is_local_block(
    conn: &rusqlite::Connection,
    point: &ChainPoint,
) -> Result<bool, SqliteClientError> {
    Ok(get_block_hash(conn, point.height)? == Some(point.hash))
}

#[cfg(feature = "transparent-inputs")]
fn height(value: u32) -> BlockHeight {
    BlockHeight::from_u32(value)
}

#[cfg(feature = "transparent-inputs")]
fn read_revision(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<RecoveryRevision, SqliteClientError> {
    Ok(RecoveryRevision {
        source: row.get(offset)?,
        revision: row.get(offset + 1)?,
        lineage: u64::try_from(row.get::<_, i64>(offset + 2)?)
            .map_err(|_| SqliteClientError::CorruptedData("negative revision lineage".into()))?,
        sealed: row.get(offset + 3)?,
        publication: PublicationAnchor {
            height: height(row.get(offset + 4)?),
            hash: BlockHash::try_from_slice(&row.get::<_, Vec<u8>>(offset + 5)?).ok_or_else(
                || SqliteClientError::CorruptedData("invalid publication hash".into()),
            )?,
        },
    })
}

#[cfg(feature = "transparent-inputs")]
fn read_hash(bytes: Vec<u8>) -> Result<BlockHash, SqliteClientError> {
    BlockHash::try_from_slice(&bytes)
        .ok_or_else(|| SqliteClientError::CorruptedData("invalid block hash".into()))
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use std::collections::BTreeMap;

    use transparent::{
        address::TransparentAddress,
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    };
    use zcash_client_backend::data_api::transparent_ledger::WatchOrigin;

    use super::{commit::atomically, watch::note_origin};
    use crate::error::SqliteClientError;

    #[test]
    fn derivation_outranks_a_standalone_import() {
        let address = TransparentAddress::PublicKeyHash([1; 20]);
        let derived = WatchOrigin::Derived {
            scope: TransparentKeyScope::EXTERNAL,
            index: NonHardenedChildIndex::ZERO,
        };
        for order in [
            [WatchOrigin::Standalone, derived],
            [derived, WatchOrigin::Standalone],
        ] {
            let mut addresses = BTreeMap::new();
            for origin in order {
                note_origin(&mut addresses, address, origin);
            }
            assert_eq!(addresses[&address], derived);
        }
    }

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
