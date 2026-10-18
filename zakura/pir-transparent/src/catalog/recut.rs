//! Re-cuts: the epoch this companion's store followed, and the check of a map's re-cut
//! declarations against what it publishes.

use std::collections::{BTreeMap, btree_map::Entry};

use rusqlite::{Connection, OptionalExtension, Transaction};
use zakura_transparent_recovery_types::RecoveryRevision;

use super::identity::Published;
use crate::batch::WithdrawnCause;
use crate::error::{RecoveryError, failure};

/// The highest re-cut epoch of a map whose ready pass found that this
/// companion's store followed its re-cuts, zero if none since the store last
/// started.
pub(crate) fn recut_epoch(conn: &Connection) -> Result<u32, RecoveryError> {
    let epoch: Option<i64> = conn
        .query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='recut-epoch'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(failure)?;
    u32::try_from(epoch.unwrap_or(0)).map_err(failure)
}

/// Records `epoch` as the re-cut epoch the store followed, replacing any recorded.
pub(super) fn record_epoch(tx: &Transaction<'_>, epoch: u32) -> Result<(), RecoveryError> {
    tx.execute(
        "INSERT OR REPLACE INTO pir_bridge_binding (key, value) VALUES ('recut-epoch', ?1)",
        [i64::from(epoch)],
    )
    .map(|_| ())
    .map_err(failure)
}

/// The first contradiction between a map's re-cut declarations and what it
/// publishes, or among the declarations, scanning `declarations` in map order.
///
/// A published revision in the source of a declared one must have a higher
/// lineage: equal is an `Equivocation`, lower a `Regression`. Two declared
/// revisions of one source at one lineage that differ are an `Equivocation`.
/// `declarations` is every revision the map declares, the superseded tails
/// included. For each declaration in turn, the first published revision of its
/// source at or below its lineage decides, else a later declaration differing
/// from it at its source and lineage.
///
/// A map may declare tens of thousands of revisions, so both are found through
/// indexes by source and lineage rather than by comparing pairs, with the
/// cause a pairwise scan in the same order would find first.
pub(crate) fn declaration_conflict(
    published: &[Published],
    declarations: &[Published],
) -> Option<WithdrawnCause> {
    // Each source's published lineages, in map order.
    let mut lineages: BTreeMap<&[u8], Vec<u64>> = BTreeMap::new();
    for entry in published {
        lineages
            .entry(entry.revision.source.as_slice())
            .or_default()
            .push(entry.revision.lineage);
    }
    // Whether a later declaration at the same source and lineage differs,
    // found from the end: for each source and lineage, the one revision the
    // declarations after this one name, or `None` once they name two.
    let mut later: BTreeMap<(&[u8], u64), Option<&RecoveryRevision>> = BTreeMap::new();
    let mut differs = vec![false; declarations.len()];
    for (index, declared) in declarations.iter().enumerate().rev() {
        let ours = &declared.revision;
        match later.entry((ours.source.as_slice(), ours.lineage)) {
            Entry::Vacant(slot) => {
                slot.insert(Some(ours));
            }
            Entry::Occupied(mut slot) => {
                differs[index] = slot.get().is_none_or(|theirs| theirs != ours);
                if differs[index] {
                    slot.insert(None);
                }
            }
        }
    }
    for (declared, differs) in declarations.iter().zip(differs) {
        let ours = &declared.revision;
        let theirs = lineages
            .get(ours.source.as_slice())
            .into_iter()
            .flatten()
            .find(|theirs| **theirs <= ours.lineage);
        match theirs {
            Some(theirs) if *theirs == ours.lineage => return Some(WithdrawnCause::Equivocation),
            Some(_) => return Some(WithdrawnCause::Regression),
            None if differs => return Some(WithdrawnCause::Equivocation),
            None => {}
        }
    }
    None
}
