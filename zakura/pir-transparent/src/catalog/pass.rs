//! One pass's catalog transaction: classifying the map's revisions, settling exported
//! ones, recording exports, and committing.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zakura_transparent_recovery_types::RecoveryBlockHash as BlockHash;
use zakura_transparent_recovery_types::{PublicationAnchor, RecoveryRevision};
use zcash_protocol::consensus::BlockHeight;

use super::exports::prune_catalog;
use super::identity::Published;
use super::recut::{declaration_conflict, record_epoch, recut_epoch};
use super::store_tables::prune_store_caches;
use crate::batch::{BatchState, WithdrawnCause};
use crate::error::{RecoveryError, failure};

/// What the catalog records of a revision a pass may export.
enum RecordedRevision {
    /// The catalog records it exactly.
    Matches,
    /// The catalog records something that contradicts it; the batch is withdrawn as
    /// an `Equivocation`.
    Contradicts,
    /// The catalog records neither.
    Unrecorded,
}

/// One pass's catalog transaction. Dropping it without [`CatalogPass::finish`] changes
/// nothing.
pub(crate) struct CatalogPass<'c> {
    /// The pass's immediate transaction on the catalog connection.
    tx: Transaction<'c>,
    /// The first contradiction found, which withdraws the batch.
    withdrawn: Option<WithdrawnCause>,
    /// Whether anything deferred the batch.
    pending: bool,
}

impl<'c> CatalogPass<'c> {
    /// Begins a pass over a map publishing `published` and declaring the sealed
    /// revisions `declared` superseded, marking current every stored row that
    /// either names exactly. A re-cut's sealed revisions stay current: the
    /// wallet keeps them as its history.
    pub(crate) fn begin(
        conn: &'c mut Connection,
        published: &[Published],
        declared: &[Published],
    ) -> Result<Self, RecoveryError> {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failure)?;
        tx.execute("UPDATE pir_bridge_catalog SET current=0", [])
            .map_err(failure)?;
        // Prepared once: a map may declare tens of thousands of revisions.
        let mut current = tx
            .prepare(
                "UPDATE pir_bridge_catalog SET current=1 WHERE source=?1 AND digest=?2 AND sealed=?3
                 AND lineage=?4 AND height=?5 AND hash=?6",
            )
            .map_err(failure)?;
        for entry in published.iter().chain(declared) {
            let revision = &entry.revision;
            current
                .execute(params![
                    revision.source,
                    entry.digest,
                    revision.sealed,
                    revision.lineage,
                    entry.height(),
                    entry.hash()
                ])
                .map_err(failure)?;
        }
        drop(current);
        Ok(Self {
            tx,
            withdrawn: None,
            pending: false,
        })
    }

    /// Withdraws the batch for `cause`, unless an earlier cause already did.
    fn withdraw(&mut self, cause: WithdrawnCause) {
        self.withdrawn.get_or_insert(cause);
    }

    /// Checks the map's re-cut declarations against what it publishes and
    /// against each other, needing no catalog history, so a recreated
    /// companion checks them too. See [`declaration_conflict`].
    pub(crate) fn check_declarations(
        &mut self,
        published: &[Published],
        declarations: &[Published],
    ) {
        if let Some(cause) = declaration_conflict(published, declarations) {
            self.withdraw(cause);
        }
    }

    /// Classifies a published revision this pass may export, recording it when
    /// it is new. Returns whether a commit may be built for it: not for a
    /// lagging revision, which defers the batch and is not recorded, nor for one
    /// that withdraws it.
    pub(crate) fn classify(&mut self, entry: &Published) -> Result<bool, RecoveryError> {
        let revision = &entry.revision;
        match self.recorded(entry)? {
            RecordedRevision::Matches => return Ok(true),
            RecordedRevision::Contradicts => return Ok(false),
            RecordedRevision::Unrecorded => {}
        }
        let newest: Option<u64> = self
            .tx
            .query_row(
                "SELECT MAX(lineage) FROM pir_bridge_catalog WHERE source=?1",
                [&revision.source],
                |row| row.get(0),
            )
            .map_err(failure)?;
        if newest.is_some_and(|newest| revision.lineage < newest) {
            // A sealed shard never goes back. An unsealed one does on a lagging
            // replica or a publisher rollback, which a later map can repair.
            if revision.sealed {
                self.withdraw(WithdrawnCause::Regression);
            } else {
                self.pending = true;
            }
            return Ok(false);
        }
        self.insert(entry)?;
        Ok(true)
    }

    /// Admits a sealed revision the map declares a re-cut superseded, on the
    /// first stored fact under it. Returns whether a commit may be built for
    /// it.
    ///
    /// The declaration must name it exactly as this companion recorded it, if
    /// at all; otherwise the batch is withdrawn as an `Equivocation`. It is
    /// recorded as current without the regression check, since its source's
    /// published successor is newer by construction.
    pub(crate) fn admit_declared(&mut self, entry: &Published) -> Result<bool, RecoveryError> {
        // A manifest digest binds its geometry and start height, so a
        // declaration naming one this companion recorded under another source
        // misstates where it was published. Only a declared revision is
        // checked so: stored facts under it outlive no set change, which
        // resets the store, while a published one may follow a set change.
        let elsewhere: bool = self
            .tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pir_bridge_catalog
                     WHERE digest=?1 AND sealed=?2 AND source<>?3)
                 OR EXISTS(SELECT 1 FROM pir_bridge_exports WHERE revision=?4 AND source<>?3)",
                params![
                    entry.digest,
                    entry.revision.sealed,
                    entry.revision.source,
                    entry.revision.revision
                ],
                |row| row.get(0),
            )
            .map_err(failure)?;
        if elsewhere {
            self.withdraw(WithdrawnCause::Equivocation);
            return Ok(false);
        }
        match self.recorded(entry)? {
            RecordedRevision::Matches => return Ok(true),
            RecordedRevision::Contradicts => return Ok(false),
            RecordedRevision::Unrecorded => {}
        }
        self.insert(entry)?;
        Ok(true)
    }

    /// Whether the catalog records `entry` exactly, records something that
    /// contradicts it (withdrawing the batch as an `Equivocation`), or neither.
    ///
    /// A contradiction is a row of its source with its digest and sealing at
    /// another lineage or endpoint, a row of its source at its lineage with
    /// another digest or sealing, or a revision ever exported at its source
    /// and lineage, or under its identity, that differs from it: the wallet
    /// would refuse it as an integrity failure and recovery suspension the account.
    fn recorded(&mut self, entry: &Published) -> Result<RecordedRevision, RecoveryError> {
        let revision = &entry.revision;
        let contradicted: bool = self
            .tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pir_bridge_exports
                 WHERE source=?1 AND (lineage=?2 OR revision=?3)
                 AND NOT (lineage=?2 AND revision=?3 AND sealed=?4 AND height=?5 AND hash=?6))",
                params![
                    revision.source,
                    revision.lineage,
                    revision.revision,
                    revision.sealed,
                    entry.height(),
                    entry.hash()
                ],
                |row| row.get(0),
            )
            .map_err(failure)?;
        if contradicted {
            self.withdraw(WithdrawnCause::Equivocation);
            return Ok(RecordedRevision::Contradicts);
        }
        let stored: Option<(u64, u32, Vec<u8>)> = self
            .tx
            .query_row(
                "SELECT lineage, height, hash FROM pir_bridge_catalog
                 WHERE source=?1 AND digest=?2 AND sealed=?3",
                params![revision.source, entry.digest, revision.sealed],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(failure)?;
        if let Some((lineage, height, hash)) = stored {
            // The same content under another revision number or endpoint.
            let same = lineage == revision.lineage
                && height == entry.height()
                && hash.as_slice() == entry.hash();
            if !same {
                self.withdraw(WithdrawnCause::Equivocation);
                return Ok(RecordedRevision::Contradicts);
            }
            return Ok(RecordedRevision::Matches);
        }
        let collides: bool = self
            .tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pir_bridge_catalog WHERE source=?1 AND lineage=?2)",
                params![revision.source, revision.lineage],
                |row| row.get(0),
            )
            .map_err(failure)?;
        if collides {
            self.withdraw(WithdrawnCause::Equivocation);
            return Ok(RecordedRevision::Contradicts);
        }
        Ok(RecordedRevision::Unrecorded)
    }

    /// Records `entry` as a new current row, not exported.
    fn insert(&self, entry: &Published) -> Result<(), RecoveryError> {
        let revision = &entry.revision;
        self.tx
            .execute(
                "INSERT INTO pir_bridge_catalog (source, start_height, digest, sealed, lineage, revision, height, hash, current)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                params![
                    revision.source,
                    entry.start_height,
                    entry.digest,
                    revision.sealed,
                    revision.lineage,
                    revision.revision,
                    entry.height(),
                    entry.hash()
                ],
            )
            .map(|_| ())
            .map_err(failure)
    }

    /// Whether a batch before this pass may have handed `revision` to the
    /// wallet. This pass's own exports are recorded only by [`CatalogPass::export`].
    pub(crate) fn was_exported(&self, revision: &RecoveryRevision) -> Result<bool, RecoveryError> {
        self.tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pir_bridge_catalog
                 WHERE source=?1 AND revision=?2 AND exported=1)",
                params![revision.source, revision.revision],
                |row| row.get(0),
            )
            .map_err(failure)
    }

    /// Defers the batch: a stored fact names a revision the map neither
    /// publishes nor declares, or does not fit the revision it names, or a
    /// shard ends on a block the wallet's chain does not hold.
    pub(crate) fn defer(&mut self) {
        self.pending = true;
    }

    /// Classifies every exported row that is no longer current (neither
    /// published nor declared superseded exactly as recorded), by the first
    /// rule that matches. While its source is published:
    ///
    /// 1. a sealed row whose source is published unsealed at a lower lineage
    ///    (a replica behind the seal): pending;
    /// 2. any other sealed row: `ChangedSealed`;
    /// 3. an unsealed row this batch commits its source above: replaced;
    /// 4. any other unsealed row: pending.
    ///
    /// While its source is not published:
    ///
    /// 5. the map ends below its start height, or reaches it inside an
    ///    unsealed shard that starts below it (the map is behind): pending;
    /// 6. otherwise its heights are published under another source:
    ///    `Retired`.
    ///
    /// `published` is every revision the map publishes, and `committed` maps
    /// each source with a commit in this batch to the highest lineage
    /// committed. Returns the replaced rows, as the wallet identifies them.
    pub(crate) fn settle(
        &mut self,
        published: &[Published],
        committed: &BTreeMap<&[u8], u64>,
    ) -> Result<Vec<RecoveryRevision>, RecoveryError> {
        let by_source: BTreeMap<&[u8], &RecoveryRevision> = published
            .iter()
            .map(|entry| (entry.revision.source.as_slice(), &entry.revision))
            .collect();
        let mut statement = self
            .tx
            .prepare(
                "SELECT source, revision, start_height, sealed, lineage, height, hash
                 FROM pir_bridge_catalog
                 WHERE exported=1 AND current=0 ORDER BY start_height DESC, lineage DESC",
            )
            .map_err(failure)?;
        let rows = statement
            .query_map([], |row| {
                let sealed = row.get::<_, bool>(3)?;
                let lineage = row.get::<_, u64>(4)?;
                Ok((
                    RecoveryRevision {
                        source: row.get(0)?,
                        revision: row.get(1)?,
                        lineage,
                        sealed,
                        publication: PublicationAnchor {
                            height: BlockHeight::from(row.get::<_, u32>(5)?),
                            hash: BlockHash::from_slice(&row.get::<_, Vec<u8>>(6)?),
                        },
                    },
                    row.get::<_, u64>(2)?,
                    sealed,
                    lineage,
                ))
            })
            .map_err(failure)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(failure)?;
        drop(statement);
        let mut replaced = vec![];
        for (row, start, sealed, lineage) in rows {
            match by_source.get(row.source.as_slice()) {
                // A replica that has not caught up with the seal.
                Some(entry) if sealed && !entry.sealed && entry.lineage < lineage => {
                    self.pending = true
                }
                Some(_) if sealed => self.withdraw(WithdrawnCause::ChangedSealed),
                Some(_) => {
                    if committed
                        .get(row.source.as_slice())
                        .is_some_and(|successor| *successor > lineage)
                    {
                        replaced.push(row);
                    } else {
                        self.pending = true;
                    }
                }
                None => {
                    let covering = published
                        .iter()
                        .find(|entry| entry.start_height <= start && start <= entry.end_height);
                    match covering {
                        None => self.pending = true,
                        // A tail the publisher has since cut at this height,
                        // still served by a replica that has not caught up.
                        Some(entry) if !entry.revision.sealed && entry.start_height < start => {
                            self.pending = true
                        }
                        Some(_) => self.withdraw(WithdrawnCause::Retired),
                    }
                }
            }
        }
        Ok(replaced)
    }

    /// The first withdrawal found, else `Pending` if anything deferred the
    /// batch, else `Ready`.
    pub(crate) fn state(&self) -> BatchState {
        match (self.withdrawn, self.pending) {
            (Some(cause), _) => BatchState::Withdrawn(cause),
            (None, true) => BatchState::Pending,
            (None, false) => BatchState::Ready,
        }
    }

    /// Records that `revisions` may reach the wallet, before they are returned.
    ///
    /// The wallet and this companion cannot share a transaction, so the intent
    /// must be durable first: a crash after the wallet applied a batch but before
    /// it was acknowledged still has to defer a pass that would forget it.
    pub(crate) fn export<'r>(
        &self,
        revisions: impl IntoIterator<Item = &'r RecoveryRevision>,
    ) -> Result<(), RecoveryError> {
        for revision in revisions {
            self.tx
                .execute(
                    "UPDATE pir_bridge_catalog SET exported=1 WHERE source=?1 AND revision=?2",
                    params![revision.source, revision.revision],
                )
                .map_err(failure)?;
            self.tx
                .execute(
                    "INSERT OR IGNORE INTO pir_bridge_exports (source, lineage, revision, sealed, height, hash)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        revision.source,
                        revision.lineage,
                        revision.revision,
                        revision.sealed,
                        u32::from(revision.publication.height),
                        revision.publication.hash.0.as_slice()
                    ],
                )
                .map_err(failure)?;
        }
        Ok(())
    }

    /// Prunes the catalog, and the store's caches to the revisions `digests`
    /// names, records that the store followed a map at re-cut `epoch`, if
    /// given, then commits the pass.
    ///
    /// The recorded epoch only rises. It never stops a sync: it only tells a
    /// map the sync refuses as a rewrite of history the store holds, but whose
    /// epoch is lower, apart as a replica still serving the publication from
    /// before a re-cut the store followed. A pass gives one only when it is
    /// ready and the store holds a fact under a revision any of the map's
    /// re-cuts superseded, or under one it publishes at or above its newest
    /// re-cut's first height, so a map whose declaration is refused, or whose
    /// re-cuts the store did not follow, cannot raise it. A forged epoch can at
    /// most turn such a refusal from withdrawn into pending.
    pub(crate) fn finish(self, digests: &[&str], epoch: Option<u32>) -> Result<(), RecoveryError> {
        prune_catalog(&self.tx)?;
        prune_store_caches(&self.tx, digests)?;
        if let Some(epoch) = epoch {
            let recorded = recut_epoch(&self.tx)?;
            record_epoch(&self.tx, recorded.max(epoch))?;
        }
        self.tx.commit().map_err(failure)
    }
}
