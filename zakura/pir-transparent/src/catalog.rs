//! The companion's revision catalog: stable revision identities, what each
//! source has published, and which revisions a batch may have handed to the
//! wallet.
//!
//! Identities are derived, never counted, so any companion bound to the same
//! account, origin and schema derives the triples the wallet already holds. The
//! catalog lets a pass tell a publication that is merely behind (`Pending`) from
//! one that contradicts what this companion recorded (`Withdrawn`); only a
//! `Ready` pass returns commits.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, named_params, params,
};
use sha2::{Digest, Sha256};
use transparent_filter::ShardMapEntry;
use transparent_wallet::SetIdentity;
use zcash_client_backend::data_api::transparent_ledger::{PublicationAnchor, RecoveryRevision};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::recovery::{RecoveryError, block, block_hash, failure, require};

/// The companion layout this build creates and reads.
const FORMAT: &str = "transparent-reference-companion-v2";

// Pruning names the reference store's cache and commit tables, and a reset names
// every store table. Re-verify those names, that `wallet_meta` keeps the schema
// version under `schema_version`, and that `last_commit` reads only the highest
// commit id, before accepting another store schema.
const _: () = assert!(transparent_wallet_store::SCHEMA_VERSION == 4);

/// The reference store's tables at schema version 4, besides `wallet_meta`.
const STORE_TABLES: [&str; 8] = [
    "scripts",
    "coverage",
    "receives",
    "spends",
    "pending_work",
    "setup_cache",
    "filter_cache",
    "commits",
];

const TABLES: &str = "CREATE TABLE pir_bridge_binding (key TEXT PRIMARY KEY, value BLOB NOT NULL);
    CREATE TABLE pir_bridge_catalog (
        source BLOB NOT NULL CHECK(length(source)=32),
        shard_id INTEGER NOT NULL CHECK(shard_id>=0),
        digest TEXT NOT NULL,
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        exported INTEGER NOT NULL DEFAULT 0 CHECK(exported IN (0,1)),
        current INTEGER NOT NULL DEFAULT 0 CHECK(current IN (0,1)),
        PRIMARY KEY(source,digest,sealed), UNIQUE(source,lineage), UNIQUE(source,revision));";

/// Whether a pass's commits may reach the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchState {
    /// The publication agrees with everything this companion recorded, and every
    /// revision it exported is still published or has a successor at a higher
    /// lineage among the batch's commits. Apply the commits, then acknowledge.
    ///
    /// A successor withdraws its predecessor's provisional evidence only when
    /// the wallet qualifies it, so `Ready` assumes the commits are applied
    /// through the trusted operation. The predecessors are the batch's
    /// [`RecoveryBatch::retired_revisions`](crate::RecoveryBatch::retired_revisions),
    /// and such a batch is acknowledged only by applying its commits through
    /// the trusted operation with `ReferenceRecovery::apply_and_acknowledge`
    /// (feature `sqlite`).
    Ready,
    /// The publication or this companion's retrieval is behind what the
    /// companion recorded: a lagging replica (one serving a shard unsealed below
    /// a revision the companion saw, even a sealed one), a map missing a shard,
    /// stored facts naming a revision the map no longer names, a shard ending on
    /// a block the wallet's chain does not hold, or an exported tail whose
    /// successor is not retrieved yet, or a store a publication change reset
    /// that has not bound the new set again. A publication that diverged from
    /// what the sync read (a shard with pending pages withdrawn, or a map
    /// refreshed mid-pass that does not continue the one the pass started
    /// from), and a map under another set that ends below the height the store
    /// synced to, are also `Pending`, with
    /// [`Outcome::Behind`](crate::Outcome::Behind). The batch has no commits or
    /// retired revisions and cannot be acknowledged; a later pass can be
    /// `Ready`.
    Pending,
    /// The publication contradicts what this companion recorded. The batch has
    /// no commits or retired revisions and cannot be acknowledged, and passes
    /// stay withdrawn until the publication changes.
    ///
    /// Keep the companion meanwhile: hold and retry later, or stop recovering
    /// from this publication. A recreated companion has no record of what this
    /// one exported, so it cannot see the contradiction and may export
    /// revisions that collide with ones the wallet already holds. Not even
    /// [`RecoveryError::PublicationChanged`] calls for a new companion: the
    /// adapter resets the companion's store itself and keeps this catalog.
    Withdrawn(WithdrawnCause),
}

/// How a publication contradicts this companion's catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawnCause {
    /// A sealed shard is published at a lower revision than this companion
    /// recorded for its source.
    Regression,
    /// One revision of a source is published as two different shard revisions.
    Equivocation,
    /// A sealed revision a batch exported is no longer published, and the map
    /// does not merely name an older unsealed revision of its shard.
    ChangedSealed,
    /// A shard a batch exported is published under another source, as after a
    /// geometry change.
    Retired,
}

/// The companion's binding: length-prefixed source, account binding, origin and
/// schema. Every source this companion derives includes it.
pub(crate) fn binding(parts: [&[u8]; 4]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for value in parts {
        length_prefixed(&mut hash, value);
    }
    hash.finalize().into()
}

fn length_prefixed(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
}

/// Creates this format's tables in a new companion, or checks that an existing
/// one has this format and is bound to `binding`.
///
/// A v1 companion counted lineage per companion, which no recreated companion
/// can reproduce, so it is refused rather than migrated.
pub(crate) fn prepare(conn: &mut Connection, binding: &[u8; 32]) -> Result<(), RecoveryError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failure)?;
    let has = |table: &str| -> Result<bool, RecoveryError> {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(failure)
    };
    let bound = has("pir_bridge_binding")?;
    let format: Option<String> = if bound {
        tx.query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='format'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(failure)?
    } else {
        None
    };
    require(
        !has("pir_bridge_revisions")? && (!bound || format.is_some()),
        "companion format v1; recreate",
    )?;
    require(
        format.as_deref().is_none_or(|format| format == FORMAT),
        "unsupported companion format",
    )?;
    if !bound {
        tx.execute_batch(TABLES).map_err(failure)?;
        tx.execute(
            "INSERT INTO pir_bridge_binding (key, value) VALUES ('format', ?1), ('account-source', ?2)",
            params![FORMAT, binding.as_slice()],
        )
        .map_err(failure)?;
    }
    let prior: Option<Vec<u8>> = tx
        .query_row(
            "SELECT value FROM pir_bridge_binding WHERE key='account-source'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(failure)?;
    require(
        prior.as_deref() == Some(binding.as_slice()),
        "companion account/source/origin/schema binding mismatch",
    )?;
    tx.commit().map_err(failure)
}

/// One published shard revision, identified as the wallet and the catalog
/// identify it.
pub(crate) struct Published {
    pub(crate) shard_id: u64,
    digest: String,
    pub(crate) revision: RecoveryRevision,
}

impl Published {
    /// `entry` of a publication whose set identity is `set`, for a companion
    /// bound to `binding`.
    pub(crate) fn of(
        binding: &[u8; 32],
        set: &SetIdentity,
        entry: &ShardMapEntry,
    ) -> Result<Self, RecoveryError> {
        Ok(Self {
            shard_id: entry.shard_id,
            digest: entry.manifest_digest.clone(),
            revision: RecoveryRevision {
                source: source(binding, set, entry)?.to_vec(),
                revision: revision(&entry.manifest_digest, entry.sealed).to_vec(),
                lineage: lineage(entry),
                sealed: entry.sealed,
                publication: PublicationAnchor {
                    height: block(entry.end_height)?,
                    hash: block_hash(&entry.terminal_block_hash)?,
                },
            },
        })
    }

    fn height(&self) -> u32 {
        u32::from(self.revision.publication.height)
    }

    fn hash(&self) -> &[u8] {
        self.revision.publication.hash.0.as_slice()
    }
}

/// The stable identity of one shard of a publication, for one companion binding.
///
/// It hashes the set-identity fields [`SetIdentity::continues`] holds fixed,
/// plus the shard's geometry, that geometry's seal parameters, shard id and
/// start height. A set growing into a new geometry tier changes no existing
/// source, and a set-identity change `continues` refuses changes every source
/// it affects. Shard ids are one gapless sequence across geometries, so
/// re-cutting another geometry can reuse an id for a different height range;
/// its start height gives that range a new source even when its own geometry
/// and seal parameters remain unchanged.
pub(crate) fn source(
    binding: &[u8; 32],
    set: &SetIdentity,
    entry: &ShardMapEntry,
) -> Result<[u8; 32], RecoveryError> {
    let seal = set
        .seal
        .get(&entry.geometry)
        .ok_or_else(|| RecoveryError::Invalid("shard geometry has no seal parameters".into()))?;
    // Canonical: serde writes the fields in declaration order.
    let seal = serde_json::to_vec(seal).map_err(failure)?;
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-source-v2");
    hash.update(binding);
    length_prefixed(&mut hash, set.shard_schema.as_bytes());
    length_prefixed(&mut hash, set.network.as_bytes());
    length_prefixed(&mut hash, set.genesis_hash.as_bytes());
    length_prefixed(&mut hash, set.profile.as_bytes());
    hash.update(set.range_envelope_version.to_le_bytes());
    hash.update(set.start_height.to_le_bytes());
    length_prefixed(&mut hash, entry.geometry.as_bytes());
    length_prefixed(&mut hash, &seal);
    hash.update(entry.shard_id.to_le_bytes());
    hash.update(entry.start_height.to_le_bytes());
    Ok(hash.finalize().into())
}

/// A shard revision's identity: its manifest digest and whether it is sealed.
fn revision(digest: &str, sealed: bool) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-revision-v2");
    hash.update(digest.as_bytes());
    hash.update([u8::from(sealed)]);
    hash.finalize().into()
}

/// The publisher's revision number, offset so a first publication is lineage 1.
fn lineage(entry: &ShardMapEntry) -> u64 {
    u64::from(entry.revision) + 1
}

/// One pass's catalog transaction. Dropping it without [`Pass::finish`] changes
/// nothing.
pub(crate) struct Pass<'c> {
    tx: Transaction<'c>,
    withdrawn: Option<WithdrawnCause>,
    pending: bool,
}

impl<'c> Pass<'c> {
    /// Begins a pass over a map publishing `published`, marking current every
    /// stored row the map still publishes unchanged.
    pub(crate) fn begin(
        conn: &'c mut Connection,
        published: &[Published],
    ) -> Result<Self, RecoveryError> {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failure)?;
        tx.execute("UPDATE pir_bridge_catalog SET current=0", [])
            .map_err(failure)?;
        for entry in published {
            let revision = &entry.revision;
            tx.execute(
                "UPDATE pir_bridge_catalog SET current=1 WHERE source=?1 AND digest=?2 AND sealed=?3
                 AND lineage=?4 AND height=?5 AND hash=?6",
                params![
                    revision.source,
                    entry.digest,
                    revision.sealed,
                    revision.lineage,
                    entry.height(),
                    entry.hash()
                ],
            )
            .map_err(failure)?;
        }
        Ok(Self {
            tx,
            withdrawn: None,
            pending: false,
        })
    }

    fn withdraw(&mut self, cause: WithdrawnCause) {
        self.withdrawn.get_or_insert(cause);
    }

    /// Classifies a published revision this pass may export, recording it when
    /// it is new. Returns whether a commit may be built for it: not for a
    /// lagging revision, which defers the batch and is not recorded, nor for one
    /// that withdraws it.
    pub(crate) fn classify(&mut self, entry: &Published) -> Result<bool, RecoveryError> {
        let revision = &entry.revision;
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
            }
            return Ok(same);
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
            return Ok(false);
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
        self.tx
            .execute(
                "INSERT INTO pir_bridge_catalog (source, shard_id, digest, sealed, lineage, revision, height, hash, current)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                params![
                    revision.source,
                    entry.shard_id,
                    entry.digest,
                    revision.sealed,
                    revision.lineage,
                    revision.revision,
                    entry.height(),
                    entry.hash()
                ],
            )
            .map_err(failure)?;
        Ok(true)
    }

    /// Whether a batch before this pass may have handed `revision` to the
    /// wallet. This pass's own exports are recorded only by [`Pass::export`].
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

    /// Defers the batch: a stored fact names a shard the map does not publish,
    /// or a revision it no longer names, or a shard ends on a block the
    /// wallet's chain does not hold.
    pub(crate) fn defer(&mut self) {
        self.pending = true;
    }

    /// Classifies every exported row the map no longer publishes unchanged, by
    /// the first rule that matches:
    ///
    /// 1. its shard id is in the map under another source: `Retired`;
    /// 2. its shard id is beyond the map's last shard (the map is behind):
    ///    pending;
    /// 3. it is sealed: `ChangedSealed`, unless the map publishes its shard
    ///    unsealed below it (a replica behind the seal), which is pending;
    /// 4. this batch commits its source at a higher lineage: replaced;
    /// 5. otherwise: pending.
    ///
    /// `published` is every revision the map publishes, and `committed` maps
    /// each source with a commit in this batch to that commit's lineage. Returns
    /// the replaced rows, as the wallet identifies them.
    pub(crate) fn settle(
        &mut self,
        published: &[Published],
        committed: &BTreeMap<&[u8], u64>,
    ) -> Result<Vec<RecoveryRevision>, RecoveryError> {
        let published: BTreeMap<u64, &RecoveryRevision> = published
            .iter()
            .map(|entry| (entry.shard_id, &entry.revision))
            .collect();
        let mut statement = self
            .tx
            .prepare(
                "SELECT source, revision, shard_id, sealed, lineage, height, hash
                 FROM pir_bridge_catalog
                 WHERE exported=1 AND current=0 ORDER BY shard_id DESC, lineage DESC",
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
        for (row, shard_id, sealed, lineage) in rows {
            match published.get(&shard_id) {
                Some(entry) if entry.source != row.source => self.withdraw(WithdrawnCause::Retired),
                // Shard ids are gapless from 0, so a missing one is beyond the
                // map's last shard: the map is behind.
                None => self.pending = true,
                // The shard published unsealed below the sealed revision: a
                // replica that has not caught up with the seal.
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
        }
        Ok(())
    }

    /// Prunes the catalog, and the store's caches to the revisions `digests`
    /// names, then commits the pass.
    pub(crate) fn finish(self, digests: &[&str]) -> Result<(), RecoveryError> {
        prune_catalog(&self.tx)?;
        let named = serde_json::to_string(digests).map_err(failure)?;
        for table in ["filter_cache", "setup_cache"] {
            self.tx
                .execute(
                    &format!(
                        "DELETE FROM {table} WHERE revision_digest NOT IN (SELECT value FROM json_each(:named))"
                    ),
                    named_params![":named": named],
                )
                .map_err(failure)?;
        }
        // The store reads only the last commit id.
        self.tx
            .execute(
                "DELETE FROM commits WHERE id < (SELECT MAX(id) FROM commits)",
                [],
            )
            .map_err(failure)?;
        self.tx.commit().map_err(failure)
    }
}

/// Clears the export intent of `replaced` rows, whose successors the wallet
/// applied after reconciling them, and prunes the catalog. The batch's own
/// revisions were recorded as exported by its pass.
pub(crate) fn acknowledge(
    conn: &mut Connection,
    replaced: &[RecoveryRevision],
) -> Result<(), RecoveryError> {
    let tx = acknowledgment_transaction(conn)?;
    acknowledge_in_transaction(&tx, replaced)?;
    tx.commit().map_err(failure)
}

pub(crate) fn acknowledgment_transaction(
    conn: &mut Connection,
) -> Result<Transaction<'_>, RecoveryError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failure)
}

pub(crate) fn acknowledge_in_transaction(
    tx: &Transaction<'_>,
    replaced: &[RecoveryRevision],
) -> Result<(), RecoveryError> {
    for row in replaced {
        tx.execute(
            "UPDATE pir_bridge_catalog SET exported=0 WHERE source=?1 AND revision=?2 AND current=0",
            params![row.source, row.revision],
        )
        .map_err(failure)?;
    }
    prune_catalog(tx)
}

/// Whether any batch may have handed a revision to the wallet.
pub(crate) fn exported_any(conn: &Connection) -> Result<bool, RecoveryError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pir_bridge_catalog WHERE exported=1)",
        [],
        |row| row.get(0),
    )
    .map_err(failure)
}

/// Restarts the companion's store for a publication whose set identity no
/// longer continues the one the store is bound to, in one transaction.
///
/// Every store table is emptied, and `wallet_meta` keeps only the schema
/// version, so the next sync binds the new set and retrieves from the floor.
/// The catalog stays: each source keeps its highest lineage, so a source the
/// new set leaves unchanged still recognizes a restarted revision number. Rows
/// of sources none of `published` names lose their export mark, because no
/// commit can succeed them, so no batch reports them as retired revisions, even
/// those a batch already listed and nobody acknowledged; the wallet keeps their
/// evidence as it is, and a later batch completes its pages under them once it
/// covers their ranges.
pub(crate) fn reset(conn: &mut Connection, published: &[Published]) -> Result<(), RecoveryError> {
    let named: BTreeSet<&[u8]> = published
        .iter()
        .map(|entry| entry.revision.source.as_slice())
        .collect();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failure)?;
    tx.execute("DELETE FROM wallet_meta WHERE key<>'schema_version'", [])
        .map_err(failure)?;
    for table in STORE_TABLES {
        tx.execute(&format!("DELETE FROM {table}"), [])
            .map_err(failure)?;
    }
    let exported = tx
        .prepare("SELECT DISTINCT source FROM pir_bridge_catalog WHERE exported=1")
        .map_err(failure)?
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(failure)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(failure)?;
    for source in exported {
        if !named.contains(source.as_slice()) {
            tx.execute(
                "UPDATE pir_bridge_catalog SET exported=0 WHERE source=?1",
                [&source],
            )
            .map_err(failure)?;
        }
    }
    tx.commit().map_err(failure)
}

/// Forgets rows that are neither published nor exported. Each source's newest
/// row stays, so a later regression or lagging replica is still recognized.
fn prune_catalog(tx: &Transaction<'_>) -> Result<(), RecoveryError> {
    tx.execute(
        "DELETE FROM pir_bridge_catalog WHERE current=0 AND exported=0
         AND lineage < (SELECT MAX(m.lineage) FROM pir_bridge_catalog m WHERE m.source=pir_bridge_catalog.source)",
        [],
    )
    .map(|_| ())
    .map_err(failure)
}
