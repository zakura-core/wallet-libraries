//! The companion's revision catalog: stable revision identities, what each
//! source has published, and which revisions a batch may have handed to the
//! wallet.
//!
//! Identities are derived, never counted, so any companion bound to the same
//! account, origin and schema derives the triples the wallet already holds. The
//! catalog lets a pass tell a publication that is merely behind (`Pending`) from
//! one that contradicts what this companion recorded (`Withdrawn`); only a
//! `Ready` pass returns commits.
//!
//! A re-cut the map declares keeps the identities the wallet holds: a sealed
//! revision it superseded stays current, and facts stored under it are still
//! exported under it. Only an undeclared change of sealed content withdraws.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, named_params, params,
};
use sha2::{Digest, Sha256};
use transparent_filter::{ShardMapEntry, SupersededShard};
use transparent_wallet::SetIdentity;
use zcash_client_backend::data_api::transparent_ledger::{PublicationAnchor, RecoveryRevision};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::recovery::{RecoveryError, block, block_hash, failure, require};

/// The companion layout this build creates and reads.
const FORMAT: &str = "transparent-reference-companion-v3";

/// The previous layout, whose catalog [`prepare`] rebuilds in place.
const FORMAT_V2: &str = "transparent-reference-companion-v2";

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

const BINDING: &str =
    "CREATE TABLE pir_bridge_binding (key TEXT PRIMARY KEY, value BLOB NOT NULL);";

const CATALOG: &str = "CREATE TABLE pir_bridge_catalog (
        source BLOB NOT NULL CHECK(length(source)=32),
        start_height INTEGER NOT NULL CHECK(start_height>=0),
        digest TEXT NOT NULL,
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        exported INTEGER NOT NULL DEFAULT 0 CHECK(exported IN (0,1)),
        current INTEGER NOT NULL DEFAULT 0 CHECK(current IN (0,1)),
        PRIMARY KEY(source,digest,sealed), UNIQUE(source,lineage), UNIQUE(source,revision));";

/// Every revision a batch handed to the wallet, never pruned. The wallet keeps
/// every revision it registered for good, so no later revision may reach it at
/// the source and lineage of one it holds under another identity, even once
/// the catalog pruned that row.
const EXPORTS: &str = "CREATE TABLE IF NOT EXISTS pir_bridge_exports (
        source BLOB NOT NULL CHECK(length(source)=32),
        lineage INTEGER NOT NULL CHECK(lineage>0),
        revision BLOB NOT NULL CHECK(length(revision)=32),
        sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
        height INTEGER NOT NULL CHECK(height>=0 AND height<=4294967295),
        hash BLOB NOT NULL CHECK(length(hash)=32),
        PRIMARY KEY(source,lineage), UNIQUE(source,revision));";

/// Whether a pass's commits may reach the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchState {
    /// The publication agrees with everything this companion recorded, and every
    /// revision it exported is still published, declared superseded by a
    /// re-cut, or has a successor at a higher lineage among the batch's
    /// commits. Apply the commits, then acknowledge.
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
    /// a revision the companion saw, even a sealed one), a map ending below an
    /// exported revision, stored facts naming a revision the map neither
    /// publishes nor declares, a shard ending on a block the wallet's chain
    /// does not hold, or an exported tail whose successor is not retrieved yet,
    /// or a store a publication change reset that has not bound the new set
    /// again. A publication that diverged from what the sync read (a map
    /// refreshed mid-pass that does not continue the one the pass started from,
    /// or, at this wallet-pir pin, one rewriting sealed history the store holds
    /// without declaring a re-cut), a map under another set that ends below the
    /// height the store synced to, and a map from before a re-cut the store
    /// already followed (a lower re-cut epoch than this companion recorded) are
    /// also `Pending`, with
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
    /// recorded for its source, or a shard is published below a revision the
    /// map declares a re-cut superseded in its source.
    Regression,
    /// One revision of a source is published or declared as two different
    /// shard revisions, or a re-cut declares a revision otherwise than this
    /// companion recorded it.
    Equivocation,
    /// A sealed revision a batch exported is neither published nor declared
    /// superseded by a re-cut, and its source is published at another revision
    /// that is not merely an older unsealed one. A declared re-cut never
    /// causes it.
    ChangedSealed,
    /// The heights of a revision a batch exported are published under another
    /// source, as after a geometry change or an undeclared re-cut. A declared
    /// re-cut never causes it.
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
/// one is bound to `binding` and brings a v2 companion to this format.
///
/// The catalog keeps, never pruned, every revision a batch exported
/// (`pir_bridge_exports`): the wallet keeps every revision it registered.
///
/// A v1 companion counted lineage per companion, which no recreated companion
/// can reproduce, so it is refused rather than migrated. A v2 catalog derived
/// its sources from shard ids, which a re-cut renumbers. Its catalog is rebuilt
/// empty in place, and its store is kept: the next pass exports the stored facts
/// again under v3 sources without retrieving anything. The application keys
/// companion files by origin and schema only, so a new file is no option.
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
        format
            .as_deref()
            .is_none_or(|format| format == FORMAT || format == FORMAT_V2),
        "unsupported companion format",
    )?;
    if !bound {
        tx.execute_batch(BINDING).map_err(failure)?;
        tx.execute_batch(CATALOG).map_err(failure)?;
        tx.execute(
            "INSERT INTO pir_bridge_binding (key, value) VALUES ('format', ?1), ('account-source', ?2)",
            params![FORMAT, binding.as_slice()],
        )
        .map_err(failure)?;
        record_epoch(&tx, 0)?;
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
    if format.as_deref() == Some(FORMAT_V2) {
        tx.execute_batch("DROP TABLE pir_bridge_catalog;")
            .map_err(failure)?;
        tx.execute_batch(CATALOG).map_err(failure)?;
        tx.execute(
            "UPDATE pir_bridge_binding SET value=?1 WHERE key='format'",
            [FORMAT],
        )
        .map_err(failure)?;
        record_epoch(&tx, 0)?;
    }
    if !has("pir_bridge_exports")? {
        tx.execute_batch(EXPORTS).map_err(failure)?;
        // A companion of this format from before the record began.
        tx.execute(
            "INSERT OR IGNORE INTO pir_bridge_exports (source, lineage, revision, sealed, height, hash)
             SELECT source, lineage, revision, sealed, height, hash FROM pir_bridge_catalog
             WHERE exported=1",
            [],
        )
        .map_err(failure)?;
    }
    tx.commit().map_err(failure)
}

/// The highest re-cut epoch of a map whose ready pass found that this
/// companion's store followed its newest re-cut, zero if none since the store
/// last started.
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

fn record_epoch(tx: &Transaction<'_>, epoch: u32) -> Result<(), RecoveryError> {
    tx.execute(
        "INSERT OR REPLACE INTO pir_bridge_binding (key, value) VALUES ('recut-epoch', ?1)",
        [i64::from(epoch)],
    )
    .map(|_| ())
    .map_err(failure)
}

/// One shard revision a map publishes, or one a re-cut it declares superseded,
/// identified as the wallet and the catalog identify it.
#[derive(Clone)]
pub(crate) struct Published {
    /// The shard id it is published, or was published, under. Manifests bind
    /// the id, so a stored fact under this revision must name it.
    pub(crate) shard_id: u64,
    pub(crate) start_height: u64,
    pub(crate) end_height: u64,
    pub(crate) digest: String,
    /// The block the revision ends on, display hex.
    pub(crate) terminal: String,
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
        Self::new(
            binding,
            set,
            Shape {
                shard_id: entry.shard_id,
                geometry: &entry.geometry,
                start_height: entry.start_height,
                end_height: entry.end_height,
                terminal: &entry.terminal_block_hash,
                digest: &entry.manifest_digest,
                revision: entry.revision,
                sealed: entry.sealed,
            },
        )
    }

    /// A revision a re-cut of a publication whose set identity is `set`
    /// declares superseded, exactly as the wallet received it when it was
    /// published, for a companion bound to `binding`.
    pub(crate) fn declared(
        binding: &[u8; 32],
        set: &SetIdentity,
        shard: &SupersededShard,
    ) -> Result<Self, RecoveryError> {
        Self::new(
            binding,
            set,
            Shape {
                shard_id: shard.shard_id,
                geometry: &shard.geometry,
                start_height: shard.start_height,
                end_height: shard.end_height,
                terminal: &shard.terminal_block_hash,
                digest: &shard.manifest_digest,
                revision: shard.revision,
                sealed: shard.sealed,
            },
        )
    }

    fn new(binding: &[u8; 32], set: &SetIdentity, shape: Shape<'_>) -> Result<Self, RecoveryError> {
        Ok(Self {
            shard_id: shape.shard_id,
            start_height: shape.start_height,
            end_height: shape.end_height,
            digest: shape.digest.to_owned(),
            terminal: shape.terminal.to_owned(),
            revision: RecoveryRevision {
                source: source(binding, set, shape.geometry, shape.start_height)?.to_vec(),
                revision: revision(shape.digest, shape.sealed).to_vec(),
                // The publisher's revision number, offset so a first
                // publication is lineage 1.
                lineage: u64::from(shape.revision) + 1,
                sealed: shape.sealed,
                publication: PublicationAnchor {
                    height: block(shape.end_height)?,
                    hash: block_hash(shape.terminal)?,
                },
            },
        })
    }

    /// Where this revision's commit is kept while a pass builds its batch: two
    /// revisions of one source share a start height but not a digest.
    pub(crate) fn key(&self) -> (u64, String) {
        (self.start_height, self.digest.clone())
    }

    fn height(&self) -> u32 {
        u32::from(self.revision.publication.height)
    }

    fn hash(&self) -> &[u8] {
        self.revision.publication.hash.0.as_slice()
    }
}

/// The fields of a map entry, published or superseded, that identify it.
struct Shape<'a> {
    shard_id: u64,
    geometry: &'a str,
    start_height: u64,
    end_height: u64,
    terminal: &'a str,
    digest: &'a str,
    revision: u32,
    sealed: bool,
}

/// The stable identity of the shards of a publication that start at
/// `start_height` under `geometry`, for one companion binding.
///
/// It hashes the set-identity fields [`SetIdentity::continues`] holds fixed,
/// plus the geometry, that geometry's seal parameters and the start height,
/// and not the shard id. A re-cut renumbers every later shard and the tail
/// without changing where they start, so their next revisions stay in the
/// sources the wallet holds, while a re-cut range, which starts elsewhere or
/// under another geometry, gets new sources. A set growing into a new geometry
/// tier changes no existing source, and a set-identity change `continues`
/// refuses changes every source it affects.
pub(crate) fn source(
    binding: &[u8; 32],
    set: &SetIdentity,
    geometry: &str,
    start_height: u64,
) -> Result<[u8; 32], RecoveryError> {
    let seal = set
        .seal
        .get(geometry)
        .ok_or_else(|| RecoveryError::Invalid("shard geometry has no seal parameters".into()))?;
    // Canonical: serde writes the fields in declaration order.
    let seal = serde_json::to_vec(seal).map_err(failure)?;
    let mut hash = Sha256::new();
    hash.update(b"transparent-reference-source-v3");
    hash.update(binding);
    length_prefixed(&mut hash, set.shard_schema.as_bytes());
    length_prefixed(&mut hash, set.network.as_bytes());
    length_prefixed(&mut hash, set.genesis_hash.as_bytes());
    length_prefixed(&mut hash, set.profile.as_bytes());
    hash.update(set.range_envelope_version.to_le_bytes());
    hash.update(set.start_height.to_le_bytes());
    length_prefixed(&mut hash, geometry.as_bytes());
    length_prefixed(&mut hash, &seal);
    hash.update(start_height.to_le_bytes());
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

/// One pass's catalog transaction. Dropping it without [`Pass::finish`] changes
/// nothing.
pub(crate) struct Pass<'c> {
    tx: Transaction<'c>,
    withdrawn: Option<WithdrawnCause>,
    pending: bool,
}

impl<'c> Pass<'c> {
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
        for entry in published.iter().chain(declared) {
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

    /// Checks the map's re-cut declarations against what it publishes and
    /// against each other, needing no catalog history, so a recreated
    /// companion checks them too.
    ///
    /// A published revision in the source of a declared one must have a higher
    /// lineage: equal is an `Equivocation`, lower a `Regression`. Two declared
    /// revisions of one source at one lineage that differ are an
    /// `Equivocation`. `declarations` is every revision the map declares, the
    /// superseded tails included.
    pub(crate) fn check_declarations(
        &mut self,
        published: &[Published],
        declarations: &[Published],
    ) {
        for (index, declared) in declarations.iter().enumerate() {
            let ours = &declared.revision;
            for entry in published {
                let theirs = &entry.revision;
                if theirs.source != ours.source {
                    continue;
                }
                if theirs.lineage == ours.lineage {
                    self.withdraw(WithdrawnCause::Equivocation);
                } else if theirs.lineage < ours.lineage {
                    self.withdraw(WithdrawnCause::Regression);
                }
            }
            if declarations[index + 1..].iter().any(|other| {
                other.revision.source == ours.source
                    && other.revision.lineage == ours.lineage
                    && other.revision != *ours
            }) {
                self.withdraw(WithdrawnCause::Equivocation);
            }
        }
    }

    /// Classifies a published revision this pass may export, recording it when
    /// it is new. Returns whether a commit may be built for it: not for a
    /// lagging revision, which defers the batch and is not recorded, nor for one
    /// that withdraws it.
    pub(crate) fn classify(&mut self, entry: &Published) -> Result<bool, RecoveryError> {
        let revision = &entry.revision;
        if let Some(same) = self.recorded(entry)? {
            return Ok(same);
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
        if let Some(same) = self.recorded(entry)? {
            return Ok(same);
        }
        self.insert(entry)?;
        Ok(true)
    }

    /// Whether the catalog records `entry` exactly (`Some(true)`), records
    /// something that contradicts it (`Some(false)`, withdrawing the batch as
    /// an `Equivocation`), or neither.
    ///
    /// A contradiction is a row of its source with its digest and sealing at
    /// another lineage or endpoint, a row of its source at its lineage with
    /// another digest or sealing, or a revision ever exported at its source
    /// and lineage, or under its identity, that differs from it: the wallet
    /// would refuse it as an integrity failure and quarantine the account.
    fn recorded(&mut self, entry: &Published) -> Result<Option<bool>, RecoveryError> {
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
            return Ok(Some(false));
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
            }
            return Ok(Some(same));
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
            return Ok(Some(false));
        }
        Ok(None)
    }

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
    /// The recorded epoch only rises: a map below it is one the store moved
    /// past, which the next pass waits out rather than syncs against. A pass
    /// gives one only when it is ready and the store holds a fact under a
    /// revision the map's newest re-cut superseded, or under one it publishes
    /// at or above that re-cut's first height, so a map whose declaration is
    /// refused, or whose re-cut the store did not follow, cannot raise it. A
    /// re-cut therefore only rolls forward: undoing one takes another re-cut at
    /// a higher epoch.
    pub(crate) fn finish(self, digests: &[&str], epoch: Option<u32>) -> Result<(), RecoveryError> {
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
        if let Some(epoch) = epoch {
            let recorded = recut_epoch(&self.tx)?;
            record_epoch(&self.tx, recorded.max(epoch))?;
        }
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
/// The recorded re-cut epoch is cleared with it: the empty store follows no
/// map. The catalog stays: each source keeps its highest lineage, so a source
/// the new set leaves unchanged still recognizes a restarted revision number.
/// Rows of sources that none of `named`, the map's published and declared
/// revisions, names lose their export mark, because no commit can succeed
/// them, so no batch reports them as retired revisions, even those a batch
/// already listed and nobody acknowledged; the wallet keeps their evidence as
/// it is, and a later batch completes its pages under them once it covers
/// their ranges.
pub(crate) fn reset(conn: &mut Connection, named: &[Published]) -> Result<(), RecoveryError> {
    let named: BTreeSet<&[u8]> = named
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
    record_epoch(&tx, 0)?;
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

/// Forgets rows that are neither current nor exported. Each source's newest
/// row stays, so a later regression or lagging replica is still recognized,
/// and `pir_bridge_exports` keeps every exported revision, so a pruned one
/// still refuses a revision that would collide with it in the wallet.
fn prune_catalog(tx: &Transaction<'_>) -> Result<(), RecoveryError> {
    tx.execute(
        "DELETE FROM pir_bridge_catalog WHERE current=0 AND exported=0
         AND lineage < (SELECT MAX(m.lineage) FROM pir_bridge_catalog m WHERE m.source=pir_bridge_catalog.source)",
        [],
    )
    .map(|_| ())
    .map_err(failure)
}
