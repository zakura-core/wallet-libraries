//! The private transparent ledger's memory: what it has recovered, which
//! scripts it is responsible for and over which ranges each is covered, what it
//! accepted as the chain's anchor, and what private work it still owes.
//!
//! This is the wallet's implementation of the durable store the retrieval
//! library (`transparent-wallet`, from `valargroup/enhance-pir`) requires of a
//! returning wallet. The library's trait is not implemented here — this crate
//! stays free of the PIR stack so the sync engine does not carry it — but every
//! rule the trait states is enforced here, in the wallet's own database and in
//! the same transaction as the wallet's own rows. The adapter in
//! `zakura-wallet-transparent` is a type mapping and nothing more.
//!
//! # One commit per shard
//!
//! Everything a shard yields is committed together — its events, the coverage
//! it establishes for each script, the page work still owed, and the
//! *projection* of those events into the wallet's own output and spend tables
//! — or none of it is. A crash between two commits loses at most one shard's
//! retrieval, which the next sync repeats; it never records coverage for events
//! it did not keep. Retrying a commit is idempotent by construction: events are
//! keyed by their stable identities, coverage by script and range, and a repeat
//! that *differs* in any field is a contradiction, refused before anything is
//! written.
//!
//! # Two tables, not one
//!
//! The events are kept in their own tables, apart from
//! `transparent_received_outputs`. That table is the wallet's view — what the
//! balance and the history read — and it is also written by a send this
//! installation built and by a transaction enhancement fetched whole. Neither of
//! those may feed the library's ledger back to it, so the ledger reads only what
//! the ledger wrote.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, Transaction, named_params};
use zakura_wallet_core::AccountId;
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::{Error, RecoveredOutput, RecoveredSpend, WalletDb, apply, schema::CACHE_SCHEMA};

/// The most page retrievals a commit may leave owed.
///
/// A bound on how much private work the wallet will carry, not a budget for
/// one sync: reaching it ends a sync incomplete with everything so far kept.
pub const DEFAULT_PENDING_LIMIT: usize = 4_096;

/// The longest script the private tables index.
///
/// The shard layout's limit, restated here so the wallet can count what falls
/// outside it without decoding a manifest. The adapter asserts the two agree.
pub const MAX_INDEXABLE_SCRIPT_BYTES: usize = 40;

/// The publication lineage the store is bound to, as the library describes it.
///
/// Opaque here. What binds and what continues a lineage is the library's rule;
/// this crate keeps the description and its digest and hands them back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentSet {
    /// The lineage's digest.
    pub digest: String,
    /// The lineage, serialised by the library.
    pub identity_json: String,
}

/// The chain block the ledger has accepted as the end of its coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentAnchor {
    /// The anchor's height.
    pub height: BlockHeight,
    /// Its block hash in display hex. A rollback records the accepted ancestor;
    /// an unscanned rewind clears the anchor instead of inventing a hash.
    pub hash: String,
}

/// One script the ledger is responsible for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentScript {
    /// The `scriptPubKey`.
    pub script: Vec<u8>,
    /// Whose it is.
    pub account: AccountId,
    /// Whether it was imported rather than derived; its history may then begin
    /// anywhere.
    pub imported: bool,
    /// The first height the wallet needs covered for it. Never raised once set.
    pub required_from: BlockHeight,
}

/// Whether a coverage range rests on a sealed shard or an unsealed tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageKind {
    /// From a sealed shard. Immutable short of a reorg.
    Settled,
    /// From an unsealed tail revision. Replaced when the tail is republished.
    Provisional,
}

impl CoverageKind {
    fn as_str(self) -> &'static str {
        match self {
            CoverageKind::Settled => "settled",
            CoverageKind::Provisional => "provisional",
        }
    }

    fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "settled" => Ok(CoverageKind::Settled),
            "provisional" => Ok(CoverageKind::Provisional),
            other => Err(Error::Corrupt(format!(
                "a transparent coverage row is of kind {other:?}, which this wallet does not write"
            ))),
        }
    }
}

/// One script's coverage over one shard's range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRange {
    /// The script covered.
    pub script: Vec<u8>,
    /// The first height of the range.
    pub start_height: BlockHeight,
    /// The last height of the range.
    pub end_height: BlockHeight,
    /// Sealed or provisional.
    pub kind: CoverageKind,
    /// The shard the range was read from.
    pub shard_id: u64,
    /// The revision of that shard.
    pub revision_digest: String,
    /// The block hash the range rests on, in display hex.
    pub terminal_block_hash: String,
    /// Original full publication endpoint, before clipping to the accepted target.
    pub source_anchor: Option<TransparentAnchor>,
}

/// The stable identity of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKey {
    /// A receive, by outpoint.
    Receive {
        /// The creating transaction.
        txid: TxId,
        /// The output's index in it.
        output_index: u32,
    },
    /// A spend, by the consuming input and the outpoint it consumed.
    Spend {
        /// The spending transaction.
        spending_txid: TxId,
        /// Which of its inputs.
        input_index: u32,
        /// The transaction that created the consumed output.
        spent_txid: TxId,
        /// The consumed output's index.
        spent_output_index: u32,
    },
}

/// One event the ledger keeps, with where it came from.
///
/// `record` is the protocol's fixed-width encoding, opaque to this crate. The
/// fields beside it are what this crate keys, counts and rolls back by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEvent {
    /// Its identity.
    pub key: EventKey,
    /// The script it was indexed under.
    pub script: Vec<u8>,
    /// The height it happened at.
    pub height: BlockHeight,
    /// The encoded event.
    pub record: Vec<u8>,
    /// The shard it was read from.
    pub shard_id: u64,
    /// The revision of that shard.
    pub revision_digest: String,
}

/// Page retrievals still owed for one script in one shard revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPages {
    /// Assigned by the store; `None` until first committed.
    pub id: Option<u64>,
    /// The shard.
    pub shard_id: u64,
    /// Its revision.
    pub revision_digest: String,
    /// The script whose pages are owed.
    pub script: Vec<u8>,
    /// The first page's ordinal.
    pub first_page: u32,
    /// How many pages there are.
    pub page_count: u32,
    /// How many events they hold in total.
    pub total_events: u32,
    /// Events already known from the directory entry, encoded back to back.
    pub inline: Vec<u8>,
    /// The next page ordinal to fetch; pages below it are committed.
    pub next_ordinal: u32,
    /// How many times fetching has been attempted.
    pub attempts: u32,
    /// Records validated, including records above the accepted target.
    pub validated_events: u32,
    /// Wallet target this page progress belongs to.
    pub target_anchor: Option<TransparentAnchor>,
}

/// What one shard's retrieval commits, all at once.
#[derive(Debug, Clone)]
pub struct ShardCommit {
    /// The shard.
    pub shard_id: u64,
    /// Its revision.
    pub revision_digest: String,
    /// Whether the revision is sealed.
    pub sealed: bool,
    /// The first height the shard covers.
    pub start_height: BlockHeight,
    /// The last height it covers.
    pub end_height: BlockHeight,
    /// The block hash at `end_height`, in display hex.
    pub terminal_block_hash: String,
    /// Original full publication endpoint, before clipping to the accepted target.
    pub source_anchor: Option<TransparentAnchor>,
    /// The events retrieved.
    pub events: Vec<LedgerEvent>,
    /// The same receives, as the wallet's projection wants them.
    pub outputs: Vec<RecoveredOutput>,
    /// The same spends, as the wallet's projection wants them.
    pub spends: Vec<RecoveredSpend>,
    /// Scripts whose coverage this commit extends over the shard's range.
    pub covered_scripts: Vec<Vec<u8>>,
    /// Pending page work created or advanced by this commit.
    pub pending_upsert: Vec<PendingPages>,
    /// Pending ids this commit finishes.
    pub pending_complete: Vec<u64>,
}

/// What a setup is keyed by: the set lineage, the exact revision, the table and
/// the segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupKey {
    /// The lineage's digest.
    pub set_digest: String,
    /// The revision's digest.
    pub revision_digest: String,
    /// The table, as the library names it.
    pub table: String,
    /// The segment.
    pub segment: u32,
}

/// Published setup parameters for one table segment, kept for reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupParams {
    /// The parameters, as published.
    pub public_params_base64: String,
    /// Their digest, as published.
    pub public_params_sha256: String,
}

/// How far the ledger has read on behalf of one script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptCoverage {
    /// The `scriptPubKey`.
    pub script: Vec<u8>,
    /// Whose it is.
    pub account: AccountId,
    /// The last height covered contiguously from the script's required height
    /// by sealed shards alone.
    pub settled_through: BlockHeight,
    /// The same, counting provisional coverage too.
    pub covered_through: BlockHeight,
}

/// What the wallet can say about how current its transparent balance is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentState {
    /// The lowest settled coverage across the account's scripts.
    ///
    /// `None` when the account watches no transparent script at all.
    pub settled_through: Option<BlockHeight>,
    /// The lowest coverage, including growing tails.
    pub covered_through: Option<BlockHeight>,
    /// Spends the ledger could not resolve to an output it holds. Non-zero
    /// forbids calling the balance synchronized.
    pub unresolved_spends: u32,
    /// How many unsealed revisions the current coverage rests on.
    pub provisional_shards: u32,
    /// Page retrievals still owed.
    pub pending_pages: u32,
    /// The anchor the ledger accepted, if any.
    pub anchor: Option<TransparentAnchor>,
    /// Why the last sync stopped, as the library states it: `complete`, or
    /// the reason it stopped short. `None` before any sync.
    pub completion: Option<String>,
    /// Scripts of this account the private tables cannot index, so their
    /// history is outside what this path recovers. Counted from the address
    /// rows, so it survives a restart and is known before any sync. Non-zero
    /// forbids calling the balance synchronized.
    pub outside_coverage: u32,
}

/// Why a shard commit was refused.
///
/// Nothing is written when one of these is returned. A contradiction is a
/// repeat that differs — the same outpoint received with another value, the
/// same output spent by another transaction — and it is reported rather than
/// resolved, because either version could be the wrong one.
#[derive(Debug)]
pub enum CommitError {
    /// An outpoint already held, with different contents.
    ConflictingReceive {
        /// The creating transaction.
        txid: TxId,
        /// The output's index.
        output_index: u32,
    },
    /// An output already spent, by a different transaction.
    DoubleSpend {
        /// The transaction that created the twice-spent output.
        spent_txid: TxId,
        /// Its index.
        spent_output_index: u32,
    },
    /// The commit would leave more page retrievals owed than the store holds.
    PendingLimit {
        /// The bound.
        limit: usize,
    },
    /// The database failed.
    Store(Error),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::ConflictingReceive { txid, output_index } => write!(
                f,
                "output {output_index} of {txid} was received before with different contents"
            ),
            CommitError::DoubleSpend {
                spent_txid,
                spent_output_index,
            } => write!(
                f,
                "output {spent_output_index} of {spent_txid} is already spent by another transaction"
            ),
            CommitError::PendingLimit { limit } => write!(
                f,
                "the commit would leave more than {limit} page retrievals owed"
            ),
            CommitError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CommitError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Error> for CommitError {
    fn from(e: Error) -> Self {
        CommitError::Store(e)
    }
}

impl From<rusqlite::Error> for CommitError {
    fn from(e: rusqlite::Error) -> Self {
        CommitError::Store(Error::Query(e))
    }
}

/// Transactions above `:height` that only the ledger produced.
///
/// A recovered transaction has a mined height and no block row, because the
/// ledger names heights and not blocks. One that also has a block row was
/// scanned, and belongs to the wallet's own rewind; one this installation
/// built or fetched whole is irreplaceable and is never deleted here.
const LEDGER_OWNED: &str = "SELECT t.id FROM cache.transactions t
     WHERE t.mined_height > :height
       AND t.block_height IS NULL
       AND t.target_height IS NULL
       AND NOT EXISTS (SELECT 1 FROM main.raw_transactions r WHERE r.txid = t.txid)
       AND NOT EXISTS (SELECT 1 FROM main.sent_outputs s WHERE s.txid = t.txid)";

fn record_commit(tx: &Transaction<'_>, kind: &str, detail: &str) -> Result<u64, Error> {
    tx.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.transparent_commits (kind, detail) VALUES (:kind, :detail)"
        ),
        named_params![":kind": kind, ":detail": detail],
    )?;
    Ok(tx.last_insert_rowid() as u64)
}

fn coverage_of(conn: &rusqlite::Connection, script: &[u8]) -> Result<Vec<CoverageRange>, Error> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT start_height, end_height, kind, shard_id, revision_digest, terminal_block_hash, source_height, source_hash
         FROM {CACHE_SCHEMA}.transparent_coverage
         WHERE script = :script
         ORDER BY start_height, end_height"
    ))?;
    let rows = stmt.query_map(named_params![":script": script], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            read_anchor(row, 6, 7)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (start, end, kind, shard, revision, terminal, source_anchor) = row?;
        out.push(CoverageRange {
            script: script.to_vec(),
            start_height: BlockHeight::from_u32(start),
            end_height: BlockHeight::from_u32(end),
            kind: CoverageKind::parse(&kind)?,
            shard_id: shard as u64,
            revision_digest: revision,
            terminal_block_hash: terminal,
            source_anchor,
        });
    }
    Ok(out)
}

/// The row one script holds at `start`, if any.
fn coverage_at(
    conn: &rusqlite::Connection,
    script: &[u8],
    start: BlockHeight,
) -> Result<Option<CoverageRange>, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT end_height, kind, shard_id, revision_digest, terminal_block_hash, source_height, source_hash
                 FROM {CACHE_SCHEMA}.transparent_coverage
                 WHERE script = :script AND start_height = :start"
            ),
            named_params![":script": script, ":start": u32::from(start)],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    read_anchor(row, 5, 6)?,
                ))
            },
        )
        .optional()?;
    row.map(|(end, kind, shard, revision, terminal, source_anchor)| {
        Ok(CoverageRange {
            script: script.to_vec(),
            start_height: start,
            end_height: BlockHeight::from_u32(end),
            kind: CoverageKind::parse(&kind)?,
            shard_id: shard as u64,
            revision_digest: revision,
            terminal_block_hash: terminal,
            source_anchor,
        })
    })
    .transpose()
}

/// Adds one range. The caller has established that no row shares its start.
fn insert_coverage(tx: &Transaction<'_>, range: &CoverageRange) -> Result<(), Error> {
    tx.execute(
        &format!(
            "INSERT INTO {CACHE_SCHEMA}.transparent_coverage
                (script, start_height, end_height, kind, shard_id, revision_digest,
                 terminal_block_hash, source_height, source_hash)
             VALUES (:script, :start, :end, :kind, :shard, :revision, :terminal, :source_height, :source_hash)"
        ),
        named_params![
            ":script": &range.script,
            ":start": u32::from(range.start_height),
            ":end": u32::from(range.end_height),
            ":kind": range.kind.as_str(),
            ":shard": range.shard_id as i64,
            ":revision": &range.revision_digest,
            ":terminal": &range.terminal_block_hash,
            ":source_height": range.source_anchor.as_ref().map(|a| u32::from(a.height)),
            ":source_hash": range.source_anchor.as_ref().map(|a| a.hash.as_str()),
        ],
    )?;
    Ok(())
}

/// Rewrites the one row at `range`'s start, in place.
fn replace_coverage(tx: &Transaction<'_>, range: &CoverageRange) -> Result<(), Error> {
    tx.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.transparent_coverage
             SET end_height = :end, kind = :kind, shard_id = :shard, revision_digest = :revision,
                 terminal_block_hash = :terminal, source_height = :source_height, source_hash = :source_hash
             WHERE script = :script AND start_height = :start"
        ),
        named_params![
            ":script": &range.script,
            ":start": u32::from(range.start_height),
            ":end": u32::from(range.end_height),
            ":kind": range.kind.as_str(),
            ":shard": range.shard_id as i64,
            ":revision": &range.revision_digest,
            ":terminal": &range.terminal_block_hash,
            ":source_height": range.source_anchor.as_ref().map(|a| u32::from(a.height)),
            ":source_hash": range.source_anchor.as_ref().map(|a| a.hash.as_str()),
        ],
    )?;
    Ok(())
}

/// Rewrites one script's ranges: sorted, exact repeats dropped, kept per shard.
///
/// Per shard rather than merged into runs, deliberately: each range carries the
/// block hash its coverage rests on, and a reorg is found by asking the
/// wallet's chain about those hashes newest first. Merging shards 0–2 into one
/// range would keep only shard 2's hash, and a reorg inside shard 1 would then
/// roll back to the set's start instead of to shard 0.
fn write_coverage(
    tx: &Transaction<'_>,
    script: &[u8],
    mut ranges: Vec<CoverageRange>,
) -> Result<(), Error> {
    ranges.sort_by_key(|r| (r.start_height, r.end_height));
    ranges.dedup();
    tx.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.transparent_coverage WHERE script = :script"),
        named_params![":script": script],
    )?;
    for range in &ranges {
        insert_coverage(tx, range)?;
    }
    Ok(())
}

/// The last height reached contiguously from `from` by `ranges`; one below
/// `from` when nothing starts there.
fn reach(ranges: &[CoverageRange], from: BlockHeight) -> BlockHeight {
    let mut sorted: Vec<&CoverageRange> = ranges.iter().collect();
    sorted.sort_by_key(|r| r.start_height);
    let mut next = u32::from(from);
    for range in sorted {
        if u32::from(range.end_height) < next {
            continue;
        }
        if u32::from(range.start_height) > next {
            break;
        }
        next = next.max(u32::from(range.end_height) + 1);
    }
    BlockHeight::from_u32(next.saturating_sub(1))
}

/// Removes everything the ledger holds above `height`, and lowers what rests
/// on it. Shared by the ledger's own rollback and the wallet's rewind.
pub(crate) fn rollback_above(
    tx: &Transaction<'_>,
    height: BlockHeight,
    reason: &str,
) -> Result<u64, Error> {
    let h = u32::from(height);
    let hash: Option<Vec<u8>> = tx
        .query_row(
            &format!("SELECT hash FROM {CACHE_SCHEMA}.blocks WHERE height = ?1"),
            [h],
            |row| row.get(0),
        )
        .optional()?;
    let hash = hash.map(|mut bytes| {
        bytes.reverse();
        hex::encode(bytes)
    });
    rollback_to(tx, height, hash.as_deref(), reason)
}

fn rollback_to(
    tx: &Transaction<'_>,
    height: BlockHeight,
    hash: Option<&str>,
    reason: &str,
) -> Result<u64, Error> {
    let h = u32::from(height);
    for table in ["transparent_receive_events", "transparent_spend_events"] {
        tx.execute(
            &format!("DELETE FROM {CACHE_SCHEMA}.{table} WHERE height > :height"),
            named_params![":height": h],
        )?;
    }
    tx.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.transparent_coverage WHERE start_height > :height"),
        named_params![":height": h],
    )?;
    tx.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.transparent_coverage SET end_height = :height, terminal_block_hash = :hash
             WHERE end_height > :height AND :hash IS NOT NULL"
        ),
        named_params![":height": h, ":hash": hash],
    )?;
    if hash.is_none() {
        tx.execute(
            &format!("DELETE FROM {CACHE_SCHEMA}.transparent_coverage WHERE end_height > ?1"),
            [h],
        )?;
    }
    tx.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.transparent_pending_pages"),
        [],
    )?;
    tx.execute(
        &format!(
            "UPDATE {CACHE_SCHEMA}.transparent_set
             SET anchor_height = CASE WHEN :hash IS NULL THEN NULL ELSE :height END, anchor_hash = :hash, completion = 'chain-rewound'
             WHERE anchor_height >= :height"
        ),
        named_params![":height": h, ":hash": hash],
    )?;
    for column in ["settled_through", "covered_through"] {
        tx.execute(
            &format!(
                "UPDATE {CACHE_SCHEMA}.transparent_set SET {column} = :height
                 WHERE {column} > :height"
            ),
            named_params![":height": h],
        )?;
    }

    // The projection follows the ledger. Spends made above the cut are
    // released, outputs created above it are gone, and what is left is what a
    // fresh sync of the surviving range would produce.
    tx.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.transparent_received_output_spends
             WHERE transaction_id IN ({LEDGER_OWNED})"
        ),
        named_params![":height": h],
    )?;
    tx.execute(
        &format!(
            "DELETE FROM {CACHE_SCHEMA}.transparent_received_outputs
             WHERE transaction_id IN ({LEDGER_OWNED})"
        ),
        named_params![":height": h],
    )?;
    tx.execute(
        &format!("DELETE FROM {CACHE_SCHEMA}.transactions WHERE id IN ({LEDGER_OWNED})"),
        named_params![":height": h],
    )?;
    apply::clamp_unspent_observation(tx, height)?;

    record_commit(tx, "rollback", &format!("{h}: {reason}"))
}

impl WalletDb {
    /// The most page retrievals a shard commit may leave owed.
    pub fn transparent_pending_limit(&self) -> usize {
        DEFAULT_PENDING_LIMIT
    }

    /// The publication lineage the ledger is bound to, if any.
    pub fn transparent_set(&self) -> Result<Option<TransparentSet>, Error> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                &format!("SELECT set_digest, identity_json FROM {CACHE_SCHEMA}.transparent_set WHERE id = 1"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row
            .filter(|(digest, _)| !digest.is_empty())
            .map(|(digest, identity_json)| TransparentSet {
                digest,
                identity_json,
            }))
    }

    /// Binds the ledger to a lineage, or records that a bound one continues.
    ///
    /// Whether the offered lineage continues the bound one is the library's
    /// decision, made before this is called; this only records the result.
    pub fn bind_transparent_set(&mut self, set: &TransparentSet) -> Result<(), Error> {
        self.conn.execute(
            &format!(
                "INSERT INTO {CACHE_SCHEMA}.transparent_set (id, set_digest, identity_json)
                 VALUES (1, :digest, :json)
                 ON CONFLICT (id) DO UPDATE SET
                    set_digest = :digest,
                    identity_json = :json"
            ),
            named_params![":digest": &set.digest, ":json": &set.identity_json],
        )?;
        Ok(())
    }

    /// The anchor the ledger accepted, if any.
    pub fn transparent_anchor(&self) -> Result<Option<TransparentAnchor>, Error> {
        let row: Option<(Option<u32>, Option<String>)> = self
            .conn
            .query_row(
                &format!("SELECT anchor_height, anchor_hash FROM {CACHE_SCHEMA}.transparent_set WHERE id = 1"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(height, hash)| {
            Some(TransparentAnchor {
                height: BlockHeight::from_u32(height?),
                hash: hash.unwrap_or_default(),
            })
        }))
    }

    /// Why the last sync stopped, as the library stated it.
    pub fn transparent_completion(&self) -> Result<Option<String>, Error> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT completion FROM {CACHE_SCHEMA}.transparent_set WHERE id = 1"),
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Records why a sync stopped.
    ///
    /// Recorded even before a lineage is bound, because a sync can stop before
    /// it reads a map — a service that refuses its schema, say — and that is
    /// still something the interface has to be able to say.
    pub fn put_transparent_completion(&mut self, completion: &str) -> Result<(), Error> {
        self.conn.execute(
            &format!(
                "INSERT INTO {CACHE_SCHEMA}.transparent_set (id, set_digest, identity_json, completion)
                 VALUES (1, '', '', :completion)
                 ON CONFLICT (id) DO UPDATE SET completion = :completion"
            ),
            named_params![":completion": completion],
        )?;
        Ok(())
    }

    /// Every script the ledger is responsible for.
    pub fn transparent_scripts(&self) -> Result<Vec<TransparentScript>, Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT script, account_id, imported, required_from
             FROM {CACHE_SCHEMA}.transparent_scripts ORDER BY script"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(TransparentScript {
                script: row.get(0)?,
                account: AccountId(row.get(1)?),
                imported: row.get::<_, i64>(2)? != 0,
                required_from: BlockHeight::from_u32(row.get(3)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Adds scripts, returning how many were new.
    ///
    /// An existing script's `required_from` is never raised: coverage once
    /// required stays required, because the old receive it keeps is what makes
    /// a recent spend resolvable.
    pub fn add_transparent_scripts(
        &mut self,
        scripts: &[TransparentScript],
    ) -> Result<usize, Error> {
        self.transactionally(|tx| {
            let mut added = 0;
            for script in scripts {
                let known: i64 = tx.query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {CACHE_SCHEMA}.transparent_scripts WHERE script = :script"
                    ),
                    named_params![":script": &script.script],
                    |row| row.get(0),
                )?;
                tx.execute(
                    &format!(
                        "INSERT INTO {CACHE_SCHEMA}.transparent_scripts
                            (script, account_id, imported, required_from)
                         VALUES (:script, :account, :imported, :from)
                         ON CONFLICT (script) DO UPDATE SET
                            required_from = MIN(required_from, :from)"
                    ),
                    named_params![
                        ":script": &script.script,
                        ":account": script.account.0,
                        ":imported": script.imported as i64,
                        ":from": u32::from(script.required_from),
                    ],
                )?;
                if known == 0 {
                    added += 1;
                }
            }
            Ok::<_, Error>(added)
        })
    }

    /// One script's coverage ranges, in height order.
    pub fn transparent_coverage_of(&self, script: &[u8]) -> Result<Vec<CoverageRange>, Error> {
        coverage_of(&self.conn, script)
    }

    /// Every provisional range across every script.
    pub fn transparent_provisional_coverage(&self) -> Result<Vec<CoverageRange>, Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT script, start_height, end_height, shard_id, revision_digest, terminal_block_hash, source_height, source_hash
             FROM {CACHE_SCHEMA}.transparent_coverage
             WHERE kind = 'provisional'
             ORDER BY script, start_height"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(CoverageRange {
                script: row.get(0)?,
                start_height: BlockHeight::from_u32(row.get(1)?),
                end_height: BlockHeight::from_u32(row.get(2)?),
                kind: CoverageKind::Provisional,
                shard_id: row.get::<_, i64>(3)? as u64,
                revision_digest: row.get(4)?,
                terminal_block_hash: row.get(5)?,
                source_anchor: read_anchor(row, 6, 7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every distinct block the ledger's coverage rests on, by height.
    ///
    /// What a sync asks the wallet's own chain about before it reads anything:
    /// a hash the wallet has since rejected at that height is a reorg.
    pub fn transparent_coverage_terminals(&self) -> Result<Vec<(BlockHeight, String)>, Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT DISTINCT end_height, terminal_block_hash
             FROM {CACHE_SCHEMA}.transparent_coverage ORDER BY end_height"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok((BlockHeight::from_u32(row.get(0)?), row.get::<_, String>(1)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every event the ledger keeps, receives then spends, each in height
    /// order. The library sorts them canonically before replaying.
    pub fn transparent_events(&self) -> Result<Vec<LedgerEvent>, Error> {
        let mut events = Vec::new();
        let mut receives = self.conn.prepare_cached(&format!(
            "SELECT txid, output_index, script, height, event, shard_id, revision_digest
             FROM {CACHE_SCHEMA}.transparent_receive_events ORDER BY height"
        ))?;
        let rows = receives.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        for row in rows {
            let (txid, output_index, script, height, record, shard_id, revision_digest) = row?;
            events.push(LedgerEvent {
                key: EventKey::Receive {
                    txid: txid_of(&txid)?,
                    output_index,
                },
                script,
                height: BlockHeight::from_u32(height),
                record,
                shard_id: shard_id as u64,
                revision_digest,
            });
        }
        let mut spends = self.conn.prepare_cached(&format!(
            "SELECT spending_txid, input_index, spent_txid, spent_output_index, script, height,
                    event, shard_id, revision_digest
             FROM {CACHE_SCHEMA}.transparent_spend_events ORDER BY height"
        ))?;
        let rows = spends.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, u32>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        for row in rows {
            let (
                spending,
                input_index,
                spent,
                spent_output_index,
                script,
                height,
                record,
                shard_id,
                revision_digest,
            ) = row?;
            events.push(LedgerEvent {
                key: EventKey::Spend {
                    spending_txid: txid_of(&spending)?,
                    input_index,
                    spent_txid: txid_of(&spent)?,
                    spent_output_index,
                },
                script,
                height: BlockHeight::from_u32(height),
                record,
                shard_id: shard_id as u64,
                revision_digest,
            });
        }
        Ok(events)
    }

    /// How many receives and spends the ledger keeps.
    pub fn transparent_event_counts(&self) -> Result<(u64, u64), Error> {
        let receives: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {CACHE_SCHEMA}.transparent_receive_events"),
            [],
            |row| row.get(0),
        )?;
        let spends: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {CACHE_SCHEMA}.transparent_spend_events"),
            [],
            |row| row.get(0),
        )?;
        Ok((receives as u64, spends as u64))
    }

    /// Commits one shard's retrieval, all of it or none of it.
    ///
    /// See the module documentation for what is checked before anything is
    /// written. Outputs at a script the wallet never derived are refused: a
    /// recovered event is indexed under the script it was stored under, so one
    /// naming a script this wallet does not own means the service answered
    /// about somebody else, and storing it would put another person's funds in
    /// this balance.
    pub fn commit_transparent_shard(&mut self, commit: &ShardCommit) -> Result<u64, CommitError> {
        let limit = self.transparent_pending_limit();
        self.transactionally(|tx| {
            // Contradictions first, before any write, so a refused commit
            // rolls back to exactly the prior state.
            // The database checks below also apply between records in this
            // very commit: INSERT OR IGNORE must not hide a conflicting retry.
            let mut receives = HashMap::new();
            let mut spends = HashMap::new();
            for event in &commit.events {
                match &event.key {
                    EventKey::Receive { txid, output_index } => {
                        if let Some(previous) = receives.insert((*txid, *output_index), event)
                            && (previous.script != event.script || previous.record != event.record) {
                                return Err(CommitError::ConflictingReceive { txid: *txid, output_index: *output_index });
                        }
                    }
                    EventKey::Spend { spent_txid, spent_output_index, .. } => {
                        if let Some(previous) = spends.insert((*spent_txid, *spent_output_index), event)
                            && (previous.key != event.key || previous.script != event.script || previous.record != event.record) {
                                return Err(CommitError::DoubleSpend { spent_txid: *spent_txid, spent_output_index: *spent_output_index });
                        }
                    }
                }
            }
            for event in &commit.events {
                match &event.key {
                    EventKey::Receive { txid, output_index } => {
                        let existing: Option<(Vec<u8>, Vec<u8>)> = tx
                            .query_row(
                                &format!(
                                    "SELECT script, event FROM {CACHE_SCHEMA}.transparent_receive_events
                                     WHERE txid = :txid AND output_index = :index"
                                ),
                                named_params![":txid": txid.as_ref(), ":index": output_index],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            )
                            .optional()?;
                        if let Some((script, record)) = existing
                            && (script != event.script || record != event.record)
                        {
                            return Err(CommitError::ConflictingReceive {
                                txid: *txid,
                                output_index: *output_index,
                            });
                        }
                    }
                    EventKey::Spend {
                        spending_txid,
                        input_index,
                        spent_txid,
                        spent_output_index,
                    } => {
                        type PriorSpend = (Vec<u8>, u32, Vec<u8>, Vec<u8>);
                        let existing: Option<PriorSpend> = tx
                            .query_row(
                                &format!(
                                    "SELECT spending_txid, input_index, event, script
                                     FROM {CACHE_SCHEMA}.transparent_spend_events
                                     WHERE spent_txid = :txid AND spent_output_index = :index"
                                ),
                                named_params![
                                    ":txid": spent_txid.as_ref(),
                                    ":index": spent_output_index
                                ],
                                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                            )
                            .optional()?;
                        if let Some((spending, input, record, script)) = existing
                            && (spending != spending_txid.as_ref()
                                || input != *input_index
                                || record != event.record || script != event.script)
                        {
                            return Err(CommitError::DoubleSpend {
                                spent_txid: *spent_txid,
                                spent_output_index: *spent_output_index,
                            });
                        }
                    }
                }
            }
            let pending_now: i64 = tx.query_row(
                &format!("SELECT COUNT(*) FROM {CACHE_SCHEMA}.transparent_pending_pages"),
                [],
                |row| row.get(0),
            )?;
            let new_items = commit
                .pending_upsert
                .iter()
                .filter(|p| p.id.is_none())
                .count() as i64;
            let finished = commit.pending_complete.len() as i64;
            if pending_now + new_items - finished > limit as i64 {
                return Err(CommitError::PendingLimit { limit });
            }

            for event in &commit.events {
                match &event.key {
                    EventKey::Receive { txid, output_index } => {
                        tx.execute(
                            &format!(
                                "INSERT OR IGNORE INTO {CACHE_SCHEMA}.transparent_receive_events
                                    (txid, output_index, script, height, event, shard_id,
                                     revision_digest)
                                 VALUES (:txid, :index, :script, :height, :event, :shard, :revision)"
                            ),
                            named_params![
                                ":txid": txid.as_ref(),
                                ":index": output_index,
                                ":script": &event.script,
                                ":height": u32::from(event.height),
                                ":event": &event.record,
                                ":shard": event.shard_id as i64,
                                ":revision": &event.revision_digest,
                            ],
                        )?;
                    }
                    EventKey::Spend {
                        spending_txid,
                        input_index,
                        spent_txid,
                        spent_output_index,
                    } => {
                        tx.execute(
                            &format!(
                                "INSERT OR IGNORE INTO {CACHE_SCHEMA}.transparent_spend_events
                                    (spending_txid, input_index, spent_txid, spent_output_index,
                                     script, height, event, shard_id, revision_digest)
                                 VALUES (:spending, :input, :spent, :spent_index, :script,
                                         :height, :event, :shard, :revision)"
                            ),
                            named_params![
                                ":spending": spending_txid.as_ref(),
                                ":input": input_index,
                                ":spent": spent_txid.as_ref(),
                                ":spent_index": spent_output_index,
                                ":script": &event.script,
                                ":height": u32::from(event.height),
                                ":event": &event.record,
                                ":shard": event.shard_id as i64,
                                ":revision": &event.revision_digest,
                            ],
                        )?;
                    }
                }
            }

            let kind = if commit.sealed {
                CoverageKind::Settled
            } else {
                CoverageKind::Provisional
            };
            for script in &commit.covered_scripts {
                let range = CoverageRange {
                    script: script.clone(),
                    start_height: commit.start_height,
                    end_height: commit.end_height,
                    kind,
                    shard_id: commit.shard_id,
                    revision_digest: commit.revision_digest.clone(),
                    terminal_block_hash: commit.terminal_block_hash.clone(),
                    source_anchor: commit.source_anchor.clone(),
                };
                // Rows are keyed by script and start height, so only the row
                // at this start can be affected by this commit. It is read
                // alone: the ordinary append — a shard this script has no row
                // for yet — touches nothing else, so the cost of the Nth
                // checkpoint does not grow with N. Reading every range and
                // rewriting them all, as this once did, made a long recovery
                // quadratic in its own progress.
                match coverage_at(tx, script, range.start_height)? {
                    None => insert_coverage(tx, &range)?,
                    // An identical retry: the row is already what it would be.
                    Some(old) if old == range => {}
                    // Re-reading the same shard at a later accepted target
                    // extends its clipped prefix; the start-keyed row is
                    // replaced in place.
                    Some(old)
                        if old.shard_id == range.shard_id
                            && old.end_height <= range.end_height =>
                    {
                        replace_coverage(tx, &range)?;
                    }
                    // Anything else keeps the historical rewrite path and its
                    // exact semantics, including the refusal of a second range
                    // at the same start.
                    Some(_) => {
                        let mut ranges = coverage_of(tx, script)?;
                        ranges.retain(|old| {
                            !(old.shard_id == range.shard_id
                                && old.start_height == range.start_height
                                && old.end_height <= range.end_height)
                        });
                        if !ranges.contains(&range) {
                            ranges.push(range);
                        }
                        write_coverage(tx, script, ranges)?;
                    }
                }
            }

            for id in &commit.pending_complete {
                tx.execute(
                    &format!("DELETE FROM {CACHE_SCHEMA}.transparent_pending_pages WHERE id = :id"),
                    named_params![":id": *id as i64],
                )?;
            }
            for pending in &commit.pending_upsert {
                match pending.id {
                    Some(id) => {
                        tx.execute(
                            &format!(
                                "UPDATE {CACHE_SCHEMA}.transparent_pending_pages
                                 SET next_ordinal = :next, attempts = :attempts, validated_events = :validated WHERE id = :id"
                            ),
                            named_params![
                                ":id": id as i64,
                                ":next": pending.next_ordinal,
                                ":attempts": pending.attempts,
                                ":validated": pending.validated_events,
                            ],
                        )?;
                    }
                    None => {
                        tx.execute(
                            &format!(
                                "INSERT INTO {CACHE_SCHEMA}.transparent_pending_pages
                                    (shard_id, revision_digest, script, first_page, page_count,
                                     total_events, inline, next_ordinal, attempts, validated_events, target_height, target_hash)
                                 VALUES (:shard, :revision, :script, :first, :count, :total,
                                         :inline, :next, :attempts, :validated, :target_height, :target_hash)"
                            ),
                            named_params![
                                ":shard": pending.shard_id as i64,
                                ":revision": &pending.revision_digest,
                                ":script": &pending.script,
                                ":first": pending.first_page,
                                ":count": pending.page_count,
                                ":total": pending.total_events,
                                ":inline": &pending.inline,
                                ":target_height": pending.target_anchor.as_ref().map(|a| u32::from(a.height)),
                                ":target_hash": pending.target_anchor.as_ref().map(|a| a.hash.as_str()),
                                ":next": pending.next_ordinal,
                                ":attempts": pending.attempts,
                                ":validated": pending.validated_events,
                            ],
                        )?;
                    }
                }
            }

            // The projection, in the same transaction as the events it
            // reflects: the balance never shows an output the ledger does not
            // hold, or misses one it does.
            let mut owners: HashMap<Vec<u8>, (i64, u32)> = HashMap::new();
            for output in &commit.outputs {
                let (address_id, account) = match owners.get(&output.script) {
                    Some(found) => *found,
                    None => {
                        let found = tx
                            .query_row(
                                &format!(
                                    "SELECT id, account_id FROM {CACHE_SCHEMA}.addresses
                                     WHERE transparent_script = :script"
                                ),
                                named_params![":script": &output.script],
                                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?)),
                            )
                            .optional()?
                            // The script itself is deliberately not named:
                            // this message reaches logs and screens, and a
                            // script is an address.
                            .ok_or_else(|| {
                                Error::Corrupt(
                                    "the ledger returned an output at a script this wallet \
                                     never derived; storing it would credit somebody else's \
                                     funds"
                                        .to_owned(),
                                )
                            })?;
                        owners.insert(output.script.clone(), found);
                        found
                    }
                };
                apply::put_recovered_output(tx, output, address_id, account)?;
            }
            for spend in &commit.spends {
                apply::put_recovered_spend(tx, spend)?;
            }

            Ok(record_commit(
                tx,
                "shard",
                &format!("{}:{}", commit.shard_id, commit.revision_digest),
            )?)
        })
    }

    /// Records the accepted anchor and the coverage summary it carries.
    pub fn commit_transparent_anchor(
        &mut self,
        anchor: &TransparentAnchor,
        settled_through: BlockHeight,
        covered_through: BlockHeight,
    ) -> Result<u64, Error> {
        self.transactionally(|tx| {
            tx.execute(
                &format!(
                    "INSERT INTO {CACHE_SCHEMA}.transparent_set
                        (id, set_digest, identity_json, anchor_height, anchor_hash,
                         settled_through, covered_through)
                     VALUES (1, '', '', :height, :hash, :settled, :covered)
                     ON CONFLICT (id) DO UPDATE SET
                        anchor_height = :height,
                        anchor_hash = :hash,
                        settled_through = :settled,
                        covered_through = :covered"
                ),
                named_params![
                    ":height": u32::from(anchor.height),
                    ":hash": &anchor.hash,
                    ":settled": u32::from(settled_through),
                    ":covered": u32::from(covered_through),
                ],
            )?;
            record_commit(tx, "anchor", &u32::from(anchor.height).to_string())
        })
    }

    /// Removes every event, coverage range and pending item above `height`,
    /// lowers the anchor to it, and rolls the projection back with them.
    ///
    /// A reorg the library found, or a provisional tail it saw replaced. The
    /// wallet's own rewind ([`WalletDb::truncate_to`]) does the same, so the two
    /// cannot disagree about what survives.
    pub fn rollback_transparent_above(
        &mut self,
        height: BlockHeight,
        reason: &str,
    ) -> Result<u64, Error> {
        self.transactionally(|tx| rollback_above(tx, height, reason))
    }

    /// Provisional coverage under `revision_digest` becomes settled: the same
    /// bytes were sealed.
    pub fn promote_transparent_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), Error> {
        self.transactionally(|tx| {
            tx.execute(
                &format!(
                    "UPDATE {CACHE_SCHEMA}.transparent_coverage SET kind = 'settled'
                     WHERE shard_id = :shard AND revision_digest = :revision
                       AND kind = 'provisional'"
                ),
                named_params![":shard": shard_id as i64, ":revision": revision_digest],
            )?;
            Ok::<_, Error>(())
        })
    }

    /// Rewinds the ledger and its projection to the exact accepted ancestor.
    pub fn rollback_transparent_to(
        &mut self,
        anchor: &TransparentAnchor,
        reason: &str,
    ) -> Result<u64, Error> {
        self.transactionally(|tx| rollback_to(tx, anchor.height, Some(&anchor.hash), reason))
    }

    /// Every page retrieval still owed, oldest first.
    pub fn transparent_pending(&self) -> Result<Vec<PendingPages>, Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT id, shard_id, revision_digest, script, first_page, page_count, total_events,
                    inline, next_ordinal, attempts, validated_events, target_height, target_hash
             FROM {CACHE_SCHEMA}.transparent_pending_pages ORDER BY id"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(PendingPages {
                id: Some(row.get::<_, i64>(0)? as u64),
                shard_id: row.get::<_, i64>(1)? as u64,
                revision_digest: row.get(2)?,
                script: row.get(3)?,
                first_page: row.get(4)?,
                page_count: row.get(5)?,
                total_events: row.get(6)?,
                inline: row.get(7)?,
                next_ordinal: row.get(8)?,
                attempts: row.get(9)?,
                validated_events: row.get(10)?,
                target_anchor: read_anchor(row, 11, 12)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Published setup parameters kept under `key`, if any.
    pub fn transparent_setup(&self, key: &SetupKey) -> Result<Option<SetupParams>, Error> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT public_params_base64, public_params_sha256
                     FROM {CACHE_SCHEMA}.transparent_setup_cache
                     WHERE set_digest = :set AND revision_digest = :revision
                       AND tbl = :table AND segment = :segment"
                ),
                named_params![
                    ":set": &key.set_digest,
                    ":revision": &key.revision_digest,
                    ":table": &key.table,
                    ":segment": key.segment,
                ],
                |row| {
                    Ok(SetupParams {
                        public_params_base64: row.get(0)?,
                        public_params_sha256: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// Keeps published setup parameters for reuse.
    pub fn put_transparent_setup(
        &mut self,
        key: &SetupKey,
        params: &SetupParams,
    ) -> Result<(), Error> {
        self.conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {CACHE_SCHEMA}.transparent_setup_cache
                    (set_digest, revision_digest, tbl, segment, public_params_base64,
                     public_params_sha256)
                 VALUES (:set, :revision, :table, :segment, :params, :sha256)"
            ),
            named_params![
                ":set": &key.set_digest,
                ":revision": &key.revision_digest,
                ":table": &key.table,
                ":segment": key.segment,
                ":params": &params.public_params_base64,
                ":sha256": &params.public_params_sha256,
            ],
        )?;
        Ok(())
    }

    /// A cached filter for `revision_digest`, if it is the one `filter_hash`
    /// names.
    pub fn transparent_filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT bytes FROM {CACHE_SCHEMA}.transparent_filter_cache
                     WHERE revision_digest = :revision AND filter_hash = :hash"
                ),
                named_params![":revision": revision_digest, ":hash": filter_hash],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Keeps a filter for reuse.
    pub fn put_transparent_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {CACHE_SCHEMA}.transparent_filter_cache
                    (revision_digest, filter_hash, sealed, bytes)
                 VALUES (:revision, :hash, :sealed, :bytes)"
            ),
            named_params![
                ":revision": revision_digest,
                ":hash": filter_hash,
                ":sealed": sealed as i64,
                ":bytes": bytes,
            ],
        )?;
        Ok(())
    }

    /// The id of the last commit, zero before any.
    pub fn transparent_last_commit(&self) -> Result<u64, Error> {
        let id: Option<i64> = self.conn.query_row(
            &format!("SELECT MAX(id) FROM {CACHE_SCHEMA}.transparent_commits"),
            [],
            |row| row.get(0),
        )?;
        Ok(id.unwrap_or(0) as u64)
    }

    /// How far the ledger has read, per script, for one account.
    ///
    /// A script the ledger was never asked about has no required height and no
    /// ranges, and is reported one below the account's birthday rather than
    /// omitted: a caller uses this to decide whether the balance is current,
    /// and a missing script must count as unread rather than be skipped.
    pub fn transparent_coverage(
        &self,
        account: AccountId,
        birthday: BlockHeight,
    ) -> Result<Vec<ScriptCoverage>, Error> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT a.transparent_script, s.required_from
             FROM {CACHE_SCHEMA}.addresses a
             LEFT JOIN {CACHE_SCHEMA}.transparent_scripts s ON s.script = a.transparent_script
             WHERE a.account_id = :account AND a.transparent_script IS NOT NULL"
        ))?;
        let rows = stmt.query_map(named_params![":account": account.0], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<u32>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (script, required_from) = row?;
            let from = required_from.map_or(birthday, BlockHeight::from_u32);
            let ranges = coverage_of(&self.conn, &script)?;
            let settled: Vec<CoverageRange> = ranges
                .iter()
                .filter(|r| r.kind == CoverageKind::Settled)
                .cloned()
                .collect();
            out.push(ScriptCoverage {
                script,
                account,
                settled_through: reach(&settled, from),
                covered_through: reach(&ranges, from),
            });
        }
        Ok(out)
    }

    /// What the wallet knows about the state of its transparent coverage.
    ///
    /// The lowest coverage of any watched script, because a balance is only as
    /// current as its least current part, together with everything that
    /// forbids calling it synchronized: unresolved spends, work still owed, and
    /// a sync that stopped short.
    pub fn transparent_state(
        &self,
        account: AccountId,
        birthday: BlockHeight,
    ) -> Result<TransparentState, Error> {
        let coverage = self.transparent_coverage(account, birthday)?;
        let unresolved: u32 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {CACHE_SCHEMA}.transparent_spend_events s
                 JOIN {CACHE_SCHEMA}.addresses a ON a.transparent_script = s.script
                 LEFT JOIN {CACHE_SCHEMA}.transparent_receive_events r
                        ON r.txid = s.spent_txid AND r.output_index = s.spent_output_index
                 WHERE a.account_id = :account AND r.txid IS NULL"
            ),
            named_params![":account": account.0],
            |row| row.get(0),
        )?;
        let provisional: u32 = self.conn.query_row(
            &format!(
                "SELECT COUNT(DISTINCT shard_id || ':' || revision_digest)
                 FROM {CACHE_SCHEMA}.transparent_coverage WHERE kind = 'provisional'"
            ),
            [],
            |row| row.get(0),
        )?;
        let pending: u32 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {CACHE_SCHEMA}.transparent_pending_pages"),
            [],
            |row| row.get(0),
        )?;
        // A script never read reports one below its required height, which
        // keeps a partly read account from looking current. A wallet in which
        // *nothing* has been read is a different state from one read through
        // the block before its birthday, and it is reported as no coverage at
        // all rather than as a height: a height on screen reads as progress.
        let anything_read: bool = self.conn.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {CACHE_SCHEMA}.transparent_coverage)"),
            [],
            |row| row.get(0),
        )?;
        let outside_coverage: u32 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {CACHE_SCHEMA}.addresses
                 WHERE account_id = :account AND transparent_script IS NOT NULL
                   AND length(transparent_script) > :max"
            ),
            named_params![":account": account.0, ":max": MAX_INDEXABLE_SCRIPT_BYTES as i64],
            |row| row.get(0),
        )?;
        let lowest = |pick: fn(&ScriptCoverage) -> BlockHeight| {
            anything_read
                .then(|| coverage.iter().map(pick).min())
                .flatten()
        };
        Ok(TransparentState {
            settled_through: lowest(|c| c.settled_through),
            covered_through: lowest(|c| c.covered_through),
            unresolved_spends: unresolved,
            provisional_shards: provisional,
            pending_pages: pending,
            anchor: self.transparent_anchor()?,
            completion: self.transparent_completion()?,
            outside_coverage,
        })
    }
}

fn txid_of(bytes: &[u8]) -> Result<TxId, Error> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Corrupt("a stored transaction id was not 32 bytes".into()))?;
    Ok(TxId::from_bytes(bytes))
}

fn read_anchor(
    row: &rusqlite::Row<'_>,
    height: usize,
    hash: usize,
) -> rusqlite::Result<Option<TransparentAnchor>> {
    match (
        row.get::<_, Option<u32>>(height)?,
        row.get::<_, Option<String>>(hash)?,
    ) {
        (None, None) => Ok(None),
        (Some(height), Some(hash)) => Ok(Some(TransparentAnchor {
            height: BlockHeight::from_u32(height),
            hash,
        })),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u32, end: u32, kind: CoverageKind) -> CoverageRange {
        CoverageRange {
            script: vec![1],
            start_height: BlockHeight::from_u32(start),
            end_height: BlockHeight::from_u32(end),
            kind,
            shard_id: 0,
            revision_digest: "d".into(),
            terminal_block_hash: "h".into(),
            source_anchor: None,
        }
    }

    #[test]
    fn reach_stops_at_the_first_gap_and_reports_one_below_a_missing_start() {
        let ranges = vec![
            range(100, 199, CoverageKind::Settled),
            range(300, 399, CoverageKind::Settled),
            range(200, 299, CoverageKind::Provisional),
        ];
        assert_eq!(
            reach(&ranges, BlockHeight::from_u32(100)),
            BlockHeight::from_u32(399)
        );
        assert_eq!(
            reach(&ranges, BlockHeight::from_u32(150)),
            BlockHeight::from_u32(399)
        );
        assert_eq!(
            reach(&ranges, BlockHeight::from_u32(50)),
            BlockHeight::from_u32(49)
        );
        assert_eq!(
            reach(&[], BlockHeight::from_u32(5)),
            BlockHeight::from_u32(4)
        );
        let settled: Vec<_> = ranges
            .iter()
            .filter(|r| r.kind == CoverageKind::Settled)
            .cloned()
            .collect();
        assert_eq!(
            reach(&settled, BlockHeight::from_u32(100)),
            BlockHeight::from_u32(199)
        );
    }
}
