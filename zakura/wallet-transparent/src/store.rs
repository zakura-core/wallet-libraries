//! The wallet's database as the library's durable store.
//!
//! [`PirStore`] implements [`WalletStore`] over a [`WalletDb`]. It is a type
//! mapping and nothing more: every rule the trait states — one atomic commit
//! per shard, idempotent retries, a differing retry refused whole, coverage per
//! script per shard with the block hash it rests on, pending work that survives
//! a crash — is enforced by `zakura_wallet_store`, in the same transaction as
//! the wallet's own balance. What happens here is that the library's types
//! become the store's plain rows and back.
//!
//! The one thing added on the way through is ownership. The library's script
//! entries carry no account, and the wallet's projection of a receive needs
//! one; the store is built with the wallet's script-to-account map and refuses
//! a script outside it, because an event indexed under a script this wallet
//! never derived is somebody else's money.

use std::collections::BTreeMap;

use transparent_events::{EVENT_BYTES, TransparentEvent};
use transparent_wallet::{
    Anchor, CoverageKind, CoverageRange, LedgerError, PendingPages, ScriptEntry, ScriptOrigin,
    SetIdentity, SetupBlob, SetupKey, ShardCommit, StoreError, StoredEvent, WalletStore,
};
use zakura_wallet_core::AccountId;
use zakura_wallet_store::{
    RecoveredOutput, RecoveredSpend, WalletDb,
    transparent::{self as rows, CommitError},
};
use zcash_protocol::{TxId, consensus::BlockHeight};

/// The wallet's database, seen as the library's store.
pub struct PirStore<'a> {
    db: &'a mut WalletDb,
    owners: BTreeMap<Vec<u8>, AccountId>,
}

impl<'a> PirStore<'a> {
    /// Wraps the wallet for one sync.
    ///
    /// `owners` is every script the wallet has derived, with the account that
    /// owns it. A script the library adds that is not among them is refused.
    pub fn new(db: &'a mut WalletDb, owners: BTreeMap<Vec<u8>, AccountId>) -> Self {
        Self { db, owners }
    }

    /// The wallet back, when the sync is done with it.
    pub fn into_inner(self) -> &'a mut WalletDb {
        self.db
    }
}

fn store(e: zakura_wallet_store::Error) -> StoreError {
    match e {
        zakura_wallet_store::Error::Corrupt(why) => StoreError::Corrupt(why),
        other => StoreError::Io(other.to_string()),
    }
}

fn height(value: u64) -> Result<BlockHeight, StoreError> {
    u32::try_from(value)
        .map(BlockHeight::from_u32)
        .map_err(|_| StoreError::Corrupt("height exceeds chain range".into()))
}
fn anchor_out(a: rows::TransparentAnchor) -> Anchor {
    Anchor {
        height: u64::from(u32::from(a.height)),
        hash: a.hash,
    }
}
fn anchor_in(a: &Anchor) -> Result<rows::TransparentAnchor, StoreError> {
    Ok(rows::TransparentAnchor {
        height: height(a.height)?,
        hash: a.hash.clone(),
    })
}

fn range_out(range: rows::CoverageRange) -> CoverageRange {
    CoverageRange {
        script: range.script,
        start_height: u64::from(u32::from(range.start_height)),
        end_height: u64::from(u32::from(range.end_height)),
        kind: match range.kind {
            rows::CoverageKind::Settled => CoverageKind::Settled,
            rows::CoverageKind::Provisional => CoverageKind::Provisional,
        },
        shard_id: range.shard_id,
        revision_digest: range.revision_digest,
        terminal_block_hash: range.terminal_block_hash,
        source_anchor: range.source_anchor.map(anchor_out),
    }
}

fn decode(record: &[u8]) -> Result<TransparentEvent, StoreError> {
    TransparentEvent::from_bytes(record).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn encode_inline(events: &[TransparentEvent]) -> Vec<u8> {
    let mut out = Vec::with_capacity(events.len() * EVENT_BYTES);
    for event in events {
        out.extend_from_slice(&event.to_bytes());
    }
    out
}

fn decode_inline(bytes: &[u8]) -> Result<Vec<TransparentEvent>, StoreError> {
    if !bytes.len().is_multiple_of(EVENT_BYTES) {
        return Err(StoreError::Corrupt(
            "inline events are not whole records".into(),
        ));
    }
    bytes.chunks_exact(EVENT_BYTES).map(decode).collect()
}

fn pending_out(pending: rows::PendingPages) -> Result<PendingPages, StoreError> {
    Ok(PendingPages {
        id: pending.id,
        shard_id: pending.shard_id,
        revision_digest: pending.revision_digest,
        script: pending.script,
        first_page: pending.first_page,
        page_count: pending.page_count,
        total_events: pending.total_events,
        inline: decode_inline(&pending.inline)?,
        target_anchor: pending.target_anchor.map(anchor_out),
        next_ordinal: pending.next_ordinal,
        attempts: pending.attempts,
        validated_events: pending.validated_events,
    })
}

fn pending_in(pending: &PendingPages) -> Result<rows::PendingPages, StoreError> {
    Ok(rows::PendingPages {
        id: pending.id,
        shard_id: pending.shard_id,
        revision_digest: pending.revision_digest.clone(),
        script: pending.script.clone(),
        first_page: pending.first_page,
        page_count: pending.page_count,
        total_events: pending.total_events,
        inline: encode_inline(&pending.inline),
        target_anchor: pending.target_anchor.as_ref().map(anchor_in).transpose()?,
        next_ordinal: pending.next_ordinal,
        attempts: pending.attempts,
        validated_events: pending.validated_events,
    })
}

impl WalletStore for PirStore<'_> {
    fn set_identity(&self) -> Result<Option<SetIdentity>, StoreError> {
        match self.db.transparent_set().map_err(store)? {
            None => Ok(None),
            Some(set) => serde_json::from_str(&set.identity_json)
                .map(Some)
                .map_err(|e| StoreError::Corrupt(e.to_string())),
        }
    }

    fn bind_set(&mut self, identity: &SetIdentity) -> Result<(), StoreError> {
        match self.set_identity()? {
            None => {}
            Some(stored) if stored.continues(identity) => {}
            Some(stored) => {
                return Err(StoreError::SetMismatch {
                    stored: stored.digest(),
                    offered: identity.digest(),
                });
            }
        }
        let identity_json =
            serde_json::to_string(identity).map_err(|e| StoreError::Io(e.to_string()))?;
        self.db
            .bind_transparent_set(&rows::TransparentSet {
                digest: identity.digest(),
                identity_json,
            })
            .map_err(store)
    }

    fn anchor(&self) -> Result<Option<Anchor>, StoreError> {
        Ok(self
            .db
            .transparent_anchor()
            .map_err(store)?
            .map(|anchor| Anchor {
                height: u64::from(u32::from(anchor.height)),
                hash: anchor.hash,
            }))
    }

    fn scripts(&self) -> Result<Vec<ScriptEntry>, StoreError> {
        Ok(self
            .db
            .transparent_scripts()
            .map_err(store)?
            .into_iter()
            .map(|script| ScriptEntry {
                script: script.script,
                origin: if script.imported {
                    ScriptOrigin::Imported
                } else {
                    ScriptOrigin::Derived
                },
                required_from: u64::from(u32::from(script.required_from)),
            })
            .collect())
    }

    fn add_scripts(&mut self, entries: &[ScriptEntry]) -> Result<usize, StoreError> {
        let mut scripts = Vec::with_capacity(entries.len());
        for entry in entries {
            let account = *self.owners.get(&entry.script).ok_or_else(|| {
                StoreError::Corrupt(format!(
                    "script {} is not one this wallet derived; the ledger cannot be \
                     responsible for it",
                    hex::encode(&entry.script)
                ))
            })?;
            scripts.push(rows::TransparentScript {
                script: entry.script.clone(),
                account,
                imported: entry.origin == ScriptOrigin::Imported,
                required_from: height(entry.required_from)?,
            });
        }
        self.db.add_transparent_scripts(&scripts).map_err(store)
    }

    fn coverage(&self, script: &[u8]) -> Result<Vec<CoverageRange>, StoreError> {
        Ok(self
            .db
            .transparent_coverage_of(script)
            .map_err(store)?
            .into_iter()
            .map(range_out)
            .collect())
    }

    fn provisional(&self) -> Result<Vec<CoverageRange>, StoreError> {
        Ok(self
            .db
            .transparent_provisional_coverage()
            .map_err(store)?
            .into_iter()
            .map(range_out)
            .collect())
    }

    fn events(&self) -> Result<Vec<StoredEvent>, StoreError> {
        let mut events = Vec::new();
        for row in self.db.transparent_events().map_err(store)? {
            events.push(StoredEvent {
                script: row.script,
                event: decode(&row.record)?,
                shard_id: row.shard_id,
                revision_digest: row.revision_digest,
            });
        }
        events.sort_by_key(|stored| stored.event.sort_key());
        Ok(events)
    }

    fn commit_shard(&mut self, commit: ShardCommit) -> Result<u64, StoreError> {
        let mut events = Vec::with_capacity(commit.events.len());
        let mut outputs = Vec::new();
        let mut spends = Vec::new();
        for stored in &commit.events {
            let key = match &stored.event {
                TransparentEvent::Receive(receive) => {
                    let mined = height(u64::from(receive.height))?;
                    outputs.push(RecoveredOutput {
                        txid: TxId::from_bytes(receive.txid.0),
                        output_index: receive.output_index,
                        script: stored.script.clone(),
                        value: receive.value,
                        mined_height: Some(mined),
                        observed_at: mined,
                        coinbase: Some(receive.coinbase),
                    });
                    rows::EventKey::Receive {
                        txid: TxId::from_bytes(receive.txid.0),
                        output_index: receive.output_index,
                    }
                }
                TransparentEvent::Spend(spend) => {
                    spends.push(RecoveredSpend {
                        spending_txid: TxId::from_bytes(spend.spending_txid.0),
                        height: height(u64::from(spend.height))?,
                        spent_txid: TxId::from_bytes(spend.spent_txid.0),
                        spent_output_index: spend.spent_output_index,
                    });
                    rows::EventKey::Spend {
                        spending_txid: TxId::from_bytes(spend.spending_txid.0),
                        input_index: spend.input_index,
                        spent_txid: TxId::from_bytes(spend.spent_txid.0),
                        spent_output_index: spend.spent_output_index,
                    }
                }
            };
            events.push(rows::LedgerEvent {
                key,
                script: stored.script.clone(),
                height: height(u64::from(stored.event.height()))?,
                record: stored.event.to_bytes().to_vec(),
                shard_id: stored.shard_id,
                revision_digest: stored.revision_digest.clone(),
            });
        }
        let commit = rows::ShardCommit {
            shard_id: commit.shard_id,
            revision_digest: commit.revision_digest,
            sealed: commit.sealed,
            start_height: height(commit.start_height)?,
            end_height: height(commit.end_height)?,
            terminal_block_hash: commit.terminal_block_hash,
            source_anchor: commit.source_anchor.as_ref().map(anchor_in).transpose()?,
            events,
            outputs,
            spends,
            covered_scripts: commit.covered_scripts,
            pending_upsert: commit
                .pending_upsert
                .iter()
                .map(pending_in)
                .collect::<Result<_, _>>()?,
            pending_complete: commit.pending_complete,
        };
        self.db
            .commit_transparent_shard(&commit)
            .map_err(|e| match e {
                CommitError::ConflictingReceive { txid, output_index } => {
                    StoreError::Contradiction(LedgerError::ConflictingReceive(
                        transparent_events::Txid(*txid.as_ref()).to_display_hex(),
                        output_index,
                    ))
                }
                CommitError::DoubleSpend {
                    spent_txid,
                    spent_output_index,
                } => StoreError::Contradiction(LedgerError::DoubleSpend(
                    transparent_events::Txid(*spent_txid.as_ref()).to_display_hex(),
                    spent_output_index,
                )),
                CommitError::PendingLimit { limit } => StoreError::PendingLimit { limit },
                CommitError::Store(e) => store(e),
            })
    }

    fn commit_anchor(
        &mut self,
        anchor: &Anchor,
        settled_through: u64,
        covered_through: u64,
    ) -> Result<u64, StoreError> {
        self.db
            .commit_transparent_anchor(
                &rows::TransparentAnchor {
                    height: height(anchor.height)?,
                    hash: anchor.hash.clone(),
                },
                height(settled_through)?,
                height(covered_through)?,
            )
            .map_err(store)
    }

    fn rollback_above(&mut self, anchor: &Anchor, reason: &str) -> Result<u64, StoreError> {
        self.db
            .rollback_transparent_to(&anchor_in(anchor)?, reason)
            .map_err(store)
    }

    fn promote_provisional(
        &mut self,
        shard_id: u64,
        revision_digest: &str,
    ) -> Result<(), StoreError> {
        self.db
            .promote_transparent_provisional(shard_id, revision_digest)
            .map_err(store)
    }

    fn pending(&self) -> Result<Vec<PendingPages>, StoreError> {
        self.db
            .transparent_pending()
            .map_err(store)?
            .into_iter()
            .map(pending_out)
            .collect()
    }

    fn pending_limit(&self) -> usize {
        self.db.transparent_pending_limit()
    }

    fn setup(&self, key: &SetupKey) -> Result<Option<SetupBlob>, StoreError> {
        Ok(self
            .db
            .transparent_setup(&rows::SetupKey {
                set_digest: key.set_digest.clone(),
                revision_digest: key.revision_digest.clone(),
                table: key.table.as_str().to_owned(),
                segment: key.segment,
            })
            .map_err(store)?
            .map(|params| SetupBlob {
                public_params_base64: params.public_params_base64,
                public_params_sha256: params.public_params_sha256,
            }))
    }

    fn put_setup(&mut self, key: &SetupKey, blob: &SetupBlob) -> Result<(), StoreError> {
        self.db
            .put_transparent_setup(
                &rows::SetupKey {
                    set_digest: key.set_digest.clone(),
                    revision_digest: key.revision_digest.clone(),
                    table: key.table.as_str().to_owned(),
                    segment: key.segment,
                },
                &rows::SetupParams {
                    public_params_base64: blob.public_params_base64.clone(),
                    public_params_sha256: blob.public_params_sha256.clone(),
                },
            )
            .map_err(store)
    }

    fn filter(
        &self,
        revision_digest: &str,
        filter_hash: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.db
            .transparent_filter(revision_digest, filter_hash)
            .map_err(store)
    }

    fn put_filter(
        &mut self,
        revision_digest: &str,
        filter_hash: &str,
        sealed: bool,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.db
            .put_transparent_filter(revision_digest, filter_hash, sealed, bytes)
            .map_err(store)
    }

    fn last_commit(&self) -> Result<u64, StoreError> {
        self.db.transparent_last_commit().map_err(store)
    }
}
