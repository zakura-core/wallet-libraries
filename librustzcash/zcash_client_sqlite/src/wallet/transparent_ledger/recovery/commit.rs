use super::*;

/// Runs `f` atomically: in a new immediate transaction, or under a savepoint inside the
/// caller's transaction. Nothing `f` wrote survives its failure, including a failure to
/// commit or release.
#[cfg(feature = "transparent-inputs")]
pub(super) fn atomically<T>(
    conn: &rusqlite::Connection,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, SqliteClientError>,
) -> Result<T, SqliteClientError> {
    if conn.is_autocommit() {
        // The guard rolls back when dropped, including after a failed commit.
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        return Ok(value);
    }
    conn.execute_batch("SAVEPOINT tpir_commit")?;
    let result = f(conn).and_then(|value| {
        conn.execute_batch("RELEASE tpir_commit")?;
        Ok(value)
    });
    if result.is_err() {
        // Undo everything since the savepoint and remove it, even when releasing it failed. If
        // this cleanup fails too, the error still aborts the caller's enclosing transaction.
        let _ = conn.execute_batch("ROLLBACK TO tpir_commit; RELEASE tpir_commit");
    }
    result
}

/// Checks everything about a commit that needs no stored state.
#[cfg(feature = "transparent-inputs")]
fn check_well_formed(commit: &TransparentLedgerCommit<AccountUuid>) -> Result<(), InvalidCommit> {
    let identifier_ok = |id: &[u8]| !id.is_empty() && id.len() <= MAX_RECOVERY_IDENTIFIER_LEN;
    if !identifier_ok(&commit.revision.source) || !identifier_ok(&commit.revision.revision) {
        return Err(InvalidCommit::Identifier);
    }
    if i64::try_from(commit.revision.lineage).is_err() {
        return Err(InvalidCommit::Lineage);
    }
    let anchor = commit.anchor.height;
    if anchor > commit.context.target.height {
        return Err(InvalidCommit::AnchorAboveTarget);
    }
    // The publication anchor is not chain evidence, but it bounds what the revision indexed.
    let publication = &commit.revision.publication;
    if anchor > publication.height
        || (anchor == publication.height && commit.anchor.hash != publication.hash)
    {
        return Err(InvalidCommit::AnchorOutsidePublication);
    }
    let check_range = |from: BlockHeight, through: BlockHeight| {
        if from > through {
            Err(InvalidCommit::EmptyRange)
        } else if through > anchor {
            Err(InvalidCommit::AboveAnchor)
        } else {
            Ok(())
        }
    };
    for range in commit.coverage.iter().chain(&commit.unsupported) {
        check_range(range.from, range.through)?;
    }
    let mut opened = BTreeSet::new();
    for page in &commit.opened_pages {
        check_range(page.from, page.through)?;
        if !identifier_ok(&page.page) {
            return Err(InvalidCommit::Identifier);
        }
        if page.addresses.is_empty() || !opened.insert(&page.page) {
            return Err(InvalidCommit::Page);
        }
    }
    if commit
        .completed_pages
        .iter()
        .any(|page| !identifier_ok(page))
    {
        return Err(InvalidCommit::Identifier);
    }
    for receive in &commit.receives {
        if receive
            .metadata
            .is_some_and(|m| !m.is_valid_for(receive.coinbase))
        {
            return Err(InvalidCommit::TransactionMetadata);
        }
    }
    for spend in &commit.spends {
        if spend.metadata.is_some_and(|m| {
            !m.is_valid_for(false) || spend.input_index >= m.transparent_input_count
        }) {
            return Err(InvalidCommit::TransactionMetadata);
        }
    }
    let mined = commit.receives.iter().map(|r| r.mined_height);
    if mined
        .chain(commit.spends.iter().map(|s| s.mined_height))
        .any(|h| h > anchor)
    {
        return Err(InvalidCommit::AboveAnchor);
    }
    Ok(())
}

/// How [`apply_commit`] treats the commit's revision.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitTrust {
    /// The revision is only registered. Qualifying it is a separate trust decision.
    Observed,
    /// The caller trusts the revision: the commit qualifies it, withdrawing older provisional
    /// evidence of its source, in the commit's own transaction. Requires `PrivateRequired` on
    /// the handle and durably.
    Qualified,
}

/// Validates and applies `commit` to the account's ledger, atomically, qualifying its revision
/// first when `trust` is [`CommitTrust::Qualified`].
///
/// An integrity failure applies none of the commit's facts and no qualification, but
/// quarantines, in the same transaction, the commit's source, its account, and every account
/// holding evidence from the source, and removes those accounts' pending pages.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn apply_commit<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    commit: TransparentLedgerCommit<AccountUuid>,
    trust: CommitTrust,
) -> Result<CommitOutcome, SqliteClientError> {
    check_well_formed(&commit).map_err(|e| reject(CommitRejection::Invalid(e)))?;
    atomically(conn, |conn| {
        // Private recovery must be selected by this handle and authorized durably. A handle
        // selecting `Public` records no recovery evidence, even over a durable private policy
        // it reads under.
        resolve_mode(conn, configured)?;
        let durable = durable_policy(conn)?.map(|policy| policy.mode);
        if configured == Some(TransparentLedgerMode::Public)
            || durable.is_none_or(|mode| mode == TransparentLedgerMode::Public)
        {
            return Err(SqliteClientError::TransparentRecoveryNotEnabled);
        }
        // Trusting a revision serves private authority only; shadow recovery observes.
        if trust == CommitTrust::Qualified && !grants_private_authority(conn, configured)? {
            return Err(SqliteClientError::TransparentRecoveryNotEnabled);
        }
        ensure_policy_generation(conn, commit.context.policy_generation)?;

        let stale = |reason| reject(CommitRejection::Stale(reason));
        let watch = Watch::load(conn, params, gap_limits, commit.context.account)?
            .ok_or_else(|| stale(StaleCommit::AccountUnknown))?;
        let account_ref = watch.account.internal_id();
        if source_quarantined(conn, &commit.revision.source)? {
            return Err(reject(CommitRejection::Refused(
                RefusedCommit::SourceQuarantined,
            )));
        }
        if account_quarantined(conn, account_ref)? {
            return Err(reject(CommitRejection::Refused(
                RefusedCommit::AccountQuarantined,
            )));
        }
        if lifecycle(conn, account_ref)? != commit.context.lifecycle {
            return Err(stale(StaleCommit::LifecycleChanged));
        }

        let target = commit.context.target;
        if fully_scanned_height(conn)?.is_none_or(|scanned| target.height > scanned)
            || !is_local_block(conn, &target)?
        {
            return Err(stale(StaleCommit::TargetNotAccepted));
        }
        if !is_local_block(conn, &commit.anchor)? {
            return Err(stale(StaleCommit::AnchorNotAccepted));
        }

        let named = commit
            .receives
            .iter()
            .map(|r| r.address)
            .chain(commit.spends.iter().map(|s| s.prevout_address))
            .chain(commit.coverage.iter().map(|r| r.address))
            .chain(commit.unsupported.iter().map(|r| r.address))
            .chain(
                commit
                    .opened_pages
                    .iter()
                    .flat_map(|p| p.addresses.iter().copied()),
            );
        for address in named {
            if !watch.addresses.contains_key(&address) {
                return Err(stale(StaleCommit::AddressNotWatched(address)));
            }
        }

        // The qualification and facts apply under a nested savepoint, so an integrity failure
        // can discard them all, including any withdrawn evidence, while its quarantine commits.
        match atomically(conn, |conn| {
            if trust == CommitTrust::Qualified {
                qualify_in(conn, &commit.revision)?;
            }
            apply_facts(conn, params, gap_limits, &watch, &commit)
        }) {
            Err(SqliteClientError::TransparentLedgerCommitRejected(
                rejection @ CommitRejection::Integrity(_),
            )) => {
                quarantine(conn, &commit.revision.source, account_ref)?;
                Ok(Err(reject(rejection)))
            }
            result => result.map(Ok),
        }
    })?
}

/// Applies a validated commit's revision, pages, events, ranges, and window growth. An active
/// account's commit also requires a qualified revision and projects its events.
#[cfg(feature = "transparent-inputs")]
fn apply_facts<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    watch: &Watch,
    commit: &TransparentLedgerCommit<AccountUuid>,
) -> Result<CommitOutcome, SqliteClientError> {
    let stale = |reason| reject(CommitRejection::Stale(reason));
    let account_ref = watch.account.internal_id();
    let target = commit.context.target;
    let active = commit.context.lifecycle == AccountLifecycle::Active;

    let revision_id = super::revisions::register_revision(conn, &commit.revision)?;
    if active && !is_qualified(conn, revision_id)? {
        return Err(reject(CommitRejection::Refused(
            RefusedCommit::UnqualifiedRevision,
        )));
    }

    for page in &commit.completed_pages {
        let removed = conn.execute(
            "DELETE FROM tpir_pending_pages
             WHERE account_id = :account_id AND revision_id = :revision_id AND page = :page",
            named_params![
                ":account_id": account_ref.0,
                ":revision_id": revision_id,
                ":page": page,
            ],
        )?;
        if removed == 0 {
            return Err(stale(StaleCommit::UnknownPage(page.clone())));
        }
    }
    for page in &commit.opened_pages {
        open_page(conn, account_ref, revision_id, &target, page)?;
    }

    for receive in &commit.receives {
        apply_receive(conn, account_ref, revision_id, receive)?;
        super::metadata::apply_metadata(
            conn,
            account_ref,
            revision_id,
            TxId::from_bytes(*receive.outpoint.hash()),
            receive.mined_height,
            receive.metadata,
        )?;
    }
    for spend in &commit.spends {
        apply_spend(conn, account_ref, revision_id, spend)?;
        super::metadata::apply_metadata(
            conn,
            account_ref,
            revision_id,
            spend.spending_txid,
            spend.mined_height,
            spend.metadata,
        )?;
    }

    for range in &commit.coverage {
        record_range(conn, account_ref, revision_id, &commit.anchor, range, true)?;
    }
    for range in &commit.unsupported {
        record_range(conn, account_ref, revision_id, &commit.anchor, range, false)?;
    }

    let window_grew = if active {
        // Read-time expansion may have found addresses beyond the wallet's gap generation.
        // Materialize that watch before projecting any receive at those addresses.
        ownership::materialize_watch(conn, params, watch)?;
        // Events join the wallet's outputs and spends, where the wallet's own gap-limit
        // generation extends its address window.
        for receive in &commit.receives {
            projection::project_receive(conn, params, gap_limits, commit.context.account, receive)?;
        }
        for spend in &commit.spends {
            projection::project_spend(conn, params, gap_limits, spend)?;
        }
        let after = Watch::load(conn, params, gap_limits, commit.context.account)?
            .ok_or(SqliteClientError::AccountUnknown)?;
        after.production_end != watch.production_end
    } else {
        let mut window_grew = false;
        for (slot, needed) in watch
            .window_needs(conn, gap_limits)?
            .into_iter()
            .enumerate()
        {
            if let Some(needed) = needed.filter(|_| watch.derivable[slot]) {
                conn.execute(
                    "INSERT INTO tpir_candidate_windows (account_id, key_scope, end_index)
                     VALUES (:account_id, :key_scope, :end_index)
                     ON CONFLICT (account_id, key_scope)
                     DO UPDATE SET end_index = MAX(end_index, excluded.end_index)",
                    named_params![
                        ":account_id": account_ref.0,
                        ":key_scope": KeyScope::try_from(WINDOW_SCOPES[slot])?.encode(),
                        ":end_index": needed,
                    ],
                )?;
                window_grew = true;
            }
        }
        window_grew
    };

    // Builds without the recovery lifecycle would leave this state stale across rewinds;
    // once any exists, they must fail closed.
    super::super::require_reader_version(conn, super::super::RECOVERY_READER_VERSION)?;

    Ok(CommitOutcome { window_grew })
}

/// Whether the stored revision `revision_id` is qualified.
#[cfg(feature = "transparent-inputs")]
fn is_qualified(conn: &rusqlite::Connection, revision_id: i64) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_qualified_revisions WHERE revision_id = :revision_id
         )",
        named_params![":revision_id": revision_id],
        |row| row.get(0),
    )?)
}

/// Returns `account_ref`'s lifecycle.
#[cfg(feature = "transparent-inputs")]
pub(super) fn lifecycle(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<AccountLifecycle, SqliteClientError> {
    let active: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_active_accounts WHERE account_id = :account_id)",
        named_params![":account_id": account_ref.0],
        |row| row.get(0),
    )?;
    Ok(if active {
        AccountLifecycle::Active
    } else {
        AccountLifecycle::Candidate
    })
}

/// Whether `source` is quarantined.
#[cfg(feature = "transparent-inputs")]
pub(super) fn source_quarantined(
    conn: &rusqlite::Connection,
    source: &[u8],
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tpir_quarantined_sources WHERE source = :source)",
        named_params![":source": source],
        |row| row.get(0),
    )?)
}

/// Whether `account_ref` is quarantined.
#[cfg(feature = "transparent-inputs")]
pub(super) fn account_quarantined(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_quarantined_accounts WHERE account_id = :account_id
         )",
        named_params![":account_id": account_ref.0],
        |row| row.get(0),
    )?)
}

/// Quarantines `source`, `account_ref`, and every account holding coverage, pages, or observed
/// events from `source`, and removes the quarantined accounts' pending pages.
#[cfg(feature = "transparent-inputs")]
fn quarantine(
    conn: &rusqlite::Connection,
    source: &[u8],
    account_ref: AccountRef,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO tpir_quarantined_sources (source) VALUES (:source)",
        named_params![":source": source],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO tpir_quarantined_accounts (account_id)
         SELECT :account_id
         UNION SELECT account_id FROM tpir_coverage
             WHERE revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)
         UNION SELECT account_id FROM tpir_pending_pages
             WHERE revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)
         UNION SELECT e.account_id FROM tpir_receive_events e
             JOIN tpir_receive_observations o ON o.receive_id = e.id
             WHERE o.revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)
         UNION SELECT e.account_id FROM tpir_spend_events e
             JOIN tpir_spend_observations o ON o.spend_id = e.id
             WHERE o.revision_id IN (SELECT id FROM tpir_revisions WHERE source = :source)",
        named_params![":account_id": account_ref.0, ":source": source],
    )?;
    conn.execute(
        "DELETE FROM tpir_pending_pages
         WHERE account_id IN (SELECT account_id FROM tpir_quarantined_accounts)",
        [],
    )?;
    super::super::require_reader_version(conn, super::super::ACTIVATION_READER_VERSION)
}

/// Authorizes a trusted revision transition, outside any commit: qualifies the exact identity
/// and atomically supersedes older provisional evidence across the wallet. This backs the test
/// and development hook; production qualification goes through [`apply_commit`] with
/// [`CommitTrust::Qualified`].
#[cfg(all(
    feature = "transparent-inputs",
    any(test, feature = "test-dependencies")
))]
pub(crate) fn qualify_revision(
    conn: &rusqlite::Connection,
    revision: &RecoveryRevision,
) -> Result<(), SqliteClientError> {
    let identifier_ok = |id: &[u8]| !id.is_empty() && id.len() <= MAX_RECOVERY_IDENTIFIER_LEN;
    if !identifier_ok(&revision.source) || !identifier_ok(&revision.revision) {
        return Err(reject(CommitRejection::Invalid(InvalidCommit::Identifier)));
    }
    if i64::try_from(revision.lineage).is_err() {
        return Err(reject(CommitRejection::Invalid(InvalidCommit::Lineage)));
    }
    atomically(conn, |conn| {
        // Qualification is ledger state; only a build that interprets the wallet's may add it.
        durable_policy(conn)?;
        qualify_in(conn, revision)
    })
}

/// Qualifies the exact `revision` in the caller's transaction, registering it first if it is
/// new, exactly as a commit would. Ordinary commits only register a revision.
///
/// Qualification binds to the exact revision: a stored revision with the same identity and
/// other lineage, sealing, or publication is an integrity failure, and a superseded provisional
/// revision is stale. The first qualification withdraws older provisional evidence of the
/// source across the wallet. Requalifying withdraws nothing: once a revision is qualified,
/// registration refuses every older provisional revision of its source, so none can have
/// gained evidence since.
#[cfg(feature = "transparent-inputs")]
fn qualify_in(
    conn: &rusqlite::Connection,
    revision: &RecoveryRevision,
) -> Result<(), SqliteClientError> {
    let revision_id = super::revisions::register_revision(conn, revision)?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO tpir_qualified_revisions (revision_id) VALUES (:revision_id)",
        named_params![":revision_id": revision_id],
    )?;
    if inserted > 0 {
        super::revisions::supersede_provisional(conn, revision)?;
    }
    super::super::require_reader_version(conn, super::super::REVISION_READER_VERSION)
}
