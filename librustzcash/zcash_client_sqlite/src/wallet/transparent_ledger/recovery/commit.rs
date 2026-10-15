use super::*;

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
/// suspends, in the same transaction, the commit's source, its account, and every account
/// holding evidence from the source, and removes those accounts' pending pages.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn apply_commit<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    session: &SessionState,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    commit: TransparentLedgerCommit<AccountUuid>,
    trust: CommitTrust,
) -> Result<CommitOutcome, SqliteClientError> {
    check_well_formed(&commit).map_err(|e| reject(CommitRejection::Invalid(e)))?;
    session.check_transaction(conn)?;
    // The facts' journal, kept only when they are; the suspension of a failed commit queues
    // nothing.
    let facts = session.transaction();
    let outcome = atomically(conn, |conn| {
        // Private recovery must be selected by this handle and authorized durably. A handle
        // selecting `Public` records no recovery evidence, even over a durable private policy
        // it reads under.
        resolve_mode(conn, configured)?;
        if !grants_private_authority(conn, configured)? {
            return Err(SqliteClientError::TransparentRecoveryNotEnabled);
        }
        check_transparent_policy_generation(conn, commit.context.policy_generation)?;

        let stale = |reason| reject(CommitRejection::Stale(reason));
        let recovery_addresses =
            AccountRecoveryAddresses::load(conn, params, gap_limits, commit.context.account)?
                .ok_or_else(|| stale(StaleCommit::AccountUnknown))?;
        let account_ref = recovery_addresses.account.internal_id();
        if source_recovery_is_suspended(conn, &commit.revision.source)? {
            return Err(reject(CommitRejection::Refused(
                RefusedCommit::SourceRecoverySuspended,
            )));
        }
        if account_recovery_is_suspended(conn, account_ref)? {
            return Err(reject(CommitRejection::Refused(
                RefusedCommit::AccountRecoverySuspended,
            )));
        }
        if account_lifecycle(conn, account_ref)? != commit.context.lifecycle {
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
            if !recovery_addresses.addresses.contains_key(&address) {
                return Err(stale(StaleCommit::AddressNotWatched(address)));
            }
        }

        // The qualification and facts apply under a nested savepoint, so an integrity failure
        // can discard them all, including any withdrawn evidence, while its recovery suspension commits.
        match atomically(conn, |conn| {
            if trust == CommitTrust::Qualified {
                qualify_in(conn, &commit.revision)?;
            }
            apply_facts(
                conn,
                &facts,
                params,
                gap_limits,
                &recovery_addresses,
                &commit,
            )
        }) {
            Err(SqliteClientError::TransparentLedgerCommitRejected(
                rejection @ CommitRejection::Integrity(_),
            )) => {
                suspend_recovery(conn, &commit.revision.source, account_ref)?;
                Ok(Err(reject(rejection)))
            }
            result => result.map(Ok),
        }
    })??;
    facts.commit();
    Ok(outcome)
}

/// Applies a validated commit's revision, pages, events, ranges, and window growth. An active
/// account's commit also requires a qualified revision and projects its events.
#[cfg(feature = "transparent-inputs")]
fn apply_facts<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    session: &SessionState,
    params: &P,
    gap_limits: &GapLimits,
    recovery_addresses: &AccountRecoveryAddresses,
    commit: &TransparentLedgerCommit<AccountUuid>,
) -> Result<CommitOutcome, SqliteClientError> {
    let stale = |reason| reject(CommitRejection::Stale(reason));
    let account_ref = recovery_addresses.account.internal_id();
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
        record_range(
            conn,
            account_ref,
            revision_id,
            &commit.anchor,
            range,
            CoverageSupport::Supported,
        )?;
    }
    for range in &commit.unsupported {
        record_range(
            conn,
            account_ref,
            revision_id,
            &commit.anchor,
            range,
            CoverageSupport::Unsupported,
        )?;
    }

    let window_grew = if active {
        // Read-time expansion may have found addresses beyond the wallet's gap generation.
        // Materialize that watch before projecting any receive at those addresses.
        ownership::materialize_recovery_addresses(conn, params, recovery_addresses)?;
        // Events join the wallet's outputs and spends, where the wallet's own gap-limit
        // generation extends its address window.
        for receive in &commit.receives {
            projection::project_receive(
                conn,
                session,
                params,
                gap_limits,
                commit.context.account,
                receive,
            )?;
        }
        for spend in &commit.spends {
            projection::project_spend(conn, session, params, gap_limits, spend)?;
        }
        // The wallet's gap rule stops at the first unused run as long as the gap limit, so
        // growth past one is read-time window growth, which the next commit materializes.
        let after =
            AccountRecoveryAddresses::load(conn, params, gap_limits, commit.context.account)?
                .ok_or(SqliteClientError::AccountUnknown)?;
        (0..WINDOW_SCOPES.len())
            .any(|slot| after.watched_end(slot) > recovery_addresses.watched_end(slot))
    } else {
        let mut window_grew = false;
        for (slot, needed) in recovery_addresses
            .window_needs(conn, gap_limits)?
            .into_iter()
            .enumerate()
        {
            if let Some(needed) = needed.filter(|_| recovery_addresses.derivable[slot]) {
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
                // Growth inside the restore window adds no watched address.
                window_grew |= needed > recovery_addresses.watched_end(slot);
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
pub(super) fn account_lifecycle(
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
