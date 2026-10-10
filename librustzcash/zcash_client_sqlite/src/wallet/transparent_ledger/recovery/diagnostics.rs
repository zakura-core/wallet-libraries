use super::*;

/// An account's candidate recovery progress at the local target, without its event lists.
#[cfg(feature = "transparent-inputs")]
pub(crate) struct RecoveryStatus {
    /// The highest contiguously scanned local block.
    pub(super) target: Option<ChainPoint>,
    /// The highest height through which every watched address is continuously covered from its
    /// required start.
    pub(crate) covered_through: Option<BlockHeight>,
    /// Why recovery is incomplete; empty when complete through the target.
    pub(super) blockers: Vec<CandidateBlocker>,
    /// The number of addresses the account must have recovered.
    pub(super) watched_addresses: usize,
    /// The number of pages opened for retrieval and not yet completed.
    pub(super) pending_pages: usize,
    /// The number of distinct outpoints a mined spend consumes without a mined receive.
    pub(super) unresolved_spends: usize,
    /// The unverified sum of mined receives no mined spend consumes; `None` above `MAX_MONEY`.
    pub(crate) recovered_unverified: Option<Zatoshis>,
}

/// Returns `watch`'s account recovery progress at the local target. The caller provides the
/// read snapshot.
#[cfg(feature = "transparent-inputs")]
pub(super) fn recovery_status(
    conn: &rusqlite::Connection,
    gap_limits: &GapLimits,
    watch: &Watch,
) -> Result<RecoveryStatus, SqliteClientError> {
    let account_ref = watch.account.internal_id();
    let target = local_target(conn)?;

    let coverage::Coverage {
        supported,
        unsupported,
    } = coverage::read(conn, account_ref)?;

    // Continuous coverage from the required start, per watched address.
    let required = u32::from(watch.required_from);
    let mut covered_through: Option<u32> = target.map(|t| u32::from(t.height));
    // A target below the required start needs no coverage yet: the interval is empty.
    let needs_coverage = target.is_some_and(|t| u32::from(t.height) >= required);
    for address in watch.addresses.keys().filter(|_| needs_coverage) {
        let reach = supported
            .get(&script_bytes(address))
            .and_then(|ranges| {
                ranges
                    .iter()
                    .find(|(from, through)| *from <= required && required <= *through)
            })
            .map(|(_, through)| *through);
        covered_through = match (covered_through, reach) {
            (Some(c), Some(r)) => Some(c.min(r)),
            _ => None,
        };
    }
    // Only the part of an unsupported range the account must cover blocks it: from the
    // required start through the target. The row is kept, so lowering the birthday brings
    // earlier parts back into scope.
    let unsupported_uncovered = target.is_some_and(|target| {
        let target = u32::from(target.height);
        unsupported.iter().any(|(script, from, through)| {
            let (from, through) = ((*from).max(required), (*through).min(target));
            from <= through
                && !supported
                    .get(script)
                    .is_some_and(|ranges| ranges.iter().any(|(f, t)| *f <= from && through <= *t))
        })
    });

    let pending_pages: usize = conn.query_row(
        "SELECT COUNT(*) FROM tpir_pending_pages WHERE account_id = :account_id",
        named_params![":account_id": account_ref.0],
        |row| row.get::<_, i64>(0),
    )? as usize;

    // Distinct outpoints consumed by a mined spend but not recovered as a mined receive.
    let unresolved_spends: usize = conn.query_row(
        "SELECT COUNT(*) FROM (
             SELECT DISTINCT s.prevout_txid, s.prevout_output_index
             FROM tpir_spend_events s
             WHERE s.account_id = :account_id AND s.mined_height IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1 FROM tpir_receive_events r
                 WHERE r.account_id = :account_id AND r.mined_height IS NOT NULL
                 AND r.txid = s.prevout_txid AND r.output_index = s.prevout_output_index
             )
         )",
        named_params![":account_id": account_ref.0],
        |row| row.get::<_, i64>(0),
    )? as usize;

    // Partially recovered receives can legitimately exceed any real balance, so a sum above
    // `MAX_MONEY` is reported as unrepresentable rather than as an error.
    let mut stmt = conn.prepare_cached(
        "SELECT r.value_zat FROM tpir_receive_events r
         WHERE r.account_id = :account_id AND r.mined_height IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM tpir_spend_events s
             WHERE s.account_id = :account_id AND s.mined_height IS NOT NULL
             AND s.prevout_txid = r.txid AND s.prevout_output_index = r.output_index
         )",
    )?;
    let mut recovered_unverified = Some(Zatoshis::ZERO);
    let mut rows = stmt.query(named_params![":account_id": account_ref.0])?;
    while let Some(row) = rows.next()? {
        let value = Zatoshis::from_nonnegative_i64(row.get(0)?)
            .map_err(|_| SqliteClientError::CorruptedData("invalid receive value".into()))?;
        recovered_unverified = recovered_unverified.and_then(|sum| sum + value);
    }

    // A window reaching `WINDOW_LIMIT` covers the last non-hardened index, which the wallet's
    // address table cannot hold: its ranges end exclusively at a child index. Promotion could
    // not make that address the wallet's own, so it is as underivable as a missing key.
    let window_underivable = watch
        .window_needs(conn, gap_limits)?
        .iter()
        .zip(watch.derivable)
        .zip(watch.candidate_end)
        .any(|((needed, derivable), end)| {
            (needed.is_some() && !derivable) || end == WINDOW_LIMIT || *needed == Some(WINDOW_LIMIT)
        });

    let mut blockers = vec![];
    match target {
        None => blockers.push(CandidateBlocker::ChainUnknown),
        Some(target) => {
            if covered_through.is_none_or(|c| c < u32::from(target.height)) {
                blockers.push(CandidateBlocker::IncompleteCoverage);
            }
        }
    }
    if pending_pages > 0 {
        blockers.push(CandidateBlocker::PendingPages);
    }
    if unresolved_spends > 0 {
        blockers.push(CandidateBlocker::UnresolvedSpends);
    }
    if unsupported_uncovered {
        blockers.push(CandidateBlocker::UnsupportedRanges);
    }
    if window_underivable {
        blockers.push(CandidateBlocker::WindowUnderivable);
    }

    Ok(RecoveryStatus {
        target,
        covered_through: covered_through.map(height),
        blockers,
        watched_addresses: watch.addresses.len(),
        pending_pages,
        unresolved_spends,
        recovered_unverified,
    })
}

/// Returns `account`'s candidate diagnostics. The caller provides the read snapshot.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn candidate_recovery<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    gap_limits: &GapLimits,
    configured: Option<TransparentLedgerMode>,
    account: AccountUuid,
) -> Result<CandidateRecovery<AccountUuid>, SqliteClientError> {
    resolve_mode(conn, configured)?;
    let watch =
        Watch::load(conn, params, gap_limits, account)?.ok_or(SqliteClientError::AccountUnknown)?;
    let account_ref = watch.account.internal_id();
    let status = recovery_status(conn, gap_limits, &watch)?;

    let receives = placed_receives(conn, account_ref)?;
    let spends = placed_spends(conn, account_ref)?;

    let spent: BTreeSet<_> = spends
        .iter()
        .map(|s| (*s.prevout.hash(), s.prevout.n()))
        .collect();
    let unspent = receives
        .iter()
        .filter(|r| !spent.contains(&(*r.outpoint.hash(), r.outpoint.n())))
        .map(|r| r.outpoint.clone())
        .collect();

    Ok(CandidateRecovery {
        account,
        target: status.target,
        covered_through: status.covered_through,
        blockers: status.blockers,
        watched_addresses: status.watched_addresses,
        pending_pages: status.pending_pages,
        unresolved_spends: status.unresolved_spends,
        unspent,
        recovered_unverified: status.recovered_unverified,
        receives,
        spends,
    })
}

/// `account_ref`'s placed receives, ordered by outpoint.
#[cfg(feature = "transparent-inputs")]
pub(super) fn placed_receives(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<Vec<ReceiveEvent>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT txid, output_index, script, value_zat, coinbase, mined_height
         FROM tpir_receive_events
         WHERE account_id = :account_id AND mined_height IS NOT NULL
         ORDER BY txid, output_index",
    )?;
    stmt.query_and_then(named_params![":account_id": account_ref.0], |row| {
        Ok::<_, SqliteClientError>(ReceiveEvent {
            metadata: super::metadata::candidate_metadata(
                conn,
                account_ref,
                TxId::from_bytes(row.get(0)?),
                height(row.get(5)?),
            )?,
            outpoint: OutPoint::new(row.get(0)?, row.get(1)?),
            address: address_from_script(row.get(2)?)?,
            value: Zatoshis::from_nonnegative_i64(row.get(3)?)
                .map_err(|_| SqliteClientError::CorruptedData("invalid receive value".into()))?,
            coinbase: row.get(4)?,
            mined_height: height(row.get(5)?),
        })
    })?
    .collect()
}

/// `account_ref`'s placed spends, ordered by spending txid and input index.
#[cfg(feature = "transparent-inputs")]
pub(super) fn placed_spends(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
) -> Result<Vec<SpendEvent>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT spending_txid, input_index, prevout_txid, prevout_output_index, prevout_script,
                mined_height
         FROM tpir_spend_events
         WHERE account_id = :account_id AND mined_height IS NOT NULL
         ORDER BY spending_txid, input_index",
    )?;
    stmt.query_and_then(named_params![":account_id": account_ref.0], |row| {
        Ok::<_, SqliteClientError>(SpendEvent {
            metadata: super::metadata::candidate_metadata(
                conn,
                account_ref,
                TxId::from_bytes(row.get(0)?),
                height(row.get(5)?),
            )?,
            spending_txid: TxId::from_bytes(row.get(0)?),
            input_index: row.get(1)?,
            prevout: OutPoint::new(row.get(2)?, row.get(3)?),
            prevout_address: address_from_script(row.get(4)?)?,
            mined_height: height(row.get(5)?),
        })
    })?
    .collect()
}
