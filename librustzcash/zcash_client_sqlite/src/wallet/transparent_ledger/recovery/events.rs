use super::*;
use rusqlite::OptionalExtension as _;

/// Refuses an event that disagrees with another event of the same transaction, across every
/// account it touches. A transaction is mined in one block. Being coinbase is a property of the
/// transaction, and a coinbase transaction spends no outputs. `coinbase` is the event's
/// classification for a receive, and `None` for a spend by the transaction.
#[cfg(feature = "transparent-inputs")]
fn check_against_ledger_events(
    conn: &rusqlite::Connection,
    txid: &[u8; 32],
    mined: u32,
    coinbase: Option<bool>,
) -> Result<(), SqliteClientError> {
    let coinbase_conflict: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_receive_events
             WHERE txid = :txid
             AND (CASE WHEN :coinbase IS NULL THEN coinbase = 1 ELSE coinbase != :coinbase END)
         ) OR (
             :coinbase IS 1 AND EXISTS (SELECT 1 FROM tpir_spend_events WHERE spending_txid = :txid)
         )",
        named_params![":txid": &txid[..], ":coinbase": coinbase],
        |row| row.get(0),
    )?;
    if coinbase_conflict {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::TransactionCoinbase(TxId::from_bytes(*txid)),
        )));
    }
    let conflicting: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_receive_events WHERE txid = :txid AND mined_height != :mined
         ) OR EXISTS (
             SELECT 1 FROM tpir_spend_events
             WHERE spending_txid = :txid AND mined_height != :mined
         )",
        named_params![":txid": &txid[..], ":mined": mined],
        |row| row.get(0),
    )?;
    if conflicting {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::TransactionPlacement(TxId::from_bytes(*txid)),
        )));
    }
    Ok(())
}

/// Records `receive` as observed in revision `revision_id`. Idempotent.
///
/// A receive is identified by its outpoint. A known one must agree in account, script, value
/// and coinbase classification, and in placement unless a rewind cleared it, in which case it
/// is placed again. It must also agree with the other events of its transaction and with every
/// recorded spend of it: the spend names the same script and is not mined earlier. Any
/// disagreement refuses the commit as an integrity failure.
#[cfg(feature = "transparent-inputs")]
pub(super) fn apply_receive(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
    revision_id: i64,
    receive: &ReceiveEvent,
) -> Result<(), SqliteClientError> {
    let outpoint = &receive.outpoint;
    let script = script_bytes(&receive.address);
    let value = i64::try_from(u64::from(receive.value)).expect("Zatoshis fit in i64");
    let mined = u32::from(receive.mined_height);
    let contradiction = || {
        reject(CommitRejection::Integrity(
            IntegrityFailure::ReceiveContent(outpoint.clone()),
        ))
    };

    let stored = conn
        .query_row(
            "SELECT id, account_id, script, value_zat, coinbase, mined_height
             FROM tpir_receive_events
             WHERE txid = :txid AND output_index = :output_index",
            named_params![":txid": &outpoint.hash()[..], ":output_index": outpoint.n()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, Option<u32>>(5)?,
                ))
            },
        )
        .optional()?;
    let id = match stored {
        None => conn.query_row(
            "INSERT INTO tpir_receive_events (
                 account_id, txid, output_index, script, value_zat, coinbase, mined_height
             )
             VALUES (:account_id, :txid, :output_index, :script, :value, :coinbase, :mined)
             RETURNING id",
            named_params![
                ":account_id": account_ref.0,
                ":txid": &outpoint.hash()[..],
                ":output_index": outpoint.n(),
                ":script": script,
                ":value": value,
                ":coinbase": receive.coinbase,
                ":mined": mined,
            ],
            |row| row.get::<_, i64>(0),
        )?,
        Some((id, stored_account, stored_script, stored_value, stored_coinbase, placement)) => {
            if (
                stored_account,
                &stored_script,
                stored_value,
                stored_coinbase,
            ) != (account_ref.0, &script, value, receive.coinbase)
            {
                return Err(contradiction());
            }
            match placement {
                Some(h) if h != mined => {
                    return Err(reject(CommitRejection::Integrity(
                        IntegrityFailure::ReceivePlacement(outpoint.clone()),
                    )));
                }
                Some(_) => {}
                None => {
                    conn.execute(
                        "UPDATE tpir_receive_events SET mined_height = :mined WHERE id = :id",
                        named_params![":mined": mined, ":id": id],
                    )?;
                }
            }
            id
        }
    };
    check_against_ledger_events(conn, outpoint.hash(), mined, Some(receive.coinbase))?;
    let spend_names_other_script: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events
             WHERE prevout_txid = :txid AND prevout_output_index = :output_index
             AND prevout_script != :script
         )",
        named_params![
            ":txid": &outpoint.hash()[..],
            ":output_index": outpoint.n(),
            ":script": script,
        ],
        |row| row.get(0),
    )?;
    if spend_names_other_script {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::SpendAddress(outpoint.clone()),
        )));
    }
    let spent_earlier: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events
             WHERE prevout_txid = :txid AND prevout_output_index = :output_index
             AND mined_height < :mined
         )",
        named_params![
            ":txid": &outpoint.hash()[..],
            ":output_index": outpoint.n(),
            ":mined": mined,
        ],
        |row| row.get(0),
    )?;
    if spent_earlier {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::SpendBeforeOutput(outpoint.clone()),
        )));
    }
    conn.execute(
        "INSERT INTO tpir_receive_observations (receive_id, revision_id)
         VALUES (:id, :revision_id)
         ON CONFLICT DO NOTHING",
        named_params![":id": id, ":revision_id": revision_id],
    )?;
    Ok(())
}

/// Records `spend` as observed in revision `revision_id`. Idempotent.
///
/// A spend is identified by its spending transaction and input index. A known one must agree in
/// account, spent outpoint and spent script, and in placement unless a rewind cleared it, in
/// which case it is placed again. It must also agree with the other events of its transaction
/// and with the recorded receive of the outpoint it spends (same script, not mined later), and
/// no other placed spend may consume that outpoint. Any disagreement refuses the commit as an
/// integrity failure. The spent output need not be recovered yet.
#[cfg(feature = "transparent-inputs")]
pub(super) fn apply_spend(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
    revision_id: i64,
    spend: &SpendEvent,
) -> Result<(), SqliteClientError> {
    let prevout = &spend.prevout;
    let script = script_bytes(&spend.prevout_address);
    let mined = u32::from(spend.mined_height);
    let txid = spend.spending_txid.as_ref().to_vec();
    let identity = || (spend.spending_txid, spend.input_index);

    let stored = conn
        .query_row(
            "SELECT id, account_id, prevout_txid, prevout_output_index, prevout_script,
                    mined_height
             FROM tpir_spend_events
             WHERE spending_txid = :txid AND input_index = :input_index",
            named_params![":txid": txid, ":input_index": spend.input_index],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<u32>>(5)?,
                ))
            },
        )
        .optional()?;
    let id = match stored {
        None => conn.query_row(
            "INSERT INTO tpir_spend_events (
                 account_id, spending_txid, input_index, prevout_txid, prevout_output_index,
                 prevout_script, mined_height
             )
             VALUES (
                 :account_id, :txid, :input_index, :prevout_txid, :prevout_output_index,
                 :script, :mined
             )
             RETURNING id",
            named_params![
                ":account_id": account_ref.0,
                ":txid": txid,
                ":input_index": spend.input_index,
                ":prevout_txid": &prevout.hash()[..],
                ":prevout_output_index": prevout.n(),
                ":script": script,
                ":mined": mined,
            ],
            |row| row.get::<_, i64>(0),
        )?,
        Some((id, stored_account, stored_txid, stored_index, stored_script, placement)) => {
            if (
                stored_account,
                &stored_txid[..],
                stored_index,
                &stored_script,
            ) != (account_ref.0, &prevout.hash()[..], prevout.n(), &script)
            {
                let (spending_txid, input_index) = identity();
                return Err(reject(CommitRejection::Integrity(
                    IntegrityFailure::SpendContent {
                        spending_txid,
                        input_index,
                    },
                )));
            }
            match placement {
                Some(h) if h != mined => {
                    let (spending_txid, input_index) = identity();
                    return Err(reject(CommitRejection::Integrity(
                        IntegrityFailure::SpendPlacement {
                            spending_txid,
                            input_index,
                        },
                    )));
                }
                Some(_) => {}
                None => {
                    conn.execute(
                        "UPDATE tpir_spend_events SET mined_height = :mined WHERE id = :id",
                        named_params![":mined": mined, ":id": id],
                    )?;
                }
            }
            id
        }
    };
    check_against_ledger_events(conn, spend.spending_txid.as_ref(), mined, None)?;
    let receive_names_other_script: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_receive_events
             WHERE txid = :txid AND output_index = :output_index AND script != :script
         )",
        named_params![
            ":txid": &prevout.hash()[..],
            ":output_index": prevout.n(),
            ":script": script,
        ],
        |row| row.get(0),
    )?;
    if receive_names_other_script {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::SpendAddress(prevout.clone()),
        )));
    }
    let output_later: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_receive_events
             WHERE txid = :txid AND output_index = :output_index AND mined_height > :mined
         )",
        named_params![
            ":txid": &prevout.hash()[..],
            ":output_index": prevout.n(),
            ":mined": mined,
        ],
        |row| row.get(0),
    )?;
    if output_later {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::SpendBeforeOutput(prevout.clone()),
        )));
    }
    let conflicting: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_spend_events
             WHERE prevout_txid = :prevout_txid AND prevout_output_index = :prevout_output_index
             AND mined_height IS NOT NULL
             AND id != :id
         )",
        named_params![
            ":prevout_txid": &prevout.hash()[..],
            ":prevout_output_index": prevout.n(),
            ":id": id,
        ],
        |row| row.get(0),
    )?;
    if conflicting {
        return Err(reject(CommitRejection::Integrity(
            IntegrityFailure::ConflictingSpends(prevout.clone()),
        )));
    }
    conn.execute(
        "INSERT INTO tpir_spend_observations (spend_id, revision_id)
         VALUES (:id, :revision_id)
         ON CONFLICT DO NOTHING",
        named_params![":id": id, ":revision_id": revision_id],
    )?;
    Ok(())
}

/// Records `page` as pending retrieval work of revision `revision_id`, for `target`.
///
/// Replaying an opening is a no-op; reopening the page with another range or address set
/// refuses the commit. A page may not overlap supported coverage the revision already recorded
/// for one of its addresses.
#[cfg(feature = "transparent-inputs")]
pub(super) fn open_page(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
    revision_id: i64,
    target: &ChainPoint,
    page: &PageRequest,
) -> Result<(), SqliteClientError> {
    let stored = conn
        .query_row(
            "SELECT id, from_height, through_height FROM tpir_pending_pages
             WHERE account_id = :account_id AND revision_id = :revision_id AND page = :page",
            named_params![
                ":account_id": account_ref.0,
                ":revision_id": revision_id,
                ":page": page.page,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                ))
            },
        )
        .optional()?;
    let scripts: BTreeSet<Vec<u8>> = page.addresses.iter().map(script_bytes).collect();
    if let Some((id, from, through)) = stored {
        // Replaying an opening is harmless; reopening it with another range or address set is
        // not, since merging would describe work no request asked for.
        let stored_scripts = conn
            .prepare_cached("SELECT script FROM tpir_pending_page_scripts WHERE page_id = :id")?
            .query_map(named_params![":id": id], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<BTreeSet<_>, _>>()?;
        if (from, through) != (u32::from(page.from), u32::from(page.through))
            || stored_scripts != scripts
        {
            return Err(reject(CommitRejection::Invalid(InvalidCommit::Page)));
        }
        return Ok(());
    }
    for address in &page.addresses {
        let covered: bool = conn.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM tpir_coverage
                 WHERE account_id = :account_id AND revision_id = :revision_id
                 AND script = :script AND supported = 1
                 AND from_height <= :through AND through_height >= :from
             )",
            named_params![
                ":account_id": account_ref.0,
                ":revision_id": revision_id,
                ":script": script_bytes(address),
                ":from": u32::from(page.from),
                ":through": u32::from(page.through),
            ],
            |row| row.get(0),
        )?;
        if covered {
            return Err(reject(CommitRejection::Invalid(
                InvalidCommit::PendingPageOverlap(*address),
            )));
        }
    }
    let page_id: i64 = conn.query_row(
        "INSERT INTO tpir_pending_pages (
             account_id, revision_id, page, from_height, through_height,
             target_height, target_hash
         )
         VALUES (
             :account_id, :revision_id, :page, :from_height, :through_height,
             :target_height, :target_hash
         )
         RETURNING id",
        named_params![
            ":account_id": account_ref.0,
            ":revision_id": revision_id,
            ":page": page.page,
            ":from_height": u32::from(page.from),
            ":through_height": u32::from(page.through),
            ":target_height": u32::from(target.height),
            ":target_hash": target.hash.0.to_vec(),
        ],
        |row| row.get(0),
    )?;
    for script in scripts {
        conn.execute(
            "INSERT INTO tpir_pending_page_scripts (page_id, script)
             VALUES (:page_id, :script)",
            named_params![":page_id": page_id, ":script": script],
        )?;
    }
    Ok(())
}

/// Whether a coverage range is one the revision indexed (supported) or one it declares it
/// cannot index (unsupported).
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CoverageSupport {
    Supported,
    Unsupported,
}

/// Records that revision `revision_id`, anchored at `anchor`, checked `range` (`Supported`) or
/// declares it cannot index it (`Unsupported`). Idempotent.
///
/// A range contradicting the revision's other support for the same address, or supported
/// coverage overlapping one of the revision's pending pages, refuses the commit.
#[cfg(feature = "transparent-inputs")]
pub(super) fn record_range(
    conn: &rusqlite::Connection,
    account_ref: AccountRef,
    revision_id: i64,
    anchor: &ChainPoint,
    range: &AddressRange,
    support: CoverageSupport,
) -> Result<(), SqliteClientError> {
    let supported = support == CoverageSupport::Supported;
    let script = script_bytes(&range.address);
    let (from, through) = (u32::from(range.from), u32::from(range.through));
    let contradicted: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM tpir_coverage
             WHERE account_id = :account_id AND revision_id = :revision_id AND script = :script
             AND supported != :supported
             AND from_height <= :through AND through_height >= :from
         )",
        named_params![
            ":account_id": account_ref.0,
            ":revision_id": revision_id,
            ":script": script,
            ":supported": supported,
            ":from": from,
            ":through": through,
        ],
        |row| row.get(0),
    )?;
    if contradicted {
        return Err(reject(CommitRejection::Invalid(
            InvalidCommit::SupportContradiction(range.address),
        )));
    }
    if supported {
        let blocked: bool = conn.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM tpir_pending_pages p
                 JOIN tpir_pending_page_scripts s ON s.page_id = p.id
                 WHERE p.account_id = :account_id AND p.revision_id = :revision_id
                 AND s.script = :script
                 AND p.from_height <= :through AND p.through_height >= :from
             )",
            named_params![
                ":account_id": account_ref.0,
                ":revision_id": revision_id,
                ":script": script,
                ":from": from,
                ":through": through,
            ],
            |row| row.get(0),
        )?;
        if blocked {
            return Err(reject(CommitRejection::Invalid(
                InvalidCommit::PendingPageOverlap(range.address),
            )));
        }
    }
    conn.execute(
        "INSERT INTO tpir_coverage (
             account_id, script, from_height, through_height, anchor_height, anchor_hash,
             revision_id, supported
         )
         SELECT :account_id, :script, :from, :through, :anchor_height, :anchor_hash,
                :revision_id, :supported
         WHERE NOT EXISTS (
             SELECT 1 FROM tpir_coverage
             WHERE account_id = :account_id AND script = :script
             AND from_height = :from AND through_height = :through
             AND revision_id = :revision_id AND supported = :supported
         )",
        named_params![
            ":account_id": account_ref.0,
            ":script": script,
            ":from": from,
            ":through": through,
            ":anchor_height": u32::from(anchor.height),
            ":anchor_hash": anchor.hash.0.to_vec(),
            ":revision_id": revision_id,
            ":supported": supported,
        ],
    )?;
    Ok(())
}
