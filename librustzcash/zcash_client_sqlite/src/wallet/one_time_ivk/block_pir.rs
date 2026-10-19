//! Durable receiver walks and candidate admission under account, history and session fences.
use super::restore::{
    apply::{Admission, Sessions, apply_payment, merkle_path, rescan_uncovered, scanned_tip},
    payments::{PendingPayment, authenticate, directory_candidate, payment},
};
use super::{
    Discovery, KeyId, account_key, block_recovery, invalid, key_ref, purpose_code, register,
};
use crate::{AccountUuid, SqliteClientError, WalletDb, util::Clock, wallet};
use rand_core::Rng;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::borrow::BorrowMut;
use zcash_client_backend::data_api::{
    one_time_ivk::{
        recovery::settlement::{OneTimePirRecovery, PirScope, PirSnapshot, PirWitness, PirWork},
        restore::{DirectoryPayment, DiscoveryWork, LookupWork, PublicationEnd},
    },
    transparent_ledger::ChainPoint,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Parameters};

/// Loads one persisted cursor without treating it as permission to apply a response.
fn load<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    key: KeyId,
) -> Result<Option<PirWork<AccountUuid>>, SqliteClientError> {
    let Some(state) = block_recovery::state(conn, params, account)? else {
        return Ok(None);
    };
    let Some(history) = state.history else {
        return Ok(None);
    };
    Ok(conn.query_row("SELECT l.work_generation, l.session, l.publication_height, l.publication_hash, l.tree_size,
             l.through_height, l.through_hash, l.applied, l.last_position, l.last_nullifier, l.enumerated,
             k.receiver FROM ironwood_block_lookups l JOIN ironwood_one_time_keys k ON k.id=l.one_time_key_id
             JOIN accounts a ON a.id=k.account_id WHERE a.uuid=?1 AND k.purpose=?2 AND k.key_index=?3",
        params![account.0,purpose_code(key.purpose())?,key.index().to_be_bytes()], |r| {
            let through=ChainPoint{height:BlockHeight::from(r.get::<_,u32>(5)?),hash:BlockHash(r.get(6)?)};
            let position:Option<u64>=r.get(8)?;
            Ok(PirWork {
                scope: PirScope{account,key,work:r.get(0)?,snapshot:PirSnapshot{history,session:r.get(1)?,publication:PublicationEnd{height:BlockHeight::from(r.get::<_,u32>(2)?),hash:r.get(3)?,tree_size:r.get(4)?}},through},
                lookup:LookupWork{work:DiscoveryWork{key,receiver:r.get(11)?},cutoff:through.height,applied:r.get(7)?,last:position.map(|p|r.get(9).map(|nf|(p,nf))).transpose()?},
                enumerated:r.get(10)?,
            })
        }).optional()?)
}

/// Requires the claimed publication to be the wallet's exact canonical block and tree size.
fn publication_connected(
    conn: &Connection,
    publication: PublicationEnd,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM blocks WHERE height=?1 AND hash=?2 AND ironwood_commitment_tree_size=?3)",params![u32::from(publication.height),publication.hash,publication.tree_size],|r|r.get(0))?)
}

/// Rechecks authority after every await, independently of whether the lookup still exists.
fn valid<P: Parameters>(
    conn: &Connection,
    params: &P,
    scope: &PirScope<AccountUuid>,
) -> Result<bool, SqliteClientError> {
    let current = block_recovery::state(conn, params, scope.account)?;
    if !current.is_some_and(|s| {
        s.enabled && s.work == scope.work && s.history == Some(scope.snapshot.history)
    }) || !publication_connected(conn, scope.snapshot.publication)?
        || wallet::get_block_hash(conn, scope.through.height)? != Some(scope.through.hash)
    {
        return Ok(false);
    }
    Ok(load(conn, params, scope.account, scope.key)?.is_some_and(|w| w.scope == *scope))
}

/// Starts only from canonical positive obligations and resumes across compatible appended sessions.
fn begin<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    account: AccountUuid,
    key: KeyId,
    snapshot: PirSnapshot,
    now: i64,
) -> Result<Option<PirWork<AccountUuid>>, SqliteClientError> {
    if now < 0 {
        return Err(invalid("negative PIR retry time"));
    }
    let Some(state) = block_recovery::state(conn, params, account)? else {
        return Ok(None);
    };
    if !state.enabled
        || state.history != Some(snapshot.history)
        || !publication_connected(conn, snapshot.publication)?
    {
        return Ok(None);
    }
    let (owner, _) = account_key(conn, params, account)?;
    let target=conn.query_row("SELECT m.height, m.hash FROM ironwood_block_matches m JOIN blocks b ON b.height=m.height AND
             b.hash=m.hash WHERE m.account_id=?1 AND m.purpose=?2 AND m.key_index=?3 AND m.height<=?4 ORDER BY
             m.height DESC LIMIT 1",params![owner.0,purpose_code(key.purpose())?,key.index().to_be_bytes(),u32::from(snapshot.publication.height)],|r|Ok(ChainPoint{height:BlockHeight::from(r.get::<_,u32>(0)?),hash:BlockHash(r.get(1)?)})).optional()?;
    let Some(target) = target else {
        return Ok(None);
    };
    register(
        conn,
        params,
        account,
        key,
        target.height,
        false,
        Discovery::Filter,
        now,
    )?;
    let id = key_ref(conn, account, key)?;
    let old = load(conn, params, account, key)?;
    if let Some(old) = old.as_ref() {
        let due: i64 = conn.query_row(
            "SELECT next_attempt_at FROM ironwood_block_lookups WHERE one_time_key_id=?1",
            [id],
            |r| r.get(0),
        )?;
        let connected = old.scope.work == state.work
            && publication_connected(conn, old.scope.snapshot.publication)?
            && wallet::get_block_hash(conn, old.scope.through.height)?
                == Some(old.scope.through.hash);
        if connected {
            if now < due || snapshot.publication.height < old.scope.snapshot.publication.height {
                return Ok(None);
            }
            let waiting: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM ironwood_block_payments WHERE one_time_key_id=?1)",
                [id],
                |r| r.get(0),
            )?;
            if old.enumerated && !waiting && target.height <= old.scope.through.height {
                settle(conn, params, &old.scope)?;
                return Ok(None);
            }
            let through = if old.enumerated && !waiting {
                target
            } else {
                old.scope.through
            };
            if through.height > snapshot.publication.height {
                return Ok(None);
            }
            if old.scope.snapshot != snapshot {
                conn.execute("UPDATE ironwood_block_payments SET witness=NULL,witness_height=NULL,witness_hash=NULL WHERE one_time_key_id=?1",[id])?;
            }
            conn.execute("UPDATE ironwood_block_lookups SET session=?2, publication_height=?3, publication_hash=?4,
             tree_size=?5, through_height=?6, through_hash=?7, enumerated=CASE WHEN through_height<?6 THEN 0 ELSE
             enumerated END WHERE one_time_key_id=?1",params![id,snapshot.session,u32::from(snapshot.publication.height),snapshot.publication.hash,snapshot.publication.tree_size,u32::from(through.height),through.hash.0])?;
            return load(conn, params, account, key);
        }
        conn.execute(
            "DELETE FROM ironwood_block_lookups WHERE one_time_key_id=?1",
            [id],
        )?;
    }
    conn.execute("INSERT INTO ironwood_block_lookups(one_time_key_id, work_generation, session, publication_height,
             publication_hash, tree_size, through_height, through_hash) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",params![id,state.work,snapshot.session,u32::from(snapshot.publication.height),snapshot.publication.hash,snapshot.publication.tree_size,u32::from(target.height),target.hash.0])?;
    load(conn, params, account, key)
}

/// Clears only covered canonical matches after enumeration and every candidate admission finish.
fn settle<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    scope: &PirScope<AccountUuid>,
) -> Result<(), SqliteClientError> {
    if !valid(conn, params, scope)? {
        return Ok(());
    }
    let id = key_ref(conn, scope.account, scope.key)?;
    let complete:bool=conn.query_row("SELECT enumerated AND NOT EXISTS(SELECT 1 FROM ironwood_block_payments p WHERE
             p.one_time_key_id=l.one_time_key_id) FROM ironwood_block_lookups l WHERE one_time_key_id=?1",[id],|r|r.get(0))?;
    if complete {
        let (owner, _) = account_key(conn, params, scope.account)?;
        conn.execute("DELETE FROM ironwood_block_matches WHERE account_id=?1 AND purpose=?2 AND key_index=?3 AND
             height<=?4 AND EXISTS(SELECT 1 FROM blocks b WHERE b.height=ironwood_block_matches.height AND
             b.hash=ironwood_block_matches.hash)",params![owner.0,purpose_code(scope.key.purpose())?,scope.key.index().to_be_bytes(),u32::from(scope.through.height)])?;
    }
    Ok(())
}

/// Validates an entire bounded page before committing candidates and the next cursor atomically.
fn record_page<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    work: &PirWork<AccountUuid>,
    start: u32,
    records: &[DirectoryPayment],
    complete: bool,
) -> Result<bool, SqliteClientError> {
    if records.len() > 64 {
        return Err(invalid("PIR page budget exceeded"));
    }
    if !valid(conn, params, &work.scope)?
        || load(conn, params, work.scope.account, work.scope.key)?.as_ref() != Some(work)
        || work.enumerated
        || (start != 0 && start != work.lookup.applied)
    {
        return Ok(false);
    }
    let scope = &work.scope;
    let id = key_ref(conn, scope.account, scope.key)?;
    let mut last = if start == 0 { None } else { work.lookup.last };
    let mut last_height = if start == 0 {
        None
    } else {
        conn.query_row(
            "SELECT last_height FROM ironwood_block_lookups WHERE one_time_key_id=?1",
            [id],
            |r| r.get::<_, Option<u32>>(0),
        )?
    };
    let mut candidates = Vec::with_capacity(records.len());
    for record in records {
        let candidate =
            directory_candidate(record).ok_or_else(|| invalid("PIR payment bounds invalid"))?;
        if candidate.height > scope.through.height
            || record.position >= scope.snapshot.publication.tree_size
            || last.is_some_and(|(p, _)| record.position <= p)
            || last_height.is_some_and(|h| record.height < h)
            || wallet::get_block_hash(conn, candidate.height)?
                .is_some_and(|hash| hash != candidate.block_hash)
        {
            return Err(invalid("PIR payment order or chain mismatch"));
        }
        let (_, note) = authenticate(conn, params, scope.account, scope.key, &candidate)?;
        let found:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n JOIN transactions t ON
             t.id_tx=n.transaction_id WHERE n.one_time_key_id=?1 AND n.nf=?2 AND t.mined_height IS NOT NULL)",params![id,note.nullifier().to_bytes()],|r|r.get(0))?;
        if !found {
            candidates.push(candidate);
        }
        last = Some((record.position, record.action_nullifier));
        last_height = Some(record.height);
    }
    if start == 0 {
        conn.execute(
            "DELETE FROM ironwood_block_payments WHERE one_time_key_id=?1",
            [id],
        )?;
    }
    for c in candidates {
        conn.execute("INSERT INTO ironwood_block_payments(one_time_key_id, txid, action_index, height, block_hash,
             tx_index, position, encrypted_note) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",params![id,c.txid.as_ref(),c.action_index,u32::from(c.height),c.block_hash.0,c.tx_index,c.position,c.encrypted_note.to_bytes().as_slice()])?;
    }
    let applied = start
        .checked_add(records.len() as u32)
        .ok_or_else(|| invalid("PIR cursor exhausted"))?;
    conn.execute("UPDATE ironwood_block_lookups SET applied=?2, last_position=?3, last_nullifier=?4, last_height=?5,
             enumerated=?6, attempts=0, next_attempt_at=0 WHERE one_time_key_id=?1",params![id,applied,last.map(|x|x.0),last.map(|x|x.1),last_height,complete])?;
    settle(conn, params, scope)?;
    Ok(true)
}

/// Reconstructs an authenticated candidate's exact wire fields for a fenced witness response.
fn directory_payment(candidate: &PendingPayment) -> DirectoryPayment {
    let bytes = candidate.encrypted_note.to_bytes();
    DirectoryPayment {
        height: u32::from(candidate.height),
        block_hash: candidate.block_hash.0,
        txid: *candidate.txid.as_ref(),
        tx_index: u32::from(candidate.tx_index),
        action_index: candidate.action_index,
        position: u64::from(candidate.position),
        action_nullifier: bytes[..32].try_into().unwrap(),
        cmx: bytes[32..64].try_into().unwrap(),
        ephemeral_key: bytes[64..96].try_into().unwrap(),
        ciphertext_prefix: bytes[96..].try_into().unwrap(),
    }
}

/// Reads a bounded set of pending paths and drops stale generations from the returned work only.
fn witnesses<P: Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    limit: u32,
    now: i64,
) -> Result<Vec<PirWitness<AccountUuid>>, SqliteClientError> {
    let (owner, _) = account_key(conn, params, account)?;
    let rows=conn.prepare("SELECT p.txid, p.action_index, p.height, p.block_hash, p.tx_index, p.position, p.encrypted_note,
             k.purpose, k.key_index FROM ironwood_block_payments p JOIN ironwood_one_time_keys k ON
             k.id=p.one_time_key_id JOIN ironwood_block_lookups l ON l.one_time_key_id=k.id JOIN
             ironwood_block_recovery r ON r.account_id=k.account_id WHERE k.account_id=?1 AND r.enabled=1 AND
             r.work_generation=l.work_generation AND l.next_attempt_at<=?3 AND p.witness IS NULL ORDER BY
             p.height, p.position LIMIT ?2")?.query_and_then(params![owner.0,limit.min(64),now],|r|Ok::<_,SqliteClientError>((payment(r)?,super::stored_key_id_offset(r,7)?)))?.collect::<Result<Vec<_>,_>>()?;
    let mut result = Vec::new();
    for (candidate, key) in rows {
        if let Some(work) = load(conn, params, account, key)?
            && valid(conn, params, &work.scope)?
        {
            result.push(PirWitness {
                scope: work.scope,
                payment: directory_payment(&candidate),
            });
        }
    }
    Ok(result)
}

/// Applies a path only to the exact saved candidate and the publication that owns its scope.
fn record_witness<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    work: &PirWitness<AccountUuid>,
    anchor: ChainPoint,
    siblings: [[u8; 32]; 32],
) -> Result<bool, SqliteClientError> {
    if !valid(conn, params, &work.scope)?
        || anchor.height != work.scope.snapshot.publication.height
        || anchor.hash.0 != work.scope.snapshot.publication.hash
    {
        return Ok(false);
    }
    let id = key_ref(conn, work.scope.account, work.scope.key)?;
    let candidate = conn
        .query_row(
            "SELECT txid, action_index, height, block_hash, tx_index, position, encrypted_note FROM
             ironwood_block_payments WHERE one_time_key_id=?1 AND position=?2",
            params![id, work.payment.position],
            payment,
        )
        .optional()?;
    if candidate.as_ref().map(directory_payment).as_ref() != Some(&work.payment) {
        return Ok(false);
    }
    conn.execute(
        "UPDATE ironwood_block_payments SET witness=?3, witness_height=?4, witness_hash=?5 WHERE
             one_time_key_id=?1 AND position=?2",
        params![
            id,
            work.payment.position,
            siblings.concat(),
            u32::from(anchor.height),
            anchor.hash.0
        ],
    )?;
    Ok(true)
}

/// Backs off a current receiver without extending any watch or making negative judgments.
fn defer<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    scope: &PirScope<AccountUuid>,
    now: i64,
) -> Result<(), SqliteClientError> {
    if now < 0 {
        return Err(invalid("negative PIR retry time"));
    }
    if !valid(conn, params, scope)? {
        return Ok(());
    }
    let id = key_ref(conn, scope.account, scope.key)?;
    let attempts: u32 = conn.query_row(
        "SELECT attempts FROM ironwood_block_lookups WHERE one_time_key_id=?1",
        [id],
        |r| r.get(0),
    )?;
    let next = now.saturating_add((60i64 << attempts.min(10)).min(43_200));
    conn.execute("UPDATE ironwood_block_lookups SET attempts=MIN(attempts+1,30),next_attempt_at=?2 WHERE one_time_key_id=?1",params![id,next])?;
    Ok(())
}

/// Reuses canonical note/witness/spend admission and settles only after its queue drains.
fn admit<P: Parameters>(
    conn: &Transaction<'_>,
    params: &P,
    sessions: &Sessions<'_>,
    account: AccountUuid,
    limit: u32,
    now: i64,
) -> Result<(), SqliteClientError> {
    let Some(through) = scanned_tip(conn)? else {
        return Ok(());
    };
    let (owner, _) = account_key(conn, params, account)?;
    let rows=conn.prepare("SELECT p.txid, p.action_index, p.height, p.block_hash, p.tx_index, p.position, p.encrypted_note,
             k.purpose, k.key_index, p.witness, p.witness_height, p.witness_hash FROM ironwood_block_payments p
             JOIN ironwood_one_time_keys k ON k.id=p.one_time_key_id JOIN ironwood_block_lookups l ON
             l.one_time_key_id=k.id JOIN ironwood_block_recovery r ON r.account_id=k.account_id WHERE
             k.account_id=?1 AND r.enabled=1 AND r.work_generation=l.work_generation AND p.witness IS NOT NULL
             ORDER BY p.height, p.position LIMIT ?2")?.query_and_then(params![owner.0,limit.min(64)],|r|Ok::<_,SqliteClientError>((payment(r)?,super::stored_key_id_offset(r,7)?,r.get::<_,Vec<u8>>(9)?,ChainPoint{height:BlockHeight::from(r.get::<_,u32>(10)?),hash:BlockHash(r.get(11)?)})))?.collect::<Result<Vec<_>,_>>()?;
    for (candidate, key, witness, anchor) in rows {
        let Some(work) = load(conn, params, account, key)? else {
            continue;
        };
        if !valid(conn, params, &work.scope)? {
            continue;
        }
        let id = key_ref(conn, account, key)?;
        let (chunks, rest) = witness.as_chunks::<32>();
        let path = <[[u8; 32]; 32]>::try_from(chunks)
            .ok()
            .filter(|_| rest.is_empty())
            .and_then(|siblings| merkle_path(candidate.position, siblings));
        let admission = match path {
            Some(path) => apply_payment(
                conn,
                sessions,
                params,
                account,
                key,
                &candidate,
                through,
                (anchor, &path),
            )?,
            None => Admission::StaleWitness,
        };
        match admission {
            Admission::Admitted => {
                conn.execute(
                    "DELETE FROM ironwood_block_payments WHERE one_time_key_id=?1 AND position=?2",
                    params![id, candidate.position],
                )?;
                settle(conn, params, &work.scope)?;
            }
            Admission::Waiting => {}
            Admission::Uncovered => rescan_uncovered(conn, owner.0, candidate.height, through)?,
            Admission::StaleWitness => {
                conn.execute("UPDATE ironwood_block_payments SET witness=NULL, witness_height=NULL, witness_hash=NULL WHERE
             one_time_key_id=?1 AND position=?2",params![id,candidate.position])?;
            }
            Admission::Rejected => {
                conn.execute(
                    "DELETE FROM ironwood_block_payments WHERE one_time_key_id=?1",
                    [id],
                )?;
                conn.execute("UPDATE ironwood_block_lookups SET applied=0, last_position=NULL, last_nullifier=NULL,
             last_height=NULL, enumerated=0 WHERE one_time_key_id=?1",[id])?;
                defer(conn, params, &work.scope, now)?;
            }
        }
    }
    Ok(())
}

impl<C: BorrowMut<Connection>, P: Parameters, CL: Clock, R: Rng> OneTimePirRecovery
    for WalletDb<C, P, CL, R>
{
    /// Captures one receiver's pending obligation without holding a connection across network work.
    fn begin_one_time_pir(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        snapshot: PirSnapshot,
        now: i64,
    ) -> Result<Option<PirWork<AccountUuid>>, SqliteClientError> {
        self.transactionally(|db| begin(db.conn.0, &db.params, account, key, snapshot, now))
    }
    /// Saves a bounded page under its exact captured authority.
    fn record_one_time_pir_page(
        &mut self,
        work: &PirWork<AccountUuid>,
        start: u32,
        records: &[DirectoryPayment],
        complete: bool,
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| {
            record_page(db.conn.0, &db.params, work, start, records, complete)
        })
    }
    /// Returns only current candidates, without changing wallet state.
    fn one_time_pir_witnesses(
        &self,
        account: AccountUuid,
        limit: u32,
    ) -> Result<Vec<PirWitness<AccountUuid>>, SqliteClientError> {
        witnesses(
            self.conn.borrow(),
            &self.params,
            account,
            limit,
            super::unix_now(&self.clock),
        )
    }
    /// Records a candidate-specific path without crediting it before admission.
    fn record_one_time_pir_witness(
        &mut self,
        work: &PirWitness<AccountUuid>,
        anchor: ChainPoint,
        siblings: [[u8; 32]; 32],
    ) -> Result<bool, SqliteClientError> {
        self.transactionally(|db| record_witness(db.conn.0, &db.params, work, anchor, siblings))
    }
    /// Atomically admits bounded candidates with ordinary local chain evidence.
    fn admit_one_time_pir(
        &mut self,
        account: AccountUuid,
        limit: u32,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| {
            admit(
                db.conn.0,
                &db.params,
                &db.one_time_sessions(),
                account,
                limit,
                super::unix_now(&db.clock),
            )
        })
    }
    /// Defers only a still-current request.
    fn defer_one_time_pir(
        &mut self,
        scope: &PirScope<AccountUuid>,
        now: i64,
    ) -> Result<(), SqliteClientError> {
        self.transactionally(|db| defer(db.conn.0, &db.params, scope, now))
    }
}
