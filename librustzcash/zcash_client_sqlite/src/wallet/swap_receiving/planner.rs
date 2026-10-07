//! Restore sweeps: one receiver-directory pass for each key recovered from the seed.
//! Preparing metadata does not derive viewing keys.
use super::{Error, KeyId, PendingPayment, account_key, corrupt, payments::key_ref, stored_key_id};
use crate::{AccountUuid, SqlTransaction, WalletDb, wallet};
use rusqlite::{Connection, params};
use std::borrow::{Borrow, BorrowMut};
use zcash_client_backend::data_api::transparent_ledger::ChainPoint;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Parameters};

/// One receiver's due sweep. Public metadata is not note ownership.
#[derive(Clone, PartialEq, Eq)]
pub struct DiscoveryWork {
    /// Derivation identity. Derive only when authenticating returned notes.
    pub key: KeyId,
    /// Canonical address bytes already stored at registration.
    pub receiver: [u8; 43],
    /// A completed lookup whose candidates are durably queued. Resume those first.
    pub lookup: Option<ChainPoint>,
}
/// Returns `anchor` only while its block is still on the wallet's chain.
pub(super) fn canonical(
    conn: &Connection,
    anchor: Option<ChainPoint>,
) -> Result<Option<ChainPoint>, Error> {
    Ok(match anchor {
        Some(a) if wallet::get_block_hash(conn, a.height)? == Some(a.hash) => Some(a),
        _ => None,
    })
}

/// Builds an anchor from a stored height and hash pair.
pub(super) fn anchor(height: Option<u32>, hash: Option<[u8; 32]>) -> Option<ChainPoint> {
    height.zip(hash).map(|(height, hash)| ChainPoint {
        height: BlockHeight::from(height),
        hash: BlockHash(hash),
    })
}

impl<C: Borrow<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Whether `account` still has restore sweeps or queued candidates through `through`.
    /// Retry backoff never makes an unfinished restore appear complete.
    pub fn swap_history_pending(
        &self,
        account: AccountUuid,
        through: BlockHeight,
    ) -> Result<bool, Error> {
        let conn = self.conn.borrow();
        let (owner, _) = account_key(conn, &self.params, account)?;
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_swap_sweeps s
                JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
                WHERE k.account_id = ?1 AND k.scan_from <= ?2 AND s.done_height IS NULL)
             OR EXISTS(SELECT 1 FROM ironwood_swap_payment_recovery p
                JOIN ironwood_receiving_keys k ON k.id = p.receiving_key_id
                WHERE k.account_id = ?1)",
            params![owner.0, u32::from(through)],
            |r| r.get(0),
        )?)
    }
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Selects at most `limit` due sweeps without reconstructing historical keys.
    /// Attempts are leased separately just before I/O, so a stopped batch cannot
    /// starve its tail.
    pub fn prepare_swap_discovery_batch(
        &mut self,
        account: AccountUuid,
        through: ChainPoint,
        now: i64,
        limit: std::num::NonZeroU32,
    ) -> Result<Vec<DiscoveryWork>, Error> {
        if now < 0 {
            return Err(corrupt("invalid recovery time"));
        }
        self.transactionally(|db| {
            let (owner, _) = account_key(db.conn.0, &db.params, account)?;
            if canonical(db.conn.0, Some(through))?.is_none() {
                return Err(Error::SweepDeferred(super::SweepDeferral::UnknownAnchor));
            }
            let rows = {
                // A finished sweep is offered again while a late lookup left candidates
                // queued.
                let mut stmt = db.conn.0.prepare(
                    "SELECT k.purpose, k.key_index, k.receiver, s.lookup_height, s.lookup_hash
                     FROM ironwood_swap_sweeps s
                     JOIN ironwood_receiving_keys k ON k.id = s.receiving_key_id
                     WHERE k.account_id = ?1 AND k.scan_from <= ?2 AND s.next_attempt_at <= ?3
                       AND (s.done_height IS NULL OR EXISTS(
                           SELECT 1 FROM ironwood_swap_payment_recovery p
                           WHERE p.receiving_key_id = s.receiving_key_id))
                     ORDER BY s.next_attempt_at, s.receiving_key_id LIMIT ?4",
                )?;
                let through_height = u32::from(through.height);
                let mut rows = stmt.query(params![owner.0, through_height, now, limit.get()])?;
                let mut out = Vec::new();
                while let Some(r) = rows.next()? {
                    out.push((
                        stored_key_id(r)?,
                        r.get::<_, Vec<u8>>(2)?,
                        anchor(r.get(3)?, r.get(4)?),
                    ));
                }
                out
            };
            let mut work = Vec::new();
            for (key, receiver, lookup) in rows {
                work.push(DiscoveryWork {
                    key,
                    receiver: receiver
                        .try_into()
                        .map_err(|_| corrupt("invalid stored receiver"))?,
                    lookup: canonical(db.conn.0, lookup)?,
                });
            }
            Ok(work)
        })
    }

    /// Leases `key`'s sweep for an attempt, just before its network lookups. Every
    /// attempt, including one that fails or the process abandons, backs off the next
    /// from one minute to twelve hours.
    pub fn begin_swap_discovery_attempt(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        now: i64,
    ) -> Result<(), Error> {
        self.transactionally(|db| {
            let id = key_ref(db.conn.0, account, key)?;
            let attempt: u32 = db.conn.0.query_row(
                "SELECT attempts FROM ironwood_swap_sweeps WHERE receiving_key_id = ?1",
                [id],
                |r| r.get(0),
            )?;
            let delay = (60i64 << attempt.min(10)).min(43200);
            db.conn.0.execute(
                "UPDATE ironwood_swap_sweeps
                 SET attempts = MIN(attempts + 1, 30), next_attempt_at = ?2
                 WHERE receiving_key_id = ?1",
                params![id, now.saturating_add(delay)],
            )?;
            Ok(())
        })
    }
}

impl<P: Parameters, CL, R> WalletDb<SqlTransaction<'_>, P, CL, R> {
    /// Atomically persists an entire validated lookup and authenticated ciphertexts.
    /// No balance is credited here. The caller validates the publication's complete
    /// coverage and pagination before invoking this method, including for empty results.
    pub(crate) fn queue_swap_lookup(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        anchor: ChainPoint,
        payments: &[PendingPayment],
    ) -> Result<(), Error> {
        let id = key_ref(self.conn.0, account, key)?;
        self.queue_swap_candidates(account, key, anchor, payments)?;
        self.conn.0.execute(
            "UPDATE ironwood_swap_sweeps SET lookup_height = ?2, lookup_hash = ?3
             WHERE receiving_key_id = ?1 AND (lookup_height IS NULL OR lookup_height <= ?2)",
            params![id, u32::from(anchor.height), anchor.hash.0],
        )?;
        Ok(())
    }

    /// Persists authenticated candidates from a lookup at `anchor` without completing
    /// it (see [`Self::queue_swap_lookup`]).
    pub(crate) fn queue_swap_candidates(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        anchor: ChainPoint,
        payments: &[PendingPayment],
    ) -> Result<(), Error> {
        if canonical(self.conn.0, Some(anchor))?.is_none() {
            return Err(Error::SweepDeferred(super::SweepDeferral::UnknownAnchor));
        }
        for payment in payments {
            if payment.height > anchor.height {
                return Err(corrupt("payment exceeds lookup coverage"));
            }
            self.queue_swap_payment(account, key, payment)?;
        }
        Ok(())
    }
}
