//! Apply discovery only after local chain and spend checks, in one transaction.
use super::{
    AccountUuid, Error, KeyId, PendingPayment, SpendStatus, corrupt,
    payments::{authenticate, spend_status},
};
use crate::{SqlTransaction, WalletDb, error::SqliteClientError, wallet};
use incrementalmerkletree::{Address, Position, Retention};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use rusqlite::{Connection, OptionalExtension, params};
use std::borrow::BorrowMut;
use zcash_client_backend::data_api::transparent_ledger::ChainPoint;
use zcash_client_backend::wallet::{WalletOrchardOutput, WalletTx};
use zcash_note_encryption::ShieldedOutput as _;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
};

/// Incomplete work stays queued and never contributes to wallet balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentApplication {
    /// The wallet must finish scanning its current accepted tip.
    AwaitingScan,
    /// No usable inclusion path exists at the accepted anchor.
    AwaitingWitness,
    /// Locally retained history cannot establish absence of a spend.
    AwaitingSpendHistory,
    /// The authenticated note predates the account's birthday, so the wallet does not
    /// track it, as with any note before the birthday. Its inclusion is still checked
    /// against the wallet's chain; its key is then marked used, advancing and paid, so
    /// the index is never issued again and the lookahead and issuance bound move past it.
    BeforeBirthday,
    /// The directory's claim failed a local check: the note's block or inclusion path,
    /// or its transaction identity against stored data. The key's queued lookup is
    /// discarded, so its next attempt asks the directory again.
    Rejected,
    /// Note, memo, witness, key identity, and any known spend were committed together,
    /// or the wallet already stored the note under another transaction.
    Applied,
}

impl<C: BorrowMut<Connection>, P: Parameters, CL, R> WalletDb<C, P, CL, R> {
    /// Applies a queued payment with `witness`, its inclusion path at an anchor on the
    /// wallet's chain. Transaction identity remains directory-provided until scanning
    /// finds the note. Inclusion authenticates the note and position, not its
    /// transaction ID. Conflicts with local data fail.
    pub(crate) fn apply_pending_swap_payment(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        candidate: &PendingPayment,
        through: ChainPoint,
        witness: (ChainPoint, &MerklePath),
    ) -> Result<PaymentApplication, Error> {
        self.transactionally(|db| {
            db.apply_pending_swap_payment(account, key, candidate, through, witness)
        })
    }
}
impl<P: Parameters, CL, R> WalletDb<SqlTransaction<'_>, P, CL, R> {
    /// Transaction-scoped application. Propagate any error to roll back the transaction.
    pub(crate) fn apply_pending_swap_payment(
        &mut self,
        account: AccountUuid,
        key: KeyId,
        candidate: &PendingPayment,
        through: ChainPoint,
        (anchor, path): (ChainPoint, &MerklePath),
    ) -> Result<PaymentApplication, Error> {
        let conn = self.conn.0;
        if !self
            .pending_swap_payments(account, key)?
            .iter()
            .any(|p| p == candidate)
        {
            return Err(corrupt("swap payment is not queued or changed"));
        }
        let (key_ref, recovered) = authenticate(conn, &self.params, account, key, candidate)?;
        // Scanning stores a note under the transaction it is found in, which no
        // directory claim overrides (see `adopt_found_note`), so a copy stored under
        // another transaction makes this answer redundant.
        let stored_elsewhere: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE n.nf = ?1 AND (t.txid != ?2 OR n.action_index != ?3))",
            params![
                recovered.nullifier().to_bytes(),
                candidate.txid.as_ref(),
                candidate.action_index
            ],
            |r| r.get(0),
        )?;
        if stored_elsewhere {
            conn.execute(
                "DELETE FROM ironwood_swap_payment_recovery
                 WHERE receiving_key_id = ?1 AND txid = ?2 AND action_index = ?3",
                params![key_ref, candidate.txid.as_ref(), candidate.action_index],
            )?;
            return Ok(PaymentApplication::Applied);
        }
        if wallet::fully_scanned_height(conn)? != Some(through.height)
            || wallet::chain_tip_height(conn)? != Some(through.height)
        {
            return Ok(PaymentApplication::AwaitingScan);
        }
        let birthday: u32 = conn.query_row(
            "SELECT birthday_height FROM accounts WHERE uuid = ?1",
            [account.0],
            |r| r.get(0),
        )?;
        // The wallet stores no block before its birthday, so an older note's position
        // is bound by its inclusion path alone.
        let before_birthday = u32::from(candidate.height) < birthday;
        if !before_birthday {
            let (end, count): (u64, u64) = conn.query_row(
                "SELECT ironwood_commitment_tree_size, ironwood_action_count FROM blocks
                 WHERE height = ?1",
                [u32::from(candidate.height)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if end
                .checked_sub(count)
                .is_none_or(|start| u64::from(candidate.position) < start)
                || u64::from(candidate.position) >= end
            {
                return reject(conn, key_ref);
            }
        }
        if anchor.height > through.height
            || through.height - anchor.height > crate::PRUNING_DEPTH
            || wallet::get_block_hash(conn, anchor.height)? != Some(anchor.hash)
        {
            return Ok(PaymentApplication::AwaitingWitness);
        }
        let oldest = u32::from(through.height).saturating_sub(crate::PRUNING_DEPTH);
        let checkpoint: Option<u32> = conn.query_row(
            "SELECT MAX(checkpoint_id) FROM ironwood_tree_checkpoints
             WHERE checkpoint_id BETWEEN ?1 AND ?2",
            params![oldest, u32::from(anchor.height)],
            |r| r.get(0),
        )?;
        let Some(checkpoint) = checkpoint.map(BlockHeight::from) else {
            return Ok(PaymentApplication::AwaitingWitness);
        };
        let mut tree = crate::ironwood_tree(conn).map_err(SqliteClientError::from)?;
        let Some(root) = tree
            .root_at_checkpoint_id(&checkpoint)
            .map_err(SqliteClientError::from)?
        else {
            return Ok(PaymentApplication::AwaitingWitness);
        };
        if !recovered.verify_position(u64::from(candidate.position), path, root.into()) {
            return reject(conn, key_ref);
        }
        if before_birthday {
            conn.execute(
                "UPDATE ironwood_receiving_keys
                 SET advances_allocation = 1, used = 1, paid_before_birthday = 1 WHERE id = ?1",
                [key_ref],
            )?;
            conn.execute(
                "DELETE FROM ironwood_swap_payment_recovery
                 WHERE receiving_key_id = ?1 AND txid = ?2 AND action_index = ?3",
                params![key_ref, candidate.txid.as_ref(), candidate.action_index],
            )?;
            return Ok(PaymentApplication::BeforeBirthday);
        }
        // An unmined transaction is one a rewind or the mempool left: its note may move
        // to a new position, but a transaction holding no such note is not this one.
        let conflict: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid = ?1 AND mined_height IS NOT NULL
                 AND (mined_height != ?2 OR tx_index != ?3))
             OR EXISTS(SELECT 1 FROM transactions t WHERE t.txid = ?1 AND t.mined_height IS NULL
                 AND NOT EXISTS(SELECT 1 FROM ironwood_received_notes n
                     WHERE n.transaction_id = t.id_tx AND n.action_index = ?4
                       AND n.receiving_key_id = ?6))
             OR EXISTS(SELECT 1 FROM ironwood_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id
                 WHERE t.txid = ?1 AND n.action_index = ?4 AND (
                     (n.nf IS NULL AND t.mined_height IS NOT NULL) OR n.nf != ?5
                     OR n.receiving_key_id IS NULL OR n.receiving_key_id != ?6
                     OR (t.mined_height IS NOT NULL AND n.commitment_tree_position IS NOT NULL
                         AND n.commitment_tree_position != ?7)))",
            params![
                candidate.txid.as_ref(),
                u32::from(candidate.height),
                candidate.tx_index,
                candidate.action_index,
                recovered.nullifier().to_bytes(),
                key_ref,
                candidate.position
            ],
            |r| r.get(0),
        )?;
        if conflict {
            return reject(conn, key_ref);
        }
        let spent = spend_status(conn, candidate, recovered.nullifier(), through)?;
        if spent == SpendStatus::Unknown {
            // Authenticate inclusion before a directory answer can trigger a replay.
            self.queue_swap_spend_history(account, through.height)?;
            return Ok(PaymentApplication::AwaitingSpendHistory);
        }
        let anchor_size: u64 = conn.query_row(
            "SELECT ironwood_commitment_tree_size FROM blocks WHERE height=?1",
            [u32::from(checkpoint)],
            |r| r.get(0),
        )?;
        // Persist only complete sibling subtrees. A partial right subtree includes
        // empty future leaves and must not become a fixed hash for future appends.
        for (level, hash) in path.auth_path().into_iter().enumerate() {
            let address = Address::from_parts(
                (level as u8).into(),
                (u64::from(candidate.position) >> level) ^ 1,
            );
            if u64::from(address.position_range_end()) <= anchor_size {
                tree.insert(address, hash)
                    .map_err(SqliteClientError::from)?;
            }
        }
        tree.batch_insert(
            Position::from(u64::from(candidate.position)),
            std::iter::once((
                MerkleHashOrchard::from_cmx(&recovered.note().commitment().into()),
                Retention::Marked,
            )),
        )
        .map_err(SqliteClientError::from)?;
        let stored_path = tree
            .witness_at_checkpoint_id(Position::from(u64::from(candidate.position)), &checkpoint)
            .map_err(SqliteClientError::from)?
            .ok_or_else(|| corrupt("stored swap witness missing"))?;
        if !recovered.verify_position(
            u64::from(candidate.position),
            &stored_path.into(),
            root.into(),
        ) {
            return Err(corrupt("stored swap witness changed"));
        }
        let tx = WalletTx::new(
            candidate.txid,
            candidate.tx_index.into(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let tx_ref = wallet::put_tx_meta(conn, &tx, candidate.height)?;
        let spent_in = if let SpendStatus::Spent(txid) = spent {
            let existing: Option<i64> = conn
                .query_row(
                    "SELECT id_tx FROM transactions WHERE txid = ?1",
                    [txid.as_ref()],
                    |r| r.get(0),
                )
                .optional()?;
            let spending = match existing {
                Some(id) => Some(crate::TxRef(id)),
                None => wallet::query_nullifier_map(
                    conn,
                    ShieldedPool::Ironwood,
                    &recovered.nullifier().to_bytes(),
                )?,
            };
            Some(spending.ok_or_else(|| corrupt("verified swap spend lost its transaction"))?)
        } else {
            None
        };
        let encrypted = &candidate.encrypted_note;
        let output = WalletOrchardOutput::from_parts(
            candidate.action_index as usize,
            encrypted.ephemeral_key(),
            (*recovered.note(), orchard::ValuePool::Ironwood),
            false,
            Position::from(u64::from(candidate.position)),
            Some(*recovered.nullifier()),
            account,
            Some(zip32::Scope::External),
        )
        .with_swap_key_id(Some(key))
        .with_compact_ciphertext(encrypted.enc_ciphertext()[..52].try_into().unwrap());
        wallet::orchard::put_received_note(
            conn,
            &self.params,
            ShieldedPool::Ironwood,
            &output,
            tx_ref,
            Some(candidate.height),
            spent_in,
        )?;
        let memo = MemoBytes::from_bytes(recovered.memo())
            .map_err(|_| corrupt("invalid recovered memo length"))?;
        conn.execute(
            "UPDATE ironwood_received_notes SET memo = ?1
             WHERE transaction_id = ?2 AND action_index = ?3",
            params![
                wallet::memo_repr(Some(&memo)),
                tx_ref.0,
                candidate.action_index
            ],
        )?;
        conn.execute(
            "DELETE FROM ironwood_memo_retrieval_queue WHERE received_note_id IN
            (SELECT id FROM ironwood_received_notes WHERE transaction_id=?1 AND action_index=?2)",
            params![tx_ref.0, candidate.action_index],
        )?;
        wallet::enhance_pir::protect_recovered_incoming(conn, tx_ref)?;
        conn.execute(
            "DELETE FROM ironwood_swap_payment_recovery
             WHERE receiving_key_id = ?1 AND txid = ?2 AND action_index = ?3",
            params![key_ref, candidate.txid.as_ref(), candidate.action_index],
        )?;
        Ok(PaymentApplication::Applied)
    }
}

/// Discards key `key_ref`'s queued lookup after the directory's claim failed a local
/// check, so the next attempt asks again. See [`PaymentApplication::Rejected`].
fn reject(conn: &Connection, key_ref: i64) -> Result<PaymentApplication, Error> {
    conn.execute(
        "DELETE FROM ironwood_swap_payment_recovery WHERE receiving_key_id = ?1",
        [key_ref],
    )?;
    conn.execute(
        "UPDATE ironwood_swap_sweeps SET lookup_height = NULL, lookup_hash = NULL,
            done_height = NULL WHERE receiving_key_id = ?1",
        [key_ref],
    )?;
    Ok(PaymentApplication::Rejected)
}
