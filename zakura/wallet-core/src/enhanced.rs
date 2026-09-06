//! What a full transaction yields that its compact form cannot.
//!
//! A compact block carries enough to notice a note arriving and enough to
//! notice one being spent, and nothing else. Two things it deliberately omits:
//! the memo, which lives past the 52 bytes of ciphertext prefix compact actions
//! carry, and the outgoing ciphertext, which is the only thing that lets the
//! sender of a payment recover what they sent and to whom.
//!
//! Both come back only from the full transaction, which is why enhancement
//! exists and why a wallet that never enhances can show a payment leaving
//! without being able to say where it went.

use orchard::note::{Note, Nullifier};
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::{account::AccountId, pool::PoolId};

/// How an output relates to the wallet that decrypted it.
///
/// Three variants, not four. The fork carries a `WalletInternal` for transfers
/// between a wallet's own transparent addresses, which cannot arise for a
/// shielded output and is `unreachable!()` on its shielded path; a variant no
/// code can construct is a variant every `match` has to pretend to handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// Received at an external address: somebody paid the wallet.
    Incoming,
    /// Received at an internal address: the wallet's own change.
    AccountInternal,
    /// Recovered with an outgoing viewing key: the wallet paid somebody.
    ///
    /// This is the one that can only come from a full transaction. It is
    /// recovered from the outgoing ciphertext, which compact blocks omit, so no
    /// amount of scanning will ever produce it.
    Outgoing,
}

/// One decrypted output of a full transaction.
#[derive(Debug, Clone)]
pub struct DecryptedOutput {
    /// The pool whose bundle carried it.
    pub pool: PoolId,
    /// Its index within that bundle.
    pub action_index: usize,
    /// The account whose key opened it.
    ///
    /// Attribution is a *result* of trial decryption, never a caller's choice:
    /// the transaction is tried against every account the wallet holds, and
    /// whichever key opens an output is the account that owns it.
    pub account: AccountId,
    /// The note itself.
    pub note: Note,
    /// The address the note was sent to.
    pub recipient: orchard::Address,
    /// The memo, exactly as encrypted: 512 bytes, lead byte and all.
    pub memo: [u8; 512],
    /// How this output relates to the wallet.
    pub transfer_type: TransferType,
}

/// A full transaction, as this wallet sees it.
#[derive(Debug, Clone)]
pub struct EnhancedTx {
    /// The transaction's identifier, verified against the bytes it came from.
    pub txid: TxId,
    /// The height past which it can no longer be mined, if it declared one.
    ///
    /// Zero means it never expires, which the protocol allows and which the
    /// expiry rules have to keep treating as "still pending" forever.
    pub expiry_height: Option<BlockHeight>,
    /// Every output the wallet could decrypt, in bundle order.
    pub outputs: Vec<DecryptedOutput>,
    /// Every shielded nullifier it revealed, whether or not the wallet holds
    /// the note being spent.
    pub spent_nullifiers: Vec<(PoolId, Nullifier)>,
    /// The sum of the shielded bundles' value balances.
    ///
    /// For a transaction with no transparent parts this *is* the fee, exactly.
    /// With transparent inputs it is only one term, and the rest depends on
    /// prevout values the wallet may not hold — which is why a fee is left
    /// unknown rather than guessed.
    pub shielded_value_balance: i64,
    /// The transaction's own bytes.
    pub raw: Vec<u8>,
}

impl EnhancedTx {
    /// Whether the wallet has any reason to store this transaction.
    ///
    /// A transaction reached through enhancement is not necessarily the
    /// wallet's: it may have been fetched because something else depended on
    /// it. Storing one that touches the wallet nowhere would fill the durable
    /// database with strangers' transactions.
    pub fn touches_wallet(&self) -> bool {
        !self.outputs.is_empty() || !self.spent_nullifiers.is_empty()
    }
}

/// A chain's answer about one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// The server does not have it.
    NotFound,
    /// The server has it, but not in the main chain: in the mempool, or mined
    /// on a fork. Either way, positive proof it is not mined here.
    NotInMainChain,
    /// Mined at this height.
    Mined(BlockHeight),
}

impl TransactionStatus {
    /// The height it was mined at, if it was.
    pub fn height(self) -> Option<BlockHeight> {
        match self {
            Self::Mined(h) => Some(h),
            _ => None,
        }
    }
}

