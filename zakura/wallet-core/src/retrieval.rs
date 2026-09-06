//! What the wallet still needs from outside, and how it names it.
//!
//! Enhancement began as one question — "give me the bytes of this
//! transaction" — and a queue keyed by transaction identifier expressed it
//! exactly. Private retrieval does not fit that shape. A PIR response is *one
//! action*: an ephemeral key, a note ciphertext, a value commitment, an
//! outgoing ciphertext and a flag byte. It is not a transaction, it carries no
//! expiry height and no mined status, and it is selected by commitment tree
//! position rather than by identifier — because the identifier is precisely
//! what must not be sent.
//!
//! So the seam is not "a different way to fetch a transaction". It is a
//! [`Locator`]: what is being asked for, and by which key. A backend serves the
//! locator kinds it can, and the write path is reached by the same route
//! whichever one answered.
//!
//! The other half is [`Guard`]. Everything a response must be checked against
//! is captured locally *before* any network I/O and rechecked inside the
//! transaction that applies the answer. Only the locator crosses the wire. That
//! is what stops a reorg letting a stale response mutate whatever now occupies
//! a position, and it is a type here rather than a discipline in the engine
//! because a discipline is something a later change can quietly drop.

use incrementalmerkletree::Position;
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::{block::BlockHash, pool::PoolId};

/// What is being asked for, and by which key.
///
/// Each variant discloses something different, and the difference is the whole
/// point of the type: naming a transaction tells a server which transaction the
/// wallet cares about, while naming a position tells it only that some wallet
/// wanted some item out of a domain of many.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Locator {
    /// Whether a transaction is mined. Discloses the transaction identifier.
    Status(TxId),
    /// A whole transaction's bytes. Discloses the transaction identifier.
    Transaction(TxId),
    /// One shielded action, by its commitment tree position.
    ///
    /// Discloses the position and nothing else. This is the locator private
    /// retrieval serves.
    Action {
        /// Which pool's tree the position is in.
        pool: PoolId,
        /// The position of the note commitment.
        position: Position,
    },
    /// One block, by height and the hash the wallet scanned there.
    ///
    /// Discloses interest in a height, which is weaker than naming a
    /// transaction and stronger than nothing. The hash is carried so the answer
    /// can be checked against what the wallet already believes rather than
    /// trusted.
    Block {
        /// The block's height.
        height: BlockHeight,
        /// The hash the wallet recorded when it scanned that height.
        hash: BlockHash,
    },
}

/// The kinds of locator a backend can serve.
///
/// A static capability rather than a per-request negotiation: a backend either
/// speaks a locator kind or it does not, and discovering that per request would
/// mean discovering it after the request had already been sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocatorKinds {
    /// Serves [`Locator::Status`].
    pub status: bool,
    /// Serves [`Locator::Transaction`].
    pub transaction: bool,
    /// Serves [`Locator::Action`].
    pub action: bool,
    /// Serves [`Locator::Block`].
    pub block: bool,
}

impl LocatorKinds {
    /// Whether `locator` is one this backend serves.
    pub fn serves(&self, locator: &Locator) -> bool {
        match locator {
            Locator::Status(_) => self.status,
            Locator::Transaction(_) => self.transaction,
            Locator::Action { .. } => self.action,
            Locator::Block { .. } => self.block,
        }
    }
}

/// The stored discriminant of a [`Locator`].
///
/// `Status` and `Transaction` keep the codes the txid-keyed queue used for the
/// same two questions, so a row means what it always meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocatorKind {
    /// [`Locator::Status`].
    Status = 0,
    /// [`Locator::Transaction`].
    Transaction = 1,
    /// [`Locator::Action`].
    Action = 2,
    /// [`Locator::Block`].
    Block = 3,
}

impl LocatorKind {
    /// The stored code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Reads a stored code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Status),
            1 => Some(Self::Transaction),
            2 => Some(Self::Action),
            3 => Some(Self::Block),
            _ => None,
        }
    }
}

impl Locator {
    /// Which kind of question this is.
    pub fn kind(&self) -> LocatorKind {
        match self {
            Locator::Status(_) => LocatorKind::Status,
            Locator::Transaction(_) => LocatorKind::Transaction,
            Locator::Action { .. } => LocatorKind::Action,
            Locator::Block { .. } => LocatorKind::Block,
        }
    }

    /// The transaction this question is about, when that is known locally.
    ///
    /// `None` for an action, whose subject is known only through the candidate
    /// row that supplies its [`Guard`] — which is the point: the wallet knows
    /// the transaction, and the request does not carry it.
    pub fn subject(&self) -> Option<TxId> {
        match self {
            Locator::Status(txid) | Locator::Transaction(txid) => Some(*txid),
            Locator::Action { .. } | Locator::Block { .. } => None,
        }
    }

    /// The height this locator names, when it names one.
    ///
    /// Held alongside the encoded key in storage rather than decoded out of it:
    /// the queue has to be *filtered* on it — a block request is only worth
    /// dispatching once the wallet can anchor the block — and SQL cannot read a
    /// big-endian prefix out of a blob.
    pub fn height(&self) -> Option<BlockHeight> {
        match self {
            Locator::Block { height, .. } => Some(*height),
            Locator::Status(_) | Locator::Transaction(_) | Locator::Action { .. } => None,
        }
    }

    /// The canonical byte encoding used as the stored key.
    ///
    /// Fixed width per kind and big-endian, so that the encoding orders the way
    /// the values do and two locators are equal exactly when their keys are.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Locator::Status(txid) | Locator::Transaction(txid) => txid.as_ref().to_vec(),
            Locator::Action { pool, position } => {
                let mut out = Vec::with_capacity(9);
                out.push(pool.code());
                out.extend_from_slice(&u64::from(*position).to_be_bytes());
                out
            }
            Locator::Block { height, hash } => {
                let mut out = Vec::with_capacity(36);
                out.extend_from_slice(&u32::from(*height).to_be_bytes());
                out.extend_from_slice(&hash.0);
                out
            }
        }
    }

    /// Reads a locator back from its stored kind and key.
    ///
    /// Returns `None` for a key whose length or contents do not match the kind,
    /// so a corrupt row is reported rather than silently becoming a request for
    /// something else.
    pub fn decode(kind: LocatorKind, bytes: &[u8]) -> Option<Self> {
        match kind {
            LocatorKind::Status | LocatorKind::Transaction => {
                let txid = TxId::from_bytes(bytes.try_into().ok()?);
                Some(match kind {
                    LocatorKind::Status => Locator::Status(txid),
                    _ => Locator::Transaction(txid),
                })
            }
            LocatorKind::Action => {
                let (code, rest) = bytes.split_first()?;
                let pool = PoolId::from_code(*code)?;
                let position = Position::from(u64::from_be_bytes(rest.try_into().ok()?));
                Some(Locator::Action { pool, position })
            }
            LocatorKind::Block => {
                if bytes.len() != 36 {
                    return None;
                }
                let height = BlockHeight::from_u32(u32::from_be_bytes(bytes[..4].try_into().ok()?));
                let hash = BlockHash(bytes[4..].try_into().ok()?);
                Some(Locator::Block { height, hash })
            }
        }
    }
}

/// The local identity a response is checked against.
///
/// Captured before the request goes out and rechecked inside the transaction
/// that applies the answer. None of it is sent.
///
/// The fields are exactly what compact scanning already recorded for the
/// action, which is why they can authenticate a response at all: a service can
/// choose *what* to return, but it cannot make a fabricated record reproduce an
/// ephemeral key and ciphertext prefix the wallet read out of a block itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guard {
    /// The transaction the action belongs to.
    pub subject: TxId,
    /// The action's index within its bundle.
    pub action_index: u32,
    /// The nullifier the action revealed.
    pub nullifier: [u8; 32],
    /// The note commitment.
    pub cmx: [u8; 32],
    /// The ephemeral key.
    pub ephemeral_key: [u8; 32],
    /// The 52 bytes of note ciphertext a compact action carries.
    pub compact_ciphertext: [u8; 52],
}

/// One action's fields, as a private retrieval returns them.
///
/// The two transparent flags are **trusted service metadata**. Note decryption
/// does not authenticate them, does not prove transparent absence, and does not
/// bind them to a transaction identifier. A service can therefore force a
/// fallback with a false positive or withhold a needed one with a false
/// negative. That is an accepted limitation, and it is the reason a flag can
/// only ever move a transaction *towards* the public path and never away from
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRecord {
    /// The ephemeral key.
    pub ephemeral_key: [u8; 32],
    /// The full note ciphertext, of which compact blocks carry the first 52
    /// bytes.
    pub enc_ciphertext: Vec<u8>,
    /// The net value commitment.
    pub cv_net: [u8; 32],
    /// The outgoing ciphertext, which compact blocks omit entirely.
    pub out_ciphertext: Vec<u8>,
    /// Whether the transaction has transparent inputs.
    pub transparent_inputs: bool,
    /// Whether it has transparent outputs.
    pub transparent_outputs: bool,
}

impl ActionRecord {
    /// Whether this record says the transaction touches the transparent pool.
    ///
    /// A transaction that does cannot be completed privately: its transparent
    /// half is not in any shielded record, so the whole transaction has to be
    /// fetched publicly.
    pub fn touches_transparent(&self) -> bool {
        self.transparent_inputs || self.transparent_outputs
    }

    /// Whether this record reproduces what the wallet already read from a block.
    ///
    /// Only the ephemeral key and the compact ciphertext prefix can be checked:
    /// they are the fields scanning saw. The rest of the record is unverified,
    /// which is why failing to recover from it is never treated as proof of
    /// anything.
    pub fn matches(&self, guard: &Guard) -> bool {
        self.ephemeral_key == guard.ephemeral_key
            && self.enc_ciphertext.len() >= 52
            && self.enc_ciphertext[..52] == guard.compact_ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases() -> Vec<Locator> {
        vec![
            Locator::Status(TxId::from_bytes([3u8; 32])),
            Locator::Transaction(TxId::from_bytes([9u8; 32])),
            Locator::Action {
                pool: PoolId::Orchard,
                position: Position::from(0),
            },
            Locator::Action {
                pool: PoolId::Ironwood,
                position: Position::from(u64::MAX),
            },
            Locator::Block {
                height: BlockHeight::from_u32(1),
                hash: BlockHash([7u8; 32]),
            },
        ]
    }

    #[test]
    fn every_locator_round_trips_through_its_stored_form() {
        for locator in cases() {
            let encoded = locator.encode();
            assert_eq!(
                Locator::decode(locator.kind(), &encoded),
                Some(locator),
                "{locator:?} must survive the round trip"
            );
        }
    }

    #[test]
    fn the_two_txid_kinds_encode_alike_and_stay_distinct() {
        // The key alone does not say which question is being asked, which is
        // why the stored primary key is the pair. Losing that would let an
        // answer to one silently satisfy the other.
        let txid = TxId::from_bytes([1u8; 32]);
        assert_eq!(
            Locator::Status(txid).encode(),
            Locator::Transaction(txid).encode()
        );
        assert_ne!(Locator::Status(txid), Locator::Transaction(txid));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_rather_than_padded() {
        assert_eq!(Locator::decode(LocatorKind::Transaction, &[0u8; 31]), None);
        assert_eq!(Locator::decode(LocatorKind::Action, &[0u8; 8]), None);
        assert_eq!(Locator::decode(LocatorKind::Block, &[0u8; 35]), None);
    }

    #[test]
    fn an_unknown_pool_code_is_refused() {
        let mut bytes = vec![0xffu8];
        bytes.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(Locator::decode(LocatorKind::Action, &bytes), None);
    }

    #[test]
    fn every_kind_code_round_trips() {
        for locator in cases() {
            let kind = locator.kind();
            assert_eq!(LocatorKind::from_code(kind.code()), Some(kind));
        }
        assert_eq!(LocatorKind::from_code(4), None);
    }
}
