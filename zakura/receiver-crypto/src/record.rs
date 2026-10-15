//! Validated receivers and payment records over the shared fixed-width row encoding.
use crate::{Error, Hash};
use orchard::{
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::IronwoodDomain,
};
use receiver_wire::RawRecord;
use zcash_note_encryption::{Domain, EphemeralKeyBytes};

/// Encoded size of one [`Record`] slot.
pub const RECORD_BYTES: usize = receiver_wire::RECORD_BYTES;

/// Full canonical receiver. The same encoding is shared by refund and incoming keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Receiver([u8; 43]);

impl Receiver {
    /// Accept only bytes that decode to a valid Ironwood address.
    pub fn from_bytes(bytes: [u8; 43]) -> Result<Self, Error> {
        Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&bytes))
            .map(|_| Self(bytes))
            .ok_or(Error::Malformed)
    }

    /// The raw 43-byte address.
    pub fn as_bytes(&self) -> &[u8; 43] {
        &self.0
    }
}

/// Compact context plus location. All hashes use protocol byte order. The note
/// commitment and Action nullifier must be canonical field elements and the ephemeral
/// key a valid Ironwood ephemeral public key; [`Record::encode`] and
/// [`Record::decode`] refuse others.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub height: u32,
    pub block_hash: Hash,
    pub txid: Hash,
    pub tx_index: u32,
    pub action_index: u32,
    pub position: u64,
    /// The Action's input nullifier, not the received note's spend nullifier.
    pub action_nullifier: Hash,
    pub cmx: Hash,
    pub ephemeral_key: Hash,
    pub ciphertext_prefix: [u8; 52],
}

impl Payment {
    /// Refuse a noncanonical note commitment or Action nullifier, or an ephemeral key
    /// that is not a valid Ironwood ephemeral public key.
    pub fn check(&self) -> Result<(), Error> {
        if ExtractedNoteCommitment::from_bytes(&self.cmx)
            .is_none()
            .into()
            || Nullifier::from_bytes(&self.action_nullifier)
                .is_none()
                .into()
            || IronwoodDomain::epk(&EphemeralKeyBytes(self.ephemeral_key)).is_none()
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// One payment per page; every page repeats the count for the same immutable
/// revision. Encoding and decoding validate the receiver, note commitment, Action
/// nullifier and ephemeral key in addition to the wire structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub receiver: Receiver,
    pub page: u32,
    pub total: u32,
    pub payment: Payment,
}

impl Record {
    /// Encode one row slot, refusing a page outside its total and any field
    /// [`Payment::check`] refuses.
    pub fn encode(&self) -> Result<[u8; RECORD_BYTES], Error> {
        self.payment.check()?;
        let p = &self.payment;
        RawRecord {
            receiver: self.receiver.0,
            page: self.page,
            total: self.total,
            payment: receiver_wire::Payment {
                height: p.height,
                block_hash: p.block_hash,
                txid: p.txid,
                tx_index: p.tx_index,
                action_index: p.action_index,
                position: p.position,
                action_nullifier: p.action_nullifier,
                cmx: p.cmx,
                ephemeral_key: p.ephemeral_key,
                ciphertext_prefix: p.ciphertext_prefix,
            },
        }
        .encode()
        .map_err(|_| Error::Malformed)
    }

    /// Only an entirely zero slot is empty; any other slot must be a well-formed,
    /// cryptographically valid record. Corruption must never advance a gap limit.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, Error> {
        let Some(raw) = RawRecord::decode(bytes).map_err(|_| Error::Malformed)? else {
            return Ok(None);
        };
        let p = raw.payment;
        let record = Self {
            receiver: Receiver::from_bytes(raw.receiver)?,
            page: raw.page,
            total: raw.total,
            payment: Payment {
                height: p.height,
                block_hash: p.block_hash,
                txid: p.txid,
                tx_index: p.tx_index,
                action_index: p.action_index,
                position: p.position,
                action_nullifier: p.action_nullifier,
                cmx: p.cmx,
                ephemeral_key: p.ephemeral_key,
                ciphertext_prefix: p.ciphertext_prefix,
            },
        };
        record.payment.check()?;
        Ok(Some(record))
    }
}
