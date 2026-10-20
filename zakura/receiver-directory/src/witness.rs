//! Companion witness tables: one lower inclusion path per payment-table ordinal.
//!
//! Each payment table has a companion table whose row `o / 8`, slot `o % 8` holds the
//! payload for the record with witness ordinal `o`. A query names only the table identity
//! the payment query already revealed. The manifest binds the payment table, so ordinals
//! never address a replacement's payloads. Payloads are untrusted: the wallet checks them
//! against its own tree.
use crate::{snapshot, Error, Hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use zakura_receiver_crypto::wire::PAYLOAD_BYTES;

/// The witness table format a manifest commits to.
pub const PROFILE: &str = "ironwood-zero-ovk-witness-v1";
/// Payloads per row.
pub const PAYLOADS: usize = snapshot::ROW_BYTES / PAYLOAD_BYTES;
const _: () = assert!(PAYLOADS == 8);

/// The payload slots in a table of `rows` rows; see [`snapshot::capacity`] for the bounds.
pub fn capacity(rows: u32) -> Result<u64, Error> {
    if !rows.is_power_of_two() || rows > snapshot::MAX_ROWS {
        return Err(Error::Malformed);
    }
    Ok(u64::from(rows) * PAYLOADS as u64)
}

/// One companion table revision. Its construction tree decides which siblings each payload
/// supplies. A payload whose Ironwood shard is still filling at `tree_size` is provisional:
/// it is usable only with the wallet's own tree at exactly this block. A full shard's
/// payload is final on this chain and usable at any later accepted anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub profile: String,
    pub genesis: Hash,
    /// The correction generation, which must equal the payment table's.
    pub history_revision: u64,
    /// [`snapshot::Manifest::revision`] of the payment table whose ordinals select payloads.
    pub payments: Hash,
    /// One payload per payment record.
    pub payloads: u64,
    pub rows: u32,
    /// The block whose commitment tree the payloads describe, at or after the payment
    /// table's end. Every Ironwood shard a final payload depends on completed by it.
    pub tree_height: u32,
    pub tree_hash: Hash,
    pub tree_size: u64,
    pub data_sha256: Hash,
}

impl Manifest {
    /// Checks the profile, tree bound and geometry, at most [`snapshot::MAX_ROWS`] rows.
    pub fn validate(&self) -> Result<(), Error> {
        if self.profile != PROFILE
            || self.tree_size > snapshot::TREE_SIZE
            || !capacity(self.rows).is_ok_and(|slots| self.payloads <= slots)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Binds every field into one immutable revision using domain-separated SHA-256 with
    /// fixed-width fields and a length-prefixed profile string.
    pub fn revision(&self) -> Result<Hash, Error> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"ironwood-receiver/v1/witness-manifest\0");
        h.update((self.profile.len() as u64).to_le_bytes());
        h.update(self.profile.as_bytes());
        h.update(self.genesis);
        h.update(self.history_revision.to_le_bytes());
        h.update(self.payments);
        h.update(self.payloads.to_le_bytes());
        h.update(self.rows.to_le_bytes());
        h.update(self.tree_height.to_le_bytes());
        h.update(self.tree_hash);
        h.update(self.tree_size.to_le_bytes());
        h.update(self.data_sha256);
        Ok(h.finalize().into())
    }

    /// Checks that this table serves `payments`: the same network and correction, its
    /// revision, one payload per record, and a tree at or past its coverage.
    pub fn check_payments(&self, payments: &snapshot::Manifest) -> Result<(), Error> {
        self.validate()?;
        if self.genesis != payments.genesis
            || self.history_revision != payments.history_revision
            || self.payments != payments.revision()?
            || self.payloads != payments.records
            || self.tree_height < payments.end_height
            || self.tree_size < payments.end_position
            || (self.tree_height == payments.end_height
                && (self.tree_hash != payments.end_hash || self.tree_size != payments.end_position))
        {
            return Err(Error::Coverage);
        }
        Ok(())
    }
}

/// The row and slot holding ordinal `ordinal`'s payload. The row is selected inside PIR.
pub fn slot_for(ordinal: u32) -> (usize, usize) {
    (ordinal as usize / PAYLOADS, ordinal as usize % PAYLOADS)
}

/// A manifest and the payload rows it commits to.
#[derive(Clone)]
pub struct Table {
    pub manifest: Manifest,
    pub data: Vec<u8>,
}

impl Table {
    /// Lays out `payloads` in ordinal order and binds their count and digest. Payload
    /// contents are the publisher's to check against the payment positions.
    pub fn build(mut manifest: Manifest, payloads: &[[u8; PAYLOAD_BYTES]]) -> Result<Self, Error> {
        manifest.payloads = payloads.len() as u64;
        if manifest.payloads > capacity(manifest.rows)? {
            return Err(Error::Capacity);
        }
        manifest.validate()?;
        let mut data = vec![0; manifest.rows as usize * snapshot::ROW_BYTES];
        for (slot, payload) in data
            .as_chunks_mut::<PAYLOAD_BYTES>()
            .0
            .iter_mut()
            .zip(payloads)
        {
            *slot = *payload;
        }
        manifest.data_sha256 = Sha256::digest(&data).into();
        Ok(Self { manifest, data })
    }

    /// Checks a supplied table whole: geometry, digest and zero unused slots.
    pub fn validate(&self) -> Result<(), Error> {
        let m = &self.manifest;
        m.validate()?;
        if self.data.len() != m.rows as usize * snapshot::ROW_BYTES
            || Hash::from(Sha256::digest(&self.data)) != m.data_sha256
            || self.data[m.payloads as usize * PAYLOAD_BYTES..]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// The untrusted payload for `ordinal` in a privately retrieved row of an accepted table.
pub fn lookup_row(m: &Manifest, ordinal: u32, bytes: &[u8]) -> Result<[u8; PAYLOAD_BYTES], Error> {
    m.validate()?;
    if u64::from(ordinal) >= m.payloads || bytes.len() != snapshot::ROW_BYTES {
        return Err(Error::Malformed);
    }
    let (_, slot) = slot_for(ordinal);
    Ok(bytes.as_chunks::<PAYLOAD_BYTES>().0[slot])
}
