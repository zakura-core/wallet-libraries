//! Companion witness table construction.
use sha2::{Digest, Sha256};
pub use zakura_pir_protocol::receiver::witness::*;
use zakura_pir_protocol::receiver::{Error, snapshot};
#[cfg(feature = "receiver-crypto")]
mod paths;
#[cfg(feature = "receiver-crypto")]
pub use paths::{SHARD_LEAVES, ShardPaths, payloads};

/// Operations owned by this role.
pub trait TablePublisherExt: Sized {
    /// Lays out `payloads` in ordinal order and binds their count and digest. Payload
    /// contents are the publisher's to check against the payment positions.
    fn build(manifest: Manifest, payloads: &[[u8; PAYLOAD_BYTES]]) -> Result<Self, Error>;
}

impl TablePublisherExt for Table {
    /// Lays out `payloads` in ordinal order and binds their count and digest. Payload
    /// contents are the publisher's to check against the payment positions.
    fn build(mut manifest: Manifest, payloads: &[[u8; PAYLOAD_BYTES]]) -> Result<Self, Error> {
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
}
