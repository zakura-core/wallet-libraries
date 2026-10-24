//! Payment table construction.
use sha2::{Digest, Sha256};
pub use zakura_pir_protocol::receiver::snapshot::*;
use zakura_pir_protocol::receiver::{Error, RECORD_BYTES, RawRecord, record};

/// Operations owned by this role.
pub trait SnapshotPublisherExt: Sized {
    /// Fails the entire candidate on row overflow or invalid payment history.
    /// Neither records nor coverage are dropped to make a publication fit.
    fn build(manifest: Manifest, records: &[RawRecord]) -> Result<Self, Error>;
}

impl SnapshotPublisherExt for Snapshot {
    /// Fails the entire candidate on row overflow or invalid payment history.
    /// Neither records nor coverage are dropped to make a publication fit.
    fn build(mut manifest: Manifest, records: &[RawRecord]) -> Result<Self, Error> {
        manifest.records = records.len() as u64;
        if manifest.records > capacity(manifest.rows)? {
            return Err(Error::Capacity);
        }
        let placement = Placement::new(&manifest)?;
        let mut data = vec![0; manifest.rows as usize * ROW_BYTES];
        let mut counts = vec![0; manifest.rows as usize];
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by_key(|r| (r.receiver, r.page));
        check_pages(sorted.iter().map(|&r| PageMeta::from(r)))?;
        check_ordinals(records.iter().map(PageMeta::from))?;
        for record in sorted {
            validate_location(&manifest, record)?;
            let row = placement.row(&record.receiver, record.page);
            if counts[row] == SLOTS {
                return Err(Error::Capacity);
            }
            let offset = row * ROW_BYTES + counts[row] * RECORD_BYTES;
            data[offset..offset + RECORD_BYTES].copy_from_slice(&record::encode(record)?);
            counts[row] += 1;
        }
        manifest.data_sha256 = Sha256::digest(&data).into();
        Ok(Self { manifest, data })
    }
}

/// Sets each record's witness ordinal to the rank of its note position, the canonical
/// mapping [`SnapshotPublisherExt::build`] requires. Positions are unique in a valid table.
pub fn assign_ordinals(records: &mut [RawRecord]) {
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by_key(|&i| records[i].payment.position);
    for (ordinal, i) in order.into_iter().enumerate() {
        records[i].ordinal = ordinal as u32;
    }
}
