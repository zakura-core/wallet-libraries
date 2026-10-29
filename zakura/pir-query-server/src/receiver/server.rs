//! Immutable CPU evaluator. HTTP admission and concurrency limits belong to the service.
use crate::native::NativePreprocessed;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zakura_pir_protocol::receiver::{
    Hash,
    native::{COLS, profile, query_bytes},
    session::{Error, HEADER_BYTES, MAGIC, Manifest, PROTOCOL, WitnessManifest},
    snapshot::{ROW_BYTES, Snapshot},
    witness,
};

/// One table's rows prepared for PIR evaluation.
struct Prepared {
    rows: u32,
    public: Vec<u8>,
    /// The rows as u16 coefficients, scanned modulo the native `q`.
    database: Database,
    preprocessed: Vec<NativePreprocessed>,
}

impl Prepared {
    /// Preparation follows Transparent's: the public hint is the query masks times the
    /// rows, and each block's two-mask packing is preprocessed from it.
    fn new(rows: u32, data: Vec<u8>) -> Result<Self, Error> {
        let profile = profile(rows)?;
        let database = Database::new(profile.rows, &data)?;
        let hint =
            zakura_pir_server_core::native::hint(&profile.masks, profile.rows, COLS, |col| {
                &database.values[col * profile.rows..(col + 1) * profile.rows]
            })
            .map_err(|_| Error::Pir)?;
        let preprocessed = zakura_pir_server_core::native::preprocess(&profile.setup, &hint)
            .map_err(|_| Error::Pir)?;
        let public =
            zakura_pir_server_core::native::publish(&preprocessed).map_err(|_| Error::Pir)?;
        Ok(Self {
            rows,
            public,
            database,
            preprocessed,
        })
    }

    /// Answer one encrypted query framed for session `id`.
    fn respond(&self, id: &Hash, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() != query_bytes(self.rows)? || &body[..4] != MAGIC {
            return Err(Error::Malformed);
        }
        if body[4..36] != *id {
            return Err(Error::Revision);
        }
        let profile = profile(self.rows)?;
        let (keys, query) =
            crate::native::parse_with(&profile.setup, &body[HEADER_BYTES..], profile.rows)
                .map_err(|_| Error::Malformed)?;
        let intermediate = self.database.multiply(&query)?;
        let mut response = body[..HEADER_BYTES].to_vec();
        response.extend(
            crate::native::pack(&self.preprocessed, &keys, &intermediate)
                .map_err(|_| Error::Pir)?,
        );
        Ok(response)
    }
}

/// Column-major full-width plaintexts for the Receiver's native ring scan.
struct Database {
    rows: usize,
    values: Vec<u16>,
}

impl Database {
    fn new(rows: usize, data: &[u8]) -> Result<Self, Error> {
        let len = rows.checked_mul(COLS).ok_or(Error::Pir)?;
        if rows == 0 || len.checked_mul(2) != Some(data.len()) {
            return Err(Error::Pir);
        }
        let mut values = Vec::new();
        values.try_reserve_exact(len).map_err(|_| Error::Pir)?;
        values.resize(len, 0);
        // Transpose short row tiles so each destination write is contiguous,
        // without repeatedly scanning the entire input at a row-sized stride.
        const TILE_ROWS: usize = 32;
        for (tile, input) in data.chunks(TILE_ROWS * ROW_BYTES).enumerate() {
            let start = tile * TILE_ROWS;
            let count = input.len() / ROW_BYTES;
            for col in 0..COLS {
                let output = &mut values[col * rows + start..][..count];
                for (value, row) in output.iter_mut().zip(input.as_chunks::<ROW_BYTES>().0) {
                    *value = u16::from_le_bytes([row[2 * col], row[2 * col + 1]]);
                }
            }
        }
        Ok(Self { rows, values })
    }

    fn multiply(&self, query: &[u64]) -> Result<Vec<u64>, Error> {
        const Q: u64 = crate::native::Q;
        const _: () = assert!(Q.is_power_of_two());
        if query.len() != self.rows || query.iter().any(|&value| value >= Q) {
            return Err(Error::Pir);
        }
        // Wrapping products and sums preserve the low bits modulo Q. This is
        // the same power-of-two scan used by the previous IPIR kernel; its
        // AVX512/NTT kernel selection did not affect this operation.
        Ok(self
            .values
            .par_chunks_exact(self.rows)
            .map(|column| {
                column.iter().zip(query).fold(0u64, |sum, (&a, &b)| {
                    sum.wrapping_add(u64::from(a).wrapping_mul(b))
                }) & (Q - 1)
            })
            .collect())
    }
}

/// A payment publication prepared for PIR evaluation.
#[derive(Clone)]
pub struct Server {
    manifest: Manifest,
    id: Hash,
    prepared: Arc<Prepared>,
}

impl Server {
    /// Verify the entire publication with [`Snapshot::validate`] before preparing its
    /// PIR data. No chain trust is implied.
    pub fn new(snapshot: Snapshot) -> Result<Self, Error> {
        snapshot.validate()?;
        let prepared = Arc::new(Prepared::new(snapshot.manifest.rows, snapshot.data)?);
        Self::with(snapshot.manifest, prepared)
    }

    /// The session for `directory` over already prepared rows.
    fn with(
        directory: zakura_pir_protocol::receiver::snapshot::Manifest,
        prepared: Arc<Prepared>,
    ) -> Result<Self, Error> {
        let manifest = Manifest {
            protocol: PROTOCOL.into(),
            directory,
            public_digest: Sha256::digest(&prepared.public).into(),
        };
        Ok(Self {
            id: manifest.id()?,
            manifest,
            prepared,
        })
    }

    /// The session manifest that clients fetch.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The session ID, [`Manifest::id`] of [`Self::manifest`].
    pub fn id(&self) -> Hash {
        self.id
    }

    /// The public setup that clients download once per session.
    pub fn public(&self) -> &[u8] {
        &self.prepared.public
    }

    /// Answer one encrypted query for this session, rejecting any other length or session.
    pub fn respond(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        self.prepared.respond(&self.id, body)
    }
}

/// A companion witness table prepared for PIR evaluation.
#[derive(Clone)]
pub struct WitnessServer {
    manifest: WitnessManifest,
    id: Hash,
    prepared: Arc<Prepared>,
}

impl WitnessServer {
    /// Verify the table with [`witness::Table::validate`] and that it serves `payments`,
    /// then prepare its PIR data. Payload contents are the publisher's to check.
    pub fn new(table: witness::Table, payments: &Server) -> Result<Self, Error> {
        table.validate()?;
        table
            .manifest
            .check_payments(&payments.manifest.directory)?;
        let prepared = Arc::new(Prepared::new(table.manifest.rows, table.data)?);
        Self::with(table.manifest, prepared)
    }

    /// The session for `table` over already prepared rows.
    fn with(table: witness::Manifest, prepared: Arc<Prepared>) -> Result<Self, Error> {
        let manifest = WitnessManifest {
            protocol: PROTOCOL.into(),
            table,
            public_digest: Sha256::digest(&prepared.public).into(),
        };
        Ok(Self {
            id: manifest.id()?,
            manifest,
            prepared,
        })
    }

    /// The session manifest that clients fetch.
    pub fn manifest(&self) -> &WitnessManifest {
        &self.manifest
    }

    /// The session ID, [`WitnessManifest::id`] of [`Self::manifest`].
    pub fn id(&self) -> Hash {
        self.id
    }

    /// The public setup that clients download once per session.
    pub fn public(&self) -> &[u8] {
        &self.prepared.public
    }

    /// Answer one encrypted query for this session, rejecting any other length or session.
    pub fn respond(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        self.prepared.respond(&self.id, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipir_sp::{SimplePirProfile, server::IPIRServer};
    use zakura_pir_protocol::receiver::session::MIN_ROWS;

    #[test]
    fn native_scan_matches_previous_evaluator() {
        const Q: u64 = crate::native::Q;
        for rows in [MIN_ROWS as usize, 2 * MIN_ROWS as usize] {
            let values: Vec<_> = (0..rows * COLS)
                .map(|i| (i as u16).wrapping_mul(40503).wrapping_add(19))
                .collect();
            let data: Vec<_> = values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            let database = Database::new(rows, &data).unwrap();
            let (_, mut params) = ipir_sp::params_for_simplepir_profile(
                rows as u64,
                (ROW_BYTES * 8) as u64,
                SimplePirProfile::P16Q48,
            )
            .unwrap();
            params.query_bits = crate::native::QUERY_BITS;
            params.q_prime_1 = 1 << crate::native::RESPONSE_BITS;
            let previous = IPIRServer::new_auto_kernel(params, values.iter().copied(), false, true);
            assert_eq!(previous.db_rows_padded(), rows);
            assert_eq!(database.values, previous.db());
            for query in [
                vec![0; rows],
                vec![Q - 1; rows],
                (0..rows)
                    .map(|i| (i as u64).wrapping_mul(Q / 3) & (Q - 1))
                    .collect(),
            ] {
                let actual = database.multiply(&query).unwrap();
                assert_eq!(
                    actual,
                    previous.try_multiply_power_of_two(Q, &query).unwrap()
                );
                for col in [0, COLS / 2, COLS - 1] {
                    let exact: u128 = (0..rows)
                        .map(|row| u128::from(values[row * COLS + col]) * u128::from(query[row]))
                        .sum();
                    assert_eq!(actual[col], (exact % u128::from(Q)) as u64);
                }
            }
            assert!(database.multiply(&vec![0; rows - 1]).is_err());
            assert!(database.multiply(&vec![Q; rows]).is_err());
        }
    }

    #[test]
    fn native_database_handles_partial_tiles_and_rejects_bad_lengths() {
        let rows = 35;
        let data: Vec<_> = (0..rows * COLS)
            .flat_map(|i| (i as u16).to_le_bytes())
            .collect();
        let database = Database::new(rows, &data).unwrap();
        for row in 0..rows {
            for col in 0..COLS {
                assert_eq!(database.values[col * rows + row], (row * COLS + col) as u16);
            }
        }
        assert!(Database::new(0, &[]).is_err());
        assert!(Database::new(rows, &data[..data.len() - 1]).is_err());
        assert!(Database::new(rows + 1, &data).is_err());
        assert!(Database::new(usize::MAX, &[]).is_err());
    }
}
