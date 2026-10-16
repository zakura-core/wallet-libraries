//! Immutable CPU evaluator. HTTP admission and concurrency limits belong to the service.
use crate::{profile, query_bytes, Error, Manifest, COLS, HEADER_BYTES, MAGIC, PROTOCOL};
use ipir_sp::{server::IPIRServer, SimplePirProfile};
use pir_native::NativePreprocessed;
use receiver_directory::{
    snapshot::{Snapshot, ROW_BYTES},
    Hash,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A publication prepared for PIR evaluation.
pub struct Server {
    manifest: Manifest,
    id: Hash,
    public: Vec<u8>,
    rows: Arc<[u8]>,
    filters: Arc<[u8]>,
    /// The rows as u16 coefficients, scanned modulo the native `q`.
    server: IPIRServer<u16>,
    preprocessed: Vec<NativePreprocessed>,
}

impl Server {
    /// Verify the entire publication with [`Snapshot::validate`] before preparing its
    /// PIR data. No chain trust is implied. Preparation follows Transparent's: the
    /// public hint is the query masks times the rows, and each block's two-mask
    /// packing is preprocessed from it.
    pub fn new(snapshot: Snapshot) -> Result<Self, Error> {
        snapshot.validate()?;
        let profile = profile(snapshot.manifest.rows)?;
        // The scan shape: full 16-bit plaintexts, one column per coefficient, and the
        // native profile's query and response widths.
        let (_, mut params) = ipir_sp::params_for_simplepir_profile(
            u64::from(snapshot.manifest.rows),
            (ROW_BYTES * 8) as u64,
            SimplePirProfile::P16Q48,
        )
        .map_err(|_| Error::Pir)?;
        params.query_bits = pir_native::QUERY_BITS;
        params.q_prime_1 = 1 << pir_native::RESPONSE_BITS;
        let values = snapshot
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]));
        let server = IPIRServer::<u16>::new_auto_kernel(params, values, false, true);
        let padded = server.db_rows_padded();
        let db = server.db();
        let hint = pir_native::hint(&profile.masks, profile.rows, COLS, |col| {
            &db[col * padded..col * padded + profile.rows]
        })
        .map_err(|_| Error::Pir)?;
        let preprocessed = pir_native::preprocess(&profile.setup, &hint).map_err(|_| Error::Pir)?;
        let public = pir_native::publish(&preprocessed).map_err(|_| Error::Pir)?;
        let manifest = Manifest {
            protocol: PROTOCOL.into(),
            directory: snapshot.manifest,
            public_digest: Sha256::digest(&public).into(),
        };
        let id = manifest.id()?;
        Ok(Self {
            manifest,
            id,
            public,
            rows: snapshot.data.into(),
            filters: snapshot.filters.into(),
            server,
            preprocessed,
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
        &self.public
    }

    /// Identical immutable directory bytes for every caller, already digest-checked.
    pub fn rows(&self) -> Arc<[u8]> {
        self.rows.clone()
    }

    /// The publication's filter file, identical for every caller and already checked.
    pub fn filters(&self) -> Arc<[u8]> {
        self.filters.clone()
    }

    /// Answer one encrypted query for this session, rejecting any other length or session.
    pub fn respond(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let rows = self.manifest.directory.rows;
        if body.len() != query_bytes(rows)? || &body[..4] != MAGIC {
            return Err(Error::Malformed);
        }
        if body[4..36] != self.id {
            return Err(Error::Revision);
        }
        let profile = profile(rows)?;
        let (keys, query) =
            pir_native::parse_with(&profile.setup, &body[HEADER_BYTES..], profile.rows)
                .map_err(|_| Error::Malformed)?;
        let intermediate = self
            .server
            .try_multiply_power_of_two(pir_native::Q, &query)
            .map_err(|_| Error::Pir)?;
        let mut response = body[..HEADER_BYTES].to_vec();
        response.extend(
            pir_native::pack(&self.preprocessed, &keys, &intermediate).map_err(|_| Error::Pir)?,
        );
        Ok(response)
    }
}
