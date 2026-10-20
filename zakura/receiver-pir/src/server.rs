//! Immutable CPU evaluator. HTTP admission and concurrency limits belong to the service.
use crate::{
    profile, query_bytes, Error, Manifest, WitnessManifest, COLS, HEADER_BYTES, MAGIC, PROTOCOL,
};
use ipir_sp::{server::IPIRServer, SimplePirProfile};
use receiver_directory::{
    snapshot::{Snapshot, ROW_BYTES},
    witness, Hash,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zakura_pir_server_core::native::NativePreprocessed;

/// One table's rows prepared for PIR evaluation.
struct Prepared {
    rows: u32,
    public: Vec<u8>,
    /// The rows as u16 coefficients, scanned modulo the native `q`.
    server: IPIRServer<u16>,
    preprocessed: Vec<NativePreprocessed>,
}

impl Prepared {
    /// Preparation follows Transparent's: the public hint is the query masks times the
    /// rows, and each block's two-mask packing is preprocessed from it.
    fn new(rows: u32, data: Vec<u8>) -> Result<Self, Error> {
        let profile = profile(rows)?;
        // The scan shape: full 16-bit plaintexts, one column per coefficient, and the
        // native profile's query and response widths.
        let (_, mut params) = ipir_sp::params_for_simplepir_profile(
            u64::from(rows),
            (ROW_BYTES * 8) as u64,
            SimplePirProfile::P16Q48,
        )
        .map_err(|_| Error::Pir)?;
        params.query_bits = zakura_pir_client::native::QUERY_BITS;
        params.q_prime_1 = 1 << zakura_pir_client::native::RESPONSE_BITS;
        let values = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]));
        let server = IPIRServer::<u16>::new_auto_kernel(params, values, false, true);
        let padded = server.db_rows_padded();
        let db = server.db();
        let hint =
            zakura_pir_server_core::native::hint(&profile.masks, profile.rows, COLS, |col| {
                &db[col * padded..col * padded + profile.rows]
            })
            .map_err(|_| Error::Pir)?;
        let preprocessed = zakura_pir_server_core::native::preprocess(&profile.setup, &hint)
            .map_err(|_| Error::Pir)?;
        let public =
            zakura_pir_server_core::native::publish(&preprocessed).map_err(|_| Error::Pir)?;
        Ok(Self {
            rows,
            public,
            server,
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
        let (keys, query) = zakura_pir_query_server::native::parse_with(
            &profile.setup,
            &body[HEADER_BYTES..],
            profile.rows,
        )
        .map_err(|_| Error::Malformed)?;
        let intermediate = self
            .server
            .try_multiply_power_of_two(zakura_pir_client::native::Q, &query)
            .map_err(|_| Error::Pir)?;
        let mut response = body[..HEADER_BYTES].to_vec();
        response.extend(
            zakura_pir_query_server::native::pack(&self.preprocessed, &keys, &intermediate)
                .map_err(|_| Error::Pir)?,
        );
        Ok(response)
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
        directory: receiver_directory::snapshot::Manifest,
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
