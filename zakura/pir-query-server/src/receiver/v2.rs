//! The v2 evaluator: P8 directory and companion tables, each prepared on its
//! own. HTTP admission and concurrency limits belong to the service.
pub use zakura_pir_protocol::receiver::v2::*;

use crate::native::{NativePreprocessed, P8, ProfileQueryExt as _, Q};
use ipir_sp::{SimplePirProfile, server::IPIRServer};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zakura_pir_protocol::receiver::{
    Hash,
    session::{Error, HEADER_BYTES},
    v2::native::{COLS, MAGIC, profile},
};
use zakura_pir_server_core::native::{ProfilePublicationExt as _, hint, preprocess};

/// One table's rows prepared for P8 evaluation.
struct Prepared {
    kind: Kind,
    rows: u32,
    query_rows: u32,
    public: Vec<u8>,
    /// The rows as byte coefficients, scanned modulo the native `q`.
    server: IPIRServer<u8>,
    preprocessed: Vec<NativePreprocessed>,
}

impl Prepared {
    /// Prepares `data`, already validated, for a table of `M`'s kind and shape:
    /// the public hint is the query masks times the rows, and each packing
    /// block's two-mask preprocessing comes from it.
    fn new<M: Table>(manifest: &M, data: Vec<u8>) -> Result<Self, Error> {
        let (kind, rows) = (M::KIND, manifest.rows());
        let profile = profile(kind, rows)?;
        // Two 16-bit instances give the scan its 4,096 columns, one per byte.
        let (_, params) = ipir_sp::params_for_simplepir_profile(
            u64::from(rows),
            (ROW_BYTES * 16) as u64,
            SimplePirProfile::P16Q48,
        )
        .map_err(|_| Error::Pir)?;
        let server = IPIRServer::<u8>::new(params, data.into_iter(), false, false);
        let db = server.db();
        let rows_usize = profile.rows;
        let hint = hint(&profile.masks, rows_usize, COLS, |col| {
            &db[col * rows_usize..(col + 1) * rows_usize]
        })
        .map_err(|_| Error::Pir)?;
        let preprocessed = preprocess(&profile.setup, &hint).map_err(|_| Error::Pir)?;
        let public = P8.publish(&preprocessed).map_err(|_| Error::Pir)?;
        Ok(Self {
            kind,
            rows,
            query_rows: manifest.query_rows(),
            public,
            server,
            preprocessed,
        })
    }

    /// Answers one encrypted query framed for session `id`. A directory query
    /// covers every row; a companion query every row or exactly its
    /// `query_rows` prefix.
    fn respond(&self, id: &Hash, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() < HEADER_BYTES || &body[..4] != MAGIC {
            return Err(Error::Malformed);
        }
        if body[4..36] != *id {
            return Err(Error::Revision);
        }
        let profile = profile(self.kind, self.rows)?;
        let (rows, upload) = (self.rows as usize, &body[HEADER_BYTES..]);
        let (keys, query) = match self.kind {
            Kind::Directory => P8.parse_accepted(&profile.setup, upload, rows),
            Kind::Companion => {
                P8.parse_selection(&profile.setup, upload, self.query_rows as usize, rows)
            }
        }
        .map_err(|_| Error::Malformed)?;
        let intermediate = self
            .server
            .try_multiply_power_of_two(Q, &query)
            .map_err(|_| Error::Pir)?;
        let mut response = body[..HEADER_BYTES].to_vec();
        response.extend(
            P8.pack(&self.preprocessed, &keys, &intermediate)
                .map_err(|_| Error::Pir)?,
        );
        Ok(response)
    }
}

/// A prepared directory or companion and its session.
#[derive(Clone)]
pub struct Server<M> {
    session: Session<M>,
    id: Hash,
    prepared: Arc<Prepared>,
}

impl Server<Directory> {
    /// Checks the whole directory with [`DirectoryTable::validate`], then
    /// prepares it. Returns its entries for preparing companions against it.
    pub fn directory(table: DirectoryTable) -> Result<(Self, Vec<Entry>), Error> {
        let entries = table.validate()?;
        Ok((Self::prepare(table.manifest, table.data)?, entries))
    }
}

impl Server<Companion> {
    /// Checks the whole companion against `directory` and its `entries` with
    /// [`CompanionTable::validate`], including the zero suffix past
    /// `query_rows`, then prepares it.
    pub fn companion(
        table: CompanionTable,
        directory: &Directory,
        entries: &[Entry],
    ) -> Result<Self, Error> {
        table.validate(directory, entries)?;
        Self::prepare(table.manifest, table.data)
    }
}

impl<M: Table> Server<M> {
    /// Prepares validated rows and derives their session.
    fn prepare(manifest: M, data: Vec<u8>) -> Result<Self, Error> {
        let prepared = Arc::new(Prepared::new(&manifest, data)?);
        let session = Session {
            manifest,
            public_digest: Sha256::digest(&prepared.public).into(),
        };
        Ok(Self {
            id: session.id()?,
            session,
            prepared,
        })
    }

    /// The session clients fetch.
    pub fn session(&self) -> &Session<M> {
        &self.session
    }

    /// The session ID, [`Session::id`] of [`Self::session`].
    pub fn id(&self) -> Hash {
        self.id
    }

    /// The public setup clients download once per session.
    pub fn public(&self) -> &[u8] {
        &self.prepared.public
    }

    /// Answers one encrypted query for this session, refusing any other length
    /// or session.
    pub fn respond(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        self.prepared.respond(&self.id, body)
    }
}

#[cfg(test)]
mod tests;
