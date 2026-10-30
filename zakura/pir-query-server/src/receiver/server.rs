//! The receiver evaluator: P8 directory and companion tables, each prepared on its
//! own. HTTP admission and concurrency limits belong to the service.
use super::*;
use crate::native::{NativePreprocessed, P8, ProfileQueryExt as _, Q};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zakura_pir_protocol::receiver::{
    Hash,
    native::{COLS, MAGIC, Profile, profile},
    session::{Error, HEADER_BYTES},
};
use zakura_pir_server_core::native::{ProfilePublicationExt as _, hint, preprocess};

/// One table's rows prepared for P8 evaluation.
struct Prepared {
    kind: Kind,
    profile: &'static Profile,
    query_rows: u32,
    public: Vec<u8>,
    /// The rows as byte coefficients, column-major, scanned modulo the native `q`.
    database: Database,
    preprocessed: Vec<NativePreprocessed>,
}

impl Prepared {
    /// Prepares `data`, already validated, for a table of `M`'s kind and shape:
    /// the public hint is the query masks times the rows, and each packing
    /// block's two-mask preprocessing comes from it.
    fn new<M: Table>(manifest: &M, data: Vec<u8>) -> Result<Self, Error> {
        let kind = M::KIND;
        let profile = profile(kind, manifest.rows())?;
        let database = Database::new(profile.rows, &data)?;
        let hint = hint(&profile.masks, profile.rows, COLS, |col| {
            &database.values[col * profile.rows..(col + 1) * profile.rows]
        })
        .map_err(|_| Error::Pir)?;
        let preprocessed = preprocess(&profile.setup, &hint).map_err(|_| Error::Pir)?;
        let public = P8.publish(&preprocessed).map_err(|_| Error::Pir)?;
        Ok(Self {
            kind,
            profile,
            query_rows: manifest.query_rows(),
            public,
            database,
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
        let (setup, rows) = (&self.profile.setup, self.profile.rows);
        let upload = &body[HEADER_BYTES..];
        let (keys, query) = match self.kind {
            Kind::Directory => P8.parse_accepted(setup, upload, rows),
            Kind::Companion => P8.parse_selection(setup, upload, self.query_rows as usize, rows),
        }
        .map_err(|_| Error::Malformed)?;
        let intermediate = self.database.multiply(&query)?;
        let mut response = body[..HEADER_BYTES].to_vec();
        response.extend(
            P8.pack(&self.preprocessed, &keys, &intermediate)
                .map_err(|_| Error::Pir)?,
        );
        Ok(response)
    }
}

/// Column-major byte plaintexts for the receiver's P8 ring scan.
struct Database {
    rows: usize,
    values: Vec<u8>,
}

impl Database {
    /// Transposes `rows` rows of [`ROW_BYTES`] bytes into one column per byte.
    /// `data` is a validated table, so it is exactly `rows` rows.
    fn new(rows: usize, data: &[u8]) -> Result<Self, Error> {
        const _: () = assert!(COLS == ROW_BYTES);
        let len = data.len();
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
                    *value = row[col];
                }
            }
        }
        Ok(Self { rows, values })
    }

    /// Multiplies `query`, one coefficient below `Q` per row, by every column modulo `Q`.
    fn multiply(&self, query: &[u64]) -> Result<Vec<u64>, Error> {
        const _: () = assert!(Q.is_power_of_two());
        if query.len() != self.rows || query.iter().any(|&value| value >= Q) {
            return Err(Error::Pir);
        }
        // Wrapping products and sums preserve the low bits modulo Q.
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
