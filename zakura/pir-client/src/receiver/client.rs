use super::{
    Hash, RawRecord, ReceiverBytes,
    native::{COLS, Profile, profile, public_bytes, response_bytes},
    session::{Error, HEADER_BYTES, MAGIC, Manifest, WitnessManifest},
    snapshot, witness,
};
use crate::native::NativeSecret;
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};

/// The PIR state one table's queries share: its session ID, profile and public setup.
struct Session {
    id: Hash,
    rows: u32,
    profile: &'static Profile,
    public: Vec<u8>,
}

impl Session {
    /// Checks `public` against `digest` for a `rows`-row table answered under `id`.
    fn new(id: Hash, rows: u32, public: &[u8], digest: &Hash) -> Result<Self, Error> {
        if public.len() != public_bytes(rows)? || Hash::from(Sha256::digest(public)) != *digest {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id,
            rows,
            profile: profile(rows)?,
            public: public.to_vec(),
        })
    }

    /// A fresh encrypted request for `row`, framed with the session header.
    fn prepare(&self, row: usize) -> Result<(Vec<u8>, NativeSecret), Error> {
        let (secret, request) = crate::native::prepare_with(
            &self.profile.setup,
            &self.profile.masks,
            self.profile.rows,
            row,
        )
        .map_err(|_| Error::Pir)?;
        let mut body = MAGIC.to_vec();
        body.extend(self.id);
        body.extend(OsRng.r#gen::<[u8; 16]>());
        body.extend(request);
        Ok((body, secret))
    }

    /// The row an answer to `body` carries, rejecting another request's or session's.
    fn decode(
        &self,
        body: &[u8],
        secret: &NativeSecret,
        response: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if body[4..36] != self.id {
            return Err(Error::Revision);
        }
        if response.len() != response_bytes(self.rows)?
            || response[..HEADER_BYTES] != body[..HEADER_BYTES]
        {
            return Err(Error::Malformed);
        }
        crate::native::decode_cols(secret, &self.public, &response[HEADER_BYTES..], COLS)
            .map_err(|_| Error::Pir)
    }
}

/// A PIR session for one payment table.
pub struct Client {
    manifest: Manifest,
    session: Session,
}

/// One fresh encryption, consumed when its response is decoded. Contains ephemeral secrets.
pub struct Query {
    body: Vec<u8>,
    secret: NativeSecret,
    receiver: ReceiverBytes,
    page: u32,
}

impl Query {
    /// The request body to POST.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Client {
    /// Check the manifest and the public setup against its digest. Chain coverage is
    /// accepted for the whole inventory (see [`super::inventory::Inventory::accept`]).
    pub fn new(manifest: Manifest, public: &[u8]) -> Result<Self, Error> {
        manifest.validate()?;
        let session = Session::new(
            manifest.id()?,
            manifest.directory.rows,
            public,
            &manifest.public_digest,
        )?;
        Ok(Self { manifest, session })
    }

    /// The session manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Bytes of public setup this session keeps.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.session.public.len()
    }

    /// Receiver and page influence only the encrypted row selection, never a public header.
    pub fn prepare(&self, receiver: ReceiverBytes, page: u32) -> Result<Query, Error> {
        let row = snapshot::row_for(&self.manifest.directory, &receiver, page)?;
        let (body, secret) = self.session.prepare(row)?;
        Ok(Query {
            body,
            secret,
            receiver,
            page,
        })
    }

    /// Decode the answer to `query`, rejecting another request's or revision's response.
    /// The record is checked structurally against the manifest; its receiver and Action
    /// fields are not cryptographically checked.
    pub fn decode(&self, query: Query, response: &[u8]) -> Result<Option<RawRecord>, Error> {
        let row = self.session.decode(&query.body, &query.secret, response)?;
        Ok(snapshot::lookup_row(
            &self.manifest.directory,
            &query.receiver,
            query.page,
            &row,
        )?)
    }
}

/// A PIR session for a companion witness table.
pub struct WitnessClient {
    manifest: WitnessManifest,
    session: Session,
}

/// One fresh witness encryption, consumed when its response is decoded.
pub struct WitnessQuery {
    body: Vec<u8>,
    secret: NativeSecret,
    ordinal: u32,
}

impl WitnessQuery {
    /// The request body to POST.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl WitnessClient {
    /// Check the manifest and the public setup against its digest. Binding to a payment
    /// table is checked by [`super::session::Publication::validate`].
    pub fn new(manifest: WitnessManifest, public: &[u8]) -> Result<Self, Error> {
        let session = Session::new(
            manifest.id()?,
            manifest.table.rows,
            public,
            &manifest.public_digest,
        )?;
        Ok(Self { manifest, session })
    }

    /// The session manifest.
    pub fn manifest(&self) -> &WitnessManifest {
        &self.manifest
    }

    /// Bytes of public setup this session keeps.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.session.public.len()
    }

    /// The ordinal influences only the encrypted row selection.
    pub fn prepare(&self, ordinal: u32) -> Result<WitnessQuery, Error> {
        if u64::from(ordinal) >= self.manifest.table.payloads {
            return Err(Error::Malformed);
        }
        let (row, _) = witness::slot_for(ordinal);
        let (body, secret) = self.session.prepare(row)?;
        Ok(WitnessQuery {
            body,
            secret,
            ordinal,
        })
    }

    /// Decode the untrusted payload answering `query`.
    pub fn decode(
        &self,
        query: WitnessQuery,
        response: &[u8],
    ) -> Result<[u8; witness::PAYLOAD_BYTES], Error> {
        let row = self.session.decode(&query.body, &query.secret, response)?;
        Ok(witness::lookup_row(
            &self.manifest.table,
            query.ordinal,
            &row,
        )?)
    }
}
