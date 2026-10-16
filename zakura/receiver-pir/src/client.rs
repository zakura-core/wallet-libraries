use crate::{
    profile, public_bytes, response_bytes, AcceptedCoverage, Error, Manifest, Profile, COLS,
    HEADER_BYTES, MAGIC,
};
use pir_native::NativeSecret;
use rand::{rngs::OsRng, Rng};
use receiver_directory::{snapshot, Hash, RawRecord, ReceiverBytes};
use sha2::{Digest, Sha256};

/// A PIR session for one manifest, accepted against the caller's chain anchor.
pub struct Client {
    manifest: Manifest,
    id: Hash,
    profile: &'static Profile,
    public: Vec<u8>,
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
    /// Check the manifest against `accepted` and the public setup against its digest.
    pub fn new(
        manifest: Manifest,
        public: &[u8],
        accepted: AcceptedCoverage,
    ) -> Result<Self, Error> {
        manifest.validate()?;
        accepted.check(&manifest.directory)?;
        if public.len() != public_bytes(manifest.directory.rows)?
            || Hash::from(Sha256::digest(public)) != manifest.public_digest
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id: manifest.id()?,
            profile: profile(manifest.directory.rows)?,
            manifest,
            public: public.to_vec(),
        })
    }

    /// The session manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Receiver and page influence only the encrypted row selection, never a public header.
    pub fn prepare(&self, receiver: ReceiverBytes, page: u32) -> Result<Query, Error> {
        let row = snapshot::row_for(&self.manifest.directory, &receiver, page)?;
        let (secret, request) = pir_native::prepare_with(
            &self.profile.setup,
            &self.profile.masks,
            self.profile.rows,
            row,
        )
        .map_err(|_| Error::Pir)?;
        let mut body = MAGIC.to_vec();
        body.extend(self.id);
        body.extend(OsRng.gen::<[u8; 16]>());
        body.extend(request);
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
        if query.body[4..36] != self.id {
            return Err(Error::Revision);
        }
        if response.len() != response_bytes(self.manifest.directory.rows)?
            || response[..HEADER_BYTES] != query.body[..HEADER_BYTES]
        {
            return Err(Error::Malformed);
        }
        let row =
            pir_native::decode_cols(&query.secret, &self.public, &response[HEADER_BYTES..], COLS)
                .map_err(|_| Error::Pir)?;
        Ok(snapshot::lookup_row(
            &self.manifest.directory,
            &query.receiver,
            query.page,
            &row,
        )?)
    }
}
