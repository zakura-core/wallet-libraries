use super::{
    Hash, Session, Table,
    native::{COLS, MAGIC, Profile, profile, public_bytes, response_bytes},
    session::{Error, HEADER_BYTES},
};
use crate::native::{D, NativeSecret, P8, ProfileClientExt as _};
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A PIR session for one Receiver directory or companion table.
pub struct Client<M> {
    session: Session<M>,
    id: Hash,
    profile: &'static Profile,
    public: Arc<Vec<u8>>,
}

/// One fresh encryption, consumed when its response is decoded. Contains ephemeral secrets.
pub struct Query {
    body: Vec<u8>,
    secret: NativeSecret,
}

impl Query {
    /// The request body to POST.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl<M: Table> Client<M> {
    /// Checks `public` against the session's setup digest and exact length. Chain coverage
    /// is accepted for the whole inventory (see [`super::inventory::Inventory::accept`]).
    pub fn new(session: Session<M>, public: Arc<Vec<u8>>) -> Result<Self, Error> {
        if public.len() != public_bytes()
            || Hash::from(Sha256::digest(&public[..])) != session.public_digest
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id: session.id()?,
            profile: profile(M::KIND, session.manifest.rows())?,
            session,
            public,
        })
    }

    /// A fresh encrypted request for `row` over the table's query rows (a companion's
    /// trimmed prefix), with the session header and a fresh nonce. The row selection stays
    /// inside the encryption; every call encrypts anew, so a retry never repeats ciphertext.
    pub fn prepare(&self, row: u32) -> Result<Query, Error> {
        let rows = self.session.manifest.query_rows();
        if row >= rows {
            return Err(Error::Malformed);
        }
        let (secret, upload) = P8
            .prepare(
                &self.profile.setup,
                &self.profile.masks[..rows as usize / D],
                rows as usize,
                row as usize,
            )
            .map_err(|_| Error::Pir)?;
        let mut body = MAGIC.to_vec();
        body.extend(self.id);
        body.extend(OsRng.r#gen::<[u8; 16]>());
        body.extend(upload);
        Ok(Query { body, secret })
    }

    /// The row the answer to `query` carries, refusing another request's response. The row
    /// is untrusted; the caller checks it with the format's lookup.
    pub fn decode(&self, query: Query, response: &[u8]) -> Result<Vec<u8>, Error> {
        if response.len() != response_bytes()
            || response[..HEADER_BYTES] != query.body[..HEADER_BYTES]
        {
            return Err(Error::Malformed);
        }
        P8.decode_cols(&query.secret, &self.public, &response[HEADER_BYTES..], COLS)
            .map_err(|_| Error::Pir)
    }
}
