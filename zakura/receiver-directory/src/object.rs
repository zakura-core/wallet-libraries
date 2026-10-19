//! The header and field reader shared by the recovery objects in [`crate::paid`],
//! [`crate::seen`] and [`crate::catalog`], whose module docs give the layout.
use crate::{snapshot::PROFILE, Error, Hash};
use sha2::{Digest, Sha256};

/// The format version of every recovery object.
const VERSION: u16 = 1;

/// Starts an object of kind `magic` for the network with `genesis`.
pub(crate) fn header(magic: &[u8; 8], genesis: &Hash) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend(VERSION.to_le_bytes());
    out.push(PROFILE.len() as u8);
    out.extend(PROFILE.as_bytes());
    out.extend(genesis);
    out
}

/// The digest of an object's canonical `encoding`.
pub(crate) fn digest(encoding: &[u8]) -> Hash {
    Sha256::digest(encoding).into()
}

/// Reads an object's fields in order. Any shortfall is [`Error::Malformed`].
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Checks that `bytes` starts with the header [`header`] writes for `magic`, and
    /// returns its genesis hash and a reader of the fields after it.
    pub(crate) fn open(bytes: &'a [u8], magic: &[u8; 8]) -> Result<(Hash, Self), Error> {
        let mut reader = Self(bytes.strip_prefix(magic).ok_or(Error::Malformed)?);
        let version = u16::from_le_bytes(reader.array()?);
        let len = reader.u8()?;
        let profile = reader.take(usize::from(len))?;
        if version != VERSION || profile != PROFILE.as_bytes() {
            return Err(Error::Malformed);
        }
        Ok((reader.array()?, reader))
    }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (taken, rest) = self.0.split_at_checked(n).ok_or(Error::Malformed)?;
        self.0 = rest;
        Ok(taken)
    }

    /// The next `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    /// The next byte.
    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    /// The next little-endian `u32`.
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// The next little-endian `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// The next little-endian `i64`.
    pub(crate) fn i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// A `u32` length and that many bytes.
    pub(crate) fn payload(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()?;
        self.take(len as usize)
    }

    /// Fails unless every byte was read.
    pub(crate) fn finish(self) -> Result<(), Error> {
        if !self.0.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
