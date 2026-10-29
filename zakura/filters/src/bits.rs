// SPDX-License-Identifier: CC0-1.0
// Extracted from rust-bitcoin 0.32.102, src/bip158.rs (CC0-1.0).
// Upstream credits Tamas Blummer's murmel implementation, relicensed CC0.

use std::cmp;
use std::io::{self, Read, Write};

/// Bitwise stream reader.
pub struct BitStreamReader<'a, R: ?Sized> {
    buffer: [u8; 1],
    offset: u8,
    reader: &'a mut R,
}

impl<'a, R: Read + ?Sized> BitStreamReader<'a, R> {
    /// Creates a new [`BitStreamReader`] that reads bitwise from a given `reader`.
    pub fn new(reader: &'a mut R) -> BitStreamReader<'a, R> {
        BitStreamReader {
            buffer: [0u8],
            reader,
            offset: 8,
        }
    }

    /// Reads nbit bits, returning the bits in a `u64` starting with the rightmost bit.
    ///
    /// # Examples
    /// ```
    /// # use zakura_filters::BitStreamReader;
    /// # let data = vec![0xff];
    /// # let mut input = data.as_slice();
    /// let mut reader = BitStreamReader::new(&mut input); // input contains all 1's
    /// let res = reader.read(1).expect("read failed");
    /// assert_eq!(res, 1_u64);
    /// ```
    pub fn read(&mut self, mut nbits: u8) -> Result<u64, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not read more than 64 bits at once",
            ));
        }
        let mut data = 0u64;
        while nbits > 0 {
            if self.offset == 8 {
                crate::read_exact(self.reader, &mut self.buffer)?;
                self.offset = 0;
            }
            let bits = cmp::min(8 - self.offset, nbits);
            data <<= bits;
            data |= ((self.buffer[0] << self.offset) >> (8 - bits)) as u64;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }
}

/// Bitwise stream writer.
pub(crate) struct BitStreamWriter<'a, W> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut W,
}

impl<'a, W: Write> BitStreamWriter<'a, W> {
    /// Creates a new [`BitStreamWriter`] that writes bitwise to a given `writer`.
    pub fn new(writer: &'a mut W) -> BitStreamWriter<'a, W> {
        BitStreamWriter {
            buffer: [0u8],
            writer,
            offset: 0,
        }
    }

    /// Writes nbits bits from data.
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not write more than 64 bits at once",
            ));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer[0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written.
    pub fn flush(&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            crate::write_all(self.writer, &self.buffer)?;
            self.buffer[0] = 0u8;
            self.offset = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}
