// SPDX-License-Identifier: CC0-1.0
// CompactSize follows rust-bitcoin 0.32.102, consensus/encode.rs (CC0-1.0).

use bitcoin_io::{self as io, Read, Write};

/// Writes the canonical CompactSize representation and returns its byte length.
///
/// Propagates write errors; a failed write may leave partial output.
pub fn write_compact_size<W: Write + ?Sized>(
    writer: &mut W,
    value: u64,
) -> Result<usize, io::Error> {
    match value {
        0..=0xfc => {
            writer.write_all(&[value as u8])?;
            Ok(1)
        }
        0xfd..=0xffff => {
            writer.write_all(&[0xfd])?;
            writer.write_all(&(value as u16).to_le_bytes())?;
            Ok(3)
        }
        0x1_0000..=0xffff_ffff => {
            writer.write_all(&[0xfe])?;
            writer.write_all(&(value as u32).to_le_bytes())?;
            Ok(5)
        }
        _ => {
            writer.write_all(&[0xff])?;
            writer.write_all(&value.to_le_bytes())?;
            Ok(9)
        }
    }
}

/// Reads a canonical CompactSize integer, rejecting non-minimal encodings.
///
/// Propagates read errors and returns `InvalidData` for a non-minimal integer.
/// No allocation limit is applied: callers must bound the value before using it
/// as a length. Bytes following the integer are left unread.
pub fn read_compact_size<R: Read + ?Sized>(reader: &mut R) -> Result<u64, io::Error> {
    let mut prefix = [0];
    reader.read_exact(&mut prefix)?;
    let (value, minimum) = match prefix[0] {
        0xfd => (u64::from(u16::from_le_bytes(read_array(reader)?)), 0xfd),
        0xfe => (u64::from(u32::from_le_bytes(read_array(reader)?)), 0x1_0000),
        0xff => (u64::from_le_bytes(read_array(reader)?), 0x1_0000_0000),
        value => return Ok(u64::from(value)),
    };
    if value < minimum {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-minimal CompactSize integer",
        ))
    } else {
        Ok(value)
    }
}

fn read_array<const N: usize, R: Read + ?Sized>(reader: &mut R) -> Result<[u8; N], io::Error> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
