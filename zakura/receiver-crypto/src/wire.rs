//! Fixed receiver record layout. Decoded data is untrusted until checked by the caller.
#![forbid(unsafe_code)]

/// Compact action bytes and their chain location, without cryptographic validation.
/// All hashes use protocol byte order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub txid: [u8; 32],
    pub tx_index: u32,
    pub action_index: u32,
    pub position: u64,
    /// The Action's input nullifier, not the received note's spend nullifier.
    pub action_nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub ciphertext_prefix: [u8; 52],
}

/// One untrusted payment page. Receiver and action bytes have not been validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawRecord {
    pub receiver: [u8; 43],
    pub page: u32,
    pub total: u32,
    pub payment: Payment,
}

/// Encoded size of one receiver record slot.
pub const RECORD_BYTES: usize = 285;

/// A slot has an invalid length, version tag, empty encoding, or page range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed receiver wire record")
    }
}

impl std::error::Error for Error {}

impl RawRecord {
    /// Encode the fixed layout after checking page bounds. This does not check
    /// receiver addresses or the cryptographic validity of action fields.
    pub fn encode(&self) -> Result<[u8; RECORD_BYTES], Error> {
        self.check()?;
        let p = &self.payment;
        let mut out = [0; RECORD_BYTES];
        out[0] = 1;
        out[1..44].copy_from_slice(&self.receiver);
        out[44..48].copy_from_slice(&self.page.to_le_bytes());
        out[48..52].copy_from_slice(&self.total.to_le_bytes());
        out[52] = 1;
        out[53..57].copy_from_slice(&p.height.to_le_bytes());
        out[57..89].copy_from_slice(&p.block_hash);
        out[89..121].copy_from_slice(&p.txid);
        out[121..125].copy_from_slice(&p.tx_index.to_le_bytes());
        out[125..129].copy_from_slice(&p.action_index.to_le_bytes());
        out[129..137].copy_from_slice(&p.position.to_le_bytes());
        out[137..169].copy_from_slice(&p.action_nullifier);
        out[169..201].copy_from_slice(&p.cmx);
        out[201..233].copy_from_slice(&p.ephemeral_key);
        out[233..285].copy_from_slice(&p.ciphertext_prefix);
        Ok(out)
    }

    /// Parse structure only. An entirely zero slot is empty; malformed nonempty
    /// slots are errors. A returned record still requires cryptographic checks.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, Error> {
        if bytes.len() != RECORD_BYTES {
            return Err(Error);
        }
        if bytes.iter().all(|&byte| byte == 0) {
            return Ok(None);
        }
        if bytes[0] != 1 || bytes[52] != 1 {
            return Err(Error);
        }
        let record = Self {
            receiver: bytes[1..44].try_into().unwrap(),
            page: u32::from_le_bytes(bytes[44..48].try_into().unwrap()),
            total: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            payment: Payment {
                height: u32::from_le_bytes(bytes[53..57].try_into().unwrap()),
                block_hash: bytes[57..89].try_into().unwrap(),
                txid: bytes[89..121].try_into().unwrap(),
                tx_index: u32::from_le_bytes(bytes[121..125].try_into().unwrap()),
                action_index: u32::from_le_bytes(bytes[125..129].try_into().unwrap()),
                position: u64::from_le_bytes(bytes[129..137].try_into().unwrap()),
                action_nullifier: bytes[137..169].try_into().unwrap(),
                cmx: bytes[169..201].try_into().unwrap(),
                ephemeral_key: bytes[201..233].try_into().unwrap(),
                ciphertext_prefix: bytes[233..285].try_into().unwrap(),
            },
        };
        record.check()?;
        Ok(Some(record))
    }

    fn check(&self) -> Result<(), Error> {
        if self.total == 0 || self.page >= self.total {
            return Err(Error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
