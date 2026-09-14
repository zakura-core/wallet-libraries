//! Encoding-validated Enhance PIR records shared by clients and wallet backends.

pub const RECORD_BYTES: usize = 725;

pub const RECORD_EPHEMERAL_KEY_OFFSET: usize = 0;
pub const RECORD_ENC_CIPHERTEXT_OFFSET: usize = 32;
pub const RECORD_CV_NET_OFFSET: usize = 612;
pub const RECORD_OUT_CIPHERTEXT_OFFSET: usize = 644;
pub const RECORD_FLAGS_OFFSET: usize = 724;
pub const FLAG_HAS_TRANSPARENT_INPUTS: u8 = 1 << 0;
pub const FLAG_HAS_TRANSPARENT_OUTPUTS: u8 = 1 << 1;
pub const KNOWN_FLAGS: u8 = FLAG_HAS_TRANSPARENT_INPUTS | FLAG_HAS_TRANSPARENT_OUTPUTS;

/// The private fields needed to enhance one compact Ironwood action.
///
/// Construction validates the wire encoding, including reserved flag bits. It does not
/// authenticate the ciphertext or server metadata; the wallet must bind and decrypt it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhanceRecord([u8; RECORD_BYTES]);

/// Named encrypted-note fields and trusted transaction-shape metadata.
pub struct EnhanceRecordParts {
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub cv_net: [u8; 32],
    pub out_ciphertext: [u8; 80],
    pub has_transparent_inputs: bool,
    pub has_transparent_outputs: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidEnhanceRecordFlags(pub u8);

impl std::fmt::Display for InvalidEnhanceRecordFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "reserved Enhance flag bits are set: 0x{:02x}",
            self.0
        )
    }
}

impl std::error::Error for InvalidEnhanceRecordFlags {}

impl EnhanceRecord {
    /// Decodes one record, rejecting reserved flag bits before exposing its fields.
    pub fn from_bytes(bytes: [u8; RECORD_BYTES]) -> Result<Self, InvalidEnhanceRecordFlags> {
        let flags = bytes[RECORD_FLAGS_OFFSET];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(InvalidEnhanceRecordFlags(flags));
        }
        Ok(Self(bytes))
    }

    pub fn from_parts(parts: EnhanceRecordParts) -> Self {
        let mut bytes = [0; RECORD_BYTES];
        bytes[RECORD_EPHEMERAL_KEY_OFFSET..RECORD_ENC_CIPHERTEXT_OFFSET]
            .copy_from_slice(&parts.ephemeral_key);
        bytes[RECORD_ENC_CIPHERTEXT_OFFSET..RECORD_CV_NET_OFFSET]
            .copy_from_slice(&parts.enc_ciphertext);
        bytes[RECORD_CV_NET_OFFSET..RECORD_OUT_CIPHERTEXT_OFFSET].copy_from_slice(&parts.cv_net);
        bytes[RECORD_OUT_CIPHERTEXT_OFFSET..RECORD_FLAGS_OFFSET]
            .copy_from_slice(&parts.out_ciphertext);
        bytes[RECORD_FLAGS_OFFSET] = (u8::from(parts.has_transparent_inputs)
            * FLAG_HAS_TRANSPARENT_INPUTS)
            | (u8::from(parts.has_transparent_outputs) * FLAG_HAS_TRANSPARENT_OUTPUTS);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RECORD_BYTES] {
        &self.0
    }

    pub fn ephemeral_key(&self) -> &[u8; 32] {
        self.0[RECORD_EPHEMERAL_KEY_OFFSET..RECORD_ENC_CIPHERTEXT_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn enc_ciphertext(&self) -> &[u8; 580] {
        self.0[RECORD_ENC_CIPHERTEXT_OFFSET..RECORD_CV_NET_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn cv_net(&self) -> &[u8; 32] {
        self.0[RECORD_CV_NET_OFFSET..RECORD_OUT_CIPHERTEXT_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn out_ciphertext(&self) -> &[u8; 80] {
        self.0[RECORD_OUT_CIPHERTEXT_OFFSET..RECORD_FLAGS_OFFSET]
            .try_into()
            .expect("fixed slice")
    }

    pub fn transparent_flags(&self) -> u8 {
        self.0[RECORD_FLAGS_OFFSET]
    }

    pub fn has_transparent_inputs(&self) -> bool {
        self.transparent_flags() & FLAG_HAS_TRANSPARENT_INPUTS != 0
    }

    pub fn has_transparent_outputs(&self) -> bool {
        self.transparent_flags() & FLAG_HAS_TRANSPARENT_OUTPUTS != 0
    }

    /// Reports trusted server metadata, not cryptographically authenticated transaction shape.
    pub fn has_transparent(&self) -> bool {
        self.has_transparent_inputs() || self.has_transparent_outputs()
    }
}

impl AsRef<[u8]> for EnhanceRecord {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_v6_bytes_and_flags_are_unchanged() {
        for flags in 0u8..4 {
            let record = EnhanceRecord::from_parts(EnhanceRecordParts {
                ephemeral_key: [1; 32],
                enc_ciphertext: [2; 580],
                cv_net: [3; 32],
                out_ciphertext: [4; 80],
                has_transparent_inputs: flags & 1 != 0,
                has_transparent_outputs: flags & 2 != 0,
            });
            let bytes = record.as_bytes();
            assert_eq!(bytes.len(), 725);
            assert_eq!(&bytes[..32], &[1; 32]);
            assert_eq!(&bytes[32..612], &[2; 580]);
            assert_eq!(&bytes[612..644], &[3; 32]);
            assert_eq!(&bytes[644..724], &[4; 80]);
            assert_eq!(bytes[724], flags);
            assert_eq!(EnhanceRecord::from_bytes(*bytes), Ok(record.clone()));
            assert_eq!(record.transparent_flags(), flags);
            assert_eq!(record.has_transparent(), flags != 0);
        }
    }

    #[test]
    fn every_reserved_flag_encoding_is_rejected() {
        for flags in 4..=u8::MAX {
            let mut bytes = [0; 725];
            bytes[724] = flags;
            assert_eq!(
                EnhanceRecord::from_bytes(bytes),
                Err(InvalidEnhanceRecordFlags(flags))
            );
        }
    }
}
