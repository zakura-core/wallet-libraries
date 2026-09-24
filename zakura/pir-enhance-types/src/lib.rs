//! Encoding-validated Enhance PIR records shared by clients and wallet backends.

pub const RECORD_BYTES: usize = 653;

pub const RECORD_ENC_CIPHERTEXT_SUFFIX_OFFSET: usize = 0;
pub const RECORD_CV_NET_OFFSET: usize = 528;
pub const RECORD_OUT_CIPHERTEXT_OFFSET: usize = 560;
pub const RECORD_FLAGS_OFFSET: usize = 640;
pub const FLAG_HAS_TRANSPARENT_INPUTS: u8 = 1 << 0;
pub const FLAG_HAS_TRANSPARENT_OUTPUTS: u8 = 1 << 1;
pub const FLAG_HAS_FEE: u8 = 1 << 2;
pub const RECORD_EXPIRY_HEIGHT_OFFSET: usize = 641;
pub const RECORD_FEE_OFFSET: usize = 645;
pub const KNOWN_FLAGS: u8 =
    FLAG_HAS_TRANSPARENT_INPUTS | FLAG_HAS_TRANSPARENT_OUTPUTS | FLAG_HAS_FEE;
pub const MAX_FEE_ZATOSHIS: u64 = 21_000_000 * 100_000_000;

/// Trusted indexer metadata, not authenticated by note decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnhanceTransactionMetadata {
    expiry_height: u32,
    fee_zatoshis: Option<u64>,
}

impl EnhanceTransactionMetadata {
    pub fn new(
        expiry_height: u32,
        fee_zatoshis: Option<u64>,
    ) -> Result<Self, InvalidEnhanceRecord> {
        if expiry_height >= 500_000_000 {
            return Err(InvalidEnhanceRecord("expiry height out of range"));
        }
        if fee_zatoshis.is_some_and(|fee| fee > MAX_FEE_ZATOSHIS) {
            return Err(InvalidEnhanceRecord("fee out of range"));
        }
        Ok(Self {
            expiry_height,
            fee_zatoshis,
        })
    }

    pub fn expiry_height(self) -> u32 {
        self.expiry_height
    }
    pub fn fee_zatoshis(self) -> Option<u64> {
        self.fee_zatoshis
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidEnhanceRecord(pub &'static str);

impl std::fmt::Display for InvalidEnhanceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for InvalidEnhanceRecord {}

/// The private fields needed to enhance one compact Ironwood action.
///
/// Construction validates the wire encoding, including reserved flag bits. It does not
/// authenticate ciphertext or server metadata. The wallet checks request identity and
/// authenticates decrypted notes; send-only association can require trust in the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhanceRecord([u8; RECORD_BYTES]);

/// Named encrypted-note fields and trusted transaction-shape metadata.
pub struct EnhanceRecordParts {
    pub enc_ciphertext_suffix: [u8; 528],
    pub cv_net: [u8; 32],
    pub out_ciphertext: [u8; 80],
    pub has_transparent_inputs: bool,
    pub has_transparent_outputs: bool,
    pub metadata: EnhanceTransactionMetadata,
}

impl EnhanceRecord {
    /// Decodes one record, rejecting reserved flag bits before exposing its fields.
    pub fn from_bytes(bytes: [u8; RECORD_BYTES]) -> Result<Self, InvalidEnhanceRecord> {
        let flags = bytes[RECORD_FLAGS_OFFSET];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(InvalidEnhanceRecord("reserved flag bits are set"));
        }
        let expiry = u32::from_le_bytes(
            bytes[RECORD_EXPIRY_HEIGHT_OFFSET..RECORD_FEE_OFFSET]
                .try_into()
                .expect("fixed slice"),
        );
        let fee = u64::from_le_bytes(
            bytes[RECORD_FEE_OFFSET..RECORD_BYTES]
                .try_into()
                .expect("fixed slice"),
        );
        if flags & FLAG_HAS_FEE == 0 && fee != 0 {
            return Err(InvalidEnhanceRecord("absent fee must have a zero payload"));
        }
        EnhanceTransactionMetadata::new(expiry, (flags & FLAG_HAS_FEE != 0).then_some(fee))?;
        Ok(Self(bytes))
    }

    pub fn from_parts(parts: EnhanceRecordParts) -> Self {
        let mut bytes = [0; RECORD_BYTES];
        bytes[RECORD_ENC_CIPHERTEXT_SUFFIX_OFFSET..RECORD_CV_NET_OFFSET]
            .copy_from_slice(&parts.enc_ciphertext_suffix);
        bytes[RECORD_CV_NET_OFFSET..RECORD_OUT_CIPHERTEXT_OFFSET].copy_from_slice(&parts.cv_net);
        bytes[RECORD_OUT_CIPHERTEXT_OFFSET..RECORD_FLAGS_OFFSET]
            .copy_from_slice(&parts.out_ciphertext);
        bytes[RECORD_FLAGS_OFFSET] = (u8::from(parts.has_transparent_inputs)
            * FLAG_HAS_TRANSPARENT_INPUTS)
            | (u8::from(parts.has_transparent_outputs) * FLAG_HAS_TRANSPARENT_OUTPUTS);
        bytes[RECORD_FLAGS_OFFSET] |=
            u8::from(parts.metadata.fee_zatoshis.is_some()) * FLAG_HAS_FEE;
        bytes[RECORD_EXPIRY_HEIGHT_OFFSET..RECORD_FEE_OFFSET]
            .copy_from_slice(&parts.metadata.expiry_height.to_le_bytes());
        bytes[RECORD_FEE_OFFSET..RECORD_BYTES]
            .copy_from_slice(&parts.metadata.fee_zatoshis.unwrap_or(0).to_le_bytes());
        Self(bytes)
    }

    pub fn metadata(&self) -> EnhanceTransactionMetadata {
        EnhanceTransactionMetadata {
            expiry_height: u32::from_le_bytes(
                self.0[RECORD_EXPIRY_HEIGHT_OFFSET..RECORD_FEE_OFFSET]
                    .try_into()
                    .expect("fixed slice"),
            ),
            fee_zatoshis: (self.0[RECORD_FLAGS_OFFSET] & FLAG_HAS_FEE != 0).then(|| {
                u64::from_le_bytes(
                    self.0[RECORD_FEE_OFFSET..RECORD_BYTES]
                        .try_into()
                        .expect("fixed slice"),
                )
            }),
        }
    }

    pub fn as_bytes(&self) -> &[u8; RECORD_BYTES] {
        &self.0
    }

    pub fn enc_ciphertext_suffix(&self) -> &[u8; 528] {
        self.0[RECORD_ENC_CIPHERTEXT_SUFFIX_OFFSET..RECORD_CV_NET_OFFSET]
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
        self.0[RECORD_FLAGS_OFFSET] & (FLAG_HAS_TRANSPARENT_INPUTS | FLAG_HAS_TRANSPARENT_OUTPUTS)
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
    fn schema_v11_suffix_offsets() {
        for flags in 0u8..4 {
            let record = EnhanceRecord::from_parts(EnhanceRecordParts {
                enc_ciphertext_suffix: [2; 528],
                cv_net: [3; 32],
                out_ciphertext: [4; 80],
                has_transparent_inputs: flags & 1 != 0,
                has_transparent_outputs: flags & 2 != 0,
                metadata: EnhanceTransactionMetadata::new(0, None).unwrap(),
            });
            let bytes = record.as_bytes();
            assert_eq!(bytes.len(), 653);
            assert_eq!(&bytes[..528], &[2; 528]);
            assert_eq!(&bytes[528..560], &[3; 32]);
            assert_eq!(&bytes[560..640], &[4; 80]);
            assert_eq!(bytes[640], flags);
            assert_eq!(EnhanceRecord::from_bytes(*bytes), Ok(record.clone()));
            assert_eq!(record.transparent_flags(), flags);
            assert_eq!(record.has_transparent(), flags != 0);
        }
    }

    #[test]
    fn every_reserved_flag_encoding_is_rejected() {
        for flags in 8..=u8::MAX {
            let mut bytes = [0; RECORD_BYTES];
            bytes[640] = flags;
            assert_eq!(
                EnhanceRecord::from_bytes(bytes),
                Err(InvalidEnhanceRecord("reserved flag bits are set"))
            );
        }
    }
    #[test]
    fn schema11_frozen_vector_and_metadata_validation() {
        let text = include_str!("../tests/fixtures/schema11-record.hex").trim();
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        let record = EnhanceRecord::from_bytes(bytes.try_into().unwrap()).unwrap();
        assert_eq!(
            record.metadata(),
            EnhanceTransactionMetadata::new(123456, Some(12345)).unwrap()
        );
        assert_eq!(record.enc_ciphertext_suffix(), &[2; 528]);
        assert_eq!(record.cv_net(), &[3; 32]);
        assert_eq!(record.out_ciphertext(), &[4; 80]);
        let mut malformed = *record.as_bytes();
        malformed[640] = 0;
        assert!(EnhanceRecord::from_bytes(malformed).is_err());
        malformed = *record.as_bytes();
        malformed[641..645].copy_from_slice(&500_000_000u32.to_le_bytes());
        assert!(EnhanceRecord::from_bytes(malformed).is_err());
        malformed = *record.as_bytes();
        malformed[645..653].copy_from_slice(&(MAX_FEE_ZATOSHIS + 1).to_le_bytes());
        assert!(EnhanceRecord::from_bytes(malformed).is_err());
        for fee in [None, Some(0), Some(MAX_FEE_ZATOSHIS)] {
            let record = EnhanceRecord::from_parts(EnhanceRecordParts {
                enc_ciphertext_suffix: [0; 528],
                cv_net: [0; 32],
                out_ciphertext: [0; 80],
                has_transparent_inputs: false,
                has_transparent_outputs: false,
                metadata: EnhanceTransactionMetadata::new(0, fee).unwrap(),
            });
            assert_eq!(
                EnhanceRecord::from_bytes(*record.as_bytes())
                    .unwrap()
                    .metadata()
                    .fee_zatoshis(),
                fee
            );
        }
    }
}
