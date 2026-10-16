//! The variable-length v1 display record: whole-transaction metadata and
//! every transparent output in order. It is no longer published. It survives
//! as the body of the v2x source record ([`crate::txid_v2x`]) that display
//! journals keep and published entries are derived from.
use crate::txid::{DisplayOutput, Error};
use transparent_events::{decode_varint, encode_varint, TransactionMetadata, Txid, MAX_MONEY};

/// Twice the supported 2 MB transaction ceiling allows varint expansion.
pub const MAX_RECORD_BYTES: usize = 4_000_000;
pub const MAX_OUTPUTS: usize = 2_000_000 / 9;

fn bad(s: &str) -> Error {
    Error(s.into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayRecord {
    pub txid: Txid,
    pub coinbase: bool,
    pub metadata: TransactionMetadata,
    pub outputs: Vec<DisplayOutput>,
}
fn read_var(bytes: &[u8], at: &mut usize, max: u64) -> Result<u64, Error> {
    let (v, n) = decode_varint(bytes.get(*at..).ok_or_else(|| bad("truncated"))?, max)
        .map_err(|e| Error(e.to_string()))?;
    *at += n;
    Ok(v)
}
impl TransparentDisplayRecord {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.metadata
            .validate(self.coinbase)
            .map_err(|e| Error(e.to_string()))?;
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(bad("output count"));
        }
        // A lower bound on the canonical transaction size: even empty input
        // scripts need an outpoint, CompactSize and sequence. The publisher
        // additionally parses canonical accepted transactions, including the
        // bytes of shielded components that this display record omits.
        let inputs = if self.coinbase {
            1
        } else {
            u64::from(self.metadata.transparent_input_count)
        };
        let compact_size = |n: u64| {
            if n < 253 {
                1
            } else if n <= 65535 {
                3
            } else {
                5
            }
        };
        let mut canonical_minimum =
            8 + compact_size(inputs) + 41 * inputs + compact_size(self.outputs.len() as u64);
        if canonical_minimum > 2_000_000 {
            return Err(bad("transaction input size bound"));
        }
        let mut out = vec![1, self.metadata.flags() | u8::from(self.coinbase)];
        self.metadata.encode(&mut out);
        encode_varint(self.outputs.len() as u64, &mut out);
        let mut sum = 0u64;
        for output in &self.outputs {
            sum = sum
                .checked_add(output.value)
                .filter(|v| *v <= MAX_MONEY)
                .ok_or_else(|| bad("output value total"))?;
            if output.script.len() > 2_000_000 {
                return Err(bad("script length"));
            }
            canonical_minimum +=
                8 + compact_size(output.script.len() as u64) + output.script.len() as u64;
            if canonical_minimum > 2_000_000 {
                return Err(bad("transaction output size bound"));
            }
            encode_varint(output.value, &mut out);
            encode_varint(output.script.len() as u64, &mut out);
            out.extend_from_slice(&output.script);
            if out.len() > MAX_RECORD_BYTES {
                return Err(bad("record length"));
            }
        }
        Ok(out)
    }
    pub fn decode(txid: Txid, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD_BYTES || bytes.len() < 3 || bytes[0] != 1 || bytes[1] & !57 != 0
        {
            return Err(bad("version, flags or size"));
        }
        let coinbase = bytes[1] & 1 != 0;
        let (metadata, n) = TransactionMetadata::decode(&bytes[2..], bytes[1] & !1, coinbase)
            .map_err(|e| Error(e.to_string()))?;
        let metadata = metadata.ok_or_else(|| bad("missing metadata"))?;
        let mut at = 2 + n;
        let count = read_var(bytes, &mut at, MAX_OUTPUTS as u64)? as usize;
        if count > bytes.len().saturating_sub(at) / 2 {
            return Err(bad("truncated output list"));
        }
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            let value = read_var(bytes, &mut at, MAX_MONEY)?;
            let len = read_var(bytes, &mut at, 2_000_000)? as usize;
            let end = at.checked_add(len).ok_or_else(|| bad("script overflow"))?;
            let script = bytes
                .get(at..end)
                .ok_or_else(|| bad("truncated script"))?
                .to_vec();
            at = end;
            outputs.push(DisplayOutput { value, script });
        }
        if at != bytes.len() {
            return Err(bad("trailing data"));
        }
        let record = Self {
            txid,
            coinbase,
            metadata,
            outputs,
        };
        if record.encode()? != bytes {
            return Err(bad("noncanonical record"));
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transparent_events::FeeState;
    fn record(n: usize) -> TransparentDisplayRecord {
        TransparentDisplayRecord {
            txid: Txid([7; 32]),
            coinbase: false,
            metadata: TransactionMetadata {
                fee: FeeState::Exact(10_000),
                transparent_input_count: 1,
                has_shielded_components: false,
            },
            outputs: vec![DisplayOutput {
                value: 5,
                script: vec![0x51; n],
            }],
        }
    }
    #[test]
    fn canonical_and_bounds() {
        let r = record(25);
        let b = r.encode().unwrap();
        assert_eq!(TransparentDisplayRecord::decode(r.txid, &b).unwrap(), r);
        for i in 0..b.len() {
            assert!(TransparentDisplayRecord::decode(r.txid, &b[..i]).is_err());
        }
        let mut b = b;
        b[1] |= 128;
        assert!(TransparentDisplayRecord::decode(r.txid, &b).is_err());
        let mut r = record(0);
        r.outputs[0].value = MAX_MONEY + 1;
        assert!(r.encode().is_err());
        let mut r = record(0);
        r.metadata.transparent_input_count = u32::MAX;
        assert!(r.encode().is_err());
        let mut r = record(0);
        r.metadata.fee = FeeState::Unknown;
        let unknown = r.encode().unwrap();
        assert_eq!(
            TransparentDisplayRecord::decode(r.txid, &unknown).unwrap(),
            r
        );
        r.metadata.fee = FeeState::Exact(0);
        assert_ne!(r.encode().unwrap(), unknown);
        r.outputs.clear();
        assert_eq!(
            TransparentDisplayRecord::decode(r.txid, &r.encode().unwrap()).unwrap(),
            r
        );
        r.coinbase = true;
        assert!(r.encode().is_err());
        r.metadata.fee = FeeState::NotApplicable;
        r.metadata.transparent_input_count = 0;
        assert_eq!(
            TransparentDisplayRecord::decode(r.txid, &r.encode().unwrap()).unwrap(),
            r
        );
        // Overlong unsigned LEB128 input count and trailing data are rejected.
        let r = record(1);
        let mut b = r.encode().unwrap();
        b.splice(2..3, [0x81, 0]);
        assert!(TransparentDisplayRecord::decode(r.txid, &b).is_err());
        let mut b = r.encode().unwrap();
        b.push(0);
        assert!(TransparentDisplayRecord::decode(r.txid, &b).is_err());
    }
}
