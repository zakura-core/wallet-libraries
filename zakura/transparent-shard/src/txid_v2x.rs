//! The display source record: the v1 record body (whole-transaction
//! metadata and every output) plus every transparent input with the value and
//! locking script of the output it spends. Display journals keep it, and
//! published v2 entries ([`crate::txid::DisplayEntry`]) are derived from it, so
//! a change to what an entry holds is a republish rather than a new ingest.
//!
//! Encoding: one version byte [`VERSION`], then the v1 record body unchanged
//! (flags, metadata, LEB128 output count, outputs), then exactly
//! `metadata.transparent_input_count` inputs in transaction order, each
//! `prevout txid (32 B) || LEB128 index || LEB128 value || LEB128 script
//! length || script`. The input count is not repeated: the metadata already
//! carries it, and one count leaves no room for disagreement. Replacing the
//! version byte with 1 and dropping the input list yields the v1 encoding of
//! [`TransparentDisplayRecordV2x::v1`], byte for byte.
use crate::txid::{DisplayFacts, DisplayOutput, DisplayRecord, Error};
use crate::txid_v1::TransparentDisplayRecord;
use transparent_events::{decode_varint, encode_varint, varint_len, FeeState, Txid, MAX_MONEY};

pub const CODEC: &str = "transparent-txid-display-v2x";
/// Never 1, so neither codec decodes the other's bytes.
pub const VERSION: u8 = 0xf2;
/// Same structural bound as a v1 output script. Consensus refuses to execute
/// locking scripts over 10,000 bytes, but the codec does not rely on that.
pub const MAX_INPUT_SCRIPT_BYTES: usize = 2_000_000;
/// The v1 encoder already bounds 41 bytes per input inside a 2 MB transaction.
pub const MAX_INPUTS: usize = 2_000_000 / 41;
/// Prevout scripts are not bounded by the spending transaction's size, so this
/// is a measurement ceiling rather than a consensus bound. A record above it
/// stops the ingest loudly instead of being truncated.
pub const MAX_RECORD_BYTES: usize = 64 << 20;

fn bad(s: &str) -> Error {
    Error(s.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayInput {
    pub prevout_txid: Txid,
    pub prevout_index: u32,
    /// The resolved value of the output this input spends.
    pub value: u64,
    /// The resolved raw locking script of the output this input spends.
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentDisplayRecordV2x {
    pub record: TransparentDisplayRecord,
    pub inputs: Vec<DisplayInput>,
}

impl DisplayInput {
    /// Encoded bytes this input adds to the record.
    pub fn encoded_len(&self) -> usize {
        32 + varint_len(u64::from(self.prevout_index))
            + varint_len(self.value)
            + varint_len(self.script.len() as u64)
            + self.script.len()
    }
}

fn read_var(bytes: &[u8], at: &mut usize, max: u64) -> Result<u64, Error> {
    let (v, n) = decode_varint(bytes.get(*at..).ok_or_else(|| bad("truncated"))?, max)
        .map_err(|e| Error(e.to_string()))?;
    *at += n;
    Ok(v)
}

impl TransparentDisplayRecordV2x {
    /// The record with its inputs stripped: exactly what v1 published.
    pub fn v1(&self) -> &TransparentDisplayRecord {
        &self.record
    }

    /// The facts a published entry is derived from: the body's metadata and
    /// outputs, and each input's spent output in input order. A published
    /// entry needs the exact fee, which every ingest resolves.
    pub fn facts(&self) -> Result<DisplayFacts, Error> {
        let fee = match self.record.metadata.fee {
            FeeState::Exact(fee) => fee,
            FeeState::NotApplicable => 0,
            FeeState::Unknown => return Err(bad("a display entry needs the exact fee")),
        };
        Ok(DisplayFacts {
            txid: self.record.txid,
            coinbase: self.record.coinbase,
            fee,
            has_shielded_components: self.record.metadata.has_shielded_components,
            spent: self
                .inputs
                .iter()
                .map(|input| DisplayOutput {
                    value: input.value,
                    script: input.script.clone(),
                })
                .collect(),
            outputs: self.record.outputs.clone(),
        })
    }

    /// The published entry of this transaction, with its txid.
    pub fn display_record(&self) -> Result<DisplayRecord, Error> {
        self.facts()?.record()
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.record.encode()?;
        let expected = if self.record.coinbase {
            0
        } else {
            self.record.metadata.transparent_input_count as usize
        };
        if self.inputs.len() != expected || self.inputs.len() > MAX_INPUTS {
            return Err(bad("input list does not match the input count"));
        }
        out[0] = VERSION;
        let mut total = 0u64;
        for input in &self.inputs {
            total = total
                .checked_add(input.value)
                .filter(|v| *v <= MAX_MONEY)
                .ok_or_else(|| bad("input value total"))?;
            if input.script.len() > MAX_INPUT_SCRIPT_BYTES {
                return Err(bad("input script length"));
            }
            out.extend_from_slice(&input.prevout_txid.0);
            encode_varint(u64::from(input.prevout_index), &mut out);
            encode_varint(input.value, &mut out);
            encode_varint(input.script.len() as u64, &mut out);
            out.extend_from_slice(&input.script);
            if out.len() > MAX_RECORD_BYTES {
                return Err(bad("record length"));
            }
        }
        // Without shielded components the whole fee is transparent, so the
        // resolved input values must account for it exactly.
        if let FeeState::Exact(fee) = self.record.metadata.fee {
            if !self.record.metadata.has_shielded_components {
                let outputs: u64 = self.record.outputs.iter().map(|o| o.value).sum();
                if outputs.checked_add(fee) != Some(total) {
                    return Err(bad("input values contradict the transparent fee"));
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        if !self
            .inputs
            .iter()
            .all(|i| seen.insert((i.prevout_txid.0, i.prevout_index)))
        {
            return Err(bad("duplicate input outpoint"));
        }
        Ok(out)
    }

    pub fn decode(txid: Txid, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD_BYTES || bytes.first() != Some(&VERSION) {
            return Err(bad("version or size"));
        }
        // The v1 decoder needs the exact end of the output list, so walk the
        // shared prefix first. Every count and length is bounded by the bytes
        // that remain before anything is allocated.
        let mut at = 2;
        let flags = *bytes.get(1).ok_or_else(|| bad("truncated"))?;
        let inputs = read_var(bytes, &mut at, u64::from(u32::MAX))? as usize;
        if flags & 8 != 0 {
            read_var(bytes, &mut at, MAX_MONEY)?;
        }
        let outputs = read_var(bytes, &mut at, crate::txid_v1::MAX_OUTPUTS as u64)? as usize;
        if outputs > bytes.len().saturating_sub(at) / 2 {
            return Err(bad("truncated output list"));
        }
        for _ in 0..outputs {
            read_var(bytes, &mut at, MAX_MONEY)?;
            let len = read_var(bytes, &mut at, 2_000_000)? as usize;
            at = at
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| bad("truncated script"))?;
        }
        let mut prefix = bytes[..at].to_vec();
        prefix[0] = 1;
        let record = TransparentDisplayRecord::decode(txid, &prefix)?;
        let inputs = if record.coinbase { 0 } else { inputs };
        if inputs > MAX_INPUTS || inputs > bytes.len().saturating_sub(at) / 35 {
            return Err(bad("truncated input list"));
        }
        let mut list = Vec::with_capacity(inputs);
        for _ in 0..inputs {
            let prevout_txid = Txid(
                bytes
                    .get(at..at + 32)
                    .ok_or_else(|| bad("truncated prevout"))?
                    .try_into()
                    .unwrap(),
            );
            at += 32;
            let prevout_index = read_var(bytes, &mut at, u64::from(u32::MAX))? as u32;
            let value = read_var(bytes, &mut at, MAX_MONEY)?;
            let len = read_var(bytes, &mut at, MAX_INPUT_SCRIPT_BYTES as u64)? as usize;
            let end = at.checked_add(len).ok_or_else(|| bad("script overflow"))?;
            let script = bytes
                .get(at..end)
                .ok_or_else(|| bad("truncated input script"))?
                .to_vec();
            at = end;
            list.push(DisplayInput {
                prevout_txid,
                prevout_index,
                value,
                script,
            });
        }
        if at != bytes.len() {
            return Err(bad("trailing data"));
        }
        let decoded = Self {
            record,
            inputs: list,
        };
        if decoded.encode()? != bytes {
            return Err(bad("noncanonical record"));
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transparent_events::TransactionMetadata;

    fn input(tag: u8, value: u64, script: usize) -> DisplayInput {
        DisplayInput {
            prevout_txid: Txid([tag; 32]),
            prevout_index: u32::from(tag),
            value,
            script: vec![0x76; script],
        }
    }
    fn spend(
        inputs: Vec<DisplayInput>,
        outputs: Vec<DisplayOutput>,
    ) -> TransparentDisplayRecordV2x {
        let total: u64 = inputs.iter().map(|i| i.value).sum();
        let out: u64 = outputs.iter().map(|o| o.value).sum();
        TransparentDisplayRecordV2x {
            record: TransparentDisplayRecord {
                txid: Txid([7; 32]),
                coinbase: false,
                metadata: TransactionMetadata {
                    fee: FeeState::Exact(total - out),
                    transparent_input_count: inputs.len() as u32,
                    has_shielded_components: false,
                },
                outputs,
            },
            inputs,
        }
    }
    fn output(value: u64, script: usize) -> DisplayOutput {
        DisplayOutput {
            value,
            script: vec![0x51; script],
        }
    }
    fn round_trip(r: &TransparentDisplayRecordV2x) -> Vec<u8> {
        let b = r.encode().unwrap();
        assert_eq!(
            TransparentDisplayRecordV2x::decode(r.record.txid, &b).unwrap(),
            *r
        );
        // Stripping the inputs is exactly the published v1 encoding.
        let v1 = r.v1().encode().unwrap();
        assert_eq!(b[1..v1.len()], v1[1..]);
        assert_eq!(
            b.len() - v1.len(),
            r.inputs
                .iter()
                .map(DisplayInput::encoded_len)
                .sum::<usize>()
        );
        assert!(TransparentDisplayRecord::decode(r.record.txid, &b).is_err());
        assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &v1).is_err());
        b
    }

    #[test]
    fn coinbase_lists_no_inputs() {
        let r = TransparentDisplayRecordV2x {
            record: TransparentDisplayRecord {
                txid: Txid([1; 32]),
                coinbase: true,
                metadata: TransactionMetadata {
                    fee: FeeState::NotApplicable,
                    transparent_input_count: 0,
                    has_shielded_components: false,
                },
                outputs: vec![output(625_000_000, 25)],
            },
            inputs: vec![],
        };
        assert_eq!(round_trip(&r).len(), r.v1().encode().unwrap().len());
        let mut listed = r.clone();
        listed.inputs.push(input(1, 0, 0));
        assert!(listed.encode().is_err());
    }

    #[test]
    fn mixed_shielded_need_not_balance_transparently() {
        // Shielded value can fund transparent outputs above the input total.
        let mut r = spend(vec![input(1, 1_000, 25)], vec![output(1_000, 25)]);
        r.record.outputs[0].value = 5_000;
        r.record.metadata.fee = FeeState::Exact(10_000);
        assert!(r.encode().is_err(), "transparent-only fee must balance");
        r.record.metadata.has_shielded_components = true;
        round_trip(&r);
        r.record.metadata.fee = FeeState::Unknown;
        round_trip(&r);
    }

    #[test]
    fn same_block_prevout_and_order_are_preserved() {
        // The codec records the outpoint as given; an input spending an output
        // created earlier in the same block is an ordinary entry.
        let mut a = input(2, 300, 25);
        a.prevout_txid = Txid([9; 32]);
        a.prevout_index = 0;
        let b = input(1, 700, 23);
        let r = spend(vec![a.clone(), b.clone()], vec![output(900, 25)]);
        round_trip(&r);
        let swapped = spend(vec![b, a.clone()], vec![output(900, 25)]);
        assert_ne!(r.encode().unwrap(), swapped.encode().unwrap());
        let duplicate = spend(vec![a.clone(), a], vec![]);
        assert!(duplicate.encode().is_err());
    }

    #[test]
    fn scripts_beyond_the_journal_ceiling_and_bounds() {
        let r = spend(vec![input(1, 1_000, 65_536)], vec![output(1, 10_001)]);
        round_trip(&r);
        let r = spend(vec![input(1, 1_000, 0)], vec![]);
        round_trip(&r);
        let r = spend(vec![input(1, 1_000, MAX_INPUT_SCRIPT_BYTES + 1)], vec![]);
        assert!(r.encode().is_err());
        let mut r = spend(vec![input(1, MAX_MONEY, 1), input(2, 1, 1)], vec![]);
        r.record.metadata.has_shielded_components = true;
        r.record.metadata.fee = FeeState::Unknown;
        assert!(r.encode().is_err(), "input total above MAX_MONEY");
        let mut r = spend(vec![input(1, 1_000, 1)], vec![]);
        r.inputs.clear();
        assert!(r.encode().is_err(), "count must match metadata");
    }

    #[test]
    fn many_inputs() {
        let inputs: Vec<_> = (0..5_000u32)
            .map(|i| DisplayInput {
                prevout_txid: Txid([(i % 251) as u8; 32]),
                prevout_index: i,
                value: 10,
                script: vec![0xa9; 23 + (i % 3) as usize],
            })
            .collect();
        let r = spend(inputs, vec![output(10, 25)]);
        let b = round_trip(&r);
        assert!(b.len() > 5_000 * 32);
    }

    #[test]
    fn malformed_bytes_are_refused() {
        let r = spend(
            vec![input(1, 1_000, 25), input(2, 2_000, 3)],
            vec![output(2_500, 25)],
        );
        let b = r.encode().unwrap();
        for i in 0..b.len() {
            assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &b[..i]).is_err());
        }
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &trailing).is_err());
        // Overlong LEB128 for the first input's prevout index.
        let v1 = r.v1().encode().unwrap().len();
        let mut overlong = b.clone();
        overlong.splice(v1 + 32..v1 + 33, [0x81, 0]);
        assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &overlong).is_err());
        // An input value that no longer balances the transparent fee.
        let mut value = b.clone();
        value[v1 + 33] ^= 1;
        assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &value).is_err());
        // A huge declared input count is refused before any allocation.
        let mut huge = b.clone();
        huge.splice(2..3, [0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &huge).is_err());
        let mut version = b;
        version[0] = 1;
        assert!(TransparentDisplayRecordV2x::decode(r.record.txid, &version).is_err());
    }

    #[test]
    fn the_published_entry_is_derived_from_the_source_record() {
        use crate::txid::{Address, AddressKind};
        let p2pkh = |b: u8| [&[0x76, 0xa9, 0x14][..], &[b; 20], &[0x88, 0xac]].concat();
        let mut first = input(1, 600, 0);
        first.script = vec![0x51];
        let mut second = input(2, 400, 0);
        second.script = p2pkh(4);
        let mut r = spend(
            vec![first, second],
            vec![DisplayOutput {
                value: 900,
                script: p2pkh(5),
            }],
        );
        let entry = r.display_record().unwrap().entry;
        assert_eq!(entry.source, Address::from_script(&p2pkh(4)));
        assert_eq!(entry.source.kind, AddressKind::P2pkh);
        assert!(entry.multiple_source_scripts);
        assert_eq!(
            (entry.fee, entry.input_count, entry.output_count),
            (100, 2, 1)
        );
        assert_eq!(entry.outputs[0].unwrap().value, 900);
        r.record.metadata.fee = FeeState::Unknown;
        assert!(r.display_record().is_err());
    }
}
