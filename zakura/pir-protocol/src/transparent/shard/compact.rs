//! Row codec with canonical, bounded transaction metadata. Introduced with
//! schema v11; schema v12's records and page rows still encode with it.
//! References are local to one entry: its first event is always self contained.

use crate::transparent::events::{EVENT_BYTES, TransactionMetadata, TransparentEvent};
use crate::transparent::shard::records::RecordError;

pub const RECEIVE_BYTES: usize = 51;
pub const SPEND_BYTES: usize = 79;
pub const LOCAL_SPEND_BYTES: usize = 43;
const LOCAL_OUTPOINT: u8 = 4;

fn local(event: &TransparentEvent, previous: Option<&TransparentEvent>) -> bool {
    matches!((previous, event),
        (Some(TransparentEvent::Receive(r)), TransparentEvent::Spend(s))
        if (r.txid, r.output_index) == (s.spent_txid, s.spent_output_index))
}

pub fn event_len(event: &TransparentEvent, previous: Option<&TransparentEvent>) -> usize {
    let base = match event {
        TransparentEvent::Receive(_) => RECEIVE_BYTES,
        TransparentEvent::Spend(_) if local(event, previous) => LOCAL_SPEND_BYTES,
        TransparentEvent::Spend(_) => SPEND_BYTES,
    };
    base + event.metadata().map_or(0, TransactionMetadata::encoded_len)
}

pub fn encoded_len(events: &[TransparentEvent]) -> usize {
    events
        .iter()
        .enumerate()
        .map(|(i, e)| event_len(e, i.checked_sub(1).map(|j| &events[j])))
        .sum()
}

pub fn encode(events: &[TransparentEvent], out: &mut Vec<u8>) -> Result<(), RecordError> {
    for (i, event) in events.iter().enumerate() {
        event.validate_metadata()?;
        // Avoid the journal encoder's debug assertion on its forbidden sentinel.
        if matches!(event, TransparentEvent::Receive(r) if r.height == 0 && r.transaction_index == 0
            && r.value == 0 && r.txid.0 == [0; 32] && r.output_index == 0 && !r.coinbase)
        {
            return Err(crate::transparent::events::EventError::Empty.into());
        }
        let mut raw = event.to_legacy_bytes();
        raw[0] |= event.metadata().map_or(0, TransactionMetadata::flags);
        let previous = i.checked_sub(1).map(|j| &events[j]);
        match event {
            TransparentEvent::Receive(_) => out.extend_from_slice(&raw[..RECEIVE_BYTES]),
            TransparentEvent::Spend(_) => {
                let reference = local(event, previous);
                out.push(raw[0] | if reference { LOCAL_OUTPOINT } else { 0 });
                out.extend_from_slice(&raw[1..7]);
                out.extend_from_slice(&raw[15..51]);
                if !reference {
                    out.extend_from_slice(&raw[51..]);
                }
            }
        }
        if let Some(metadata) = event.metadata() {
            metadata.encode(out);
        }
    }
    Ok(())
}

/// Decode exactly `count` events, returning the bytes consumed. Callers bound
/// count before allocation and independently require zero trailing row padding.
pub fn decode(bytes: &[u8], count: usize) -> Result<(Vec<TransparentEvent>, usize), RecordError> {
    if count > crate::transparent::shard::layout::EVENTS_PER_PAGE as usize {
        return Err(RecordError::TooManyEvents(count));
    }
    let mut events = Vec::with_capacity(count);
    let mut at = 0usize;
    for _ in 0..count {
        let flags = *bytes
            .get(at)
            .ok_or_else(|| RecordError::Malformed("truncated compact event".into()))?;
        if flags & !63 != 0 || flags & 1 == 0 && flags & LOCAL_OUTPOINT != 0 || flags & 3 == 3 {
            return Err(crate::transparent::events::EventError::Flags(flags).into());
        }
        let len = if flags & 1 == 0 {
            RECEIVE_BYTES
        } else if flags & LOCAL_OUTPOINT != 0 {
            LOCAL_SPEND_BYTES
        } else {
            SPEND_BYTES
        };
        let body = bytes
            .get(at..at + len)
            .ok_or_else(|| RecordError::Malformed("truncated compact event".into()))?;
        let mut raw = [0; EVENT_BYTES];
        if flags & 1 == 0 {
            raw[..RECEIVE_BYTES].copy_from_slice(body);
            raw[0] &= 3;
        } else {
            raw[0] = 1;
            raw[1..7].copy_from_slice(&body[1..7]);
            raw[15..51].copy_from_slice(&body[7..43]);
            if flags & LOCAL_OUTPOINT != 0 {
                let Some(TransparentEvent::Receive(r)) = events.last() else {
                    return Err(RecordError::Malformed(
                        "local outpoint without preceding receive".into(),
                    ));
                };
                raw[51..83].copy_from_slice(&r.txid.0);
                raw[83..].copy_from_slice(&r.output_index.to_le_bytes());
            } else {
                raw[51..].copy_from_slice(&body[43..]);
            }
        }
        let (metadata, metadata_len) =
            TransactionMetadata::decode(&bytes[at + len..], flags & 56, flags & 2 != 0)?;
        let event = TransparentEvent::from_legacy_bytes(&raw)?.with_metadata(metadata);
        event.validate_metadata()?;
        if event_len(&event, events.last()) != len + metadata_len {
            return Err(RecordError::Malformed(
                "noncanonical full outpoint after its receive".into(),
            ));
        }
        events.push(event);
        at += len + metadata_len;
    }
    Ok((events, at))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::transparent::events::{ReceiveEvent, SpendEvent, Txid};

    #[test]
    fn metadata_is_attributed_to_each_event_and_framed_after_local_outpoints() {
        let [receive, spend] = pair(100, 5);
        let receive = match receive {
            TransparentEvent::Receive(mut r) => {
                r.value = 1000;
                TransparentEvent::Receive(r)
            }
            _ => unreachable!(),
        }
        .with_metadata(Some(TransactionMetadata {
            fee: crate::transparent::events::FeeState::NotApplicable,
            transparent_input_count: 0,
            has_shielded_components: true,
        }));
        let spend = match spend {
            TransparentEvent::Spend(mut s) => {
                s.input_index = 0;
                TransparentEvent::Spend(s)
            }
            _ => unreachable!(),
        }
        .with_metadata(Some(TransactionMetadata {
            fee: crate::transparent::events::FeeState::Exact(500),
            transparent_input_count: 1,
            has_shielded_components: false,
        }));
        let mut bytes = Vec::new();
        encode(&[receive, spend], &mut bytes).unwrap();
        assert_eq!(bytes.len(), 98);
        assert_eq!(bytes[0], 50);
        assert_eq!(bytes[51], 0);
        assert_eq!(bytes[52], 45);
        assert_eq!(decode(&bytes, 2).unwrap(), (vec![receive, spend], 98));
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end], 2).is_err());
        }
    }

    pub(crate) fn pair(height: u32, nonce: u32) -> [TransparentEvent; 2] {
        let mut txid = [0x12; 32];
        txid[..4].copy_from_slice(&nonce.to_le_bytes());
        [
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height,
                transaction_index: 0,
                txid: Txid(txid),
                output_index: u32::MAX,
                value: u64::MAX,
                coinbase: true,
            }),
            TransparentEvent::Spend(SpendEvent {
                metadata: None,
                height,
                transaction_index: u16::MAX,
                spending_txid: Txid([0x34; 32]),
                input_index: u32::MAX,
                spent_txid: Txid(txid),
                spent_output_index: u32::MAX,
            }),
        ]
    }

    #[test]
    fn widths_reconstruction_and_independent_wire_vectors() {
        let [receive, spend] = pair(u32::MAX, 0x12121212);
        let mut expected = vec![2, 0, 0];
        expected.extend([0xff; 12]); // height and value, little endian
        expected.extend([0x12; 32]);
        expected.extend([0xff; 4]);
        expected.extend([5, 0xff, 0xff]);
        expected.extend([0xff; 4]);
        expected.extend([0x34; 32]);
        expected.extend([0xff; 4]);
        let mut encoded = Vec::new();
        encode(&[receive, spend], &mut encoded).unwrap();
        assert_eq!(encoded.len(), 94);
        assert_eq!(encoded, expected);
        assert_eq!(decode(&expected, 2).unwrap(), (vec![receive, spend], 94));
        let mut standalone = Vec::new();
        encode(&[spend], &mut standalone).unwrap();
        assert_eq!(standalone.len(), 79);
        assert_eq!(standalone[0], 1);
        assert_eq!(&standalone[43..75], &[0x12; 32]);
        assert_eq!(decode(&standalone, 1).unwrap().0, vec![spend]);
        assert_eq!(receive.to_bytes().unwrap().len(), 87);
        assert_eq!(spend.to_bytes().unwrap().len(), 87);
    }

    #[test]
    fn malformed_reference_flags_counts_and_truncation_are_refused() {
        let pair = pair(100, 5);
        let mut encoded = Vec::new();
        encode(&pair, &mut encoded).unwrap();
        for end in 0..encoded.len() {
            assert!(decode(&encoded[..end], 2).is_err());
        }
        assert!(decode(&encoded[51..], 1).is_err());
        for flag in [3, 4, 6, 7, 8, 255] {
            let mut bad = encoded.clone();
            bad[0] = flag;
            assert!(decode(&bad, 2).is_err(), "flag {flag}");
        }
        assert!(decode(&encoded, 87).is_err());
        assert!(decode(&[0; 51], 1).is_err());
        let mut noncanonical = encoded[..51].to_vec();
        encode(&pair[1..], &mut noncanonical).unwrap();
        assert!(decode(&noncanonical, 2).is_err());
        let mut after_spend = Vec::new();
        encode(&pair[1..], &mut after_spend).unwrap();
        after_spend.extend_from_slice(&encoded[51..]);
        assert!(decode(&after_spend, 2).is_err());
    }
}
