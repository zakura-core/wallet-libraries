use super::*;

fn record() -> RawRecord {
    RawRecord {
        receiver: [0xa1; 43],
        page: 1,
        total: 2,
        payment: Payment {
            height: 0x04030201,
            block_hash: [0xb2; 32],
            txid: [0xc3; 32],
            tx_index: 0x08070605,
            action_index: 0x0c0b0a09,
            position: 0x14131211100f0e0d,
            action_nullifier: [0xd4; 32],
            cmx: [0xe5; 32],
            ephemeral_key: [0xf6; 32],
            ciphertext_prefix: [0x87; 52],
        },
        ordinal: 0x18171615,
    }
}

#[test]
fn fixed_layout_preserves_every_field_and_byte_order() {
    let hex = concat!(
        "01a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "a1a1a1a1a1a101000000020000000101020304b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "b2b2b2b2b2b2b2b2b2b2b2b2b2c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
        "c3c3c3c3c3c3c305060708090a0b0c0d0e0f1011121314d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
        "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
        "e5e5e5e5e5e5e5e5e5e5e5f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
        "f6f6f6f6f6878787878787878787878787878787878787878787878787878787878787878787",
        "8787878787878787878787878787878787878715161718",
    );
    let expected: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(record().encode().unwrap().as_slice(), expected);
    assert_eq!(RawRecord::decode(&expected), Ok(Some(record())));
}

#[test]
fn only_a_complete_zero_slot_is_empty() {
    assert_eq!(RawRecord::decode(&[0; RECORD_BYTES]), Ok(None));
    for offset in 0..RECORD_BYTES {
        let mut bytes = [0; RECORD_BYTES];
        bytes[offset] = 1;
        assert_eq!(RawRecord::decode(&bytes), Err(Error), "offset {offset}");
    }
}

#[test]
fn truncated_and_extended_slots_are_rejected() {
    let mut bytes = record().encode().unwrap().to_vec();
    for len in 0..RECORD_BYTES {
        assert_eq!(RawRecord::decode(&bytes[..len]), Err(Error));
    }
    bytes.push(0);
    assert_eq!(RawRecord::decode(&bytes), Err(Error));
}

#[test]
fn unknown_record_and_payment_tags_are_rejected() {
    for offset in [0, 52] {
        for tag in [0, 2, 255] {
            let mut bytes = record().encode().unwrap();
            bytes[offset] = tag;
            assert_eq!(RawRecord::decode(&bytes), Err(Error));
        }
    }
}

#[test]
fn pages_must_be_inside_a_nonempty_total() {
    for (page, total) in [(0, 0), (1, 1), (2, 1), (u32::MAX, u32::MAX)] {
        let mut raw = record();
        raw.page = page;
        raw.total = total;
        assert_eq!(raw.encode(), Err(Error));
        let mut bytes = record().encode().unwrap();
        bytes[44..48].copy_from_slice(&page.to_le_bytes());
        bytes[48..52].copy_from_slice(&total.to_le_bytes());
        assert_eq!(RawRecord::decode(&bytes), Err(Error));
    }
    let mut raw = record();
    raw.page = u32::MAX - 1;
    raw.total = u32::MAX;
    assert_eq!(RawRecord::decode(&raw.encode().unwrap()), Ok(Some(raw)));
}

#[test]
fn raw_records_do_not_claim_cryptographic_validation() {
    let mut raw = record();
    raw.receiver = [255; 43];
    raw.payment.action_nullifier = [255; 32];
    raw.payment.cmx = [255; 32];
    raw.payment.ephemeral_key = [255; 32];
    assert_eq!(RawRecord::decode(&raw.encode().unwrap()), Ok(Some(raw)));
}

#[test]
fn payloads_carry_only_complete_siblings() {
    // Position 5 at tree size 7: siblings 4 (level 0) and [6, 8) (level 1, partial)
    // and [0, 4) (level 2, complete); everything above starts at or past 8.
    assert!(supplied(5, 7, 0));
    assert!(!supplied(5, 7, 1));
    assert!(supplied(5, 7, 2));
    assert!((3..16).all(|level| !supplied(5, 7, level)));
    let mut siblings = [None; 16];
    siblings[0] = Some([1; 32]);
    siblings[2] = Some([2; 32]);
    let bytes = encode_payload(&siblings, 5, 7).unwrap();
    assert_eq!(&bytes[..32], &[1; 32]);
    assert!(bytes[32..64].iter().all(|b| *b == 0));
    assert_eq!(decode_payload(&bytes, 5, 7), Ok(siblings));
    // A slot the tree size says is incomplete must be zero, and supplied ones present.
    let mut extra = bytes;
    extra[40] = 1;
    assert_eq!(decode_payload(&extra, 5, 7), Err(Error));
    let mut missing = siblings;
    missing[2] = None;
    assert_eq!(encode_payload(&missing, 5, 7), Err(Error));
    assert_eq!(decode_payload(&bytes, 7, 7), Err(Error));
    assert_eq!(decode_payload(&bytes[..511], 5, 7), Err(Error));
}

#[test]
fn a_full_shard_makes_every_lower_sibling_final() {
    let shard_end = 1 << 16;
    assert!(!is_final(5, shard_end - 1));
    assert!(is_final(5, shard_end));
    assert!((0..16).all(|level| supplied(5, shard_end, level)));
    assert!(!is_final(shard_end, shard_end + 1));
    assert!(is_final(shard_end, 2 * shard_end));
}
