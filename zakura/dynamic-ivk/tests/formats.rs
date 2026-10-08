use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zakura_dynamic_ivk::{KeyId, Purpose, RefundMemo, has_same_spending_authority};

#[test]
fn derived_keys_separate_purposes_and_preserve_only_authority() {
    let account = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
    let foreign = FullViewingKey::from(&SpendingKey::from_bytes([1; 32]).unwrap());
    let mut receivers = vec![account.address_at(0u32, Scope::External)];
    for index in [0, 1, u64::MAX] {
        for purpose in [Purpose::Refund, Purpose::Receive] {
            let id = KeyId::new(purpose, index);
            let key = id.derive(&account).unwrap();
            assert!(has_same_spending_authority(&account, &key));
            assert!(!has_same_spending_authority(&foreign, &key));
            assert_eq!(key.to_bytes(), id.derive(&account).unwrap().to_bytes());
            let address = key.address_at(0u32, Scope::External);
            assert!(!receivers.contains(&address));
            receivers.push(address);
        }
    }

    // Comparing only ak would let a substituted nullifier authority through.
    let mut substituted = account.to_bytes();
    substituted[32..64].copy_from_slice(&foreign.to_bytes()[32..64]);
    let substituted = FullViewingKey::from_bytes(&substituted).unwrap();
    assert!(!has_same_spending_authority(&account, &substituted));
    let mut substituted = account.to_bytes();
    substituted[..32].copy_from_slice(&foreign.to_bytes()[..32]);
    let substituted = FullViewingKey::from_bytes(&substituted).unwrap();
    assert!(!has_same_spending_authority(&account, &substituted));
}

#[test]
fn memo_has_exact_wire_layout() {
    let record = RefundMemo::new(0x0807060504030201);
    let bytes = record.encode();
    assert_eq!(&bytes[..7], b"\xffZSWP\x01\x00");
    assert_eq!(&bytes[7..15], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(bytes[15..].iter().all(|b| *b == 0));
    assert_eq!(RefundMemo::decode(&bytes), Some(record));
    for index in [0, u64::MAX] {
        let record = RefundMemo::new(index);
        assert_eq!(RefundMemo::decode(&record.encode()), Some(record));
    }
}

#[test]
fn reserved_bytes_are_ignored() {
    let mut arbitrary = RefundMemo::new(u64::MAX).encode();
    arbitrary[15..].fill(0xff);
    assert_eq!(
        RefundMemo::decode(&arbitrary),
        Some(RefundMemo::new(u64::MAX))
    );
}

#[test]
fn malformed_and_future_memos_cannot_look_like_completed_recovery() {
    let valid = RefundMemo::new(0).encode();
    assert_eq!(RefundMemo::decode(&[0; 512]), None);
    let mut unrelated = valid;
    unrelated[0] = b'Z';
    assert_eq!(RefundMemo::decode(&unrelated), None);
    // Callers keep a marked record they cannot decode pending.
    for (offset, value) in [(5, 0), (5, 2), (6, 1)] {
        let mut bytes = valid;
        bytes[offset] = value;
        assert_eq!(RefundMemo::decode(&bytes), None);
    }
}
