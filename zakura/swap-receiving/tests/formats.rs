use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zakura_swap_receiving::{
    MemoError, Purpose, RefundMemo, derive_full_viewing_key, has_same_spending_authority,
};
use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

#[test]
fn derived_keys_separate_purposes_and_preserve_only_authority() {
    let account = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap());
    let foreign = FullViewingKey::from(&SpendingKey::from_bytes([1; 32]).unwrap());
    let mut receivers = vec![account.address_at(0u32, Scope::External)];
    for index in [0, 1, u64::MAX] {
        for purpose in [Purpose::Refund, Purpose::Receive] {
            let key = derive_full_viewing_key(&account, purpose, index).unwrap();
            assert!(has_same_spending_authority(&account, &key));
            assert!(!has_same_spending_authority(&foreign, &key));
            assert_eq!(
                key.to_bytes(),
                derive_full_viewing_key(&account, purpose, index)
                    .unwrap()
                    .to_bytes()
            );
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

fn deposit(network: NetworkType) -> String {
    ZcashAddress::from_transparent_p2pkh(network, [7; 20]).to_string()
}

#[test]
fn memo_has_exact_wire_layout_and_network_validation() {
    let address = deposit(NetworkType::Main);
    let record = RefundMemo::new(NetworkType::Main, 0x0807060504030201, &address).unwrap();
    let bytes = record.encode();
    assert_eq!(&bytes[..7], b"\xffZSWP\x01\x00");
    assert_eq!(&bytes[7..15], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&bytes[15..17], &(address.len() as u16).to_le_bytes());
    assert_eq!(&bytes[17..17 + address.len()], address.as_bytes());
    assert!(bytes[17 + address.len()..].iter().all(|b| *b == 0));
    assert_eq!(
        RefundMemo::decode(NetworkType::Main, &bytes),
        Ok(Some(record))
    );
    assert_eq!(
        RefundMemo::decode(NetworkType::Test, &bytes),
        Err(MemoError::InvalidAddress)
    );

    let test = RefundMemo::new(NetworkType::Test, u64::MAX, &deposit(NetworkType::Test)).unwrap();
    // Transparent testnet and regtest addresses intentionally share an encoding.
    assert_eq!(
        RefundMemo::decode(NetworkType::Regtest, &test.encode()),
        Ok(Some(test))
    );
}

#[test]
fn malformed_and_future_memos_cannot_look_like_completed_recovery() {
    let valid = RefundMemo::new(NetworkType::Main, 0, &deposit(NetworkType::Main))
        .unwrap()
        .encode();
    assert_eq!(RefundMemo::decode(NetworkType::Main, &[0; 512]), Ok(None));
    for (offset, value, expected) in [
        (5, 2, MemoError::UnsupportedVersion(2)),
        (6, 1, MemoError::InvalidPurpose(1)),
        (16, 2, MemoError::InvalidLength),
        (17, 0xff, MemoError::InvalidAddress),
        (511, 1, MemoError::NonzeroPadding),
    ] {
        let mut bytes = valid;
        bytes[offset] = value;
        assert_eq!(RefundMemo::decode(NetworkType::Main, &bytes), Err(expected));
    }
    let mut empty = valid;
    empty[15..17].fill(0);
    assert_eq!(
        RefundMemo::decode(NetworkType::Main, &empty),
        Err(MemoError::InvalidLength)
    );
    for address in [String::new(), "t".repeat(496)] {
        assert_eq!(
            RefundMemo::new(NetworkType::Main, 0, &address),
            Err(MemoError::InvalidLength)
        );
    }
    for address in ["é", "not an address"] {
        assert_eq!(
            RefundMemo::new(NetworkType::Main, 0, address),
            Err(MemoError::InvalidAddress)
        );
    }
    assert_eq!(
        RefundMemo::new(
            NetworkType::Main,
            0,
            &format!(" {} ", deposit(NetworkType::Main))
        ),
        Err(MemoError::InvalidAddress)
    );
}
