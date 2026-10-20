#![cfg(feature = "crypto")]
//! Receivers, records and zero-OVK recovery.
mod common;
use common::{RECEIVER_HEX, action, receiver, record};
use zakura_receiver_crypto::{Error, RECORD_BYTES, Receiver, Record};

#[test]
fn public_refund_requires_authenticated_recovery() {
    // Recovery must yield exactly the independently decoded receiver, which the
    // fixture also carries for the probe.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/zero-ovk-action.json")).unwrap();
    assert_eq!(fixture["receiver"], RECEIVER_HEX);
    let recovered = action().recover_receiver().unwrap().unwrap();
    assert_eq!(
        recovered.as_bytes().as_slice(),
        hex::decode(RECEIVER_HEX).unwrap()
    );
    let mut a = action();
    a.out_ciphertext[0] ^= 1;
    assert!(a.recover_receiver().unwrap().is_none());
    let mut a = action();
    a.enc_ciphertext[579] ^= 1;
    assert!(a.recover_receiver().unwrap().is_none());
    for field in 0..3 {
        let mut a = action();
        *[&mut a.cmx, &mut a.nullifier, &mut a.cv][field] = [255; 32];
        assert_eq!(
            a.recover_receiver().err(),
            Some(Error::Malformed),
            "{field}"
        );
    }
}

#[test]
fn receivers_must_be_ironwood_addresses() {
    assert_eq!(
        receiver().as_bytes().as_slice(),
        hex::decode(RECEIVER_HEX).unwrap()
    );
    // A diversifier whose hash is not a valid base point, and a transmission key
    // that is not a point.
    let mut bad = *receiver().as_bytes();
    bad[11..].fill(255);
    assert_eq!(Receiver::from_bytes(bad), Err(Error::Malformed));
    assert_eq!(Receiver::from_bytes([0; 43]), Err(Error::Malformed));
}

/// The layout is the canonical codec's, byte for byte.
#[test]
fn wire_layout_and_strict_empty_slots() {
    let r = record(0, 1);
    let b = r.encode().unwrap();
    assert_eq!(b.len(), RECORD_BYTES);
    assert_eq!(b[0], 1);
    assert_eq!(&b[1..44], receiver().as_bytes());
    assert_eq!(&b[44..52], &[0, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(b[52], 1);
    assert_eq!(&b[53..57], &101u32.to_le_bytes());
    assert_eq!(&b[129..137], &200u64.to_le_bytes());
    assert_eq!(&b[233..285], &[8; 52]);
    assert_eq!(&b[285..289], &3u32.to_le_bytes());
    let raw = zakura_receiver_crypto::wire::RawRecord::decode(&b)
        .unwrap()
        .unwrap();
    assert_eq!(raw.encode().unwrap(), b);
    assert_eq!(Record::decode(&b).unwrap(), Some(r));
    assert!(Record::decode(&[0; RECORD_BYTES]).unwrap().is_none());
    let mut corrupt = [0; RECORD_BYTES];
    corrupt[288] = 1;
    assert_eq!(Record::decode(&corrupt), Err(Error::Malformed));
    assert_eq!(Record::decode(&b[..288]), Err(Error::Malformed));
    let mut trailing = b.to_vec();
    trailing.push(0);
    assert_eq!(Record::decode(&trailing), Err(Error::Malformed));
    for (page, total) in [(1, 1), (0, 0)] {
        assert_eq!(record(page, total).encode(), Err(Error::Malformed));
    }
}

/// Structural decoding never makes invalid cryptographic fields acceptable, including
/// when bytes came from the raw encoder.
#[test]
fn structurally_valid_records_still_require_cryptographic_checks() {
    let valid = record(0, 1).encode().unwrap();
    for field in [1..44, 137..169, 169..201, 201..233] {
        let mut bytes = valid;
        bytes[field.clone()].fill(255);
        let raw = zakura_receiver_crypto::wire::RawRecord::decode(&bytes)
            .unwrap()
            .unwrap();
        assert_eq!(raw.encode().unwrap(), bytes);
        assert_eq!(Record::decode(&bytes), Err(Error::Malformed), "{field:?}");
    }
}

#[test]
fn records_refuse_noncanonical_fields() {
    let a = action();
    let mut real = record(0, 1);
    (
        real.payment.action_nullifier,
        real.payment.cmx,
        real.payment.ephemeral_key,
    ) = (a.nullifier, a.cmx, a.ephemeral_key);
    assert_eq!(Record::decode(&real.encode().unwrap()).unwrap(), Some(real));
    for field in 0..3 {
        let mut r = record(0, 1);
        let p = &mut r.payment;
        *[&mut p.action_nullifier, &mut p.cmx, &mut p.ephemeral_key][field] = [255; 32];
        assert_eq!(r.encode(), Err(Error::Malformed));
        assert_eq!(r.payment.check(), Err(Error::Malformed));
    }
}

#[test]
fn only_unified_ironwood_receivers_for_the_network_count() {
    use zakura_receiver_crypto::Network;
    // A Vizor swap address from 2026-10-07.
    let swap = "u14nnj43rj7dpf7qh6gu24fuyu8vld9fgatxd32xre27yqgu6p0yq0sf0t3uxnwts4968hf7d8nvyh4wfzqtmcdt6xzk7el6pn0ufx6pdg";
    let parsed = Receiver::from_unified_address(swap, Network::Main).unwrap();
    assert_eq!(&parsed.as_bytes()[..4], &[0x15, 0x5f, 0x51, 0xfe]);
    assert_eq!(
        Receiver::from_unified_address(&parsed.to_unified_address(Network::Main), Network::Main),
        Ok(parsed)
    );
    let test = receiver().to_unified_address(Network::Test);
    assert_eq!(
        Receiver::from_unified_address(&test, Network::Test),
        Ok(receiver())
    );
    for (address, network) in [
        (swap, Network::Test),
        (test.as_str(), Network::Main),
        ("t1KfwsnwJeNRVjQGBDZhwKskpQbih2qx5Ua", Network::Main),
        ("check-alice.near", Network::Main),
    ] {
        assert_eq!(
            Receiver::from_unified_address(address, network),
            Err(Error::Malformed),
            "{address}"
        );
    }
}
