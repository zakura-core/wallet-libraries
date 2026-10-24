//! Fixtures shared by the receiver validation tests.
#![allow(dead_code)]
use zakura_pir_protocol::receiver::crypto::{Payment, Receiver, Record, recovery::Action};

/// A public mainnet refund Action, recoverable with the zero OVK.
pub fn action() -> Action {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/zero-ovk-action.json")).unwrap();
    fn field<const N: usize>(v: &serde_json::Value, key: &str) -> [u8; N] {
        hex::decode(v["action"][key].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    Action {
        cv: field(&v, "cv"),
        nullifier: field(&v, "nullifier"),
        cmx: field(&v, "cmx"),
        ephemeral_key: field(&v, "ephemeralKey"),
        enc_ciphertext: field(&v, "encCiphertext"),
        out_ciphertext: field(&v, "outCiphertext"),
    }
}

/// The Orchard receiver that [`action`] pays, decoded without this crate from the
/// swap's `refundTo` address; see `fixtures/zero-ovk-action-oracle/README.md`. The
/// fixture's `receiver` field holds the same bytes.
pub const RECEIVER_HEX: &str =
    "42cd776949bba6f2164b347ebdbf9c225028ed0f5b6eaa3a402f3322c6aadfbde6288d167dbcaed0fdf01e";

/// The receiver that [`action`] pays, from [`RECEIVER_HEX`].
pub fn receiver() -> Receiver {
    Receiver::from_bytes(hex::decode(RECEIVER_HEX).unwrap().try_into().unwrap()).unwrap()
}

/// Page `page` of `total` payments to [`receiver`].
pub fn record(page: u32, total: u32) -> Record {
    Record {
        receiver: receiver(),
        page,
        total,
        payment: Payment {
            height: 101,
            block_hash: [3; 32],
            txid: [page as u8; 32],
            tx_index: page + 1,
            action_index: 0,
            position: 200 + u64::from(page),
            action_nullifier: [5; 32],
            cmx: [6; 32],
            ephemeral_key: [7; 32],
            ciphertext_prefix: [8; 52],
        },
        ordinal: 3 + page,
    }
}
