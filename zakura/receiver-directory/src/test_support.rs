//! Fixtures shared by the receiver crates' integration tests, included with `#[path]`.
#![allow(dead_code)]
use receiver_directory::{
    Payment, Receiver, Record,
    extract::Action,
    snapshot::{Manifest, PROFILE},
};

/// A public mainnet refund Action, recoverable with the zero OVK.
pub fn action() -> Action {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("test-fixtures/zero-ovk-action.json")).unwrap();
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

/// A publication with `rows` rows covering heights 100 to 101 and positions 200 to 300.
pub fn manifest(rows: u32) -> Manifest {
    Manifest {
        profile: PROFILE.into(),
        genesis: [1; 32],
        start_height: 100,
        start_parent: [2; 32],
        start_position: 200,
        end_height: 101,
        end_hash: [3; 32],
        end_position: 300,
        rows,
        salt: [4; 32],
        records: 0,
        data_sha256: [0; 32],
        filters: vec![receiver_directory::snapshot::FilterSet {
            label: receiver_directory::filter::PAID.into(),
            count: 0,
            window_secs: None,
            since_unix: None,
            until_unix: None,
        }],
        filters_sha256: [0; 32],
    }
}

/// Page `page` of `total` payments to [`receiver`], in the last block of [`manifest`].
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
    }
}
