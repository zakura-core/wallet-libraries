//! Fixtures for the receiver client tests.
#![allow(dead_code)]
use zakura_pir_client::receiver::{
    ChoiceRef, Companion, Coverage, Directory, Publication, ReceiverBytes, SCHEMA, Session, Table,
    Tree, choice_bytes, query_rows,
};

/// The Orchard receiver that the Action in `zakura-pir-protocol`'s
/// `tests/receiver/fixtures/zero-ovk-action.json` pays, decoded independently from the
/// swap's `refundTo` address; see that fixture's `zero-ovk-action-oracle/README.md`.
pub const RECEIVER_HEX: &str =
    "42cd776949bba6f2164b347ebdbf9c225028ed0f5b6eaa3a402f3322c6aadfbde6288d167dbcaed0fdf01e";

/// The receiver from [`RECEIVER_HEX`], a valid Ironwood address.
pub fn receiver() -> ReceiverBytes {
    hex::decode(RECEIVER_HEX).unwrap().try_into().unwrap()
}

/// The sessions of an empty segment over `coverage`, its companion built at `tree`. Public
/// setup digests are placeholders: an inventory binds session IDs, not evaluation.
pub fn empty_segment(coverage: Coverage, tree: Tree) -> Publication {
    let directory = Directory {
        schema: SCHEMA.into(),
        coverage: coverage.clone(),
        salt: [4; 32],
        entries: 0,
        payments: 0,
        choice: ChoiceRef {
            digest: [5; 32],
            bytes: choice_bytes(0) as u32,
            keys: 0,
        },
        data_sha256: [0; 32],
    };
    let companion = Companion {
        schema: SCHEMA.into(),
        coverage,
        directory: directory.revision().unwrap(),
        rows: query_rows(0),
        query_rows: query_rows(0),
        payments: 0,
        tree,
        data_sha256: [0; 32],
    };
    Publication {
        directory: Session {
            manifest: directory,
            public_digest: [7; 32],
        },
        companion: Session {
            manifest: companion,
            public_digest: [8; 32],
        },
    }
}
