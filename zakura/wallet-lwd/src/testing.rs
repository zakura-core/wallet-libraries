//! Turning the wallet's own block types back into wire messages.
//!
//! This exists for one purpose: the differential test needs to hand *identical
//! bytes* to this wallet and to the forked one, and the only way to generate
//! blocks containing notes a test key actually owns is to build them
//! synthetically. The builder in `zakura_wallet_scan::testing` produces domain
//! types, so they have to be encoded before the fork can parse them.
//!
//! This is deliberately not the inverse of the parsing path — it is not used in
//! production, and nothing depends on it round-tripping. It exists so that two
//! implementations can be compared on the same input.

use zakura_wallet_core::CompactBlock;
use zcash_note_encryption::{COMPACT_NOTE_SIZE, ShieldedOutput};

use crate::proto;

/// Encodes a block as the wire message a light server would have sent.
pub fn to_wire(block: &CompactBlock) -> proto::CompactBlock {
    proto::CompactBlock {
        height: u64::from(u32::from(block.height)),
        hash: block.hash.0.to_vec(),
        prev_hash: block.prev_hash.0.to_vec(),
        time: block.time,
        header: Vec::new(),
        vtx: block.txs.iter().map(tx_to_wire).collect(),
        chain_metadata: Some(proto::ChainMetadata {
            // This wallet does not track Sapling, and a synthetic chain has
            // none; the field exists because the fork still reads it.
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: block.tree_sizes.orchard,
            ironwood_commitment_tree_size: block.tree_sizes.ironwood,
        }),
    }
}

fn tx_to_wire(tx: &zakura_wallet_core::CompactTx) -> proto::CompactTx {
    proto::CompactTx {
        index: tx.index,
        txid: tx.txid.as_ref().to_vec(),
        fee: 0,
        spends: Vec::new(),
        outputs: Vec::new(),
        actions: tx.orchard_actions.iter().map(action_to_wire).collect(),
        ironwood_actions: tx.ironwood_actions.iter().map(action_to_wire).collect(),
        vin: tx
            .vin
            .iter()
            .map(|o| proto::CompactTxIn {
                prevout_txid: o.hash().to_vec(),
                prevout_index: o.n(),
            })
            .collect(),
        vout: tx
            .vout
            .iter()
            .map(|o| proto::TxOut {
                value: o.value().into_u64(),
                script_pub_key: o.script_pubkey().0.0.clone(),
            })
            .collect(),
    }
}

fn action_to_wire(action: &orchard::note_encryption::CompactAction) -> proto::CompactOrchardAction {
    // Which domain is named here does not matter: `ephemeral_key` and
    // `enc_ciphertext` read the same bytes whichever version's domain asks for
    // them, and this is a serialisation, not a decryption.
    type Domain = orchard::note_encryption::OrchardDomain;

    proto::CompactOrchardAction {
        nullifier: action.nullifier().to_bytes().to_vec(),
        cmx: action.cmx().to_bytes().to_vec(),
        ephemeral_key: ShieldedOutput::<Domain, COMPACT_NOTE_SIZE>::ephemeral_key(action)
            .0
            .to_vec(),
        ciphertext: ShieldedOutput::<Domain, COMPACT_NOTE_SIZE>::enc_ciphertext(action).to_vec(),
    }
}
