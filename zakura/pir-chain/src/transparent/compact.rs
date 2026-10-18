//! Compact blocks reconstructed from raw blocks, in the fields of lightwalletd's
//! `CompactBlock` message, independently of any service's journal.
use crate::chain::{Action, Input};

use super::{FetchedBlock, Output};

/// An input's spent outpoint; the txid is in protocol byte order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactInput {
    pub prevout_txid: [u8; 32],
    pub prevout_index: u32,
}

/// A Sapling output's note commitment, ephemeral key and 52-byte compact ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactSaplingOutput {
    pub cmu: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// An Orchard or Ironwood Action's nullifier, commitment, ephemeral key and 52-byte
/// compact ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactAction {
    pub nullifier: Vec<u8>,
    pub cmx: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// One transaction's compact parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactTransaction {
    pub index: u64,
    pub txid: [u8; 32],
    /// Inputs that spend an earlier output; the coinbase input spends nothing.
    pub inputs: Vec<CompactInput>,
    pub outputs: Vec<Output>,
    pub sapling_spends: Vec<[u8; 32]>,
    pub sapling_outputs: Vec<CompactSaplingOutput>,
    pub orchard_actions: Vec<CompactAction>,
    pub ironwood_actions: Vec<CompactAction>,
}

/// A compact block, with the Sapling, Orchard and Ironwood commitment tree sizes
/// after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub time: u32,
    pub transactions: Vec<CompactTransaction>,
    pub sapling_tree_size: u32,
    pub orchard_tree_size: u32,
    pub ironwood_tree_size: u32,
}

impl FetchedBlock {
    /// This block at `height` as a compact block. `counts` holds the Sapling, Orchard
    /// and Ironwood tree sizes before it and is advanced past it only on success; an
    /// error leaves all three unchanged.
    pub fn compact(
        &self,
        height: u64,
        counts: &mut [u32; 3],
    ) -> Result<CompactBlock, Box<dyn std::error::Error + Send + Sync>> {
        let block = &self.0;
        let mut after = *counts;
        let mut transactions = Vec::new();
        for (index, tx) in block.transactions.iter().enumerate() {
            let inputs = tx
                .inputs()
                .iter()
                .filter_map(|input| match input {
                    Input::PrevOut { outpoint, .. } => Some(CompactInput {
                        prevout_txid: outpoint.hash.0,
                        prevout_index: outpoint.index,
                    }),
                    Input::Coinbase { .. } => None,
                })
                .collect();
            let outputs = tx
                .outputs()
                .iter()
                .map(|output| Output {
                    value: u64::from(output.value),
                    script: output.lock_script.as_raw_bytes().to_vec(),
                })
                .collect();
            let sapling_spends = tx
                .wallet()
                .sapling_bundle()
                .into_iter()
                .flat_map(|bundle| bundle.shielded_spends())
                .map(|spend| spend.nullifier().0)
                .collect();
            let sapling_outputs = tx
                .wallet()
                .sapling_bundle()
                .into_iter()
                .flat_map(|bundle| bundle.shielded_outputs())
                .map(|output| {
                    Ok(CompactSaplingOutput {
                        cmu: output.cmu().to_bytes().to_vec(),
                        ephemeral_key: output.ephemeral_key().0.to_vec(),
                        ciphertext: output.enc_ciphertext()[..52].to_vec(),
                    })
                })
                .collect::<Result<Vec<_>, std::io::Error>>()?;
            let orchard_actions = tx
                .orchard_actions()
                .map(action)
                .collect::<Result<Vec<_>, _>>()?;
            let ironwood_actions = tx
                .ironwood_actions()
                .map(action)
                .collect::<Result<Vec<_>, _>>()?;
            for (count, n) in after.iter_mut().zip([
                sapling_outputs.len(),
                orchard_actions.len(),
                ironwood_actions.len(),
            ]) {
                *count = count
                    .checked_add(u32::try_from(n)?)
                    .ok_or("commitment tree size overflow")?;
            }
            transactions.push(CompactTransaction {
                index: index as u64,
                txid: tx.hash().0,
                inputs,
                outputs,
                sapling_spends,
                sapling_outputs,
                orchard_actions,
                ironwood_actions,
            });
        }
        let compact = CompactBlock {
            height,
            hash: block.hash().0,
            prev_hash: block.header.previous_block_hash.0,
            time: u32::try_from(block.header.time)?,
            transactions,
            sapling_tree_size: after[0],
            orchard_tree_size: after[1],
            ironwood_tree_size: after[2],
        };
        *counts = after;
        Ok(compact)
    }
}

fn action(a: Action) -> Result<CompactAction, std::io::Error> {
    Ok(CompactAction {
        nullifier: <[u8; 32]>::from(a.nullifier).to_vec(),
        cmx: <[u8; 32]>::from(a.cm_x).to_vec(),
        ephemeral_key: a.ephemeral_key.to_vec(),
        ciphertext: a.enc_ciphertext[..52].to_vec(),
    })
}
