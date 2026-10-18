use super::{Hash, Height, Input, OutPoint, Output, Script, Utxo};
use std::{
    collections::HashMap,
    io::{self, Read},
};
use zcash_primitives::transaction::Transaction as WalletTransaction;
use zcash_protocol::{
    consensus::BranchId,
    value::{ZatBalance, Zatoshis},
};
use zcash_script::{opcode::Evaluable as _, script::Evaluable};

/// Only the action fields ingestion consumes, in their canonical byte encodings.
pub(crate) struct Action {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub cm_x: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}
#[derive(Debug)]
pub(crate) struct Transaction {
    inner: WalletTransaction,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}
impl Transaction {
    pub(crate) fn zcash_deserialize(reader: impl Read) -> io::Result<Self> {
        // Legacy transaction IDs hash the serialized bytes, independently of the
        // branch passed here. V5/V6 read their branch ID from the transaction.
        // We do not use this value to make signatures or validate consensus.
        let inner = WalletTransaction::read(reader.take(super::MAX_BLOCK_BYTES), BranchId::Sprout)?;
        if matches!(inner.version(), zcash_primitives::transaction::TxVersion::Sprout(version) if version > 2)
        {
            return Err(io::Error::other("unsupported legacy transaction version"));
        }
        if u32::from(inner.expiry_height()) > i32::MAX as u32 {
            return Err(io::Error::other("expiry height out of range"));
        }
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        if let Some(bundle) = inner.transparent_bundle() {
            for input in &bundle.vin {
                let prevout = input.prevout();
                if prevout.hash() == &[0; 32] && prevout != &transparent::bundle::OutPoint::NULL {
                    return Err(io::Error::other("invalid null input index"));
                }
                inputs.push(if prevout == &transparent::bundle::OutPoint::NULL {
                    Input::Coinbase {
                        height: Some(
                            coinbase_height(&input.script_sig().0.to_bytes()).ok_or_else(|| {
                                io::Error::other("invalid coinbase height or script length")
                            })?,
                        ),
                    }
                } else {
                    Input::PrevOut {
                        outpoint: OutPoint {
                            hash: Hash(*prevout.hash()),
                            index: prevout.n(),
                        },
                    }
                });
            }
            outputs.extend(bundle.vout.iter().map(|output| Output {
                value: output.value(),
                lock_script: Script::new(&output.script_pubkey().0.to_bytes()),
            }));
        }
        Ok(Self {
            inner,
            inputs,
            outputs,
        })
    }
    pub(crate) fn hash(&self) -> Hash {
        Hash(*self.inner.txid().as_ref())
    }
    pub(crate) fn inputs(&self) -> &[Input] {
        &self.inputs
    }
    pub(crate) fn outputs(&self) -> &[Output] {
        &self.outputs
    }
    pub(crate) fn is_coinbase(&self) -> bool {
        self.inputs
            .iter()
            .any(|i| matches!(i, Input::Coinbase { .. }))
    }
    pub(crate) fn has_transparent_inputs(&self) -> bool {
        !self.inputs.is_empty()
    }
    pub(crate) fn has_transparent_outputs(&self) -> bool {
        !self.outputs.is_empty()
    }
    pub(crate) fn has_shielded_data(&self) -> bool {
        self.inner.sprout_bundle().is_some()
            || self.inner.sapling_bundle().is_some()
            || self.inner.orchard_bundle().is_some()
            || self.inner.ironwood_bundle().is_some()
    }
    pub(crate) fn expiry_height(&self) -> Option<Height> {
        Some(Height(self.inner.expiry_height().into()))
    }
    pub(crate) fn ironwood_actions(&self) -> impl Iterator<Item = Action> + '_ {
        self.inner
            .ironwood_bundle()
            .into_iter()
            .flat_map(|b| b.actions().iter())
            .map(action)
    }
    pub(crate) fn orchard_actions(&self) -> impl Iterator<Item = Action> + '_ {
        self.inner
            .orchard_bundle()
            .into_iter()
            .flat_map(|b| b.actions().iter())
            .map(action)
    }
    pub(crate) fn wallet(&self) -> &WalletTransaction {
        &self.inner
    }
    pub(crate) fn fee(&self, utxos: &HashMap<OutPoint, Utxo>) -> Result<u64, String> {
        let inputs = self
            .inputs
            .iter()
            .filter_map(Input::outpoint)
            .map(|o| {
                utxos
                    .get(&o)
                    .map(|u| u.output.value)
                    .ok_or_else(|| format!("missing spent output {}:{}", o.hash, o.index))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let input_value = inputs
            .into_iter()
            .sum::<Option<Zatoshis>>()
            .ok_or("transparent input value out of range")?;
        let output_value = self
            .outputs
            .iter()
            .map(|o| o.value)
            .sum::<Option<Zatoshis>>()
            .ok_or("transparent output value out of range")?;
        let transparent = (ZatBalance::from(input_value) - output_value)
            .ok_or("transparent balance out of range")?;
        let sprout = self
            .inner
            .sprout_bundle()
            .map(|b| b.value_balance())
            .unwrap_or(Some(ZatBalance::zero()))
            .ok_or("Sprout balance out of range")?;
        let sapling = self
            .inner
            .sapling_bundle()
            .map(|b| *b.value_balance())
            .unwrap_or(ZatBalance::zero());
        let orchard = self
            .inner
            .orchard_bundle()
            .map(|b| *b.value_balance())
            .unwrap_or(ZatBalance::zero());
        let ironwood = self
            .inner
            .ironwood_bundle()
            .map(|b| *b.value_balance())
            .unwrap_or(ZatBalance::zero());
        let balance = [transparent, sprout, sapling, orchard, ironwood]
            .into_iter()
            .sum::<Option<ZatBalance>>()
            .ok_or("transaction balance out of range")?;
        u64::try_from(balance).map_err(|e| e.to_string())
    }
}
fn action(
    a: &orchard::Action<
        orchard::primitives::redpallas::Signature<orchard::primitives::redpallas::SpendAuth>,
    >,
) -> Action {
    let note = a.encrypted_note();
    Action {
        cv: a.cv_net().to_bytes(),
        nullifier: a.nullifier().to_bytes(),
        cm_x: a.cmx().to_bytes(),
        ephemeral_key: note.epk_bytes,
        enc_ciphertext: note.enc_ciphertext,
        out_ciphertext: note.out_ciphertext,
    }
}

/// BIP34 script numbers, including the small integer opcodes used at early heights.
fn coinbase_height(script: &[u8]) -> Option<Height> {
    if !(2..=100).contains(&script.len()) {
        return None;
    }
    // The shared mainnet, testnet and regtest genesis script has no BIP34 height.
    const GENESIS_SCRIPT: &[u8] = b"\x04\xff\xff\x07\x1f\x01\x04\x45Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34";
    if script == GENESIS_SCRIPT {
        return Some(Height(0));
    }
    let (height, size) = match *script.first()? {
        opcode @ 0x51..=0x60 => (u32::from(opcode - 0x50), 1),
        size @ 1..=5 => {
            let bytes = script.get(1..=usize::from(size))?;
            let mut value = 0u64;
            for (i, byte) in bytes.iter().enumerate() {
                value |= u64::from(*byte) << (8 * i);
            }
            (u32::try_from(value).ok()?, 1 + bytes.len())
        }
        _ => return None,
    };
    if height > i32::MAX as u32
        || script[..size] != zcash_script::pattern::push_num(i64::from(height)).to_bytes()
    {
        return None;
    }
    Some(Height(height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_heights_require_canonical_positive_script_numbers() {
        for (script, height) in [
            (&[0x51, 0][..], 1),
            (&[0x60, 0][..], 16),
            (&[1, 17][..], 17),
            (&[2, 0x80, 0][..], 128),
        ] {
            assert_eq!(coinbase_height(script).map(|h| h.0), Some(height));
        }
        for script in [
            &[][..],
            &[0, 0],
            &[1, 1],
            &[2, 17, 0],
            &[1, 0x80],
            &[2, 0x80],
            &[5, 0, 0, 0, 0x80, 0],
        ] {
            assert!(
                coinbase_height(script).is_none(),
                "accepted invalid height {script:?}"
            );
        }
        assert!(coinbase_height(&[0x51; 101]).is_none());
    }
}
