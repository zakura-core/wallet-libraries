//! Turning wire messages into the wallet's own types.
//!
//! This is where a malformed or hostile response is rejected, and it is the
//! only place in the wallet that has to. Everything above receives types whose
//! invariants already hold: a nullifier that is a field element, a commitment
//! that is canonical, a ciphertext prefix that is exactly 52 bytes. The scanner
//! never has to ask whether its input decodes, because by then it has.

use orchard::{
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::CompactAction,
};
use transparent::{
    address::Script,
    bundle::{OutPoint, TxOut},
};
use zakura_wallet_core::enhanced::TransactionStatus;
use zakura_wallet_core::{
    BlockHash, CompactBlock, CompactTx,
    pool::TreeSizes,
};
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_protocol::{TxId, consensus::BlockHeight, value::Zatoshis};

use crate::{proto, source::LwdError};

/// The number of ciphertext bytes a compact action carries.
const COMPACT_CIPHERTEXT: usize = 52;

/// Converts a wire block, rejecting anything malformed.
pub(crate) fn block(block: proto::CompactBlock) -> Result<CompactBlock, LwdError> {
    let height = u32::try_from(block.height)
        .map_err(|_| LwdError::Malformed("a block height exceeded u32".into()))?;

    // The chain metadata is what the scanner checks its derived tree sizes
    // against. Without it there is nothing to check against, and a source that
    // omits an action would go unnoticed — so its absence is an error, not a
    // default of zero.
    let metadata = block.chain_metadata.ok_or_else(|| {
        LwdError::Malformed(format!("block {height} carried no chain metadata"))
    })?;

    Ok(CompactBlock {
        height: BlockHeight::from_u32(height),
        hash: hash(&block.hash, height, "hash")?,
        prev_hash: hash(&block.prev_hash, height, "prevHash")?,
        time: block.time,
        tree_sizes: TreeSizes {
            orchard: metadata.orchard_commitment_tree_size,
            ironwood: metadata.ironwood_commitment_tree_size,
        },
        txs: block
            .vtx
            .into_iter()
            .map(|tx| transaction(tx, height))
            .collect::<Result<_, _>>()?,
    })
}

fn transaction(tx: proto::CompactTx, height: u32) -> Result<CompactTx, LwdError> {
    let txid = TxId::from_bytes(<[u8; 32]>::try_from(&tx.txid[..]).map_err(|_| {
        LwdError::Malformed(format!("block {height} carried a txid of the wrong length"))
    })?);

    Ok(CompactTx {
        index: tx.index,
        txid,
        orchard_actions: tx
            .actions
            .into_iter()
            .map(|a| action(a, &txid))
            .collect::<Result<_, _>>()?,
        ironwood_actions: tx
            .ironwood_actions
            .into_iter()
            .map(|a| action(a, &txid))
            .collect::<Result<_, _>>()?,
        vin: tx
            .vin
            .into_iter()
            .map(|i| {
                let prevout = <[u8; 32]>::try_from(&i.prevout_txid[..]).map_err(|_| {
                    LwdError::Malformed(format!("{txid} spent an outpoint with a malformed txid"))
                })?;
                Ok(OutPoint::new(prevout, i.prevout_index))
            })
            .collect::<Result<_, _>>()?,
        vout: tx
            .vout
            .into_iter()
            .map(|o| {
                let value = Zatoshis::from_u64(o.value).map_err(|_| {
                    LwdError::Malformed(format!("{txid} carried an out-of-range output value"))
                })?;
                Ok(TxOut::new(
                    value,
                    Script(zcash_script::script::Code(o.script_pub_key)),
                ))
            })
            .collect::<Result<_, _>>()?,
    })
}

fn action(a: proto::CompactOrchardAction, txid: &TxId) -> Result<CompactAction, LwdError> {
    let nullifier = <[u8; 32]>::try_from(&a.nullifier[..])
        .ok()
        .and_then(|b| Option::from(Nullifier::from_bytes(&b)))
        .ok_or_else(|| {
            LwdError::Malformed(format!("{txid} carried an action with an invalid nullifier"))
        })?;

    let cmx = <[u8; 32]>::try_from(&a.cmx[..])
        .ok()
        .and_then(|b| Option::from(ExtractedNoteCommitment::from_bytes(&b)))
        .ok_or_else(|| {
            LwdError::Malformed(format!("{txid} carried an action with an invalid commitment"))
        })?;

    let ephemeral_key = <[u8; 32]>::try_from(&a.ephemeral_key[..]).map_err(|_| {
        LwdError::Malformed(format!(
            "{txid} carried an action with a malformed ephemeral key"
        ))
    })?;

    let ciphertext = <[u8; COMPACT_CIPHERTEXT]>::try_from(&a.ciphertext[..]).map_err(|_| {
        LwdError::Malformed(format!(
            "{txid} carried an action whose ciphertext was {} bytes, not {COMPACT_CIPHERTEXT}",
            a.ciphertext.len()
        ))
    })?;

    Ok(CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(ephemeral_key),
        ciphertext,
    ))
}

fn hash(bytes: &[u8], height: u32, field: &str) -> Result<BlockHash, LwdError> {
    BlockHash::from_slice(bytes).ok_or_else(|| {
        LwdError::Malformed(format!(
            "block {height} carried a {field} of {} bytes, not 32",
            bytes.len()
        ))
    })
}

/// Reads the commitment tree sizes out of a `TreeState` response.
///
/// The tree state carries each pool's commitment tree as hex; the wallet needs
/// only the sizes.
pub(crate) fn tree_sizes(state: &proto::TreeState) -> Result<TreeSizes, LwdError> {
    Ok(TreeSizes {
        orchard: commitment_tree_size(&state.orchard_tree, "orchard")?,
        ironwood: commitment_tree_size(&state.ironwood_tree, "ironwood")?,
    })
}

/// Returns the number of leaves in a hex-encoded commitment tree.
///
/// The tree state a light server serves is the *legacy* `CommitmentTree`
/// encoding, not a frontier: an optional left node, an optional right node,
/// then a vector of optional parents, innermost first. Its leaf count is
///
/// ```text
/// left.is_some() + right.is_some() + sum over i of (parents[i].is_some() ? 2^(i+1) : 0)
/// ```
///
/// because a present parent at level `i` stands for a full subtree of `2^(i+1)`
/// leaves.
///
/// Only the count is decoded. The nodes themselves would require a hash type
/// and a tree implementation in the transport layer, and the scanner needs
/// nothing but the size in order to derive note positions.
fn commitment_tree_size(hex_tree: &str, pool: &str) -> Result<u32, LwdError> {
    if hex_tree.is_empty() {
        return Ok(0);
    }

    let bytes = hex::decode(hex_tree)
        .map_err(|_| LwdError::Malformed(format!("the {pool} tree state was not valid hex")))?;
    let malformed = |what: &str| LwdError::Malformed(format!("the {pool} tree state {what}"));

    let mut cursor = 0usize;
    let optional_node = |cursor: &mut usize| -> Result<bool, LwdError> {
        let present = match bytes.get(*cursor) {
            Some(0) => false,
            Some(1) => true,
            Some(_) => return Err(malformed("held a value that was not an optional node")),
            None => return Err(malformed("ended before a node it promised")),
        };
        *cursor += 1;
        if present {
            *cursor = cursor
                .checked_add(32)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| malformed("ended part way through a node"))?;
        }
        Ok(present)
    };

    let left = optional_node(&mut cursor)?;
    let right = optional_node(&mut cursor)?;
    let parents = compact_size(&bytes, &mut cursor)
        .ok_or_else(|| malformed("held no parent count"))?;

    let mut size = u64::from(left) + u64::from(right);
    for level in 0..parents {
        if optional_node(&mut cursor)? {
            let level = u32::try_from(level)
                .map_err(|_| malformed("described a tree deeper than any that can exist"))?;
            size += 1u64 << (level + 1);
        }
    }

    // Every byte must be accounted for. A trailing remainder means the encoding
    // is not what this decoder thinks it is, and a size derived from a
    // misparsed tree would put every note at the wrong position.
    if cursor != bytes.len() {
        return Err(malformed("had bytes left over after decoding"));
    }

    u32::try_from(size).map_err(|_| malformed("described more leaves than a u32 can hold"))
}

/// Reads a Bitcoin-style `CompactSize` length prefix.
fn compact_size(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let first = *bytes.get(*cursor)?;
    *cursor += 1;
    let width = match first {
        ..=252 => return Some(u64::from(first)),
        253 => 2,
        254 => 4,
        _ => 8,
    };
    let end = cursor.checked_add(width)?;
    let slice = bytes.get(*cursor..end)?;
    *cursor = end;
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(slice);
    Some(u64::from_le_bytes(buf))
}

/// Interprets a `RawTransaction`'s height field.
///
/// The field is a `uint64` that carries three different meanings, because the
/// original protobuf definition could not represent the `-1` that `zcashd`
/// returns for a transaction mined on a fork. Getting this mapping wrong is not
/// a cosmetic bug: `NotInMainChain` is positive proof a transaction is not
/// mined, which is what eventually expires it and releases the notes it spends.
/// Reading a mined height as a sentinel would release live funds; reading a
/// sentinel as a height would record a transaction as mined at block zero.
pub(crate) fn transaction_status(height: u64) -> TransactionStatus {
    match height {
        // Absent from the message, which protobuf renders as zero: the
        // transaction is in the mempool. Known to the server, not mined.
        0 => TransactionStatus::NotInMainChain,
        // The remapped `-1`: mined, but on a chain that lost.
        u64::MAX => TransactionStatus::NotInMainChain,
        h => match u32::try_from(h) {
            Ok(h) => TransactionStatus::Mined(BlockHeight::from_u32(h)),
            // A height above `u32::MAX` that is not the sentinel is a server
            // talking about a chain this wallet does not understand. Treating
            // it as unmined would be a guess; it is not representable.
            Err(_) => TransactionStatus::NotInMainChain,
        },
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn the_three_sentinels_are_distinguished() {
        assert_eq!(transaction_status(0), TransactionStatus::NotInMainChain);
        assert_eq!(transaction_status(u64::MAX), TransactionStatus::NotInMainChain);
        assert_eq!(
            transaction_status(3_473_359),
            TransactionStatus::Mined(BlockHeight::from_u32(3_473_359))
        );
    }

    #[test]
    fn a_mined_height_is_never_read_as_a_sentinel() {
        // The failure this guards against frees a live transaction's notes.
        for h in [1u64, 2, 419_200, 3_000_000, u64::from(u32::MAX)] {
            assert_eq!(
                transaction_status(h),
                TransactionStatus::Mined(BlockHeight::from_u32(h as u32)),
                "height {h} must read as mined"
            );
        }
    }
}
