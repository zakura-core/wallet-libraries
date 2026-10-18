//! Conversions from the reference client's values to the wallet's.

use transparent::address::TransparentAddress;
use transparent_events::FeeState;
use zakura_transparent_recovery_types::RecoveryBlockHash as BlockHash;
use zakura_transparent_recovery_types::{TransactionMetadata, WholeTransactionFee};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::error::{RecoveryError, ensure_valid, failure};

/// The `scriptPubKey` paying `address`: P2PKH or P2SH. The reference client keys
/// scripts, filters and stored facts by it.
pub(crate) fn address_script(address: TransparentAddress) -> Vec<u8> {
    match address {
        TransparentAddress::PublicKeyHash(hash) => {
            [vec![0x76, 0xa9, 20], hash.to_vec(), vec![0x88, 0xac]].concat()
        }
        TransparentAddress::ScriptHash(hash) => {
            [vec![0xa9, 20], hash.to_vec(), vec![0x87]].concat()
        }
    }
}

/// A wallet height as the reference client counts heights.
pub(crate) fn height_u64(height: BlockHeight) -> u64 {
    u64::from(u32::from(height))
}

/// A reference-client height as a wallet height, failing above `u32::MAX`.
pub(crate) fn block_height(height: u64) -> Result<BlockHeight, RecoveryError> {
    Ok(BlockHeight::from(u32::try_from(height).map_err(failure)?))
}

/// A block hash from its display hex, which reverses the internal byte order, as
/// publications and the reference client write it. Fails on malformed hex or a
/// length other than 32 bytes.
pub(crate) fn block_hash_from_display(display: &str) -> Result<BlockHash, RecoveryError> {
    let mut bytes = hex::decode(display).map_err(failure)?;
    ensure_valid(bytes.len() == 32, "invalid publication block hash")?;
    bytes.reverse();
    Ok(BlockHash::from_slice(&bytes))
}

/// The wallet's transaction metadata from what a stored event recorded, if it
/// recorded any. Fails on an exact fee above `MAX_MONEY`.
pub(crate) fn ledger_metadata(
    meta: Option<transparent_events::TransactionMetadata>,
) -> Result<Option<TransactionMetadata>, RecoveryError> {
    meta.map(|meta| {
        Ok(TransactionMetadata {
            fee: match meta.fee {
                FeeState::Exact(value) => {
                    WholeTransactionFee::Exact(Zatoshis::from_u64(value).map_err(failure)?)
                }
                FeeState::Unknown => WholeTransactionFee::Unknown,
                FeeState::NotApplicable => WholeTransactionFee::NotApplicable,
            },
            transparent_input_count: meta.transparent_input_count,
            has_shielded_components: meta.has_shielded_components,
        })
    })
    .transpose()
}
