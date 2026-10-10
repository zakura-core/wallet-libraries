//! Conversions from the reference client's values to the wallet's.

use transparent::address::TransparentAddress;
use transparent_events::FeeState;
use zcash_client_backend::data_api::transparent_ledger::{
    TransactionMetadata, WholeTransactionFee,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::error::{RecoveryError, ensure_valid, failure};

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

pub(crate) fn block_height(height: u64) -> Result<BlockHeight, RecoveryError> {
    Ok(BlockHeight::from(u32::try_from(height).map_err(failure)?))
}

pub(crate) fn block_hash_from_display(display: &str) -> Result<BlockHash, RecoveryError> {
    let mut bytes = hex::decode(display).map_err(failure)?;
    ensure_valid(bytes.len() == 32, "invalid publication block hash")?;
    bytes.reverse();
    Ok(BlockHash::from_slice(&bytes))
}

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
