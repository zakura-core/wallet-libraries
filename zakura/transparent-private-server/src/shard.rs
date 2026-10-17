//! Building the immutable shards a wallet privately retrieves history from,
//! and the txid display tables.
//!
//! A shard's boundaries are decided by what it contains rather than by a fixed
//! block width; see [`seal`]. The layout, manifests and codecs the builders
//! produce are [`zakura_transparent_private_shared::shard`]. This module decides
//! boundaries and lays out tables. It does not fetch chain data and it does not
//! serve queries.

pub mod build;
pub mod choice;
pub mod display;
pub mod manifest;
pub mod packing;
pub mod seal;
pub mod tag;
pub mod txid;
pub mod txid_v1;
pub mod txid_v2x;

pub use build::{
    build_directory_shard, choice_table, place_scripts, placement_order, verify_choice, Block,
    BuildError, Built, BuiltChild, BuiltDirectory, DirectoryBuilder, Placement, ShardStream,
};
pub use choice::ChoiceBuild;
pub use packing::PackedDemand;
pub use seal::{
    ChoiceMeasure, Closed, DecoupledPolicy, DisplacementSealer, Limit, Occupancy, SealError,
    SealPolicy, SealReason, SealedChild, SealedDirectory, SealedShard, Sealer,
};
pub use tag::{resolve_page_tag_salt, resolve_tag_salt};

/// Events the builders' tests lay out: a receive and the spend of it, at
/// the widest values every field takes.
#[cfg(test)]
pub(crate) mod test_events {
    use zakura_transparent_private_shared::events::{
        ReceiveEvent, SpendEvent, TransparentEvent, Txid,
    };

    pub(crate) fn pair(height: u32, nonce: u32) -> [TransparentEvent; 2] {
        let mut txid = [0x12; 32];
        txid[..4].copy_from_slice(&nonce.to_le_bytes());
        [
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height,
                transaction_index: 0,
                txid: Txid(txid),
                output_index: u32::MAX,
                value: u64::MAX,
                coinbase: true,
            }),
            TransparentEvent::Spend(SpendEvent {
                metadata: None,
                height,
                transaction_index: u16::MAX,
                spending_txid: Txid([0x34; 32]),
                input_index: u32::MAX,
                spent_txid: Txid(txid),
                spent_output_index: u32::MAX,
            }),
        ]
    }
}
