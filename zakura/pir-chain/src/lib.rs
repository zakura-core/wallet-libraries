//! Zakura node reads and chain interpretation for the PIR services.
//!
//! The PIR services (in wallet-pir) serve encrypted lookups over data they derive
//! from the chain. This crate is where that data is read from a Zakura node and
//! interpreted: blocks and transactions are decoded and checked against their
//! headers, hashes converted between the node's display order and protocol order,
//! activation rules applied, receiver payments and note positions found, Enhance
//! actions extracted with their transactions' exact fees (resolving spent outputs
//! through a bounded cache and batched reads), Status blocks and mempools read, and
//! every transparent output and spent output read raw, with exact fees, for the
//! transparent services, over RPC or (with `rocksdb`) from the node's own database.
//!
//! Every result is a plain, chain-neutral value owned by this crate: bytes, heights,
//! amounts and positions, never a node type. The services map these onto their own
//! protocol records, so they need no node or Common dependency of their own.
//!
//! Decoding and interpretation are synchronous and need no runtime or HTTP stack.
//! The `rpc` feature adds the node JSON-RPC client ([`NodeClient`] and each
//! product's asynchronous reads), for service hosts and tools; product cores take
//! the decoded values without it.
//!
//! This crate is server-only: it lives in its own `zakura/pir-chain` workspace
//! and is never part of a wallet build.
#![forbid(unsafe_code)]

mod chain;
#[cfg(feature = "enhance")]
pub mod enhance;
mod error;
mod fee;
pub mod hash;
#[cfg(feature = "receiver")]
pub mod receiver;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(feature = "status")]
pub mod status;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "transparent")]
pub mod transparent;

pub use error::NodeError;
pub use fee::{DEFAULT_CACHE_OUTPUTS, FeeError};
#[cfg(feature = "rpc")]
pub use rpc::NodeClient;

/// A Zakura network for genesis identity and explicit activation-height queries.
/// The receiver backfill and combined Enhance block reader currently apply mainnet
/// activation rules only; selecting this enum does not configure a node client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    #[cfg(feature = "rocksdb")]
    pub(crate) fn node(self) -> zakura_chain::parameters::Network {
        match self {
            Self::Mainnet => zakura_chain::parameters::Network::Mainnet,
            Self::Testnet => zakura_chain::parameters::Network::new_default_testnet(),
        }
    }

    /// The network's genesis block hash, in protocol byte order.
    pub fn genesis_hash(self) -> [u8; 32] {
        crate::hash::parse_display(match self {
            Self::Mainnet => "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
            Self::Testnet => "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
        })
        .expect("fixed genesis hash")
    }

    /// The first height with an Ironwood note commitment tree (NU6.3).
    pub fn ironwood_activation(self) -> u32 {
        zcash_protocol::consensus::Parameters::activation_height(
            &match self {
                Self::Mainnet => zcash_protocol::consensus::Network::MainNetwork,
                Self::Testnet => zcash_protocol::consensus::Network::TestNetwork,
            },
            zcash_protocol::consensus::NetworkUpgrade::Nu6_3,
        )
        .expect("Ironwood activates on every supported network")
        .into()
    }
}
