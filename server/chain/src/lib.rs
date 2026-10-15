//! Zakura node reads and chain interpretation for the PIR services.
//!
//! The PIR services (in wallet-pir) serve encrypted lookups over data they derive
//! from the chain. This crate is where that data is read from a Zakura node and
//! interpreted: blocks and transactions are decoded and checked against their
//! headers, hashes converted between the node's display order and protocol order,
//! activation rules applied, receiver payments and note positions found, Enhance
//! actions extracted with their transactions' exact fees (resolving spent outputs
//! through a bounded cache and batched reads), and Status blocks and mempools read.
//!
//! Every result is a plain, chain-neutral value owned by this crate: bytes, heights,
//! amounts and positions, never a node type. The services map these onto their own
//! protocol records, so they need no node or Common dependency of their own.
//!
//! This crate is server-only: it lives in its own workspace and is never part of a
//! wallet build.
#![forbid(unsafe_code)]

pub mod enhance;
mod fee;
pub mod hash;
pub mod receiver;
pub mod rpc;
pub mod status;
#[cfg(feature = "testing")]
pub mod testing;

pub use fee::{DEFAULT_CACHE_OUTPUTS, FeeError};
pub use rpc::{NodeClient, NodeError};

/// A Zakura network whose consensus rules this crate applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn node(self) -> zakura_chain::parameters::Network {
        match self {
            Self::Mainnet => zakura_chain::parameters::Network::Mainnet,
            Self::Testnet => zakura_chain::parameters::Network::new_default_testnet(),
        }
    }

    /// The network's genesis block hash, in protocol byte order.
    pub fn genesis_hash(self) -> [u8; 32] {
        self.node().genesis_hash().0
    }

    /// The first height with an Ironwood note commitment tree (NU6.3).
    pub fn ironwood_activation(self) -> u32 {
        zakura_chain::parameters::NetworkUpgrade::Nu6_3
            .activation_height(&self.node())
            .expect("Ironwood activates on every supported network")
            .0
    }
}
