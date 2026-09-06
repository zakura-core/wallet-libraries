//! What a wallet needs to know before it can open.

use std::path::{Path, PathBuf};

use zcash_protocol::consensus::Network;

/// Which chain the wallet is on.
///
/// A plain enum rather than a generic `P: Parameters`, because the whole point
/// of this crate is to have one concrete type an application can name. The
/// generic parameter stops here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    /// Zcash mainnet.
    Main,
    /// Zcash testnet.
    Test,
}

impl NetworkKind {
    /// Returns the consensus parameters the core crates take.
    pub fn params(self) -> Network {
        match self {
            NetworkKind::Main => Network::MainNetwork,
            NetworkKind::Test => Network::TestNetwork,
        }
    }
}

/// Where the wallet's two files live, and what it talks to.
///
/// The two database paths are separate because the split is load-bearing: the
/// durable file holds what cannot be recovered from the chain, and the cache
/// can be deleted and rebuilt. Putting them in one directory is a convention,
/// not a requirement, so both are named.
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Which chain.
    pub network: NetworkKind,
    /// The durable database: accounts, keys, and sent transactions.
    pub wallet_path: PathBuf,
    /// The derived database, which may be deleted and rebuilt.
    pub cache_path: PathBuf,
    /// The lightwalletd endpoint, as a URL.
    pub lightwalletd_url: String,
    /// How many bytes of blocks to fetch at once.
    ///
    /// The default is the mobile budget, because the cost of guessing wrong is
    /// asymmetric: too large stalls a phone, too small only costs round trips.
    pub batch_bytes: usize,
}

impl WalletConfig {
    /// Builds a configuration with the two databases side by side in `dir`.
    pub fn in_dir(network: NetworkKind, dir: &Path, lightwalletd_url: impl Into<String>) -> Self {
        Self {
            network,
            wallet_path: dir.join("wallet.db"),
            cache_path: dir.join("cache.db"),
            lightwalletd_url: lightwalletd_url.into(),
            batch_bytes: zakura_wallet_sync::ByteBudget::MOBILE.bytes(),
        }
    }
}
