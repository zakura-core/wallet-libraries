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
    /// Where the private transparent ledger reads from.
    ///
    /// `None` means the wallet cannot ask, and it says so rather than showing
    /// a transparent balance of zero — the two are different states and a
    /// person acts differently on them. Transparent funds are discovered by
    /// this and by nothing else; see `docs/zakura_transparent_pir.md`.
    ///
    /// Two URLs, and deliberately not one. Public filter bytes are identical
    /// for every wallet and reveal nothing about which one asked; the private
    /// queries that follow reveal which chain ranges had probable activity.
    /// One host serving both can join those facts together, and no property of
    /// the protocol prevents it.
    pub transparent: Option<zakura_wallet_transparent::Endpoints>,
    /// How much private work one transparent sync may do before it stops and
    /// keeps the rest for the next one.
    ///
    /// The mobile bound by default. A sync that reaches it is reported as
    /// incomplete with its reason, never as a synchronized balance.
    pub transparent_limits: zakura_wallet_transparent::WorkLimits,
    /// How many bytes of blocks to fetch at once.
    ///
    /// The default is the mobile budget, because the cost of guessing wrong is
    /// asymmetric: too large stalls a phone, too small only costs round trips.
    pub batch_bytes: usize,
    /// How long to wait, once caught up, before looking for new blocks.
    ///
    /// Zcash blocks are about seventy-five seconds apart, so polling much
    /// faster than this only costs battery and gives a light server a clearer
    /// picture of when the wallet is awake.
    pub poll_interval: std::time::Duration,
    /// Whether this wallet may only recover: restore, synchronise, and read.
    ///
    /// When set, [`crate::Wallet::quote`] and [`crate::Wallet::send`] refuse
    /// with [`crate::Error::SendDisabled`] whatever they are given, and
    /// opening refuses a configuration a recovery cannot be honest under:
    /// no transparent services, one host serving both, or either over
    /// plaintext. A build that is only meant to recover sets this at open
    /// and nothing later can unset it.
    pub recovery_only: bool,
}

impl WalletConfig {
    /// Builds a configuration with the two databases side by side in `dir`.
    pub fn in_dir(network: NetworkKind, dir: &Path, lightwalletd_url: impl Into<String>) -> Self {
        Self {
            network,
            wallet_path: dir.join("wallet.db"),
            cache_path: dir.join("cache.db"),
            lightwalletd_url: lightwalletd_url.into(),
            transparent: None,
            transparent_limits: zakura_wallet_transparent::MOBILE_LIMITS,
            batch_bytes: zakura_wallet_sync::ByteBudget::MOBILE.bytes(),
            poll_interval: std::time::Duration::from_secs(20),
            recovery_only: false,
        }
    }

    /// What a recovery-only wallet requires of its configuration, or why it
    /// cannot be opened.
    ///
    /// A recovery that cannot ask about transparent history would show a
    /// transparent balance of nothing and call it recovered; a pair of
    /// services on one host lets that host join what the filters do not
    /// reveal to what the queries do; and a private query over plaintext is
    /// not private. None of these is a state to run in quietly.
    pub fn recovery_requirements(&self) -> Result<(), String> {
        if !self.recovery_only {
            return Ok(());
        }
        let Some(endpoints) = &self.transparent else {
            return Err(
                "no transparent services are configured; a recovery cannot read transparent \
                 history without them, and their absence is not an empty history"
                    .to_owned(),
            );
        };
        for (what, url) in [
            ("filter service", &endpoints.filters_url),
            ("shard service", &endpoints.shards_url),
            ("light server", &self.lightwalletd_url),
        ] {
            if !url.starts_with("https://") && !fixture_loopback(url) {
                return Err(format!("the {what} is not reached over TLS"));
            }
        }
        if endpoints.shares_a_host() {
            return Err(
                "the filter service and the shard service are one host, which could join \
                 the public filter reads to the private queries"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Whether `url` is a plaintext loopback address a fixture build may use.
///
/// Only a build made with the `fixture-loopback` feature, and only when the
/// process also carries `ZAKURA_FIXTURE_LOOPBACK=1`, and only for the
/// loopback interface. A shipped build has none of the three.
#[cfg(feature = "fixture-loopback")]
fn fixture_loopback(url: &str) -> bool {
    std::env::var("ZAKURA_FIXTURE_LOOPBACK").as_deref() == Ok("1")
        && (url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:"))
}

#[cfg(not(feature = "fixture-loopback"))]
fn fixture_loopback(_: &str) -> bool {
    false
}
