//! The seen set, which wallets read before issuing a swap address.
use receiver_directory::seen::SeenSet;
use receiver_pir::transport::DirectoryClient;
use zakura_receiver_crypto::Receiver;

use crate::{DirectoryError, Transport};

/// The seen set of one receiver directory publication: every receiver the swap provider
/// feeds reported, as a monotone set every wallet downloads alike.
pub struct Seen(SeenSet);

impl Seen {
    /// When the provider feeds started, in Unix seconds. Receivers given earlier may be
    /// missing.
    pub fn since(&self) -> i64 {
        self.0.since_unix
    }

    /// When the feeds' last complete read of the providers began, in Unix seconds.
    /// Receivers given later may be missing.
    pub fn until(&self) -> i64 {
        self.0.until_unix
    }

    /// Whether the set holds each of `receivers`, in order. It may hold a receiver it was
    /// never given, at its false match rate. A receiver that is not a valid Orchard-format
    /// receiver is reported as held.
    pub fn contains(&self, receivers: &[[u8; 43]]) -> Vec<bool> {
        let valid: Vec<_> = receivers
            .iter()
            .map(|r| Receiver::from_bytes(*r).is_ok())
            .collect();
        self.0
            .matches(receivers)
            .into_iter()
            .zip(valid)
            .map(|(held, valid)| held || !valid)
            .collect()
    }
}

/// Downloads the seen set of the publication `origin` serves, through the catalog head its
/// manifest commits to. The publication must commit to the network's `genesis`
/// ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS) on mainnet), as for `recover`, since
/// another network's set says nothing of this one's quotes.
pub async fn fetch_seen<T: Transport>(
    origin: &str,
    transport: &T,
    genesis: [u8; 32],
) -> Result<Seen, DirectoryError> {
    let manifest = DirectoryClient::fetch_manifest(origin, transport).await?;
    // The error `recover`'s coverage check gives for another genesis.
    if manifest.directory.genesis != genesis {
        return Err(receiver_directory::Error::Coverage.into());
    }
    let head = DirectoryClient::fetch_catalog(origin, transport, &manifest).await?;
    Ok(Seen(
        DirectoryClient::fetch_seen(origin, transport, &head).await?,
    ))
}
