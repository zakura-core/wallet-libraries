//! Swap provider seen sets, which wallets read before issuing a swap address.
use std::collections::BTreeMap;

use receiver_directory::{
    ReceiverBytes,
    filter::{Filter, RECENT, SEEN},
    snapshot::FilterSet,
};
use receiver_pir::transport::DirectoryClient;
use zakura_receiver_crypto::Receiver;

use crate::{DirectoryError, Transport};

/// The swap provider seen sets of one receiver directory publication: every receiver
/// each provider was given while its feed ran. Every wallet downloads them alike.
pub struct Seen {
    salt: receiver_directory::Hash,
    sets: Vec<Filter>,
    since: i64,
    until: i64,
}

impl Seen {
    /// When the latest-starting provider feed started, in Unix seconds. Receivers given
    /// earlier may be missing.
    pub fn since(&self) -> i64 {
        self.since
    }

    /// When the earliest of the feeds' last complete reads began, in Unix seconds.
    /// Receivers given later may be missing.
    pub fn until(&self) -> i64 {
        self.until
    }

    /// Whether any provider's set holds each of `receivers`, in order. A set may hold a
    /// receiver it was never given, at its filter's false positive rate. A receiver
    /// that is not a valid Orchard-format receiver is reported as held.
    pub fn contains(&self, receivers: &[[u8; 43]]) -> Vec<bool> {
        let parsed: Vec<_> = receivers
            .iter()
            .map(|r| Receiver::from_bytes(*r).ok())
            .collect();
        let valid: Vec<ReceiverBytes> = parsed.iter().flatten().map(|r| *r.as_bytes()).collect();
        let mut held = vec![false; valid.len()];
        for set in &self.sets {
            for (held, hit) in held.iter_mut().zip(set.matches(&self.salt, &valid)) {
                *held |= hit;
            }
        }
        let mut held = held.into_iter();
        parsed
            .iter()
            .map(|r| r.is_none() || held.next().unwrap_or(true))
            .collect()
    }
}

/// Downloads the seen sets of the publication `origin` serves, which must commit to
/// the network's `genesis` ([`MAINNET_GENESIS`](crate::MAINNET_GENESIS) on mainnet), as
/// for `sweep`, since another network's sets say nothing of this one's quotes. Fails if
/// it declares no seen sets, or unless every provider with a recent or seen set has a
/// seen set dated with its feed's read times, since receivers a provider without one had
/// would look unseen.
pub async fn fetch_seen<T: Transport>(
    origin: &str,
    transport: &T,
    genesis: [u8; 32],
) -> Result<Seen, DirectoryError> {
    let manifest = DirectoryClient::fetch_manifest(origin, transport).await?;
    // The error `sweep`'s coverage check gives for another genesis.
    if manifest.directory.genesis != genesis {
        return Err(receiver_directory::Error::Coverage.into());
    }
    let filters = DirectoryClient::fetch_filters(origin, transport, &manifest).await?;
    let mut seen = Seen {
        salt: manifest.directory.salt,
        sets: Vec::new(),
        since: i64::MIN,
        until: i64::MAX,
    };
    for (label, since, until) in seen_sets(&manifest.directory.filters)? {
        seen.since = seen.since.max(since);
        seen.until = seen.until.min(until);
        // Fetching the filters checked them against the manifest's sets.
        seen.sets
            .push(filters.get(label).ok_or(DirectoryError::Malformed)?.clone());
    }
    Ok(seen)
}

/// The labels and feed read times of the seen sets among a publication's filter `sets`,
/// failing as [`fetch_seen`] does.
pub(crate) fn seen_sets(sets: &[FilterSet]) -> Result<Vec<(&str, i64, i64)>, DirectoryError> {
    let mut providers = BTreeMap::<&str, Option<(&str, i64, i64)>>::new();
    for set in sets {
        match set.label.split_once('/') {
            Some((provider, RECENT)) => {
                providers.entry(provider).or_default();
            }
            Some((provider, SEEN)) => {
                let (Some(since), Some(until)) = (set.since_unix, set.until_unix) else {
                    return Err(DirectoryError::Malformed);
                };
                providers.insert(provider, Some((&set.label, since, until)));
            }
            _ => {}
        }
    }
    if providers.is_empty() {
        return Err(DirectoryError::Malformed);
    }
    providers
        .into_values()
        .map(|seen| seen.ok_or(DirectoryError::Malformed))
        .collect()
}
