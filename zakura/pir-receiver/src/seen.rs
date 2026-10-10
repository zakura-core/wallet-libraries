//! Swap provider seen sets, which wallets read before issuing a swap address.
use std::collections::BTreeMap;

use receiver_directory::{
    Receiver,
    filter::{Filter, RECENT, SEEN},
    snapshot::FilterSet,
};
use receiver_pir::transport::DirectoryClient;

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
        let valid: Vec<_> = parsed.iter().flatten().copied().collect();
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

/// Downloads the seen sets of the publication `origin` serves. Fails if it declares
/// none, or if any provider with a set lacks a seen set with its feed's read times (see
/// [`seen_sets`]).
pub async fn fetch_seen<T: Transport>(origin: &str, transport: &T) -> Result<Seen, DirectoryError> {
    let manifest = DirectoryClient::fetch_manifest(origin, transport).await?;
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
    if seen.sets.is_empty() {
        return Err(DirectoryError::Malformed);
    }
    Ok(seen)
}

/// The labels and feed read times of the seen sets among a publication's filter `sets`.
/// Fails unless every provider with a recent or seen set has a dated seen set, since
/// receivers a provider without one had would look unseen.
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
    providers
        .into_values()
        .map(|seen| seen.ok_or(DirectoryError::Malformed))
        .collect()
}
