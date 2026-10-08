//! Swap provider seen sets, which wallets read before issuing a swap address.
use receiver_directory::{
    Receiver,
    filter::{Filter, SEEN},
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
/// none, or a seen set without its feed's read times.
pub async fn fetch_seen<T: Transport>(origin: &str, transport: &T) -> Result<Seen, DirectoryError> {
    let manifest = DirectoryClient::fetch_manifest(origin, transport).await?;
    let filters = DirectoryClient::fetch_filters(origin, transport, &manifest).await?;
    let mut seen = Seen {
        salt: manifest.directory.salt,
        sets: Vec::new(),
        since: i64::MIN,
        until: i64::MAX,
    };
    for set in &manifest.directory.filters {
        if set.label.split_once('/').map(|(_, kind)| kind) != Some(SEEN) {
            continue;
        }
        let (Some(since), Some(until)) = (set.since_unix, set.until_unix) else {
            return Err(DirectoryError::Malformed);
        };
        seen.since = seen.since.max(since);
        seen.until = seen.until.min(until);
        // Fetching the filters checked them against the manifest's sets.
        seen.sets.push(
            filters
                .get(&set.label)
                .ok_or(DirectoryError::Malformed)?
                .clone(),
        );
    }
    if seen.sets.is_empty() {
        return Err(DirectoryError::Malformed);
    }
    Ok(seen)
}
