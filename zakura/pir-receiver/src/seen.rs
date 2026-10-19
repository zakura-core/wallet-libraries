//! Swap provider seen sets, which wallets read before issuing a swap address.
use std::collections::BTreeMap;

use receiver_directory::{
    filter::{RECENT, SEEN},
    seen::SeenSet,
    snapshot::FilterSet,
};
use receiver_pir::archive::ArchiveClient;
use zakura_receiver_crypto::Receiver;

use crate::{DirectoryError, Transport};

/// The permanent provider-membership object advertised by a validated archive head.
/// Everyone downloads the same object. Membership never authorizes a payment lookup.
pub struct Seen {
    set: SeenSet,
    digest: receiver_directory::Hash,
}

impl Seen {
    /// The supported provider-history start, in Unix seconds.
    pub fn since(&self) -> i64 {
        self.set.since_unix
    }

    /// The last complete provider read's start, in Unix seconds.
    pub fn until(&self) -> i64 {
        self.set.until_unix
    }

    /// Identifies the exact validated bytes for resumable wallet membership checks.
    pub fn digest(&self) -> receiver_directory::Hash {
        self.digest
    }

    /// Tests the permanent fixed hash universe in input order. Invalid receivers fail closed.
    pub fn contains(&self, receivers: &[[u8; 43]]) -> Vec<bool> {
        let parsed: Vec<_> = receivers
            .iter()
            .map(|r| Receiver::from_bytes(*r).ok().map(|r| *r.as_bytes()))
            .collect();
        let valid: Vec<_> = parsed.iter().flatten().copied().collect();
        let mut held = self.set.matches(&valid).into_iter();
        parsed
            .iter()
            .map(|r| r.is_none() || held.next().unwrap_or(true))
            .collect()
    }
}

/// Downloads complete provider membership independently of PIR session preparation.
/// Missing history, another network, or inconsistent bytes are errors. The wallet checks freshness.
pub async fn fetch_seen<T: Transport>(
    origin: &str,
    transport: &T,
    genesis: [u8; 32],
) -> Result<Seen, DirectoryError> {
    let head = ArchiveClient::head(origin, transport).await?;
    if head.genesis != genesis {
        return Err(receiver_directory::Error::Coverage.into());
    }
    let set = ArchiveClient::seen(origin, transport, &head).await?;
    let digest = set.digest()?;
    Ok(Seen { set, digest })
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

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use receiver_directory::{
        archive::{Head, SeenRef},
        blocks::BlockId,
    };
    use std::{collections::BTreeMap, sync::Mutex};

    /// Serves only the public archive routes, recording every request.
    struct PublicArchive {
        bodies: BTreeMap<String, Vec<u8>>,
        requests: Mutex<Vec<String>>,
    }
    impl Transport for PublicArchive {
        /// Enforces the caller's public-response limit before handing over bytes.
        async fn get(&self, url: &str, limit: usize) -> Result<Vec<u8>, DirectoryError> {
            self.requests.lock().unwrap().push(url.to_owned());
            let bytes = self.bodies.get(url).ok_or(DirectoryError::Revision)?;
            if bytes.len() > limit {
                return Err(DirectoryError::Malformed);
            }
            Ok(bytes.clone())
        }
        /// Provider checks must never send an encrypted receiver query or session setup.
        async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, DirectoryError> {
            panic!("provider membership requested PIR")
        }
    }
    /// Builds a fixed-universe capture and the immutable object its head declares.
    fn fixture() -> (PublicArchive, SeenSet, [[u8; 43]; 2]) {
        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let receivers =
            [0u32, 1].map(|i| fvk.address_at(i, Scope::External).to_raw_address_bytes());
        let mut set = SeenSet::new([1; 32], 100).union([&receivers[0]]);
        set.until_unix = 200;
        let digest = set.digest().unwrap();
        let head = Head {
            genesis: [1; 32],
            archive: [2; 32],
            epoch: 0,
            first_height: 1,
            frontier: BlockId {
                height: 10,
                hash: [3; 32],
            },
            index_root: [4; 32],
            seen: Some(SeenRef {
                digest,
                since_unix: 100,
                until_unix: 200,
            }),
        };
        let bodies = BTreeMap::from([
            (
                "https://receiver.test/v1/receiver/archive/head".into(),
                head.encode().unwrap(),
            ),
            (
                format!(
                    "https://receiver.test/v1/receiver/archive/seen/{}",
                    hex::encode(digest)
                ),
                set.encode().unwrap(),
            ),
        ]);
        (
            PublicArchive {
                bodies,
                requests: Mutex::new(vec![]),
            },
            set,
            receivers,
        )
    }
    /// The caller gets the exact object digest, dates and conservative receiver membership without PIR.
    #[tokio::test]
    async fn provider_capture_uses_only_public_archive_routes() {
        let (http, set, receivers) = fixture();
        let fetched = fetch_seen("https://receiver.test/", &http, [1; 32])
            .await
            .unwrap();
        assert_eq!(fetched.digest(), set.digest().unwrap());
        assert_eq!((fetched.since(), fetched.until()), (100, 200));
        assert_eq!(fetched.contains(&receivers), [true, false]);
        assert!(fetched.contains(&[[255; 43]])[0]);
        let paths = http.requests.lock().unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.contains("/archive/")));
    }
    /// Another network and an unavailable or inconsistent object cannot be mistaken for an empty set.
    #[tokio::test]
    async fn provider_capture_refuses_incomplete_or_mismatched_history() {
        let (http, _, _) = fixture();
        assert!(
            fetch_seen("https://receiver.test", &http, [8; 32])
                .await
                .is_err()
        );
        assert_eq!(http.requests.lock().unwrap().len(), 1);
        for mode in ["missing", "absent", "changed"] {
            let (mut http, _, _) = fixture();
            let key = "https://receiver.test/v1/receiver/archive/head";
            let mut head = Head::decode(&http.bodies[key]).unwrap();
            let object = format!(
                "https://receiver.test/v1/receiver/archive/seen/{}",
                hex::encode(head.seen.as_ref().unwrap().digest)
            );
            match mode {
                "missing" => {
                    head.seen = None;
                    http.bodies.insert(key.into(), head.encode().unwrap());
                }
                "absent" => {
                    http.bodies.remove(&object);
                }
                _ => {
                    http.bodies
                        .insert(object, SeenSet::new([1; 32], 100).encode().unwrap());
                }
            }
            assert!(
                fetch_seen("https://receiver.test", &http, [1; 32])
                    .await
                    .is_err(),
                "{mode}"
            );
        }
    }
}
