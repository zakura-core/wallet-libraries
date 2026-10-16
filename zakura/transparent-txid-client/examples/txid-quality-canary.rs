//! One private txid display lookup over `/v2/txid`, checked against a pinned entry hash.
//!
//! The fixture is `{"txid": "<display hex>", "height": <mined height>,
//! "entry_sha256": "<hex>"}`: one sample of a `txid-inventory fixture` document,
//! whose `entry_sha256` is the SHA-256 of the entry's canonical 113-byte
//! encoding, taken from the publisher's own files rather than from a server
//! answer. Pin an archive-tier sample: a recent-tier one can fall below the
//! recent floor or move to an archive.
//!
//! Prints one JSON line, `{"passed", "category", "duration_seconds"}`, and exits
//! 1 unless the lookup returned exactly the pinned entry. Categories:
//! `answer_mismatch` (an entry other than the pinned one, or none), `oracle_invalid`
//! (the fixture does not parse, or the service publishes a schema this build
//! does not know), `placement_unknown`, `recent_below_floor`, `unavailable` and
//! `protocol_failure`. Neither the txid, the query nor any server text is printed.
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use transparent_txid_client::{
    Method, TransportError, TxidDisplayClient, TxidError, TxidLookup, TxidReply, TxidRequest,
    TxidTransport,
};

#[derive(Parser)]
struct Args {
    /// Public origin; the client appends the `/v2/txid/` paths.
    #[arg(long, default_value = "https://transparent-pir.valargroup.dev")]
    url: String,
    /// The pinned `{"txid", "height", "entry_sha256"}` document.
    #[arg(long)]
    fixture: PathBuf,
    /// Per-request timeout. A cold lookup fetches init, the map, an index
    /// chunk, a manifest and the bucket's setups before its one query.
    #[arg(long, default_value_t = 15)]
    timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    txid: String,
    height: u64,
    entry_sha256: String,
}

/// The pinned lookup: the txid in internal byte order, its mined height and
/// the expected entry digest.
#[derive(Debug, PartialEq, Eq)]
struct Pin {
    txid: [u8; 32],
    height: u64,
    entry_sha256: [u8; 32],
}

fn parse_fixture(bytes: &[u8]) -> Option<Pin> {
    let fixture: Fixture = serde_json::from_slice(bytes).ok()?;
    let hex32 = |text: &str| -> Option<[u8; 32]> {
        // Lowercase only, so a pin has one spelling.
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        hex::decode(text).ok()?.try_into().ok()
    };
    let mut txid = hex32(&fixture.txid)?;
    // Fixtures and explorers show txids in display order, the reverse of
    // the internal order the client hashes.
    txid.reverse();
    (fixture.height > 0).then_some(())?;
    Some(Pin {
        txid,
        height: fixture.height,
        entry_sha256: hex32(&fixture.entry_sha256)?,
    })
}

/// The category one lookup earns; empty when it returned the pinned entry.
fn judge(outcome: Result<TxidLookup, TxidError>, pin: &Pin) -> &'static str {
    match outcome {
        Ok(TxidLookup::Found { entry, .. }) => match entry.encode() {
            Ok(bytes) if <[u8; 32]>::from(Sha256::digest(bytes)) == pin.entry_sha256 => "",
            _ => "answer_mismatch",
        },
        // The pinned txid is mined at the pinned height, so absence is a wrong answer.
        Ok(TxidLookup::Absent) => "answer_mismatch",
        Ok(TxidLookup::Unsupported) => "oracle_invalid",
        Ok(TxidLookup::PlacementUnknown(_)) => "placement_unknown",
        Ok(TxidLookup::RecentBelowFloor) => "recent_below_floor",
        Err(TxidError::Protocol(_)) => "protocol_failure",
        Err(_) => "unavailable",
    }
}

/// Blocking HTTPS transport. Error text stays inside this process.
struct Http {
    client: reqwest::blocking::Client,
    base: String,
}

impl TxidTransport for Http {
    fn send(&mut self, request: TxidRequest) -> Result<TxidReply, TransportError> {
        let url = format!("{}{}", self.base, request.path());
        let builder = match request.method {
            Method::Get => self.client.get(url),
            Method::Post => self
                .client
                .post(url)
                .header("content-type", request.content_type().unwrap_or_default())
                .body(request.body),
        };
        let response = builder
            .send()
            .map_err(|_| TransportError("request failed".into()))?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let (status, retry_after, map_sha256) = (
            response.status().as_u16(),
            header("retry-after"),
            header("x-txid-map-sha256"),
        );
        let body = response
            .bytes()
            .map_err(|_| TransportError("body failed".into()))?
            .to_vec();
        Ok(TxidReply {
            status,
            retry_after,
            map_sha256,
            body,
        })
    }
}

fn probe(args: &Args) -> &'static str {
    let Some(pin) = std::fs::read(&args.fixture)
        .ok()
        .and_then(|bytes| parse_fixture(&bytes))
    else {
        return "oracle_invalid";
    };
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(args.timeout_seconds))
        .user_agent("pir-independent-canary")
        .build()
    else {
        return "unavailable";
    };
    let mut transport = Http {
        client,
        base: args.url.trim_end_matches('/').to_string(),
    };
    // A fresh client every run: the cold path, with no cached map or setups.
    let outcome = TxidDisplayClient::new().lookup(&mut transport, pin.txid, pin.height, &|| false);
    judge(outcome, &pin)
}

fn main() {
    let args = Args::parse();
    let start = Instant::now();
    let category = probe(&args);
    println!(
        "{}",
        serde_json::json!({"passed":category.is_empty(),"category":category,"duration_seconds":start.elapsed().as_secs_f64()})
    );
    if !category.is_empty() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transparent_events::Txid;
    use transparent_shard::txid::{Address, AddressKind, DisplayEntry, EntryOutput, Tag};
    use transparent_txid_client::{Placement, ProtocolKind};

    const TXID_DISPLAY: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

    fn entry(txid: [u8; 32], value: u64) -> DisplayEntry {
        DisplayEntry {
            tag: Tag::of(&Txid(txid)),
            coinbase: true,
            shielded_components: false,
            multiple_source_scripts: false,
            shielded_and_transparent_funding: false,
            fee: 0,
            input_count: 0,
            output_count: 1,
            source: Address::ABSENT,
            outputs: [
                Some(EntryOutput {
                    value,
                    address: Address {
                        kind: AddressKind::P2pkh,
                        hash: [7; 20],
                    },
                }),
                None,
            ],
        }
    }

    fn fixture_for(entry: &DisplayEntry) -> Vec<u8> {
        let digest = hex::encode(Sha256::digest(entry.encode().unwrap()));
        serde_json::to_vec(
            &serde_json::json!({"txid": TXID_DISPLAY, "height": 2_000_000, "entry_sha256": digest}),
        )
        .unwrap()
    }

    fn found(entry: DisplayEntry) -> Result<TxidLookup, TxidError> {
        Ok(TxidLookup::Found {
            entry,
            provenance: transparent_txid_client::Provenance {
                map_sha256: String::new(),
                shard_id: 1,
                revision: 0,
                manifest_digest: String::new(),
                tier: transparent_txid_client::Tier::Archive,
            },
        })
    }

    #[test]
    fn fixture_txid_is_display_order_and_fields_are_exact() {
        let mut internal = [0u8; 32];
        internal[0] = 0xab;
        let pinned = entry(internal, 5);
        let pin = parse_fixture(&fixture_for(&pinned)).unwrap();
        assert_eq!((pin.txid, pin.height), (internal, 2_000_000));

        let mut value: serde_json::Value = serde_json::from_slice(&fixture_for(&pinned)).unwrap();
        for (field, bad) in [
            ("txid", serde_json::json!("ab")),
            ("txid", serde_json::json!(TXID_DISPLAY.to_uppercase())),
            ("entry_sha256", serde_json::json!("00")),
            ("height", serde_json::json!(0)),
            ("extra", serde_json::json!(1)),
        ] {
            let saved = value.get(field).cloned();
            value[field] = bad;
            assert_eq!(
                parse_fixture(&serde_json::to_vec(&value).unwrap()),
                None,
                "{field}"
            );
            match saved {
                Some(saved) => value[field] = saved,
                None => {
                    value.as_object_mut().unwrap().remove(field);
                }
            }
        }
        assert!(parse_fixture(&serde_json::to_vec(&value).unwrap()).is_some());
    }

    #[test]
    fn only_the_pinned_entry_passes() {
        let mut internal = [0u8; 32];
        internal[0] = 0xab;
        let pinned = entry(internal, 5);
        let pin = parse_fixture(&fixture_for(&pinned)).unwrap();
        assert_eq!(judge(found(pinned), &pin), "");
        assert_eq!(judge(found(entry(internal, 6)), &pin), "answer_mismatch");
        assert_eq!(judge(Ok(TxidLookup::Absent), &pin), "answer_mismatch");
        assert_eq!(judge(Ok(TxidLookup::Unsupported), &pin), "oracle_invalid");
        assert_eq!(
            judge(Ok(TxidLookup::PlacementUnknown(Placement::Above)), &pin),
            "placement_unknown"
        );
        assert_eq!(
            judge(Ok(TxidLookup::RecentBelowFloor), &pin),
            "recent_below_floor"
        );
        assert_eq!(
            judge(Err(TxidError::Protocol(ProtocolKind::Decode)), &pin),
            "protocol_failure"
        );
        assert_eq!(
            judge(Err(TxidError::Unavailable { retry_after: None }), &pin),
            "unavailable"
        );
    }
}
