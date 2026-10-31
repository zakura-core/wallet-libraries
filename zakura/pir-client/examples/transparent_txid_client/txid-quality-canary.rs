//! One private txid display lookup over `/transparent/v1/txid`, checked against a pinned entry hash.
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
#[path = "../../src/cli_args.rs"]
mod cli_args;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    time::{Duration, Instant},
};
use zakura_pir_client::transparent::txid_client::{
    Method, TransportError, TxidDisplayClient, TxidError, TxidLookup, TxidReply, TxidRequest,
    TxidTransport,
};
use zakura_pir_protocol::endpoint::Endpoint;

#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// Public server base; the client appends the `/transparent/v1/txid/`
    /// paths below its path. Required: there is no default server.
    url: String,
    /// The pinned `{"txid", "height", "entry_sha256"}` document.
    fixture: PathBuf,
    /// Per-request timeout. A cold lookup fetches init, the map, an index
    /// chunk, a manifest and the bucket's setups before its one query.
    timeout_seconds: u64,
}

const HELP: &str = r##"Usage: {program} [OPTIONS] --url <URL> --fixture <FIXTURE>

Options:
      --url <URL>
          Public server base; the client appends the `/transparent/v1/txid/` paths below its path. Required: there is no default server
      --fixture <FIXTURE>
          The pinned `{"txid", "height", "entry_sha256"}` document
      --timeout-seconds <TIMEOUT_SECONDS>
          Per-request timeout. A cold lookup fetches init, the map, an index chunk, a manifest and the bucket's setups before its one query [default: 15]
  -h, --help
          Print help
"##;

fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<Option<Args>, String> {
    let mut arguments = arguments.into_iter();
    let mut url = None;
    let mut fixture = None;
    let mut timeout_seconds = None;
    while let Some(argument) = arguments.next() {
        if cli_args::is_help(&argument) {
            return Ok(None);
        }
        if argument == "--" {
            if arguments.next().is_some() {
                return Err("unexpected positional argument".into());
            }
            break;
        }
        if let Some(value) = cli_args::take_value(&argument, "--url", &mut arguments) {
            if url.is_some() {
                return Err("--url cannot be used multiple times".into());
            }
            url = Some(value?.into_string().map_err(|_| "--url requires UTF-8")?);
        } else if let Some(value) = cli_args::take_value(&argument, "--fixture", &mut arguments) {
            if fixture.is_some() {
                return Err("--fixture cannot be used multiple times".into());
            }
            fixture = Some(PathBuf::from(value?));
        } else if let Some(value) =
            cli_args::take_value(&argument, "--timeout-seconds", &mut arguments)
        {
            if timeout_seconds.is_some() {
                return Err("--timeout-seconds cannot be used multiple times".into());
            }
            timeout_seconds = Some(cli_args::number(value?, "--timeout-seconds")?);
        } else {
            return Err("unexpected argument; use --help for usage".into());
        }
    }
    Ok(Some(Args {
        url: url.ok_or("--url is required")?,
        fixture: fixture.ok_or("--fixture is required")?,
        timeout_seconds: timeout_seconds.unwrap_or(15),
    }))
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
    base: Endpoint,
}

impl TxidTransport for Http {
    fn send(&mut self, request: TxidRequest) -> Result<TxidReply, TransportError> {
        let url = self
            .base
            .join(request.path())
            .map_err(|_| TransportError("invalid route".into()))?;
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
    let Ok(base) = Endpoint::parse(&args.url) else {
        return "unavailable";
    };
    let mut transport = Http { client, base };
    // A fresh client every run: the cold path, with no cached map or setups.
    let outcome = TxidDisplayClient::new().lookup(&mut transport, pin.txid, pin.height, &|| false);
    judge(outcome, &pin)
}

fn main() {
    let mut arguments = std::env::args_os();
    let executable = arguments.next().unwrap_or_default();
    let program = std::path::Path::new(&executable)
        .file_name()
        .unwrap_or(OsStr::new("txid-quality-canary"))
        .to_string_lossy();
    let args = match parse_args(arguments) {
        Ok(Some(args)) => args,
        Ok(None) => {
            print!("{}", HELP.replace("{program}", &program));
            return;
        }
        Err(error) => {
            eprintln!("error: {error}\n\n{}", HELP.replace("{program}", &program));
            std::process::exit(2);
        }
    };
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
    use zakura_pir_client::transparent::txid_client::{Placement, ProtocolKind};
    use zakura_pir_protocol::transparent::events::Txid;
    use zakura_pir_publisher::transparent::txid::{
        Address, AddressKind, DisplayEntry, EntryOutput, Tag,
    };

    const TXID_DISPLAY: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

    fn parse(arguments: &[&str]) -> Result<Option<Args>, String> {
        parse_args(arguments.iter().map(OsString::from))
    }

    #[test]
    fn argument_defaults_empty_values_and_numeric_limits() {
        assert_eq!(
            parse(&["--url=x", "--fixture", "pin.json"]),
            Ok(Some(Args {
                url: "x".into(),
                fixture: "pin.json".into(),
                timeout_seconds: 15,
            }))
        );
        assert_eq!(
            parse(&[
                "--fixture=-h",
                "--url",
                "",
                "--timeout-seconds=18446744073709551615",
                "--"
            ]),
            Ok(Some(Args {
                url: String::new(),
                fixture: "-h".into(),
                timeout_seconds: u64::MAX,
            }))
        );
        assert_eq!(
            parse(&["--url=x", "--fixture=f", "--timeout-seconds=+1"])
                .unwrap()
                .unwrap()
                .timeout_seconds,
            1
        );
    }

    #[test]
    fn argument_errors_and_help_preserve_validation_order() {
        for arguments in [
            vec![],
            vec!["--url=x"],
            vec!["--fixture=f"],
            vec!["--url", "--help"],
            vec!["--timeout-seconds=bad", "--help"],
            vec!["--timeout-seconds=18446744073709551616", "--help"],
            vec!["--url=x", "--url=x", "--help"],
            vec!["--timeout-seconds=1", "--timeout-seconds=1", "--help"],
            vec!["--unknown", "--help"],
            vec!["--url=x", "--fixture=f", "--", "--help"],
        ] {
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
        for arguments in [vec!["--help", "--unknown"], vec!["-hfoo"]] {
            assert!(parse(&arguments).unwrap().is_none());
        }
    }

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
            provenance: zakura_pir_client::transparent::txid_client::Provenance {
                map_sha256: String::new(),
                shard_id: 1,
                revision: 0,
                manifest_digest: String::new(),
                tier: zakura_pir_client::transparent::txid_client::Tier::Archive,
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
