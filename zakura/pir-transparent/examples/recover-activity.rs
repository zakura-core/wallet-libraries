//! An executable walkthrough of transparent history recovery into a candidate wallet.
//!
//! Run with an independently collected snapshot, a new output directory, and a
//! PIR origin. The snapshot supplies `birthday`, `through`, standard locking
//! `scripts`, and consecutive RPC `headers` from birthday minus one through the
//! target. Header hashes use RPC display order; each header also has `height`,
//! `time`, and `previousblockhash` (the first header needs no parent).
//!
//! The walkthrough builds a controlled wallet, retrieves real published history,
//! applies it as untrusted candidate evidence, and checks that reopening SQLite
//! preserves the result. It writes the input snapshot, companion, wallet copy,
//! and a readable `result.json` to the output directory. Failed runs leave their
//! partial evidence there rather than overwriting an earlier run.
//!
//! Read `main` in phase order. `TransparentHistoryRecovery` handles retrieval and batch
//! construction; its catalog checks publication continuity; the wallet validates
//! and stores each commit. Txid receipt lookup is a separate operation and is
//! not needed to establish the recovered receives and spends shown here.
//!
//! Public scripts stand in for owned addresses without supplying their keys.
//! Empty fixture blocks stand in for shielded scanning; only their block hashes
//! and times are replaced with independent RPC observations. This demonstrates
//! delivery and persistence, not shielded recovery or permission to spend.
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, fs, path::PathBuf, time::Duration};
use transparent::address::TransparentAddress;
use transparent_wallet::{ChainView, StaticChain};
use zakura_pir_transparent::{
    BatchState, HoldCause, HttpExchange, HttpFailure, HttpMethod, HttpReply, HttpRequest,
    PassLimits, PassPlan, Retry, Step, TransparentHistoryRecovery,
    TransparentHistoryRecoveryConfig, Trust, Ungated,
};
use zcash_client_backend::data_api::{
    Account as _,
    chain::ChainState,
    testing::{InitialChainState, TestBuilder, TestRng},
    transparent_ledger::{
        AccountLifecycle, TransactionMetadata, TransparentLedgerMode::PrivateRequired,
        TransparentLedgerRead as _, TransparentLedgerWrite as _, WholeTransactionFee,
    },
};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    testing::{BlockCache, db::TestDbFactory},
    util::SystemClock,
};
use zcash_keys::address::Address;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// Bound on each decoded HTTP response body.
const RESPONSE_LIMIT: usize = 64 * 1024 * 1024;

/// The harness's exchange with the origin: one blocking request at a time, a 30 s
/// deadline, and no retries, as an `HttpExchange` must.
struct Exchange {
    client: reqwest::blocking::Client,
    origin: String,
}

impl HttpExchange for Exchange {
    fn send(&self, request: &HttpRequest) -> Result<HttpReply, HttpFailure> {
        let url = format!("{}{}", self.origin.trim_end_matches('/'), request.path);
        let sending = match request.method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post => self
                .client
                .post(url)
                .header("content-type", "application/octet-stream")
                .body(request.body.clone()),
        };
        let failure = |error: reqwest::Error| {
            if error.is_timeout() {
                HttpFailure::Timeout
            } else {
                HttpFailure::Unreachable
            }
        };
        let response = sending.send().map_err(failure)?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (retry_after, map_sha256) = (header("retry-after"), header("x-txid-map-sha256"));
        let mut body = response.bytes().map_err(failure)?.to_vec();
        if (200..300).contains(&status) {
            if body.len() > request.limit {
                return Err(HttpFailure::TooLarge);
            }
        } else {
            body.truncate(request.error_limit);
        }
        Ok(HttpReply {
            status,
            retry_after,
            map_sha256,
            body,
        })
    }
}

/// Converts a 32-byte RPC display-order hex hash to the wallet's internal order.
/// Rejects malformed hex or a hash of any other length.
fn block_hash(display: &str) -> Result<BlockHash, Box<dyn Error>> {
    let mut bytes = hex::decode(display)?;
    if bytes.len() != 32 {
        return Err("block hash must be 32 bytes".into());
    }
    bytes.reverse();
    Ok(BlockHash::from_slice(&bytes))
}

/// Reads a required unsigned integer from the snapshot; missing or mistyped fields fail.
fn number(value: &Value, key: &str) -> Result<u64, Box<dyn Error>> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("missing {key}").into())
}

/// Borrows a required string from the snapshot; missing or mistyped fields fail.
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}

/// Renders optional transaction metadata while preserving unknown and inapplicable fees.
/// No metadata produces JSON null; an unknown fee never becomes a zero-valued fee.
fn metadata(value: Option<TransactionMetadata>) -> Value {
    value
        .map(|m| {
            json!({
                "fee": match m.fee {
                    WholeTransactionFee::Exact(v) => {
                        json!({"state": "exact", "value": v.into_u64()})
                    },
                    WholeTransactionFee::Unknown => json!({"state": "unknown"}),
                    WholeTransactionFee::NotApplicable => json!({"state": "not-applicable"}),
                },
                "input_count": m.transparent_input_count,
                "shielded": m.has_shielded_components
            })
        })
        .unwrap_or(Value::Null)
}

/// Reconstructs a standard P2PKH or P2SH locking script for the evidence report.
fn locking_script(address: TransparentAddress) -> Vec<u8> {
    match address {
        TransparentAddress::PublicKeyHash(hash) => {
            [vec![0x76, 0xa9, 20], hash.to_vec(), vec![0x88, 0xac]].concat()
        }
        TransparentAddress::ScriptHash(hash) => {
            [vec![0xa9, 20], hash.to_vec(), vec![0x87]].concat()
        }
    }
}

/// Recovers a bounded fixture into fresh evidence files and verifies candidate persistence.
/// Returns an error on invalid input, incomplete recovery, or any unexpected authority;
/// partially written output is retained for inspection.
fn main() -> Result<(), Box<dyn Error>> {
    // 1. Establish the experiment's inputs before creating evidence files.
    // The headers must come from an independent chain source, not a PIR manifest.
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: recover-activity <independent-snapshot.json> <new-output-directory> <origin>"
                .into(),
        );
    }
    let input = fs::read(&args[1])?;
    if input.len() > 2 * 1024 * 1024 {
        return Err("snapshot exceeds 2 MiB".into());
    }
    let snapshot: Value = serde_json::from_slice(&input)?;
    let birthday = u32::try_from(number(&snapshot, "birthday")?)?;
    let through = u32::try_from(number(&snapshot, "through")?)?;
    if birthday == 0 || through < birthday || through - birthday >= 10_000 {
        return Err("bounded snapshot range required".into());
    }
    let headers = snapshot["headers"].as_array().ok_or("missing headers")?;
    if headers.len() != (through - birthday + 2) as usize {
        return Err("complete independent headers including birthday predecessor required".into());
    }
    // This chain view is the independent reference against which recovered
    // shard anchors are checked. Consecutive heights alone are insufficient:
    // the parent hashes must link the supplied observations as well.
    let mut chain = StaticChain {
        hashes: BTreeMap::new(),
    };
    for (index, h) in headers.iter().enumerate() {
        let height = number(h, "height")?;
        if height != u64::from(birthday - 1) + index as u64 {
            return Err("nonconsecutive independent headers".into());
        }
        let hash = text(h, "hash")?;
        block_hash(hash)?;
        if index > 0 && text(h, "previousblockhash")? != text(&headers[index - 1], "hash")? {
            return Err("independent header parent mismatch".into());
        }
        chain.hashes.insert(height, hash.into());
    }
    let scripts = snapshot["scripts"]
        .as_array()
        .ok_or("missing public fixture scripts")?;
    if scripts.is_empty() || scripts.len() > 64 {
        return Err("one to 64 fixture scripts required".into());
    }
    let directory = PathBuf::from(&args[2]);
    fs::create_dir(&directory)?; // Existing evidence must never be overwritten.
    fs::write(directory.join("input-snapshot.json"), &input)?;

    // 2. Build the wallet-side fixture. Empty scanned blocks initialize the
    // wallet's chain state without pretending to recover real shielded notes.
    let mut state = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_block_cache(BlockCache::new())
        .with_initial_chain_state(|_, _| InitialChainState {
            chain_state: ChainState::empty(
                BlockHeight::from(birthday - 1),
                block_hash(chain.hashes.get(&u64::from(birthday - 1)).unwrap()).unwrap(),
            ),
            prior_sapling_roots: vec![],
            prior_orchard_roots: vec![],
        })
        .with_account_having_current_birthday()
        .build();
    state.generate_and_scan_empty_blocks((through - birthday + 1) as usize);
    let account = state.test_account().unwrap().id();
    // Replace fixture placement hashes/times with the independent observations.
    // The remaining scan data is still synthetic, as the report states.
    for h in headers.iter().skip(1) {
        let changed = state.wallet().conn().execute(
            "UPDATE blocks SET hash=?1, time=?2 WHERE height=?3",
            params![
                block_hash(text(h, "hash")?)?.0.as_slice(),
                number(h, "time")?,
                number(h, "height")?
            ],
        )?;
        if changed != 1 {
            return Err("missing scanned fixture block".into());
        }
    }
    // Inject public scripts as watched addresses. This is controlled fixture
    // setup, not an ownership check or an example of importing spend authority.
    for script in scripts {
        let bytes = hex::decode(script.as_str().ok_or("fixture script must be hex")?)?;
        let address = match bytes.as_slice() {
            [0x76, 0xa9, 20, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
                TransparentAddress::PublicKeyHash(hash.try_into()?)
            }
            [0xa9, 20, hash @ .., 0x87] if hash.len() == 20 => {
                TransparentAddress::ScriptHash(hash.try_into()?)
            }
            _ => return Err("fixture requires standard P2PKH/P2SH locking scripts".into()),
        };
        let encoded = Address::Transparent(address).encode(state.network());
        state.wallet().conn().execute("INSERT INTO addresses
            (account_id,key_scope,address,cached_transparent_receiver_address,receiver_flags,imported_transparent_receiver_script)
            SELECT id,-1,?1,?1,1,?2 FROM accounts WHERE uuid=?3",
            params![encoded,bytes,account.expose_uuid().as_bytes().as_slice()])?;
    }
    // 3. Require private recovery, while keeping the account a candidate.
    // Policy is durable; the handle mode is also configured explicitly.
    let db = state.wallet_mut().db_mut();
    db.apply_transparent_policy(PrivateRequired)?;
    db.set_transparent_ledger_mode(PrivateRequired);
    let origin = &args[3];
    let config = TransparentHistoryRecoveryConfig {
        source: b"activity-v11-public-script-shadow-harness".to_vec(),
        account_binding: account.expose_uuid().as_bytes().to_vec(),
        origin: origin.clone(),
        scripts: 512,
        shards: 128,
        events: 100_000,
        queries: 10_000,
        private_bytes: 512 * 1024 * 1024,
    };
    let companion_path = directory.join("reference.sqlite");
    let mut reference = TransparentHistoryRecovery::open(&companion_path, config.clone())?;

    // 4. Supply the network boundary. The adapter receives an exchange rather
    // than choosing a route. This one sends one request at a time, with a
    // bounded body and timeout, and never retries. Use a controlled capture
    // proxy as the origin to inspect the actual traffic.
    let exchange = Exchange {
        client: reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
        origin: origin.clone(),
    };

    // 5. Retrieve, validate, save, and acknowledge in that order, as the
    // library's pass plan says. The plan reads a fresh watch set after each
    // settlement, so it includes any address-window growth from earlier
    // commits. Commits are only observed: this harness never qualifies, so a
    // batch listing retired revisions, which only trusted reconciliation
    // resolves, holds the account and fails the run.
    let mut plan = PassPlan::new(
        state.wallet().db().transparent_watch_set(account)?,
        PassLimits::default(),
    );
    let mut step = plan.first();
    let mut passes = vec![];
    let mut last = None;
    loop {
        match step {
            Step::Pass | Step::Refresh => {}
            Step::Wait(wait) => std::thread::sleep(wait),
            Step::Done(_) => break,
            Step::Hold(HoldCause::Withdrawn(cause)) => {
                return Err(format!("publication withdrawn: {cause:?}").into());
            }
            Step::Hold(HoldCause::Unreconciled) => {
                return Err(
                    "frozen fixture unexpectedly requires trusted revision reconciliation".into(),
                );
            }
            other => return Err(format!("recovery stopped: {other:?}").into()),
        }
        let watch = plan.watch();
        if watch.target.unwrap().height != BlockHeight::from(through)
            || chain.is_accepted(u64::from(through), &watch.target.unwrap().hash.to_string())
                != transparent_wallet::Acceptance::Accepted
        {
            return Err("wallet target differs from independent chain".into());
        }
        // Retrieval updates the companion, not wallet balances. The catalog
        // permits commits only when publication continuity is Ready, and the
        // pass holds only a Ready batch.
        let report = reference.pass(watch, &chain, &exchange, RESPONSE_LIMIT, &|| false)?;
        let mut receives = 0;
        let mut spends = 0;
        for commit in reference
            .latest::<AccountUuid>()
            .map_or(&[][..], |batch| batch.commits())
        {
            receives += commit.receives.len();
            spends += commit.spends.len();
            if commit.receives.iter().any(|e| e.metadata.is_none())
                || commit.spends.iter().any(|e| e.metadata.is_none())
            {
                return Err("v11 event missing metadata".into());
            }
        }
        // The ordinary writer rechecks the captured account, policy, and chain
        // context for every commit. Observed commits are stored as candidate
        // evidence without qualifying the publisher or projecting these events
        // into usable funds; the batch is acknowledged once every one applied.
        let settled =
            reference.settle_latest(state.wallet_mut().db_mut(), Trust::Observed, &mut Ungated);
        let grew = matches!(&settled, Ok(Some(applied)) if applied.stats.window_grew);
        passes.push(json!({
            "pass": passes.len(),
            "state": format!("{:?}", report.state),
            "receives": receives,
            "spends": spends,
            "covered_through": report.progress.covered_through,
            "outcome": format!("{:?}", report.progress.outcome),
            "window_grew": grew,
            "publication_changed": report.publication_changed
        }));
        step = plan.next(
            &report,
            &settled,
            state.wallet().db().transparent_watch_set(account)?,
        );
        if step == Step::Fail {
            return Err(settled.unwrap_err().into());
        }
        last = Some(report);
        // Reopening the companion tests saved continuation and catalog history.
        // It is not recreated: recreating would discard continuity evidence.
        drop(reference);
        reference = TransparentHistoryRecovery::open(&companion_path, config.clone())?;
    }
    if step != Step::Done(Some(Retry::Complete))
        || last.is_none_or(|report| {
            report.state != BatchState::Ready
                || report.progress.covered_through < u64::from(through)
        })
    {
        return Err("recovery did not complete within eight bounded passes".into());
    }

    // 6. Verify the wallet's durable result, independently of the live handle.
    // Require real events so a successful empty lookup cannot pass this harness.
    let before = state
        .wallet()
        .db()
        .transparent_candidate_recovery(account)?;
    if before.receives.is_empty() && before.spends.is_empty() {
        return Err("nonempty real recovery required".into());
    }
    let wallet_path = directory.join("wallet.sqlite");
    // VACUUM INTO copies a consistent SQLite database. Reopening that copy
    // checks persistence without carrying the original connection's state.
    state.wallet().conn().execute(
        "VACUUM INTO ?1",
        [wallet_path.to_str().ok_or("invalid wallet path")?],
    )?;
    let reopened = WalletDb::from_connection(
        Connection::open(&wallet_path)?,
        *state.network(),
        SystemClock,
        TestRng::seed_from_u64(0),
    )
    .with_transparent_ledger_mode(PrivateRequired);
    let after = reopened.transparent_candidate_recovery(account)?;
    if before != after {
        return Err("library SQLite reopen changed candidate facts".into());
    }
    // Complete retrieval is not qualification or activation. These assertions
    // make that distinction observable in both the API and persisted tables.
    if reopened.transparent_watch_set(account)?.lifecycle != AccountLifecycle::Candidate {
        return Err("harness unexpectedly activated account".into());
    }
    let conn = Connection::open(&wallet_path)?;
    for table in ["tpir_qualified_revisions", "tpir_active_accounts"] {
        let count: i64 =
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        if count != 0 {
            return Err("metadata delivery granted authority".into());
        }
    }
    let reader: i64 = conn.query_row(
        "SELECT min_reader_version FROM tpir_meta WHERE id=0",
        [],
        |r| r.get(0),
    )?;
    if reader != 7 {
        return Err("metadata reader fence missing".into());
    }

    // 7. Export facts and their limitations. Whole-transaction metadata is
    // separate from the owned receive/spend effects; it does not identify a
    // sender, external recipient, or the account's share of a fee.
    let receives: Vec<_> = after
        .receives
        .iter()
        .map(|e| {
            json!({
                "txid": e.outpoint.txid().to_string(),
                "output_index": e.outpoint.n(),
                "script": hex::encode(locking_script(e.address)),
                "value": e.value.into_u64(),
                "coinbase": e.coinbase,
                "height": u32::from(e.mined_height),
                "metadata": metadata(e.metadata)
            })
        })
        .collect();
    let spends: Vec<_> = after
        .spends
        .iter()
        .map(|e| {
            json!({
                "txid": e.spending_txid.to_string(),
                "input_index": e.input_index,
                "prevout_txid": e.prevout.txid().to_string(),
                "prevout_index": e.prevout.n(),
                "script": hex::encode(locking_script(e.prevout_address)),
                "height": u32::from(e.mined_height),
                "metadata": metadata(e.metadata)
            })
        })
        .collect();
    let report = json!({
        "schema": "activity-library-shadow-recovery-v1",
        "birthday": birthday,
        "through": through,
        "fixture_scripts": scripts,
        "independent_headers": headers.len(),
        "passes": passes,
        "receives": receives,
        "spends": spends,
        "reopened_equal": true,
        "qualified_revisions": 0,
        "active_accounts": 0,
        "reader_version": reader,
        "pending_pages": after.pending_pages,
        "unresolved_spends": after.unresolved_spends,
        "limitation": "Public scripts stand in for ownership; shielded scan is a controlled empty-block fixture. No account activation or financial authority."
    });
    fs::write(
        directory.join("result.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "recovered {} receives and {} spends; SQLite reopen agrees; account remains a candidate",
        after.receives.len(),
        after.spends.len()
    );
    Ok(())
}
