//! Headless real-HTTP recovery into a controlled SQLite wallet, as an unpromoted candidate.
//!
//! Public chain scripts are injected as fixture watches, without claiming their
//! keys. Shielded scanning uses empty fixture blocks. Independently collected RPC
//! headers bind transparent anchors. This is delivery evidence, not promotion,
//! shielded recovery, or authority to spend any chain funds.
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, fs, path::PathBuf, time::Duration};
use transparent::address::TransparentAddress;
use transparent_wallet::http::{HttpFilterSource, HttpOptions, HttpShardTransport};
use transparent_wallet::{ChainView, StaticChain};
use zakura_pir_transparent::{BatchState, RecoveryConfig, ReferenceRecovery};
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
    WalletDb,
    testing::{BlockCache, db::TestDbFactory},
    util::SystemClock,
};
use zcash_keys::address::Address;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

/// Bound on each decoded HTTP response body.
const RESPONSE_LIMIT: usize = 64 * 1024 * 1024;

fn block_hash(display: &str) -> Result<BlockHash, Box<dyn Error>> {
    let mut bytes = hex::decode(display)?;
    if bytes.len() != 32 {
        return Err("block hash must be 32 bytes".into());
    }
    bytes.reverse();
    Ok(BlockHash::from_slice(&bytes))
}
fn number(value: &Value, key: &str) -> Result<u64, Box<dyn Error>> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}
fn metadata(value: Option<TransactionMetadata>) -> Value {
    value
        .map(|m| {
            json!({"fee": match m.fee {
        WholeTransactionFee::Exact(v) => json!({"state":"exact", "value":v.into_u64()}),
        WholeTransactionFee::Unknown => json!({"state":"unknown"}),
        WholeTransactionFee::NotApplicable => json!({"state":"not-applicable"}),
    }, "input_count":m.transparent_input_count, "shielded":m.has_shielded_components})
        })
        .unwrap_or(Value::Null)
}
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
fn main() -> Result<(), Box<dyn Error>> {
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
    let db = state.wallet_mut().db_mut();
    db.apply_transparent_policy(PrivateRequired)?;
    db.set_transparent_ledger_mode(PrivateRequired);
    let origin = &args[3];
    let config = RecoveryConfig {
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
    let mut reference = ReferenceRecovery::open(&companion_path, config.clone())?;
    // The adapter takes the caller's transports; this harness uses the reference
    // HTTP clients, one request at a time with bounded transient retries.
    let options = HttpOptions {
        timeout: Duration::from_secs(30),
        ..HttpOptions::default()
    };
    let mut filters = HttpFilterSource::new(origin, &options)
        .map_err(|error| error as Box<dyn Error>)?
        .with_response_limit(RESPONSE_LIMIT)
        .with_prefetch_concurrency(1)
        .with_transient_retry_attempts(3);
    let mut transport = HttpShardTransport::new(origin, &options)
        .map_err(|error| error as Box<dyn Error>)?
        .with_response_limit(RESPONSE_LIMIT)
        .with_concurrency(1)
        .with_transient_retry_attempts(3);
    let mut passes = vec![];
    let mut finished = false;
    for pass in 0..8 {
        let watch = state.wallet().db().transparent_watch_set(account)?;
        if watch.target.unwrap().height != BlockHeight::from(through)
            || chain.is_accepted(u64::from(through), &watch.target.unwrap().hash.to_string())
                != transparent_wallet::Acceptance::Accepted
        {
            return Err("wallet target differs from independent chain".into());
        }
        let batch = reference.recover(&watch, &chain, &mut filters, &mut transport)?;
        if let BatchState::Withdrawn(cause) = batch.state() {
            return Err(format!("publication withdrawn: {cause:?}").into());
        }
        // Only the wallet's trusted operation resolves retired revisions, and only
        // `apply_and_acknowledge` with trusted commits (feature `sqlite`)
        // acknowledges a batch listing them. This harness
        // never qualifies, so it stops before applying such a batch and leaves
        // the notifications in the companion.
        if !batch.retired_revisions().is_empty() {
            return Err(
                "frozen fixture unexpectedly requires trusted revision reconciliation".into(),
            );
        }
        let mut grew = false;
        let mut receives = 0;
        let mut spends = 0;
        for commit in batch.commits() {
            receives += commit.receives.len();
            spends += commit.spends.len();
            if commit.receives.iter().any(|e| e.metadata.is_none())
                || commit.spends.iter().any(|e| e.metadata.is_none())
            {
                return Err("v11 event missing metadata".into());
            }
            grew |= state
                .wallet_mut()
                .db_mut()
                .apply_transparent_ledger_commit(commit.clone())?
                .window_grew;
        }
        // A `Pending` batch has no commits and is not acknowledged. A `Ready` one
        // without retirements is acknowledged once every commit applied.
        if batch.state() == BatchState::Ready {
            reference.acknowledge_applied(&batch)?;
        }
        passes.push(json!({"pass":pass,"state":format!("{:?}",batch.state()),"receives":receives,"spends":spends,
            "covered_through":batch.progress().covered_through,"outcome":format!("{:?}",batch.progress().outcome),"window_grew":grew}));
        // Exercise durable companion reopen between passes.
        drop(reference);
        reference = ReferenceRecovery::open(&companion_path, config.clone())?;
        if batch.state() == BatchState::Ready
            && !grew
            && batch.progress().covered_through >= u64::from(through)
        {
            finished = true;
            break;
        }
    }
    if !finished {
        return Err("recovery did not complete within eight bounded passes".into());
    }
    let before = state
        .wallet()
        .db()
        .transparent_candidate_recovery(account)?;
    if before.receives.is_empty() && before.spends.is_empty() {
        return Err("nonempty real recovery required".into());
    }
    let wallet_path = directory.join("wallet.sqlite");
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
    let receives:Vec<_> = after.receives.iter().map(|e| json!({"txid":e.outpoint.txid().to_string(),"output_index":e.outpoint.n(),
        "script":hex::encode(locking_script(e.address)),"value":e.value.into_u64(),"coinbase":e.coinbase,"height":u32::from(e.mined_height),"metadata":metadata(e.metadata)})).collect();
    let spends:Vec<_> = after.spends.iter().map(|e| json!({"txid":e.spending_txid.to_string(),"input_index":e.input_index,
        "prevout_txid":e.prevout.txid().to_string(),"prevout_index":e.prevout.n(),"script":hex::encode(locking_script(e.prevout_address)),
        "height":u32::from(e.mined_height),"metadata":metadata(e.metadata)})).collect();
    let report = json!({"schema":"activity-library-shadow-recovery-v1","birthday":birthday,"through":through,"fixture_scripts":scripts,
        "independent_headers":headers.len(),"passes":passes,"receives":receives,"spends":spends,
        "reopened_equal":true,"qualified_revisions":0,"active_accounts":0,"reader_version":reader,
        "pending_pages":after.pending_pages,"unresolved_spends":after.unresolved_spends,
        "limitation":"Public scripts stand in for ownership; shielded scan is a controlled empty-block fixture. No account promotion or financial authority."});
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
