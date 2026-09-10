//! Reading a shadow-validation profile without touching it, and comparing
//! what it holds with an independent reconstruction.
//!
//! A shadow profile is a wallet the application syncs for comparison only.
//! Its store is opened here read-only and immutable — never through the
//! wallet's own database type, which runs schema statements and switches the
//! journal mode on open — and nothing in this module knows a network address,
//! so a comparison can neither repair the profile nor consult a service. The
//! reconstruction it is compared with comes from the caller: blocks read by
//! code that shares nothing with the ledger.
//!
//! What leaves this module for a record is counts and digests. The snapshot
//! itself names outpoints and heights and is written only where the caller
//! asks, outside any evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use transparent_events::TransparentEvent;

/// The application's namespace, as its profile markers state it.
pub const NAMESPACE: &str = "org.valargroup.zakura-recovery-beta";

/// Why a profile could not be read or compared.
#[derive(Debug)]
pub enum ShadowError {
    /// The directory is not marked as a shadow validation profile.
    NotShadow(PathBuf, String),
    /// The profile's write-ahead log is not empty: something has it open.
    Busy(PathBuf),
    /// The store could not be read.
    Read(PathBuf, String),
    /// A stored event would not decode.
    Corrupt(String),
    /// Anything else.
    Io(String),
}

impl std::fmt::Display for ShadowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShadowError::NotShadow(path, why) => {
                write!(
                    f,
                    "{} is not a shadow validation profile: {why}",
                    path.display()
                )
            }
            ShadowError::Busy(path) => write!(
                f,
                "{} is in use: its write-ahead log is not empty; close the application first",
                path.display()
            ),
            ShadowError::Read(path, why) => write!(f, "reading {}: {why}", path.display()),
            ShadowError::Corrupt(why) => write!(f, "a stored event would not decode: {why}"),
            ShadowError::Io(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for ShadowError {}

/// One recovered output, keyed by outpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveFact {
    /// SHA-256 of the script, so the snapshot names no address.
    pub script_sha256: String,
    /// The output's value in zatoshis.
    pub value: u64,
    /// The height it was created at.
    pub height: u32,
    /// The creating transaction's index in its block.
    pub transaction_index: u16,
    /// Whether it is a coinbase output.
    pub coinbase: bool,
}

/// One spend of a recovered output, keyed by the outpoint it consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendFact {
    /// SHA-256 of the script the spend was indexed under: the consumed
    /// output's.
    pub script_sha256: String,
    /// The consuming transaction, in display hex.
    pub spending_txid: String,
    /// Its index in its block.
    pub transaction_index: u16,
    /// Which of its inputs.
    pub input_index: u32,
    /// The height it was mined at.
    pub height: u32,
}

/// What a transparent ledger holds, in a form two sources can produce.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ShadowSnapshot {
    /// The height the ledger accepted as the end of complete coverage.
    pub anchor_height: Option<u32>,
    /// That block's hash, in display hex.
    pub anchor_hash: Option<String>,
    /// Why the last sync stopped, in the ledger's words.
    pub completion: Option<String>,
    /// Keyed by `txid:index`, txid in display hex.
    pub receives: BTreeMap<String, ReceiveFact>,
    /// Keyed by the consumed `txid:index`.
    pub spends: BTreeMap<String, SpendFact>,
}

fn outpoint(txid: &[u8; 32], index: u32) -> String {
    let mut display = *txid;
    display.reverse();
    format!("{}:{index}", hex::encode(display))
}

impl ShadowSnapshot {
    /// Outpoints received and not spent.
    pub fn utxos(&self) -> BTreeSet<&String> {
        self.receives
            .keys()
            .filter(|k| !self.spends.contains_key(*k))
            .collect()
    }

    /// The value of every unspent output.
    pub fn balance(&self) -> u64 {
        self.utxos()
            .into_iter()
            .map(|k| self.receives[k].value)
            .sum()
    }

    /// Spends whose consumed output the snapshot does not hold.
    pub fn unresolved(&self) -> usize {
        self.spends
            .keys()
            .filter(|k| !self.receives.contains_key(*k))
            .count()
    }

    /// Whether the last run completed to its target.
    pub fn is_complete(&self) -> bool {
        self.completion.as_deref() == Some("complete")
    }

    /// A digest over everything the snapshot holds, in a fixed order.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"shadow-snapshot-v2\n");
        hasher.update(format!(
            "anchor {:?} {:?}\n",
            self.anchor_height, self.anchor_hash
        ));
        for (k, r) in &self.receives {
            hasher.update(format!(
                "R {k} {} {} {} {} {}\n",
                r.script_sha256, r.value, r.height, r.transaction_index, r.coinbase
            ));
        }
        for (k, s) in &self.spends {
            hasher.update(format!(
                "S {k} {} {} {} {} {}\n",
                s.script_sha256, s.spending_txid, s.transaction_index, s.input_index, s.height
            ));
        }
        hex::encode(hasher.finalize())
    }

    /// Adds one event as the ledger indexes it, refusing a second event for
    /// an outpoint already held: a snapshot that overwrote would hide a
    /// contradiction.
    pub fn add_event(
        &mut self,
        script: &[u8],
        event: &TransparentEvent,
    ) -> Result<(), ShadowError> {
        match event {
            TransparentEvent::Receive(r) => {
                let key = outpoint(&r.txid.0, r.output_index);
                let fact = ReceiveFact {
                    script_sha256: hex::encode(Sha256::digest(script)),
                    value: r.value,
                    height: r.height,
                    transaction_index: r.transaction_index,
                    coinbase: r.coinbase,
                };
                if self.receives.insert(key, fact).is_some() {
                    return Err(ShadowError::Corrupt(
                        "an outpoint was received twice".into(),
                    ));
                }
            }
            TransparentEvent::Spend(s) => {
                let key = outpoint(&s.spent_txid.0, s.spent_output_index);
                let fact = SpendFact {
                    script_sha256: hex::encode(Sha256::digest(script)),
                    spending_txid: {
                        let mut d = s.spending_txid.0;
                        d.reverse();
                        hex::encode(d)
                    },
                    transaction_index: s.transaction_index,
                    input_index: s.input_index,
                    height: s.height,
                };
                if self.spends.insert(key, fact).is_some() {
                    return Err(ShadowError::Corrupt("an outpoint was spent twice".into()));
                }
            }
        }
        Ok(())
    }
}

/// Reads the marker a beta profile carries and refuses anything but a
/// shadow validation profile. Nothing else in the directory is opened.
pub fn check_marker(profile: &Path) -> Result<(), ShadowError> {
    let marker = profile.join("profile.json");
    let text = std::fs::read_to_string(&marker)
        .map_err(|e| ShadowError::NotShadow(profile.to_path_buf(), format!("no marker: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| ShadowError::NotShadow(profile.to_path_buf(), format!("bad marker: {e}")))?;
    let field = |name: &str| value[name].as_str().unwrap_or_default().to_owned();
    if field("namespace") != NAMESPACE {
        return Err(ShadowError::NotShadow(
            profile.to_path_buf(),
            "the marker names another application".into(),
        ));
    }
    if field("mode") != "shadow" {
        return Err(ShadowError::NotShadow(
            profile.to_path_buf(),
            format!("the marker names mode {:?}", field("mode")),
        ));
    }
    Ok(())
}

/// Reads the profile's ledger without opening it for writing.
///
/// The cache database is opened read-only and immutable: SQLite neither
/// takes a lock nor creates a journal. That is only correct when nothing
/// else has the database open, which is why a non-empty write-ahead log is
/// refused rather than read around.
pub fn read_shadow_snapshot(profile: &Path) -> Result<ShadowSnapshot, ShadowError> {
    check_marker(profile)?;
    let cache = profile.join("cache.db");
    for suffix in ["-wal", "-shm"] {
        let side = profile.join(format!("cache.db{suffix}"));
        if std::fs::metadata(&side).is_ok_and(|meta| meta.len() > 0) {
            return Err(ShadowError::Busy(profile.to_path_buf()));
        }
    }
    let uri = format!("file:{}?mode=ro&immutable=1", cache.display());
    let conn = rusqlite::Connection::open_with_flags(
        &uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| ShadowError::Read(cache.clone(), e.to_string()))?;
    let read = |e: rusqlite::Error| ShadowError::Read(cache.clone(), e.to_string());

    let mut snapshot = ShadowSnapshot::default();
    let set: Option<(Option<u32>, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT anchor_height, anchor_hash, completion FROM transparent_set WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(read)?;
    if let Some((height, hash, completion)) = set {
        snapshot.anchor_height = height;
        snapshot.anchor_hash = hash;
        snapshot.completion = completion;
    }
    for table in ["transparent_receive_events", "transparent_spend_events"] {
        let mut stmt = conn
            .prepare(&format!("SELECT script, event FROM {table}"))
            .map_err(read)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(read)?;
        for row in rows {
            let (script, record) = row.map_err(read)?;
            let event = TransparentEvent::from_bytes(&record)
                .map_err(|e| ShadowError::Corrupt(e.to_string()))?;
            snapshot.add_event(&script, &event)?;
        }
    }
    Ok(snapshot)
}

/// How two snapshots differ.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Comparison {
    /// Whether the profile's last run completed, the two agree on the anchor
    /// and on every event, and neither holds a spend the other resolves.
    pub equal: bool,
    /// Whether the profile's last run completed to its target.
    pub complete: bool,
    /// Whether the anchors agree.
    pub anchor_equal: bool,
    /// Expected receives the profile lacks, by outpoint.
    pub missing_receives: Vec<String>,
    /// Receives the profile holds that were not expected.
    pub extra_receives: Vec<String>,
    /// Receives both hold with differing contents.
    pub differing_receives: Vec<String>,
    /// Expected spends the profile lacks, by consumed outpoint.
    pub missing_spends: Vec<String>,
    /// Spends the profile holds that were not expected.
    pub extra_spends: Vec<String>,
    /// Spends both hold with differing contents.
    pub differing_spends: Vec<String>,
    /// What the profile holds.
    pub actual: ShadowSnapshot,
    /// What it was expected to hold.
    pub expected: ShadowSnapshot,
}

/// What a comparison may say in a record: counts and digests, never an
/// outpoint, a script or a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedReport {
    /// `equal` or `differs`.
    pub result: String,
    /// The digest of what the profile holds.
    pub actual_digest: String,
    /// The digest of what was expected.
    pub expected_digest: String,
    /// The profile's accepted anchor height.
    pub anchor_height: Option<u32>,
    /// Why the profile's last sync stopped.
    pub completion: Option<String>,
    /// Whether that sync completed to its target.
    pub complete: bool,
    /// Spends the profile holds whose receive it does not.
    pub actual_unresolved: usize,
    /// Spends expected without a receive expected.
    pub expected_unresolved: usize,
    /// Receives the profile holds.
    pub actual_receives: usize,
    /// Receives expected.
    pub expected_receives: usize,
    /// Spends the profile holds.
    pub actual_spends: usize,
    /// Spends expected.
    pub expected_spends: usize,
    /// Unspent outputs the profile holds.
    pub actual_utxos: usize,
    /// Unspent outputs expected.
    pub expected_utxos: usize,
    /// How many expected receives are missing.
    pub missing_receives: usize,
    /// How many receives were not expected.
    pub extra_receives: usize,
    /// How many receives differ in contents.
    pub differing_receives: usize,
    /// How many expected spends are missing.
    pub missing_spends: usize,
    /// How many spends were not expected.
    pub extra_spends: usize,
    /// How many spends differ in contents.
    pub differing_spends: usize,
    /// Whether the anchors agree.
    pub anchor_equal: bool,
    /// Whether the balances agree.
    pub balance_equal: bool,
}

/// Compares what a profile holds with what it was expected to hold.
pub fn compare(actual: &ShadowSnapshot, expected: &ShadowSnapshot) -> Comparison {
    let mut c = Comparison {
        actual: actual.clone(),
        expected: expected.clone(),
        ..Comparison::default()
    };
    for (k, e) in &expected.receives {
        match actual.receives.get(k) {
            None => c.missing_receives.push(k.clone()),
            Some(a) if a != e => c.differing_receives.push(k.clone()),
            Some(_) => {}
        }
    }
    for k in actual.receives.keys() {
        if !expected.receives.contains_key(k) {
            c.extra_receives.push(k.clone());
        }
    }
    for (k, e) in &expected.spends {
        match actual.spends.get(k) {
            None => c.missing_spends.push(k.clone()),
            Some(a) if a != e => c.differing_spends.push(k.clone()),
            Some(_) => {}
        }
    }
    for k in actual.spends.keys() {
        if !expected.spends.contains_key(k) {
            c.extra_spends.push(k.clone());
        }
    }
    c.anchor_equal = actual.anchor_height == expected.anchor_height
        && (expected.anchor_hash.is_none() || actual.anchor_hash == expected.anchor_hash);
    c.complete = actual.is_complete();
    c.equal = c.complete
        && c.anchor_equal
        && actual.unresolved() == expected.unresolved()
        && c.missing_receives.is_empty()
        && c.extra_receives.is_empty()
        && c.differing_receives.is_empty()
        && c.missing_spends.is_empty()
        && c.extra_spends.is_empty()
        && c.differing_spends.is_empty();
    c
}

impl Comparison {
    /// The comparison as a record may carry it.
    pub fn sanitized(&self) -> SanitizedReport {
        SanitizedReport {
            result: if self.equal {
                "equal".into()
            } else {
                "differs".into()
            },
            actual_digest: self.actual.digest(),
            expected_digest: self.expected.digest(),
            anchor_height: self.actual.anchor_height,
            completion: self.actual.completion.clone(),
            complete: self.complete,
            actual_unresolved: self.actual.unresolved(),
            expected_unresolved: self.expected.unresolved(),
            actual_receives: self.actual.receives.len(),
            expected_receives: self.expected.receives.len(),
            actual_spends: self.actual.spends.len(),
            expected_spends: self.expected.spends.len(),
            actual_utxos: self.actual.utxos().len(),
            expected_utxos: self.expected.utxos().len(),
            missing_receives: self.missing_receives.len(),
            extra_receives: self.extra_receives.len(),
            differing_receives: self.differing_receives.len(),
            missing_spends: self.missing_spends.len(),
            extra_spends: self.extra_spends.len(),
            differing_spends: self.differing_spends.len(),
            anchor_equal: self.anchor_equal,
            balance_equal: self.actual.balance() == self.expected.balance(),
        }
    }

    /// Everything, for a local file that is not evidence.
    pub fn detail(&self) -> serde_json::Value {
        serde_json::json!({
            "equal": self.equal,
            "anchor_equal": self.anchor_equal,
            "missing_receives": self.missing_receives,
            "extra_receives": self.extra_receives,
            "differing_receives": self.differing_receives,
            "missing_spends": self.missing_spends,
            "extra_spends": self.extra_spends,
            "differing_spends": self.differing_spends,
            "actual": self.actual,
            "expected": self.expected,
        })
    }
}

/// SHA-256 of every regular file under `dir`, by relative path.
pub fn tree_digests(dir: &Path) -> Result<BTreeMap<String, String>, ShadowError> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current).map_err(|e| ShadowError::Io(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| ShadowError::Io(e.to_string()))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let bytes = std::fs::read(&path).map_err(|e| ShadowError::Io(e.to_string()))?;
                let rel = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                out.insert(rel, hex::encode(Sha256::digest(&bytes)));
            }
        }
    }
    Ok(out)
}

/// The whole comparison as the command runs it.
///
/// Refuses a profile that is not a shadow profile before opening anything;
/// digests every file under the profile and under every `untouched`
/// directory before and after, and reports failure if any changed; writes
/// the sanitized report to `report` and, only if asked, the full detail to
/// `detail`. Returns the process exit status: 0 equal, 1 differs, 3 not a
/// shadow profile, 4 busy, 5 something changed, 2 other error.
pub fn run_compare(
    profile: &Path,
    expected: &Path,
    report: &Path,
    detail: Option<&Path>,
    untouched: &[PathBuf],
) -> Result<i32, ShadowError> {
    check_marker(profile)?;
    let before: Vec<_> = std::iter::once(profile.to_path_buf())
        .chain(untouched.iter().cloned())
        .map(|dir| tree_digests(&dir))
        .collect::<Result<_, _>>()?;
    let expected_text =
        std::fs::read_to_string(expected).map_err(|e| ShadowError::Io(e.to_string()))?;
    let expected: ShadowSnapshot =
        serde_json::from_str(&expected_text).map_err(|e| ShadowError::Io(e.to_string()))?;
    let actual = read_shadow_snapshot(profile)?;
    let comparison = compare(&actual, &expected);
    let after: Vec<_> = std::iter::once(profile.to_path_buf())
        .chain(untouched.iter().cloned())
        .map(|dir| tree_digests(&dir))
        .collect::<Result<_, _>>()?;
    if before != after {
        return Ok(5);
    }
    let sanitized = serde_json::to_string_pretty(&comparison.sanitized())
        .map_err(|e| ShadowError::Io(e.to_string()))?;
    std::fs::write(report, format!("{sanitized}\n")).map_err(|e| ShadowError::Io(e.to_string()))?;
    if let Some(detail_path) = detail {
        let text = serde_json::to_string_pretty(&comparison.detail())
            .map_err(|e| ShadowError::Io(e.to_string()))?;
        std::fs::write(detail_path, format!("{text}\n"))
            .map_err(|e| ShadowError::Io(e.to_string()))?;
    }
    Ok(if comparison.equal { 0 } else { 1 })
}

impl ShadowError {
    /// The exit status this error means.
    pub fn exit_code(&self) -> i32 {
        match self {
            ShadowError::NotShadow(..) => 3,
            ShadowError::Busy(..) => 4,
            _ => 2,
        }
    }
}
