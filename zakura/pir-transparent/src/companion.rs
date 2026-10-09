//! Where a wallet's companions live, and who may use one.
//!
//! A [`CompanionDir`] holds one wallet's companions, one per account and
//! origin: `{account}-{tag}.sqlite`, where the tag is sixteen hex digits of
//! `sha256(origin || 0 || SCHEMA)`, so another origin or schema names another
//! companion rather than failing the open. Each companion has a lock file
//! beside it, `{account}-{tag}.lock`. An open companion holds an operating
//! system lock on it for its whole life, so no other handle, in this process
//! or another, opens or deletes the companion meanwhile.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::recovery::{RecoveryConfig, RecoveryError, ReferenceRecovery, SCHEMA};

/// SQLite files a companion may leave, after its base name.
const FILES: [&str; 4] = ["", "-wal", "-shm", "-journal"];
const EXTENSION: &str = ".sqlite";
const LOCK: &str = ".lock";
/// Hex digits of a companion's tag.
const TAG: usize = 16;
/// How often a wait for a companion's lock polls it.
const WAIT_STEP: Duration = Duration::from_millis(10);

/// The directory holding one wallet's companions.
///
/// Accounts are named by the caller: a nonempty name of at most 64 ASCII
/// letters, digits, `-` and `_`, such as a hyphenated UUID. Each account's
/// companion for an origin is opened, and deleted, only under its lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompanionDir {
    path: PathBuf,
}

/// An open companion and the lock it holds until dropped.
pub struct Companion {
    recovery: ReferenceRecovery,
    _lock: File,
}

impl Deref for Companion {
    type Target = ReferenceRecovery;

    fn deref(&self) -> &ReferenceRecovery {
        &self.recovery
    }
}

impl DerefMut for Companion {
    fn deref_mut(&mut self) -> &mut ReferenceRecovery {
        &mut self.recovery
    }
}

/// Why [`CompanionDir::open`] opened nothing.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The account name is not one a companion file can carry.
    #[error("companion: invalid account name")]
    Account,
    /// Another handle held the companion until the caller stopped waiting.
    #[error("companion: in use")]
    Busy,
    /// The directory or the lock file could not be used.
    #[error("companion: {0}")]
    Io(#[from] io::Error),
    /// The adapter refused the companion; see [`ReferenceRecovery::open`].
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
}

impl CompanionDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The companion file of `account` for `origin`.
    pub fn companion_path(&self, account: &str, origin: &str) -> PathBuf {
        self.path
            .join(format!("{account}-{}{EXTENSION}", tag(origin)))
    }

    /// Opens `account`'s companion for `config.origin`, creating the directory
    /// and the companion on first use, and holds its lock until the companion
    /// is dropped.
    ///
    /// First deletes the companions nobody holds of `account` for other
    /// origins or schemas, and of accounts not in `accounts`, the wallet's
    /// current accounts. Waits for a companion another handle holds while
    /// `keep_waiting` returns true, then fails with [`OpenError::Busy`].
    pub fn open(
        &self,
        account: &str,
        config: RecoveryConfig,
        accounts: &BTreeSet<String>,
        keep_waiting: &dyn Fn() -> bool,
    ) -> Result<Companion, OpenError> {
        if !valid_account(account) {
            return Err(OpenError::Account);
        }
        std::fs::create_dir_all(&self.path)?;
        let path = self.companion_path(account, &config.origin);
        for (owner, base) in self.companions()? {
            if base != path && (owner == account || !accounts.contains(&owner)) {
                // One in use is left for a later open or sweep.
                let _ = remove_unless_held(&base);
            }
        }
        let lock = lock(&path, keep_waiting)?.ok_or(OpenError::Busy)?;
        Ok(Companion {
            recovery: ReferenceRecovery::open(&path, config)?,
            _lock: lock,
        })
    }

    /// Deletes every companion of `account`, waiting at most `wait` for each
    /// one another handle holds. A missing directory has none.
    pub fn remove(&self, account: &str, wait: Duration) -> io::Result<()> {
        let deadline = Instant::now() + wait;
        for (_, base) in self
            .companions_or_none()?
            .into_iter()
            .filter(|(owner, _)| owner == account)
        {
            let _lock = lock(&base, &|| Instant::now() < deadline)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "companion in use"))?;
            remove_files(&base)?;
        }
        Ok(())
    }

    /// Deletes the companions of accounts that `accounts` does not return,
    /// skipping any another handle holds.
    ///
    /// Lists the companions before calling `accounts`, so a companion created
    /// for an account added meanwhile is never taken for an orphan. Attempts
    /// every orphan, then returns the first failure; failing to read the
    /// accounts deletes nothing. A missing directory has nothing to delete.
    pub fn retain(
        &self,
        accounts: impl FnOnce() -> io::Result<BTreeSet<String>>,
    ) -> io::Result<()> {
        let found = self.companions_or_none()?;
        if found.is_empty() {
            return Ok(());
        }
        let accounts = accounts()?;
        let mut first_error = None;
        for (_, base) in found
            .into_iter()
            .filter(|(owner, _)| !accounts.contains(owner))
        {
            if let Err(error) = remove_unless_held(&base) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// The companions in the directory, by owning account and companion file
    /// path. Each is listed once, whether its file, a SQLite sidecar or only
    /// its lock file remains.
    fn companions(&self) -> io::Result<BTreeSet<(String, PathBuf)>> {
        let mut found = BTreeSet::new();
        for entry in std::fs::read_dir(&self.path)? {
            let name = entry?.file_name();
            if let Some((account, base)) = name.to_str().and_then(companion_name) {
                found.insert((account.to_owned(), self.path.join(base)));
            }
        }
        Ok(found)
    }

    fn companions_or_none(&self) -> io::Result<BTreeSet<(String, PathBuf)>> {
        match self.companions() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            found => found,
        }
    }
}

/// Sixteen hex digits of `sha256(origin || 0 || SCHEMA)`.
fn tag(origin: &str) -> String {
    let digest = Sha256::new()
        .chain_update(origin.as_bytes())
        .chain_update([0])
        .chain_update(SCHEMA.as_bytes())
        .finalize();
    hex::encode(&digest[..TAG / 2])
}

fn valid_account(account: &str) -> bool {
    (1..=64).contains(&account.len())
        && account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The owning account and companion file name of `name`, a companion's file,
/// SQLite sidecar or lock file: `{account}-{16 hex}.sqlite` followed by a
/// sidecar suffix or nothing, or `{account}-{16 hex}.lock`. Anything else in
/// the directory is not a companion's.
fn companion_name(name: &str) -> Option<(&str, String)> {
    let stem = name.strip_suffix(LOCK).or_else(|| {
        let (stem, suffix) = name.split_once(EXTENSION)?;
        FILES.contains(&suffix).then_some(stem)
    })?;
    let (account, tag) = stem.rsplit_once('-')?;
    (tag.len() == TAG && tag.bytes().all(|byte| byte.is_ascii_hexdigit()) && valid_account(account))
        .then(|| (account, format!("{stem}{EXTENSION}")))
}

/// The lock file of the companion at `base`.
fn lock_path(base: &Path) -> PathBuf {
    base.with_extension(&LOCK[1..])
}

/// Takes the lock of the companion at `base`, polling while `keep_waiting`
/// returns true; `None` once it returns false with another handle holding it.
///
/// A lock taken on a file a removal unlinked meanwhile is let go and taken
/// again on the file now at the path, so two handles never hold one path.
fn lock(base: &Path, keep_waiting: &dyn Fn() -> bool) -> io::Result<Option<File>> {
    let path = lock_path(base);
    loop {
        let opened = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path);
        let held = match opened {
            Ok(file) => try_lock(&file)?.then_some(file),
            Err(error) if pending_deletion(&error) => None,
            Err(error) => return Err(error),
        };
        if let Some(file) = held {
            match same_file::Handle::from_path(&path) {
                Ok(current) if current == same_file::Handle::from_file(file.try_clone()?)? => {
                    return Ok(Some(file));
                }
                // Unlinked, or replaced: lock the file now at the path.
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) if pending_deletion(&error) => continue,
                Err(error) => return Err(error),
            }
        }
        if !keep_waiting() {
            return Ok(None);
        }
        std::thread::sleep(WAIT_STEP);
    }
}

/// Whether `error` is Windows refusing a lock file that a removal deleted
/// while holding it: the name stays pending deletion, and refuses every open,
/// until that handle closes. Another handle holds the companion meanwhile.
fn pending_deletion(error: &io::Error) -> bool {
    cfg!(windows) && error.kind() == io::ErrorKind::PermissionDenied
}

/// Takes `file`'s exclusive lock without waiting; `false` while another
/// handle holds it.
///
/// On Unix this is `flock` itself, which the standard library's
/// `File::try_lock` reports as unsupported on Android before Rust 1.98.
#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<bool> {
    use rustix::fs::{FlockOperation, flock};
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn try_lock(file: &File) -> io::Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

/// Deletes the companion at `base` unless another handle holds it.
fn remove_unless_held(base: &Path) -> io::Result<()> {
    match lock(base, &|| false)? {
        Some(_lock) => remove_files(base),
        None => Ok(()),
    }
}

/// Deletes the companion file at `base`, its sidecars and then its lock file,
/// whose lock the caller holds. Missing files are not an error.
fn remove_files(base: &Path) -> io::Result<()> {
    let files = FILES.iter().map(|suffix| {
        let mut path = base.as_os_str().to_owned();
        path.push(suffix);
        PathBuf::from(path)
    });
    for path in files.chain([lock_path(base)]) {
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "5d1f6e4e-3f0b-4f43-9b0e-6cf1d7c2a001";
    const B: &str = "5d1f6e4e-3f0b-4f43-9b0e-6cf1d7c2a002";
    const ORIGIN: &str = "https://transparent-pir.example";
    const OTHER: &str = "https://elsewhere.example";

    fn config(account: &str, origin: &str) -> RecoveryConfig {
        RecoveryConfig {
            source: b"test".to_vec(),
            account_binding: account.as_bytes().to_vec(),
            origin: origin.to_owned(),
            scripts: 1,
            shards: 1,
            events: 1,
            queries: 1,
            private_bytes: 1,
        }
    }

    fn accounts(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn files(dir: &CompanionDir) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn open(dir: &CompanionDir, account: &str, origin: &str, current: &[&str]) -> Companion {
        dir.open(
            account,
            config(account, origin),
            &accounts(current),
            &|| false,
        )
        .unwrap()
    }

    #[test]
    fn names_bind_the_account_origin_and_schema() {
        let dir = CompanionDir::new("/wallet.db.tpir");
        let path = dir.companion_path(A, ORIGIN);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, format!("{A}-{}.sqlite", tag(ORIGIN)));
        assert_ne!(tag(ORIGIN), tag(OTHER));
        assert_eq!(tag(ORIGIN).len(), TAG);
        for suffix in ["", "-wal", "-shm", "-journal"] {
            assert_eq!(
                companion_name(&format!("{name}{suffix}")),
                Some((A, name.to_owned()))
            );
        }
        let lock = format!("{A}-{}.lock", tag(ORIGIN));
        assert_eq!(companion_name(&lock), Some((A, name.to_owned())));
        for other in [
            format!("{name}-other"),
            format!("{A}-{}.sqlite", "x".repeat(TAG)),
            format!("{A}-{}.sqlite", "a".repeat(TAG - 1)),
            format!("{A}.sqlite"),
            "notes.txt".to_owned(),
            format!("a b-{}.sqlite", "a".repeat(TAG)),
        ] {
            assert_eq!(companion_name(&other), None, "{other}");
        }
    }

    #[test]
    fn an_open_companion_excludes_every_other_handle() {
        let root = tempfile::tempdir().unwrap();
        let dir = CompanionDir::new(root.path().join("wallet.db.tpir"));
        let held = open(&dir, A, ORIGIN, &[A]);
        assert!(matches!(
            dir.open(A, config(A, ORIGIN), &accounts(&[A]), &|| false),
            Err(OpenError::Busy)
        ));
        // Neither a removal nor a sweep deletes it.
        assert_eq!(
            dir.remove(A, Duration::from_millis(20)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        dir.retain(|| Ok(BTreeSet::new())).unwrap();
        assert!(dir.companion_path(A, ORIGIN).exists());
        drop(held);
        let _reopened = open(&dir, A, ORIGIN, &[A]);
    }

    #[test]
    fn opening_prunes_other_origins_and_deleted_accounts() {
        let root = tempfile::tempdir().unwrap();
        let dir = CompanionDir::new(root.path().join("wallet.db.tpir"));
        drop(open(&dir, A, OTHER, &[A, B]));
        drop(open(&dir, B, ORIGIN, &[A, B]));
        std::fs::write(dir.path().join("notes.txt"), b"kept").unwrap();
        // A held companion is left for later.
        let other_b = open(&dir, B, OTHER, &[A, B]);

        let _a = open(&dir, A, ORIGIN, &[A]);
        let name = |account: &str, origin: &str| format!("{account}-{}", tag(origin));
        let names = files(&dir);
        assert!(names.contains(&format!("{}.sqlite", name(A, ORIGIN))));
        assert!(!names.iter().any(|file| file.starts_with(&name(A, OTHER))));
        assert!(!names.iter().any(|file| file.starts_with(&name(B, ORIGIN))));
        assert!(names.contains(&format!("{}.sqlite", name(B, OTHER))));
        assert!(names.contains(&"notes.txt".to_owned()));
        drop(other_b);
    }

    #[test]
    fn removal_and_the_sweep_delete_every_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = CompanionDir::new(root.path().join("wallet.db.tpir"));
        drop(open(&dir, A, ORIGIN, &[A, B]));
        drop(open(&dir, B, ORIGIN, &[A, B]));
        let base = dir.companion_path(A, ORIGIN);
        // A sidecar alone still names its companion.
        std::fs::write(format!("{}-wal", base.display()), b"").unwrap();

        dir.remove(A, Duration::ZERO).unwrap();
        assert!(files(&dir).iter().all(|file| !file.starts_with(A)));
        assert!(files(&dir).iter().any(|file| file.starts_with(B)));

        // The sweep lists before it reads the accounts, and a failed read
        // deletes nothing.
        assert!(dir.retain(|| Err(io::Error::other("unreadable"))).is_err());
        assert!(files(&dir).iter().any(|file| file.starts_with(B)));
        dir.retain(|| Ok(accounts(&[A]))).unwrap();
        assert!(files(&dir).is_empty());
        // Nothing to do without a directory.
        let missing = CompanionDir::new(root.path().join("missing.tpir"));
        missing.remove(A, Duration::ZERO).unwrap();
        missing.retain(|| panic!("no companion to sweep")).unwrap();
    }

    #[test]
    fn a_waiting_open_takes_the_lock_once_it_is_free() {
        let root = tempfile::tempdir().unwrap();
        let dir = CompanionDir::new(root.path().join("wallet.db.tpir"));
        let held = open(&dir, A, ORIGIN, &[A]);
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| {
                dir.open(A, config(A, ORIGIN), &accounts(&[A]), &|| true)
                    .map(|_| ())
            });
            std::thread::sleep(Duration::from_millis(30));
            drop(held);
            waiting.join().unwrap().unwrap();
        });
    }

    #[test]
    fn a_lock_on_an_unlinked_file_is_taken_again() {
        let root = tempfile::tempdir().unwrap();
        let dir = CompanionDir::new(root.path().join("wallet.db.tpir"));
        std::fs::create_dir_all(dir.path()).unwrap();
        let base = dir.companion_path(A, ORIGIN);
        let first = lock(&base, &|| false).unwrap().unwrap();
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| lock(&base, &|| true).unwrap().unwrap());
            std::thread::sleep(Duration::from_millis(30));
            // A removal unlinks the lock file while holding it.
            remove_files(&base).unwrap();
            drop(first);
            let second = waiting.join().unwrap();
            // The waiter holds the file now at the path, so no third handle
            // can take it.
            assert!(lock(&base, &|| false).unwrap().is_none());
            drop(second);
        });
    }

    /// The lock is the operating system's: a second handle on the same file
    /// is refused until the first closes.
    #[test]
    fn a_lock_excludes_a_second_handle_until_it_closes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("lock");
        let open = || {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .unwrap()
        };
        let first = open();
        assert!(try_lock(&first).unwrap());
        let second = open();
        assert!(!try_lock(&second).unwrap());
        drop(first);
        assert!(try_lock(&second).unwrap());
    }

    #[test]
    fn invalid_account_names_open_nothing() {
        let root = tempfile::tempdir().unwrap();
        let dir = CompanionDir::new(root.path().join("wallet.db.tpir"));
        for account in ["", "../escape", "a b", &"a".repeat(65)] {
            assert!(matches!(
                dir.open(account, config("x", ORIGIN), &accounts(&[]), &|| false),
                Err(OpenError::Account)
            ));
        }
        assert!(!dir.path().exists());
    }
}
