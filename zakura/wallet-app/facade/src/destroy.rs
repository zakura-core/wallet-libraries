//! Forgetting a wallet: deleting the files it lives in.

use std::path::Path;

use crate::{Error, WalletConfig};

/// Deletes the wallet's files, so that the next open starts empty.
///
/// The wallet must not be open. This is the only way to change wallets while
/// the store holds a single account: forget this one, then create or restore
/// another. The same path re-runs a recovery, for a birthday that turned out
/// to be too high.
///
/// Removes both databases and the sidecar files SQLite may have left beside
/// them. A file that is not there is not an error — a wallet that was never
/// created, or was already forgotten, is fine to forget again. Any other
/// failure names the path, and leaves whatever was already removed removed.
pub fn destroy(config: &WalletConfig) -> Result<(), Error> {
    for base in [&config.wallet_path, &config.cache_path] {
        remove(base)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut name = base.as_os_str().to_owned();
            name.push(suffix);
            remove(Path::new(&name))?;
        }
    }
    Ok(())
}

fn remove(path: &Path) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Storage(format!(
            "could not remove {}: {e}",
            path.display()
        ))),
    }
}
