#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# A sibling can enable backend PIR while SQLite still uses ordinary enhancement.
# Keep the library-only check separate so dev dependencies cannot mask this graph.
cargo check -p zakura-client-sqlite --locked --no-default-features \
  --features orchard,zcash_client_backend/zakura-pir-enhance
cargo test -p zakura-client-sqlite --locked --no-default-features \
  --features orchard,zcash_client_backend/zakura-pir-enhance,test-dependencies \
  --lib non_pir_enhancement_hook_preserves_ordinary_intent

probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
python3 - "$PWD" "$probe" <<'PY'
import json, shutil, sys
from pathlib import Path
repo, probe = map(Path, sys.argv[1:])
shutil.copyfile(repo / 'Cargo.lock', probe / 'Cargo.lock')
(probe / 'Cargo.toml').write_text('[workspace]\nmembers = ["consumer", "pir-enabler"]\nresolver = "2"\n')
for name, features in [('consumer', ''), ('pir-enabler', ', features = ["zakura-pir-enhance"]')]:
    package = probe / name
    (package / 'src').mkdir(parents=True)
    (package / 'Cargo.toml').write_text(f'''[package]
name = "{name}"
version = "0.0.0"
edition = "2024"
[dependencies]
zcash_client_sqlite = {{ package = "zakura-client-sqlite", path = {json.dumps(str(repo / 'librustzcash/zcash_client_sqlite'))}, default-features = false{features} }}
rusqlite = "0.37"
''')
    (package / 'src/lib.rs').write_text('')
(probe / 'consumer/src/lib.rs').write_text('''use zcash_client_sqlite::WalletDb;
pub fn from_connection<P, CL, R>(conn: rusqlite::Connection, params: P, clock: CL, rng: R)
    -> WalletDb<rusqlite::Connection, P, CL, R> {
    WalletDb::from_connection(conn, params, clock, rng)
}
pub fn for_path<P, CL, R>(path: &std::path::Path, params: P, clock: CL, rng: R)
    -> Result<WalletDb<rusqlite::Connection, P, CL, R>, rusqlite::Error> {
    WalletDb::for_path(path, params, clock, rng)
}
''')
PY
# Compile identical consumer source first alone, then with PIR enabled by a sibling.
cargo check --manifest-path "$probe/Cargo.toml" --target-dir "${CARGO_TARGET_DIR:-$PWD/target}" -p consumer
cargo check --manifest-path "$probe/Cargo.toml" --target-dir "${CARGO_TARGET_DIR:-$PWD/target}" --workspace --locked
