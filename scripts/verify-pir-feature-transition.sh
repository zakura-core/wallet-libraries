#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
artifacts=$(mktemp)
trap 'rm -f "$artifacts"' EXIT
# Separate builds are required: Cargo otherwise unifies the PIR feature.
cargo test -p zakura-client-sqlite --locked --no-default-features --features orchard,test-dependencies --lib --no-run --message-format=json-render-diagnostics > "$artifacts"
PIR_DISABLED_TEST_BINARY=$(python3 - "$artifacts" <<'PYTHON'
import json, sys
for line in open(sys.argv[1]):
    entry = json.loads(line)
    if entry.get("reason") == "compiler-artifact" and entry.get("executable") and entry["target"]["name"] == "zcash_client_sqlite":
        print(entry["executable"])
PYTHON
)
test -n "$PIR_DISABLED_TEST_BINARY"
export PIR_DISABLED_TEST_BINARY
cargo test -p zakura-client-sqlite --locked --features zakura-pir-enhance,test-dependencies --lib across_pir_feature_builds -- --ignored --nocapture
