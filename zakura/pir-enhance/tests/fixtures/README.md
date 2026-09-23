# Wallet v5 fixtures and historical server v4 fixtures

`wallet-schema11.json` is a synthetic wallet-only fixture generated with:

```sh
cargo run -p zakura-pir-enhance --example generate_wallet_fixture --locked > zakura/pir-enhance/tests/fixtures/wallet-schema11.json
```

It checks schema 11, 653-byte records, 33 records per row, derived parameters,
setup lengths, and wallet acceptance. It is **not** evidence of interoperability
with an updated server. The wallet tests retain `upstream-session.json` unchanged
to check that the historical schema-10 server manifest is rejected.

The following generator, HTTP harness, commands, and recorded results describe the
historical v4 contract only. They do not qualify the v5 client and must not be
presented as current verification. Updating and running the server harness requires
separate server-side work.

## Historical Enhance PIR v4 conformance fixtures

`upstream-session.json` is emitted by `generate.rs` using the reference server crate at
`wallet-pir` revision `436dcc7efda3e09a6734342fd4f55e07bf1d9d95` and
`ipir-sp` revision `225972648cc2982abfac66ba5b7a3930b223051a`. The Rust
sources are identical at candidate revision
`9718a6dcf9801385f69f31bb71f02efd261914f0`. The generator calls the
server's `Lifecycle`, parameter, parameter ID, and setup seed functions. Its
67-record coverage, anchor, content digest, and all-zero public material are
synthetic. This fixture checks the serialized contract and setup length; it
is not a decrypted-answer vector.

The ordinary `compatibility.rs` test validates the fixture with the wallet
client and independently supplied wallet anchor and resource limits. The
separate `http_integration.rs` test uses an application provided loopback HTTP
transport and starts the reference coordinator and two actual workers. It
sends encrypted wallet-libraries queries, checks recovered 737-byte records,
expires the first generation, and requires fresh wallet acceptance. Its
ignored release test covers every v4 query domain, including the last record
of a full 32K shard, loan growth and return, and retained old-session answers. These processes never contact production services.

From a clean checkout of the pinned server revision, set both checkout paths:

```sh
export ENHANCE_PIR_CHECKOUT=/absolute/path/to/wallet-pir
export WALLET_LIBRARIES_CHECKOUT=/absolute/path/to/wallet-libraries
```

Regenerate the JSON using a temporary project:

```sh
fixture_project=$(mktemp -d)
cat > "$fixture_project/Cargo.toml" <<EOF_MANIFEST
[package]
name = "wallet-v4-fixture-gen"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "generate"
path = "$WALLET_LIBRARIES_CHECKOUT/zakura/pir-enhance/tests/fixtures/generate.rs"
[dependencies]
enhance-pir = { path = "$ENHANCE_PIR_CHECKOUT/enhance/crates/enhance-pir" }
ipir-sp = { git = "https://github.com/valargroup/ipir-sp.git", rev = "225972648cc2982abfac66ba5b7a3930b223051a" }
base64 = "0.22"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
hex = "0.4"
EOF_MANIFEST
cargo run --quiet --manifest-path "$fixture_project/Cargo.toml" > "$fixture_project/upstream-session.json"
diff -u "$WALLET_LIBRARIES_CHECKOUT/zakura/pir-enhance/tests/fixtures/upstream-session.json" "$fixture_project/upstream-session.json"
```

To run the real server HTTP tests, create another temporary project:

```sh
http_project=$(mktemp -d)
cat > "$http_project/Cargo.toml" <<EOF_MANIFEST
[package]
name = "wallet-v4-http-test"
version = "0.0.0"
edition = "2021"
[[test]]
name = "http_integration"
path = "$WALLET_LIBRARIES_CHECKOUT/zakura/pir-enhance/tests/fixtures/http_integration.rs"
[dependencies]
enhance-pir-server = { path = "$ENHANCE_PIR_CHECKOUT/enhance/services/enhance-pir-server" }
zakura-pir-enhance = { path = "$WALLET_LIBRARIES_CHECKOUT/zakura/pir-enhance" }
axum = "0.7"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
tempfile = "3"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
futures-util = "0.3"
EOF_MANIFEST
cargo test --release --manifest-path "$http_project/Cargo.toml" --test http_integration
cargo test --release --manifest-path "$http_project/Cargo.toml" --test http_integration -- --ignored
```

The ignored test creates about 1.2 million synthetic records and requires
substantial local RAM, disk, and runtime. Review fixture differences against
server changes before accepting them. Full application integration through
Vizor remains a separate verification step.

Verified locally on 2026-09-23 with the pinned server checkout and a temporary
HTTP test project: fixture regeneration matched `upstream-session.json` byte for
byte; `cargo test -p zakura-pir-enhance --locked --test compatibility` passed
5/5 tests (also 5/5 with `--no-default-features`); the release HTTP command
above passed 1/1 small test in 59.70 seconds; and its `--ignored` release
command passed 1/1 all-domain, loan and return test in 186.52 seconds. The
large test's observed process RSS peaked near 14 GiB.
