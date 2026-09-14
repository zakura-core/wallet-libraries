# Enhance PIR conformance fixture

`upstream-session.json` freezes the schema-7 JSON contract, new setup seed,
one-shard geometry, generated parameters and public-parameter length.
`generate.rs` imports the server protocol crate from an explicit checkout;
it does not import the wallet's copy. The pinned `ipir-sp` revision remains
`accc424e879d8da425fa620aad80f0f2c4e0defd`.

The anchor, group name, and hashes are synthetic test metadata. The published
coefficients are zero and are **not** a server snapshot or a decryption vector.
The ordinary conformance test independently supplies the synthetic wallet anchor,
accepts this session, and checks exact JSON round-trip equality.

`full_shard_production_round_trip` separately builds a deterministic 8,192-row
database with nine 737-byte records per row, packs each row into 14-bit
coefficients like the Enhance server, and computes real published parameters
with the pinned server primitives. It checks fresh randomized queries at row
boundaries and the last position, plus a dummy query, through the public wallet
client API. It uses the production degree, moduli, and Gaussian sampler. This is
a local cryptographic interoperability test, not a deployed HTTP/fleet test.
Run it with:

```sh
cargo test -p zakura-pir-enhance --release --locked --test compatibility -- --ignored
```

It is ignored in ordinary test runs because full-shard preprocessing is expensive;
CI runs it explicitly in release mode.

To regenerate the JSON, set `ENHANCE_PIR_CHECKOUT` to a clean checkout of the
schema-7 server revision. From the wallet-libraries root, create a temporary
Cargo project, so no upstream checkout or wallet manifest is modified:

```sh
export ENHANCE_PIR_CHECKOUT=/path/to/enhance-pir
fixture_project=$(mktemp -d)
cat > "$fixture_project/Cargo.toml" <<EOF_MANIFEST
[package]
name = "enhance-conformance-generator"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "generate"
path = "$PWD/zakura/pir-enhance/tests/fixtures/generate.rs"
[dependencies]
enhance-pir = { path = "$ENHANCE_PIR_CHECKOUT/pir/enhance" }
ipir-sp = { git = "https://github.com/valargroup/ipir-sp.git", rev = "accc424e879d8da425fa620aad80f0f2c4e0defd" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
sha2 = "0.10"
hex = "0.4"
EOF_MANIFEST
cargo run --quiet --manifest-path "$fixture_project/Cargo.toml" > "$fixture_project/session.json"
cp "$fixture_project/session.json" zakura/pir-enhance/tests/fixtures/upstream-session.json
rm -r "$fixture_project"
```

Review fixture differences against upstream changes before accepting them. Never
regenerate a fixture just to make a failing conformance assertion pass.
