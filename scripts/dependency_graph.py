#!/usr/bin/env python3
"""Check wallet dependency boundaries using fresh external consumer lockfiles."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def consumer_graph(directory, dependency, features, *, default_features=True):
    """Resolve one path dependency outside the workspace's feature unification."""
    package = directory.name
    subject = tomllib.loads((ROOT / dependency / "Cargo.toml").read_text())["package"]["name"]
    (directory / "src").mkdir(parents=True)
    (directory / "src/lib.rs").write_text("")
    (directory / "Cargo.toml").write_text(
        f'[package]\nname = "{package}"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\nresolver = "2"\n[dependencies]\n'
        f'subject = {{ package = {json.dumps(subject)}, path = {json.dumps(str(ROOT / dependency))}, '
        f'features = {json.dumps(features)}, default-features = {json.dumps(default_features)} }}\n'
    )
    result = subprocess.check_output(
        ["cargo", "tree", "--manifest-path", str(directory / "Cargo.toml"),
         "-e", "normal,build", "--prefix", "none", "--format", "{p}"],
        text=True,
    )
    return sorted({line.split(" (")[0].removesuffix(" (*)") for line in result.splitlines()})


def check_role_api(directory, product, role):
    """Compile a selected product, then reject APIs belonging to another product or role."""
    source = directory / "src/lib.rs"
    command = ["cargo", "check", "--locked", "--quiet", "--manifest-path", str(directory / "Cargo.toml")]
    source.write_text(f"pub use subject::{product};\n")
    subprocess.run(command, check=True)
    forbidden = [f"subject::{other}" for other in ("enhance", "status", "transparent", "receiver") if other != product]
    forbidden.append({"client": "subject::native::parse_selection", "publisher": "subject::native::ProfileQueryExt", "query-server": "subject::native::prepare_with"}[role])
    for symbol in forbidden:
        source.write_text(f"pub use {symbol};\n")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0 or "error[E0432]" not in result.stderr:
            raise RuntimeError(f"{directory.name}: expected unavailable API {symbol}; {result.stderr[-1000:]}")
    source.write_text(f"pub use subject::{product};\n")


def check_previous_endpoint(directory):
    """Retain the previous URL parser as an independent, verification-only oracle."""
    (directory / "src").mkdir(parents=True)
    protocol = ROOT / "zakura/pir-protocol"
    (directory / "Cargo.toml").write_text(
        '[package]\nname = "previous-endpoint-counterpart"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\nresolver = "2"\n[dependencies]\n'
        f'candidate_protocol = {{ package = "zakura-pir-protocol", path = {json.dumps(str(protocol))}, features = ["http-endpoint"] }}\n'
        'url = "=2.5.8"\n'
    )
    (directory / "src/main.rs").write_text((ROOT / "scripts/probes/previous_endpoint.rs").read_text())
    subprocess.run(["cargo", "run", "--quiet", "--manifest-path",
                    str(directory / "Cargo.toml")], check=True)


def check_bitcoin_oracles(directory):
    """Run the pinned Bitcoin codec/vector oracles outside workspace test builds."""
    (directory / "src").mkdir(parents=True)
    (directory / "src/lib.rs").write_text("")
    manifest = (
        '[package]\nname = "bitcoin-filter-counterpart"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\nresolver = "2"\n[profile.test]\nopt-level = 3\n[dependencies]\n'
        'bitcoin = { version = "=0.32.102", default-features = false, features = ["std"] }\n'
        'bitcoin-io = { version = "=0.1.101", default-features = false, features = ["std"] }\n'
        'hex = "0.4"\nserde_json = "1"\nsha2 = "0.10"\n'
    )
    for package, features in (("filters", []), ("pir-client", ["transparent"]),
                              ("pir-protocol", ["receiver"]), ("pir-publisher", ["transparent"])):
        manifest += (f'zakura-{package} = {{ path = {json.dumps(str(ROOT / "zakura" / package))}, '
                     f'features = {json.dumps(features)} }}\n')
    for name, source in (
        ("codec", "zakura/filters/tests/oracles/upstream.rs"),
        ("bip158_vectors", "zakura/pir-client/tests/transparent_filter/bip158_vectors.rs"),
        ("parent", "zakura/pir-client/tests/transparent_filter/oracles/parent.rs"),
        ("receiver", "zakura/pir-protocol/tests/receiver/oracles/bitcoin.rs"),
    ):
        manifest += f'\n[[test]]\nname = "{name}"\npath = {json.dumps(str(ROOT / source))}\n'
    (directory / "Cargo.toml").write_text(manifest)
    subprocess.run(["cargo", "test", "--quiet", "--manifest-path",
                    str(directory / "Cargo.toml")], check=True)


def check_previous_provider(directory, *, emit_fixtures=False):
    """Keep IPIR's independent setup/codec/scan oracles out of ordinary builds."""
    (directory / "src").mkdir(parents=True)
    manifest = (
        '[package]\nname = "previous-provider-counterpart"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\nresolver = "2"\n[profile.test]\nopt-level = 3\n[dependencies]\n'
        f'candidate_protocol = {{ package = "zakura-pir-protocol", path = {json.dumps(str(ROOT / "zakura/pir-protocol"))}, features = ["native", "enhance", "receiver", "transparent"] }}\n'
        'ipir-sp = { git = "https://github.com/valargroup/ipir-sp", rev = "5ea080a3281a01c5459f585e0a1bbbde50ec2bd2", version = "=0.1.0-rc.7" }\n'
        'ipir-native-client = { git = "https://github.com/valargroup/ipir-sp", rev = "5ea080a3281a01c5459f585e0a1bbbde50ec2bd2", version = "=0.1.0-rc.1" }\n'
        'hex = "0.4"\nserde_json = "1"\nsha2 = "0.10"\n'
    )
    (directory / "Cargo.toml").write_text(manifest)
    files = {
        "main.rs": "scripts/probes/previous_provider.rs",
        "reference_bits.rs": "zakura/pir-client/tests/support/reference_bits.rs",
        "metadata.json": "zakura/pir-protocol/testdata/previous_provider_metadata.json",
        "receiver_scans.json": "zakura/pir-query-server/testdata/previous_provider_scans.json",
    }
    for target, source in files.items():
        (directory / "src" / target).write_text((ROOT / source).read_text())
    command = ["cargo", "run", "--profile", "test", "--quiet", "--manifest-path",
               str(directory / "Cargo.toml")]
    if emit_fixtures:
        return subprocess.check_output(command + ["--", "--emit-fixtures"], text=True)
    subprocess.run(command, check=True)


def check_previous_native(directory):
    """Cross both directions with pinned pre-packaging code, independently of workspace features."""
    directory.mkdir()
    (directory / "src").mkdir()
    dependencies = [
        'previous_native = { package = "zakura-pir-native", git = "https://github.com/zakura-core/wallet-libraries", rev = "4631f32f815f160ccd561540e7ae92e026fc7ee5" }',
    ]
    roles = (("candidate_client", "client"), ("candidate_core", "server-core"),
             ("candidate_query", "query-server"), ("candidate_protocol", "protocol"))
    for alias, role in roles:
        path = ROOT / "zakura" / ("pir-" + role)
        features = ', features = ["native"]' if role in {"client", "protocol"} else ""
        dependencies.append(f'{alias} = {{ package = "zakura-pir-{role}", path = {json.dumps(str(path))}{features} }}')
    manifest = ('[package]\nname = "frozen-native-counterpart"\nversion = "0.0.0"\nedition = "2024"\n'
                '[workspace]\n[profile.test]\nopt-level = 3\n[dependencies]\n')
    (directory / "Cargo.toml").write_text(manifest + "\n".join(dependencies) + "\n")
    (directory / "src/main.rs").write_text((ROOT / "scripts/probes/frozen_pir.rs").read_text())
    subprocess.run(["cargo", "run", "--profile", "test", "--quiet", "--manifest-path",
                    str(directory / "Cargo.toml")], check=True)


def main():
    bitcoin_helpers = {"bitcoin", "bitcoin_hashes", "bitcoin-io", "bitcoin-consensus-encoding",
                       "bitcoin-internals", "hex-conservative"}
    legacy_helpers = {"ipir-sp", "ipir-native-client", "simplepir-kernel"} | bitcoin_helpers
    workspace_lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    retained = legacy_helpers & {package["name"] for package in workspace_lock["package"]}
    if retained:
        raise RuntimeError(f"verification-only providers in workspace lockfile: {sorted(retained)}")
    # Check both feature-off libraries and real consumer capabilities. The
    # proving consumer also ensures the real fixture remains available.
    pczt_macros = {"serde_with_macros", "darling", "darling_core", "darling_macro", "ident_case", "strsim"}
    endpoint_stack = {"url", "idna", "idna_adapter", "icu_provider", "icu_normalizer", "icu_properties"}
    recovery_forbidden = {
        "zakura-client-backend", "zakura-client-sqlite", "zakura-primitives", "zakura-pczt",
        "zakura-orchard", "zakura-orchard-legacy", "zakura-sapling-crypto",
        "zakura-halo2-proofs", "zakura-halo2-gadgets", "zakura-bellman",
    }
    # Full wallets also need SHA-1 through zcash_script; only protocol-only
    # consumers can forbid it independently of the IPIR evaluator boundary.
    native_evaluators = {"ipir-native-client", "ipir-sp", "simplepir-kernel", "clap", "env_logger"}
    server_roles = {"zakura-pir-publisher", "zakura-pir-query-server", "zakura-pir-server-core", "zakura-server-chain"}
    wallet_roles = {"ipir-native-client", "zakura-pir-client", "zakura-client-backend", "zakura-client-sqlite", "zakura-protocol", "zakura-transparent", "zakura-orchard"}
    cases = [
        ("filter-codec", "zakura/filters", [], bitcoin_helpers, {"siphasher"}),
        ("scanning", "librustzcash/zcash_client_backend", [], {"nanorand", "futures-core", "futures-sink"}, {"flume"}),
        ("async-scanning", "librustzcash/zcash_client_backend", ["sync-decryptor"], {"nanorand"}, {"flume", "futures-core", "futures-sink", "tokio"}),
        ("record-types", "zakura/pir-protocol", ["enhance"], endpoint_stack | server_roles | {"http", "bytes", "ipir-native-client", "reinspiring"}, set()),
        ("endpoint", "zakura/pir-protocol", ["http-endpoint"], endpoint_stack | server_roles, {"http"}),
        ("recovery-types", "zakura/pir-protocol", ["transparent-inputs"], recovery_forbidden | server_roles, {"zakura-protocol"}),
        ("recovery", "zakura/pir-client", ["recovery"], recovery_forbidden | endpoint_stack | server_roles | native_evaluators, {"zakura-pir-protocol"}),
        ("sqlite-default", "librustzcash/zcash_client_sqlite", [], {"rand_distr"}, set()),
        ("tor", "librustzcash/zcash_client_backend", ["tor"], {"dynosaur", "dynosaur_derive", "trait-variant", "liblzma", "liblzma-sys", "zstd", "zstd-safe", "zstd-sys", "jobserver"}, {"arti-client", "rust_decimal", "flate2", "miniz_oxide", "tor-hsclient"}),
        ("wallet", "librustzcash/zcash_client_sqlite", ["orchard", "transparent-inputs"], {"prost-build", "tonic-prost-build", "which", "regex", "regex-automata", "regex-syntax"} | pczt_macros, {"rand_distr"}),
        ("pczt", "librustzcash/pczt", [], pczt_macros, {"serde_with"}),
        ("pir", "zakura/pir-client", ["native"], native_evaluators | server_roles | {"sha1"}, {"reinspiring"}),
        ("status-policy", "zakura/pir-client", ["status"], recovery_forbidden | server_roles | native_evaluators | {"tonic", "tonic-prost", "tokio", "hyper", "hyper-util", "h2"}, {"zakura-protocol"}),
        ("status-lightwalletd", "zakura/pir-client", ["lightwalletd"], server_roles, {"zakura-client-backend", "tonic", "tokio"}),
        ("receiver-evaluator", "zakura/pir-query-server", ["receiver"], wallet_roles | native_evaluators | {"zakura-pir-publisher", "zakura-server-chain", "sha1"}, {"reinspiring", "rayon"}),
        ("filter", "zakura/pir-protocol", ["transparent"], {"bitcoin", "secp256k1", "secp256k1-sys", "zakura-protocol", "zakura-transparent"} | server_roles, {"bitcoin_hashes"}),
        ("filter-cli", "zakura/pir-client", ["cli"], {"anstream", "anstyle-parse", "colorchoice"}, {"clap"}),
        ("filter-http", "zakura/pir-client", ["transparent", "reqwest"], {"reqwest", "quinn", "hyper", "hyper-util", "hyper-rustls", "h2", "tokio", "url", "idna"}, {"ureq"}),
        ("filters", "zakura/filters", [], {"bitcoin", "secp256k1", "secp256k1-sys"}, {"bitcoin_hashes"}),
        ("receiver-formats", "zakura/pir-protocol", ["receiver"], {"bitcoin", "secp256k1", "secp256k1-sys"} | server_roles | wallet_roles, {"zakura-filters", "bitcoin_hashes"}),
        ("receiver-wallet", "zakura/pir-client", ["receiver-wallet"], {"bitcoin", "base58ck", "bitcoin-units", "hex_lit"} | native_evaluators | server_roles, {"zakura-filters", "reinspiring"}),
        # The borrowed reader needs only protocol value types and the txid hashes.
        ("transaction-wire", "zakura/transaction-wire", [], recovery_forbidden | wallet_roles - {"zakura-protocol"} | server_roles | {"zakura-transparent", "zakura-redjubjub", "zakura-pasta-curves", "zakura-jubjub", "zakura-bls12-381"}, {"zakura-protocol", "sha2", "blake2b_simd"}),
        # Config resolution is shared with zcash_voting and must stay free of
        # wallet, PIR, server, async runtime and HTTP crates.
        ("service-config", "zakura/service-config", [], wallet_roles | server_roles | native_evaluators | endpoint_stack | {"zakura-pir-protocol", "tokio", "reqwest", "hyper"}, {"serde_json", "sha2"}),
        # The wallet PIR config profile adds only the endpoint parser to it.
        ("pir-config", "zakura/pir-config", [], wallet_roles | server_roles | native_evaluators | endpoint_stack | {"tokio", "reqwest", "hyper", "zakura-filters", "zcash_protocol"}, {"zakura-service-config", "zakura-pir-protocol", "http"}),
        ("test-support", "librustzcash/zcash_client_sqlite", ["test-dependencies"], {"wagyu-zcash-parameters"}, set()),
        ("proving", "librustzcash/zcash_client_sqlite", ["pczt-tests"], set(), {"wagyu-zcash-parameters"}),
    ]
    for product in ("enhance", "status", "transparent", "receiver"):
        cases.extend([
            (f"{product}-client", "zakura/pir-client", [product], server_roles | native_evaluators | endpoint_stack, {"zakura-pir-protocol", "reinspiring"}),
            (f"{product}-publisher", "zakura/pir-publisher", [product], wallet_roles | {"zakura-pir-query-server", "zakura-server-chain"}, {"zakura-pir-protocol", "zakura-pir-server-core"}),
            (f"{product}-query-server", "zakura/pir-query-server", [product], wallet_roles | native_evaluators | {"zakura-pir-publisher", "zakura-server-chain"}, {"zakura-pir-protocol", "zakura-pir-server-core"}),
        ])
    defaults_disabled = set()
    receipt = {}
    with tempfile.TemporaryDirectory(prefix="wallet-dependency-graph-") as temporary:
        for name, dependency, features, forbidden, required in cases:
            graph = consumer_graph(
                Path(temporary) / name, dependency, features,
                default_features=name not in defaults_disabled,
            )
            names = {line.split()[0] for line in graph}
            unexpected = forbidden & names
            missing = required - names
            if unexpected or missing:
                raise RuntimeError(f"{name}: unexpected {sorted(unexpected)}; missing {sorted(missing)}")
            if name == "recovery":
                # Build and execute actual recovery APIs outside workspace feature unification.
                example = ROOT / "zakura/pir-client/examples/transparent/recovery-without-backend.rs"
                source = example.read_text().replace("zakura_pir_client", "subject")
                (Path(temporary) / name / "src/main.rs").write_text(source)
                subprocess.run(
                    ["cargo", "run", "--locked", "--quiet", "--manifest-path",
                     str(Path(temporary) / name / "Cargo.toml")], check=True,
                )
            if name == "async-scanning":
                (Path(temporary) / name / "src/lib.rs").write_text(
                    "pub use subject::sync::decryptor;\n"
                )
                subprocess.run(
                    ["cargo", "check", "--locked", "--quiet", "--manifest-path",
                     str(Path(temporary) / name / "Cargo.toml")], check=True,
                )
            if name == "status-policy":
                # The example constructs a TxId using the same protocol package
                # as the workspace, without reaching through transaction parsing.
                protocol = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["dependencies"]["zcash_protocol"]
                manifest = Path(temporary) / name / "Cargo.toml"
                with manifest.open("a") as consumer:
                    fields = ", ".join(f"{key} = {json.dumps(value)}" for key, value in protocol.items())
                    consumer.write(f"zcash_protocol = {{ {fields} }}\n")
                example = ROOT / "zakura/pir-client/examples/transaction_status/private-source.rs"
                source = example.read_text().replace("zakura_pir_client", "subject")
                (Path(temporary) / name / "src/main.rs").write_text(source)
                subprocess.run(
                    ["cargo", "run", "--quiet", "--manifest-path",
                     str(Path(temporary) / name / "Cargo.toml")], check=True,
                )
            if name == "status-lightwalletd":
                (Path(temporary) / name / "src/lib.rs").write_text(
                    "pub use subject::status::policy::lightwalletd::{LightwalletdSource, observe_response};\n"
                )
                subprocess.run(
                    ["cargo", "check", "--locked", "--quiet", "--manifest-path",
                     str(Path(temporary) / name / "Cargo.toml")], check=True,
                )
            if name == "receiver-evaluator":
                (Path(temporary) / name / "src/lib.rs").write_text("pub use subject::receiver::server::Server;\n")
                subprocess.run(["cargo", "check", "--locked", "--quiet", "--manifest-path",
                                str(Path(temporary) / name / "Cargo.toml")], check=True)
            for product in ("enhance", "status", "transparent", "receiver"):
                for role in ("client", "publisher", "query-server"):
                    if name == f"{product}-{role}":
                        check_role_api(Path(temporary) / name, product, role)
            receipt[name] = graph
            print(f"{name}: {len(graph) - 1} dependency packages; boundary passed", flush=True)
        check_previous_endpoint(Path(temporary) / "previous-endpoint-counterpart")
        check_bitcoin_oracles(Path(temporary) / "bitcoin-filter-counterpart")
        check_previous_provider(Path(temporary) / "previous-provider-counterpart")
        check_previous_native(Path(temporary) / "frozen-native-counterpart")
    output = Path(os.environ["CARGO_TARGET_DIR"]) / "dependency-graphs.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"graphs: {output}")


if __name__ == "__main__":
    main()
