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


def consumer_graph(directory, dependency, features):
    """Resolve one path dependency outside the workspace's feature unification."""
    package = directory.name
    subject = tomllib.loads((ROOT / dependency / "Cargo.toml").read_text())["package"]["name"]
    (directory / "src").mkdir(parents=True)
    (directory / "src/lib.rs").write_text("")
    (directory / "Cargo.toml").write_text(
        f'[package]\nname = "{package}"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\nresolver = "2"\n[dependencies]\n'
        f'subject = {{ package = {json.dumps(subject)}, path = {json.dumps(str(ROOT / dependency))}, '
        f'features = {json.dumps(features)} }}\n'
    )
    result = subprocess.check_output(
        ["cargo", "tree", "--manifest-path", str(directory / "Cargo.toml"),
         "-e", "normal,build", "--prefix", "none", "--format", "{p}"],
        text=True,
    )
    return sorted({line.split(" (")[0].removesuffix(" (*)") for line in result.splitlines()})


def main():
    # Check both feature-off libraries and real consumer capabilities. The
    # proving consumer also ensures the real fixture remains available.
    pczt_macros = {"serde_with_macros", "darling", "darling_core", "darling_macro", "ident_case", "strsim"}
    endpoint_stack = {"url", "idna", "idna_adapter", "icu_provider", "icu_normalizer", "icu_properties"}
    recovery_forbidden = {
        "zakura-client-backend", "zakura-client-sqlite", "zakura-primitives", "zakura-pczt",
        "zakura-orchard", "zakura-orchard-legacy", "zakura-sapling-crypto",
        "zakura-halo2-proofs", "zakura-halo2-gadgets", "zakura-bellman",
    }
    native_evaluators = {"ipir-sp", "simplepir-kernel", "sha1", "clap", "env_logger"}
    cases = [
        ("record-types", "zakura/pir-enhance-types", [], endpoint_stack | {"http", "bytes"}, set()),
        ("endpoint", "zakura/pir-enhance-types", ["http-endpoint"], endpoint_stack, {"http"}),
        ("enhance", "zakura/pir-enhance", [], endpoint_stack, {"zakura-pir-enhance-types"}),
        ("transparent-wallet", "zakura/pir-transparent", ["wallet"],
         endpoint_stack | native_evaluators, {"zakura-pir-enhance-types", "ipir-native-client"}),
        ("recovery-types", "zakura/transparent-recovery-types", ["transparent-inputs"],
         recovery_forbidden, {"zakura-protocol"}),
        ("recovery", "zakura/pir-transparent", ["recovery"],
         recovery_forbidden | endpoint_stack, {"zakura-transparent-recovery-types"}),
        ("wallet", "librustzcash/zcash_client_sqlite", ["orchard", "transparent-inputs"],
         {"prost-build", "tonic-prost-build", "which", "regex", "regex-automata", "regex-syntax"} | pczt_macros, set()),
        ("pczt", "librustzcash/pczt", [], pczt_macros, {"serde_with"}),
        ("pir", "zakura/pir-native", [], native_evaluators, {"ipir-native-client"}),
        ("status-client", "zakura/pir-status", [], native_evaluators, {"ipir-native-client"}),
        ("receiver-client", "zakura/receiver-pir", [], native_evaluators, {"ipir-native-client"}),
        ("receiver-server", "zakura/receiver-pir", ["server"], set(), {"ipir-sp", "simplepir-kernel"}),
        ("filter", "zakura/transparent-filter", [], {"bitcoin", "secp256k1", "secp256k1-sys"},
         {"bitcoin_hashes"}),
        ("filters", "zakura/filters", [], {"bitcoin", "secp256k1", "secp256k1-sys"},
         {"bitcoin_hashes"}),
        ("receiver-directory", "zakura/receiver-directory", [],
         {"bitcoin", "secp256k1", "secp256k1-sys"}, {"zakura-filters", "bitcoin_hashes"}),
        ("receiver-wallet", "zakura/pir-receiver", ["wallet"],
         {"bitcoin", "base58ck", "bitcoin-units", "hex_lit"} | native_evaluators,
         {"zakura-filters", "ipir-native-client"}),
        ("engine", "zakura/pir-transparent", ["engine"],
         {"url", "idna", "icu_provider", "bitcoin"} | native_evaluators, {"ipir-native-client"}),
        ("test-support", "librustzcash/zcash_client_sqlite", ["test-dependencies"],
         {"wagyu-zcash-parameters"}, set()),
        ("proving", "librustzcash/zcash_client_sqlite", ["pczt-tests"],
         set(), {"wagyu-zcash-parameters"}),
    ]
    receipt = {}
    with tempfile.TemporaryDirectory(prefix="wallet-dependency-graph-") as temporary:
        for name, dependency, features, forbidden, required in cases:
            graph = consumer_graph(Path(temporary) / name, dependency, features)
            names = {line.split()[0] for line in graph}
            unexpected = forbidden & names
            missing = required - names
            if unexpected or missing:
                raise RuntimeError(f"{name}: unexpected {sorted(unexpected)}; missing {sorted(missing)}")
            if name == "recovery":
                # Build and execute actual recovery APIs outside workspace feature unification.
                example = ROOT / "zakura/pir-transparent/examples/recovery-without-backend.rs"
                source = example.read_text().replace("zakura_pir_transparent", "subject")
                (Path(temporary) / name / "src/main.rs").write_text(source)
                subprocess.run(
                    ["cargo", "run", "--locked", "--quiet", "--manifest-path",
                     str(Path(temporary) / name / "Cargo.toml")], check=True,
                )
            receipt[name] = graph
            print(f"{name}: {len(graph) - 1} dependency packages; boundary passed", flush=True)
    output = Path(os.environ["CARGO_TARGET_DIR"]) / "dependency-graphs.json"
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"graphs: {output}")


if __name__ == "__main__":
    main()
