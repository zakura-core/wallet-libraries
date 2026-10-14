#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$repo_root" <<'PY'
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("receiver_dependencies", root / "scripts/check-receiver-dependencies.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
with tempfile.TemporaryDirectory(prefix="receiver-consumers-") as temporary:
    for mode in ("client", "server"):
        consumer = Path(temporary) / mode
        (consumer / "src").mkdir(parents=True)
        dependencies = {}
        for directory in ("receiver-directory", "receiver-pir", *(["receiver-pir-server"] if mode == "server" else [])):
            path = root / "zakura" / directory
            package = tomllib.loads((path / "Cargo.toml").read_text())["package"]
            dependencies[directory] = {"package": package["name"], "version": "=" + package["version"], "path": str(path)}
        lines = ['[package]', 'name = "fresh-receiver-' + mode + '"', 'version = "0.0.0"', 'edition = "2024"', '[workspace]', '[dependencies]']
        for alias, dependency in dependencies.items():
            lines.append(alias + ' = { ' + ', '.join(key + ' = ' + json.dumps(value) for key, value in dependency.items()) + ' }')
        (consumer / "Cargo.toml").write_text('\n'.join(lines) + '\n')
        source = 'pub fn validate(bytes: [u8;43]) { let _ = receiver_directory::Receiver::from_bytes(bytes); }\n'
        if mode == "server":
            source += 'pub fn serve() { let _ = receiver_pir_server::router_with_publications(receiver_pir_server::Publications::default()); }\n'
        (consumer / "src/lib.rs").write_text(source)
        manifest = str(consumer / "Cargo.toml")
        subprocess.run(['cargo', 'generate-lockfile', '--manifest-path', manifest], check=True)
        metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version', '1', '--manifest-path', manifest], text=True))
        assert not check.violations(metadata), check.violations(metadata)
        common = {p['name']: p['version'] for p in metadata['packages'] if p['name'] in {'zakura-orchard', 'zakura-note-encryption'}}
        assert common == {'zakura-orchard': '3.0.0', 'zakura-note-encryption': '3.0.0'}, common
        subprocess.run(['cargo', 'check', '--locked', '--manifest-path', manifest], check=True)
        print('verified fresh receiver ' + mode + ': Common 3, no wallet-pir or node dependency', flush=True)
PY
