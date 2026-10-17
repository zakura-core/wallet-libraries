#!/usr/bin/env python3
"""Explicitly compare or regenerate checked-in protobuf bindings."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

import dev


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "write"))
    args = parser.parse_args()
    version = (dev.ROOT / "scripts/protoc-version.txt").read_text().strip()
    protoc = os.environ.get("PROTOC") or shutil.which("protoc")
    if not protoc or subprocess.check_output([protoc, "--version"], text=True).strip() != f"libprotoc {version}":
        parser.error(f"use libprotoc {version}; select the executable with PROTOC")
    root = Path(os.environ.get("WALLET_LIB_BUILD_ROOT", str(Path.home() / ".cache/wallet-libraries/targets"))).expanduser().resolve()
    with dev.Lease(root, dev.build_identity("protobuf", "dev")) as lease:
        generated = lease.path / "generated"
        generated.mkdir(exist_ok=True)
        env = dict(os.environ, PROTOC=protoc, OUT_DIR=str(generated), CARGO_TARGET_DIR=str(lease.path))
        code = subprocess.call(["cargo", "run", "--locked", "--manifest-path", str(dev.ROOT / "tools/proto/Cargo.toml"), "--", str(dev.ROOT), args.mode], cwd=dev.ROOT, env=env, pass_fds=(lease.lock.fileno(),))
        return code


if __name__ == "__main__":
    sys.exit(main())
