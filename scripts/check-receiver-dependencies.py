#!/usr/bin/env python3
"""Keep wallet release and test graphs independent of the PIR service repository."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
RECEIVER_PACKAGES = {"receiver-directory", "receiver-pir", "receiver-pir-server"}
NODE_PACKAGES = {"zakura-chain", "zakura-state"}


def service_repository(value: str | None) -> bool:
    """Recognize Cargo Git sources and repository metadata, including refs."""
    if not value:
        return False
    value = value.removeprefix("git+").replace("git@github.com:", "https://github.com/")
    url = urlparse(value)
    return url.hostname == "github.com" and url.path.rstrip("/").removesuffix(".git").lower() == "/valargroup/wallet-pir"


def violations(metadata: dict) -> list[str]:
    """Inspect every resolved package and declared edge, including optional/dev/target edges."""
    problems = []
    for package in metadata["packages"]:
        name = package["name"]
        if name in NODE_PACKAGES:
            problems.append(f"{name}: node code entered the wallet dependency graph")
        if service_repository(package.get("source")) or (name in RECEIVER_PACKAGES and service_repository(package.get("repository"))):
            problems.append(f"{name}: package owned by wallet-pir entered the wallet dependency graph")
        for dependency in package.get("dependencies", []):
            if service_repository(dependency.get("source")):
                kind = dependency.get("kind") or "normal"
                problems.append(f"{name}: {kind} dependency on wallet-pir ({dependency['name']})")
    return sorted(set(problems))


def main() -> int:
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--all-features", "--format-version", "1",
        "--manifest-path", str(ROOT / "Cargo.toml"),
    ], text=True))
    problems = violations(metadata)
    if problems:
        print("wallet release dependencies must not point at wallet-pir or node packages:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("verified: wallet and development dependencies are independent of wallet-pir and node packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
