#!/usr/bin/env python3
"""Keep wallet release and test graphs independent of the PIR service repository."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
# Existing, independently published transparent transport dependencies predate
# the receiver extraction. Keep this allowance exact so new service-owned
# helpers cannot sneak back through registry packaging or development edges.
EXISTING_TRANSPORT_RELEASES = {
    (name, "0.1.0") for name in ("pir-control", "pir-native", "pir-observability")
} | {
    (name, "0.1.0-rc.4") for name in (
        "transparent-events", "transparent-filter", "transparent-native",
        "transparent-shard", "transparent-shard-server", "transparent-txid-client",
        "transparent-wallet", "transparent-wallet-store",
    )
}
NODE_PACKAGES = {"zakura-chain", "zakura-state"}


def owned_repository(value: str | None, repository: str) -> bool:
    """Recognize Cargo Git sources and repository metadata, including refs."""
    if not value:
        return False
    value = value.removeprefix("git+").replace("git@github.com:", "https://github.com/")
    url = urlparse(value)
    return url.hostname == "github.com" and url.path.rstrip("/").removesuffix(".git").lower() == "/" + repository


def service_repository(value: str | None) -> bool:
    return owned_repository(value, "valargroup/wallet-pir")


def violations(metadata: dict) -> list[str]:
    """Inspect every resolved package and declared edge, including optional/dev/target edges."""
    problems = []
    for package in metadata["packages"]:
        name = package["name"]
        if name in NODE_PACKAGES or any(owned_repository(package.get(field), "zakura-core/zakura") for field in ("source", "repository")):
            problems.append(f"{name}: node code entered the wallet dependency graph")
        if service_repository(package.get("source")) or ((name, package.get("version")) not in EXISTING_TRANSPORT_RELEASES and service_repository(package.get("repository"))):
            problems.append(f"{name}: package owned by wallet-pir entered the wallet dependency graph")
        for dependency in package.get("dependencies", []):
            if owned_repository(dependency.get("source"), "zakura-core/zakura"):
                problems.append(f"{name}: declared dependency on node code ({dependency['name']})")
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
