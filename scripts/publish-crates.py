#!/usr/bin/env python3
"""Publish the wallet release in dependency order; dry-run unless --publish is given."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
# Include optional and development dependencies in the order, since Cargo
# resolves them when it prepares the package for the registry.
ORDER = (
    "zakura/pir-enhance-types",
    "zakura/pir-native",
    "librustzcash/pczt",
    "librustzcash/zcash_client_backend",
    "librustzcash/zcash_client_sqlite",
    "zakura/pir-status",
    "zakura/pir-enhance",
    "zakura/transaction-status",
    "wallet-lib",
    "zakura/pir-transparent",
)


class ReleaseError(Exception):
    pass


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def check_checkout(root, head):
    if git(root, "rev-parse", "HEAD") != head:
        raise ReleaseError("The checkout changed during publishing. Stop and use the original release commit.")
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ReleaseError("Use a clean checkout with all release changes committed.")


def dependency_tables(manifest):
    for section in (manifest, *manifest.get("target", {}).values()):
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield section.get(key, {})


def release_packages(root, without_transparent=False):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    packages = []
    for directory in ORDER:
        path = root / directory / "Cargo.toml"
        manifest = tomllib.loads(path.read_text())
        package = manifest["package"]
        if without_transparent and package["name"] == "zakura-pir-transparent":
            continue
        if package.get("publish") is False:
            raise ReleaseError(f"{package['name']} disables publication.")
        packages.append({"name": package["name"], "version": package["version"],
                         "path": path, "manifest": manifest})
    names = {p["name"]: p for p in packages}
    seen = set()
    upstream = set()
    for package in packages:
        for table in dependency_tables(package["manifest"]):
            for alias, dep in table.items():
                if not isinstance(dep, dict):
                    continue
                if dep.get("workspace"):
                    dep = workspace["dependencies"][alias]
                if not isinstance(dep, dict):
                    continue
                name = dep.get("package", alias)
                if name in names:
                    version = names[name]["version"]
                    if dep.get("version", "").removeprefix("=") != version:
                        raise ReleaseError(f"{package['name']} has a mismatched dependency on {name}.")
                    if name not in seen:
                        raise ReleaseError(f"{name} must be published before {package['name']}.")
                elif "git" in dep:
                    requirement = dep.get("version", "")
                    if not requirement.startswith("="):
                        raise ReleaseError(f"{name} needs an exact registry version before publishing.")
                    upstream.add((name, requirement[1:]))
        seen.add(package["name"])
    return packages, sorted(upstream)


def registry_version(name, version):
    """Return absent/available/yanked; network errors must not mean absent."""
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "wallet-libraries-release-script"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)["version"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return "absent"
        raise ReleaseError(f"Cannot check {name} {version}: registry HTTP {error.code}.") from None
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as error:
        raise ReleaseError(f"Cannot check {name} {version}: {type(error).__name__}.") from None
    return "yanked" if data["yanked"] else "available"


def wait_for_publication(name, version):
    deadline = time.monotonic() + 120
    while True:
        status = registry_version(name, version)
        if status == "available":
            return
        if status == "yanked" or time.monotonic() >= deadline:
            raise ReleaseError(f"Confirm {name} {version} on crates.io before rerunning the script.")
        time.sleep(5)


def run_release(root, publish=False, plan=False, without_transparent=False):
    head = git(root, "rev-parse", "HEAD")
    check_checkout(root, head)
    packages, upstream = release_packages(root, without_transparent)
    print(f"Release commit: {head}", flush=True)
    print("Mode: " + ("plan only" if plan else "publish" if publish else "dry run"), flush=True)
    missing = []
    for name, version in upstream:
        status = registry_version(name, version)
        print(f"Upstream: {name} {version}: {status}", flush=True)
        if status != "available":
            missing.append(f"{name} {version} ({status})")
    statuses = {}
    for package in packages:
        name, version = package["name"], package["version"]
        status = registry_version(name, version)
        statuses[name] = status
        print(f"Release: {name} {version}: {status}", flush=True)
        if status == "yanked":
            raise ReleaseError(f"{name} {version} is yanked. Prepare a new version instead.")
    if missing:
        raise ReleaseError("Publish the required wallet-pir versions first: " + ", ".join(missing)
                           + ". Use --without-transparent to release the other crates separately.")
    if plan:
        return
    # A fresh target directory belongs exclusively to this invocation. No shared
    # dev.py build lease or source-tree target is touched by Cargo packaging.
    with tempfile.TemporaryDirectory(prefix="wallet-crate-release-") as target:
        for package in packages:
            name, version = package["name"], package["version"]
            if statuses[name] == "available":
                print(f"Skip already published: {name} {version}", flush=True)
                continue
            check_checkout(root, head)
            if not publish:
                # Separate dry runs cannot resolve unpublished local releases:
                # packaging replaces the local path with a registry dependency.
                for table in dependency_tables(package["manifest"]):
                    for alias, dep in table.items():
                        if isinstance(dep, dict) and dep.get("workspace"):
                            dep = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["dependencies"][alias]
                        name_dep = dep.get("package", alias) if isinstance(dep, dict) else alias
                        if name_dep in statuses and statuses[name_dep] != "available":
                            raise ReleaseError(f"Dry run of {name} needs {name_dep} published first. "
                                               "Use --publish for sequential verification and uploads.")
            command = ["cargo", "publish", "--manifest-path", str(package["path"]),
                       "--registry", "crates-io", "--target-dir", target]
            print(f"Verify package: {name} {version}", flush=True)
            subprocess.run([*command, "--dry-run"], cwd=root, check=True)
            check_checkout(root, head)
            if publish:
                print(f"Upload: {name} {version}", flush=True)
                subprocess.run(command, cwd=root, check=True)
                wait_for_publication(name, version)
                check_checkout(root, head)
    print("Selected crates published." if publish else "Selected dry runs passed.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="Check registry prerequisites and print versions without building or uploading")
    mode.add_argument("--dry-run", action="store_true", help="Verify packages without uploading (the default)")
    mode.add_argument("--publish", action="store_true", help="Verify then upload each unpublished version to crates.io")
    parser.add_argument("--without-transparent", action="store_true", help="Exclude transparent PIR and its wallet-pir prerequisites")
    args = parser.parse_args()
    try:
        run_release(ROOT, args.publish, args.plan, args.without_transparent)
    except (ReleaseError, subprocess.CalledProcessError, OSError) as error:
        print(f"Release stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
