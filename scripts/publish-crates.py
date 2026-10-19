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
# Share the graph check's repository predicate, also when loaded from another directory.
sys.path.insert(0, str(ROOT / "scripts"))
import server_graph  # noqa: E402
# Include optional and development dependencies in the order, since Cargo
# resolves them when it prepares the package for the registry.
ORDER = (
    "zakura/filters",
    "zakura/pir-protocol",
    "zakura/pir-server-core",
    "zakura/pir-publisher",
    "zakura/pir-query-server",
    "zakura/receiver-crypto",
    "zakura/receiver-directory",
    "zakura/one-time-ivk",
    "zakura/near-intents",
    "librustzcash/pczt",
    "librustzcash/zcash_client_backend",
    "librustzcash/zcash_client_sqlite",
    "wallet-lib",
    "zakura/pir-client",
    "zakura/receiver-pir",
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


def wallet_pir_owned(root, name, dep):
    """A wallet-libraries release never waits on wallet-pir: refuse its packages under any source."""
    owned = tomllib.loads((root / "manifests/sources.toml").read_text())["server"]["wallet_pir_packages"]
    return name in owned or server_graph.wallet_pir_owned(dep.get("git"))


def release_packages(root):
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    packages = []
    for directory in ORDER:
        path = root / directory / "Cargo.toml"
        manifest = tomllib.loads(path.read_text())
        package = manifest["package"]
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
                if isinstance(dep, str):
                    dep = {"version": dep}
                if dep.get("workspace"):
                    dep = workspace["dependencies"][alias]
                    if isinstance(dep, str):
                        dep = {"version": dep}
                name = dep.get("package", alias)
                if wallet_pir_owned(root, name, dep):
                    raise ReleaseError(f"{package['name']} depends on the wallet-pir package {name}.")
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


def output_path(root, path):
    if path is None:
        return None
    path = Path(path).resolve()
    if path.is_relative_to(root.resolve()):
        raise ReleaseError("Write release receipts outside the checkout.")
    return path


def save_receipt(path, receipt):
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.replace(path)


def validate_receipt(path, head, packages):
    try:
        receipt = json.loads(Path(path).read_text())
        expected = [(p["name"], p["version"]) for p in packages]
        actual = [(p["name"], p["version"]) for p in receipt["packages"]]
        valid = (receipt["schema_version"] == 2
                 and receipt["commit"] == head
                 and receipt["verification_passed"] is True
                 and actual == expected
                 and all(p["registry_status"] in ("available", "absent")
                         for p in receipt["packages"]))
    except (OSError, ValueError, KeyError, TypeError):
        valid = False
    if not valid:
        raise ReleaseError("The verification receipt must match this commit, selection, and ordered crate versions.")


def observe_package(record, receipt, output):
    try:
        status = registry_version(record["name"], record["version"])
        record["registry_status"] = status
        if status == "yanked":
            raise ReleaseError(f"{record['name']} {record['version']} is yanked. Prepare a new version instead.")
        if status == "available":
            record["result"] = "previously_available"
    except ReleaseError:
        record["result"] = "failed"
        save_receipt(output, receipt)
        raise
    save_receipt(output, receipt)
    return status


def run_release(root, publish=False, plan=False,
                output=None, publish_verified=None):
    head = git(root, "rev-parse", "HEAD")
    check_checkout(root, head)
    packages, upstream = release_packages(root)
    output = output_path(root, output)
    if publish_verified is not None:
        validate_receipt(publish_verified, head, packages)
    publishing = publish or publish_verified is not None
    receipt = {"schema_version": 2, "commit": head,
               "verification_passed": publish_verified is not None,
               "packages": [{"name": p["name"], "version": p["version"],
                             "registry_status": "unknown", "result": "remaining"}
                            for p in packages]}
    save_receipt(output, receipt)
    print(f"Release commit: {head}", flush=True)
    print("Mode: " + ("plan only" if plan else "publish" if publishing else "dry run"), flush=True)
    missing = []
    for name, version in upstream:
        status = registry_version(name, version)
        print(f"Upstream: {name} {version}: {status}", flush=True)
        if status != "available":
            missing.append(f"{name} {version} ({status})")
    for package, record in zip(packages, receipt["packages"]):
        name, version = package["name"], package["version"]
        status = observe_package(record, receipt, output)
        print(f"Release: {name} {version}: {status}", flush=True)
    if missing:
        raise ReleaseError("Publish the required upstream versions first: " + ", ".join(missing) + ".")
    if plan:
        return
    # A fresh target directory belongs exclusively to this invocation. No shared
    # dev.py build lease or source-tree target is touched by Cargo packaging.
    with tempfile.TemporaryDirectory(prefix="wallet-crate-release-") as target:
        if not publishing:
            # Cargo overlays all selected .crate archives on the registry while
            # verifying, so unpublished workspace versions can resolve each other.
            # Include published versions too: the goal is to verify this checkout.
            command = ["cargo", "publish", "--manifest-path", str(root / "Cargo.toml"),
                       "--registry", "crates-io", "--target-dir", target,
                       "--dry-run", "--keep-going", "--locked"]
            for package in packages:
                command.extend(["--package", package["name"]])
            check_checkout(root, head)
            print("Verify all selected release packages together.", flush=True)
            subprocess.run(command, cwd=root, check=True)
            check_checkout(root, head)
            receipt["verification_passed"] = True
            save_receipt(output, receipt)
            print("All selected release packages passed dry-run verification; nothing uploaded.", flush=True)
            return
        for package, record in zip(packages, receipt["packages"]):
            name, version = package["name"], package["version"]
            # Another publisher may have completed this version during verification.
            status = observe_package(record, receipt, output)
            if status == "available":
                print(f"Skip already published: {name} {version}", flush=True)
                continue
            check_checkout(root, head)
            command = ["cargo", "publish", "--manifest-path", str(package["path"]),
                       "--registry", "crates-io", "--target-dir", target, "--locked"]
            try:
                if publish_verified is not None:
                    command.append("--no-verify")
                else:
                    print(f"Verify package: {name} {version}", flush=True)
                    subprocess.run([*command, "--dry-run"], cwd=root, check=True)
                check_checkout(root, head)
                print(f"Upload: {name} {version}", flush=True)
                subprocess.run(command, cwd=root, check=True)
                record["result"] = "uploaded_unconfirmed"
                save_receipt(output, receipt)
                wait_for_publication(name, version)
                check_checkout(root, head)
                record["registry_status"] = "available"
                record["result"] = "published"
                save_receipt(output, receipt)
            except (ReleaseError, subprocess.CalledProcessError, OSError):
                if record["result"] != "uploaded_unconfirmed":
                    record["result"] = "failed"
                save_receipt(output, receipt)
                raise
    print("Selected crates published.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="Check registry prerequisites and print versions without building or uploading")
    mode.add_argument("--dry-run", action="store_true", help="Verify packages without uploading (the default)")
    mode.add_argument("--publish", action="store_true", help="Verify then upload each unpublished version to crates.io")
    mode.add_argument("--publish-verified", metavar="RECEIPT", help="Upload without recompiling after validating a successful receipt for this checkout")
    parser.add_argument("--output", type=Path, help="Write the release receipt and progress outside the checkout")
    args = parser.parse_args()
    try:
        run_release(ROOT, args.publish, args.plan,
                    output=args.output, publish_verified=args.publish_verified)
    except (ReleaseError, subprocess.CalledProcessError, OSError) as error:
        print(f"Release stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
