#!/usr/bin/env python3
"""Check release CI, summarize receipts, and confirm trusted publication."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request


REPOSITORY = "zakura-core/wallet-libraries"


def require_verified_ci(repository, commit):
    if repository != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Release CI requires this repository and a full commit SHA.")
    endpoint = (f"repos/{repository}/actions/workflows/verify.yml/runs"
                f"?head_sha={commit}&branch=main&event=push&per_page=100")
    data = json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))
    runs = [run for run in data["workflow_runs"]
            if run["head_sha"] == commit and run["head_branch"] == "main"
            and run["event"] == "push"]
    if not runs:
        raise ValueError(f"Verify wallet libraries has no main push run for {commit}.")
    latest = max(runs, key=lambda run: (run["run_number"], run["run_attempt"]))
    if latest["status"] != "completed" or latest["conclusion"] != "success":
        raise ValueError("Verify wallet libraries must finish successfully for this commit: "
                         + latest["html_url"])
    print("Required verification passed: " + latest["html_url"])


def summarize(receipt):
    rows = ["## Crate release", "", f"Commit: `{receipt['commit']}`", "",
            "Package verification: " + ("passed" if receipt["verification_passed"] else "not completed"),
            "", "| Crate | Version | Registry | Result |", "| --- | --- | --- | --- |"]
    for package in receipt["packages"]:
        rows.append(f"| `{package['name']}` | `{package['version']}` | "
                    f"{package['registry_status']} | {package['result']} |")
    rows.extend(["", "If publication stopped, rerun from this same commit. "
                 "Available versions will be skipped; crate versions cannot be overwritten."])
    return "\n".join(rows) + "\n"


def registry_record(name, version):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "wallet-libraries-release-ci"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)["version"]


def confirm_publication(receipt, repository, run_id, commit):
    if repository != REPOSITORY or receipt["commit"] != commit:
        raise ValueError("Publication confirmation must match this repository and release commit.")
    errors = []
    for package in receipt["packages"]:
        result = package["result"]
        if result not in ("previously_available", "published", "uploaded_unconfirmed"):
            errors.append(f"{package['name']} {package['version']}: {result}")
            continue
        try:
            version = registry_record(package["name"], package["version"])
            if version["yanked"]:
                raise ValueError("version is yanked")
            if result != "previously_available":
                attestation = version.get("trustpub_data") or {}
                actual = (attestation.get("provider"), attestation.get("repository"),
                          str(attestation.get("run_id")), attestation.get("sha"))
                if actual != ("github", repository, str(run_id), commit):
                    raise ValueError("registry publication is not attributed to this workflow run and commit")
            print(f"Confirmed {package['name']} {package['version']}: {result}")
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f"{package['name']} {package['version']}: {error}")
    if errors:
        raise ValueError("Publication is incomplete:\n" + "\n".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    check = modes.add_parser("check-ci")
    check.add_argument("--repository", required=True)
    check.add_argument("--commit", required=True)
    summary = modes.add_parser("summary")
    summary.add_argument("receipt", type=Path)
    confirm = modes.add_parser("confirm")
    confirm.add_argument("receipt", type=Path)
    confirm.add_argument("--repository", required=True)
    confirm.add_argument("--run-id", required=True)
    confirm.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "check-ci":
            require_verified_ci(args.repository, args.commit)
        else:
            receipt = json.loads(args.receipt.read_text())
            if args.mode == "summary":
                print(summarize(receipt), end="")
            else:
                confirm_publication(receipt, args.repository, args.run_id, args.commit)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Release CI stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
