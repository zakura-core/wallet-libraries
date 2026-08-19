#!/usr/bin/env python3
"""Report which vendored sources have a newer upstream release.

The script reads `manifests/sources.toml`, lists the remote tags of every
source, keeps the tags matching that source's `tag_pattern`, and compares the
highest semantic version against the currently pinned `ref`.

It prints a JSON array of `{"name": ..., "ref": ...}` objects on stdout, ready
to be consumed as a GitHub Actions matrix. Human-readable progress goes to
stderr so it stays out of the JSON.

An explicit `--override name=ref` bypasses discovery for that source and emits
the requested ref verbatim, which is how the manual workflow inputs pin a tag
the automatic rules would skip (a prerelease, an older release, a raw commit).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent.parent / "manifests" / "sources.toml"


def parse_version(version: str) -> tuple | None:
    """Return a sortable key for a semantic version, or None if unparseable.

    Release versions sort above their own prereleases, and prerelease
    identifiers compare per the semver specification: numeric identifiers
    numerically and below alphanumeric ones, a longer identifier list above a
    shorter but otherwise equal one. Build metadata is ignored.
    """
    match = re.fullmatch(
        r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", version
    )
    if match is None:
        return None

    core = tuple(int(part) for part in match.group(1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return (core, (1,))

    identifiers = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            identifiers.append((0, int(identifier), ""))
        else:
            identifiers.append((1, 0, identifier))
    return (core, (0, tuple(identifiers)))


def is_prerelease(version: str) -> bool:
    key = parse_version(version)
    return key is not None and key[1][0] == 0


def remote_tags(url: str) -> list[str]:
    """List the peeled-free tag names of a remote repository."""
    completed = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", url],
        check=True,
        capture_output=True,
        text=True,
    )
    tags = []
    for line in completed.stdout.splitlines():
        _, _, ref = line.partition("\t")
        if ref.startswith("refs/tags/"):
            tags.append(ref[len("refs/tags/") :])
    return tags


def latest_release(source: dict) -> tuple[str, str] | None:
    """Return the (tag, version) of the highest release matching the source."""
    pattern = re.compile(source["tag_pattern"])
    allow_prerelease = source.get("allow_prerelease", False)

    candidates = []
    for tag in remote_tags(source["url"]):
        match = pattern.fullmatch(tag)
        if match is None:
            continue
        version = match.group("version")
        key = parse_version(version)
        if key is None:
            continue
        if not allow_prerelease and is_prerelease(version):
            continue
        candidates.append((key, tag, version))

    if not candidates:
        return None
    _, tag, version = max(candidates)
    return tag, version


def pinned_version(source: dict) -> str | None:
    match = re.compile(source["tag_pattern"]).fullmatch(source["ref"])
    return None if match is None else match.group("version")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--override",
        action="append",
        default=[],
        metavar="NAME=REF",
        help="pin a source to an explicit ref instead of discovering one",
    )
    args = parser.parse_args()

    overrides = {}
    for override in args.override:
        name, separator, ref = override.partition("=")
        if not separator or not name or not ref:
            parser.error(f"invalid override {override!r}; expected name=ref")
        overrides[name] = ref

    with MANIFEST.open("rb") as manifest_file:
        sources = tomllib.load(manifest_file)["source"]

    known = {source["name"] for source in sources}
    for name in overrides:
        if name not in known:
            parser.error(f"unknown source in override: {name}")

    targets = []
    for source in sources:
        name = source["name"]

        if name in overrides:
            print(f"{name}: pinned by override to {overrides[name]}", file=sys.stderr)
            targets.append({"name": name, "ref": overrides[name]})
            continue

        if "tag_pattern" not in source:
            print(f"{name}: no tag_pattern, skipping discovery", file=sys.stderr)
            continue

        latest = latest_release(source)
        if latest is None:
            print(f"{name}: no tag matched tag_pattern", file=sys.stderr)
            continue

        tag, version = latest
        if tag == source["ref"]:
            print(f"{name}: up to date at {tag}", file=sys.stderr)
            continue

        current = pinned_version(source)
        current_key = None if current is None else parse_version(current)
        if current_key is not None and parse_version(version) <= current_key:
            # The pin is ahead of, or equal to, the newest matching release:
            # someone deliberately pinned a commit or a newer prerelease.
            print(
                f"{name}: pinned {source['ref']} is not older than {tag}",
                file=sys.stderr,
            )
            continue

        print(f"{name}: {source['ref']} -> {tag}", file=sys.stderr)
        targets.append({"name": name, "ref": tag})

    print(json.dumps(targets))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
