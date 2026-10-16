#!/usr/bin/env python3
"""Conservatively select wallet validation; unknown paths require full checks."""
import argparse
from pathlib import PurePosixPath
import subprocess


def needs_rust(paths):
    for name in paths:
        path = PurePosixPath(name)
        if path.parts[0] in {"zakura", "librustzcash", "wallet-lib"}:
            return True
        if path.suffix in {".md", ".mdc"}:
            continue
        if path.parts[0] in {".cursor", ".agents"} and path.suffix not in {".rs", ".toml", ".py", ".sh"}:
            continue
        if name in {"LICENSE-MIT", "LICENSE-APACHE", ".gitignore"}:
            continue
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="PR base commit; use 'all' for push/manual runs")
    args = parser.parse_args()
    paths = [] if args.base == "all" else subprocess.check_output(["git", "diff", "--name-only", "-z", args.base, "HEAD"], text=True).split("\0")
    print("rust=" + str(args.base == "all" or needs_rust(p for p in paths if p)).lower())


if __name__ == "__main__":
    main()
