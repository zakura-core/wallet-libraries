#!/usr/bin/env python3
"""Measure one-time recovery's per-batch scan overhead in release mode.

Runs the ignored `one_time_batch_overhead` timing test several times and prints, per account
count and step, the median of the per-run medians with recovery never enabled and enabled,
and their ratio. `hook` is `after_blocks_stored` alone; `scanN` scans N empty blocks.
"""
import argparse
import os
import re
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINE = re.compile(r"BENCH accounts=(\d+) enabled=(\w+) step=(\w+) ms=([\d.]+)")


def main() -> int:
    """Builds once, runs the timing test `--runs` times and prints the summary table."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, type=Path, help="absolute Cargo target directory")
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    argv = [
        "cargo", "test", "--locked", "--release", "-p", "zakura-client-sqlite",
        "--features", "orchard,test-dependencies", "--lib", "one_time_batch_overhead",
        "--", "--ignored", "--nocapture", "--test-threads=1",
    ]
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
    samples = defaultdict(list)
    for run in range(args.runs):
        output = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        if output.returncode != 0:
            print(output.stdout + output.stderr)
            return output.returncode
        for accounts, enabled, step, ms in LINE.findall(output.stdout):
            samples[(int(accounts), step, enabled == "true")].append(float(ms))
        print(f"run {run + 1}/{args.runs} done", flush=True)
    print(f"{'accounts':>8} {'step':>6} {'off ms':>8} {'on ms':>8} {'ratio':>6}")
    for accounts, step in sorted({(a, s) for a, s, _ in samples}, key=lambda k: (k[0], k[1] != "hook", len(k[1]), k[1])):
        off = statistics.median(samples[(accounts, step, False)])
        on = statistics.median(samples[(accounts, step, True)])
        print(f"{accounts:>8} {step:>6} {off:>8.3f} {on:>8.3f} {on / off:>6.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
