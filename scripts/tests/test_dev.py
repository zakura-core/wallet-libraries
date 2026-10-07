"""Behavioral regressions for leases, filtered checks, and source attribution."""
import argparse
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("dev", Path(__file__).parents[1] / "dev.py")
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)


def acquire(root, ready, release):
    with dev.Lease(Path(root), "test") as lease:
        ready.put(str(lease.path))
        release.get(timeout=10)


class WorkflowTests(unittest.TestCase):
    def test_custom_target_stays_under_build_root_and_tracks_json_changes(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target.json"
            target.write_text('{"arch":"x86_64"}')
            with patch.dict(os.environ, {"CARGO_BUILD_TARGET": str(target)}), patch.object(dev, "capture", return_value="host: x86_64-unknown-linux-gnu"):
                first = dev.build_identity("default", "test")
                self.assertFalse(Path(first).is_absolute())
                self.assertEqual(Path(first).parts[0], "target.json")
                target.write_text('{"arch":"aarch64"}')
                self.assertNotEqual(first, dev.build_identity("default", "test"))

    def test_parallel_owners_reuse_released_directory(self):
        with tempfile.TemporaryDirectory() as root:
            context = multiprocessing.get_context("fork")
            ready, release = context.Queue(), context.Queue()
            child = context.Process(target=acquire, args=(root, ready, release))
            child.start()
            first = Path(ready.get(timeout=10))
            try:
                with dev.Lease(Path(root), "test") as second:
                    self.assertNotEqual(first, second.path)
                release.put(True)
                child.join(timeout=10)
                self.assertEqual(child.exitcode, 0)
                with dev.Lease(Path(root), "test") as reused:
                    self.assertEqual(first, reused.path)
            finally:
                if child.is_alive():
                    child.kill()
                    child.join()

    def test_killed_owner_releases_lease(self):
        with tempfile.TemporaryDirectory() as root:
            context = multiprocessing.get_context("fork")
            ready, release = context.Queue(), context.Queue()
            child = context.Process(target=acquire, args=(root, ready, release))
            child.start()
            first = Path(ready.get(timeout=10))
            child.kill()
            child.join()
            with dev.Lease(Path(root), "test") as reused:
                self.assertEqual(first, reused.path)
                self.assertEqual(json.loads((reused.path / "owner.json").read_text())["pid"], os.getpid())

    def test_child_retains_lease_after_wrapper_exit(self):
        with tempfile.TemporaryDirectory() as root:
            with dev.Lease(Path(root), "test") as owner:
                first = owner.path
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], pass_fds=(owner.lock.fileno(),))
            try:
                with dev.Lease(Path(root), "test") as second:
                    self.assertNotEqual(first, second.path)
            finally:
                child.terminate()
                child.wait(timeout=10)
            with dev.Lease(Path(root), "test") as reused:
                self.assertEqual(first, reused.path)

    def run_filtered(self, listing, states=None):
        args = argparse.Namespace(command="test", config="transparent", package=["zakura-client-sqlite"], profile=None, only=None, filter="ledger", exact=False)
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"WALLET_LIB_BUILD_ROOT": root}), patch.object(dev, "build_identity", return_value="test"), patch.object(dev, "source_state", side_effect=states or [{"sha": "a", "inputs": "b"}] * 3), patch.object(dev, "run", side_effect=[subprocess.CompletedProcess([], 0, listing), subprocess.CompletedProcess([], 0)]) as run:
            code = dev.execute(args)
            result = json.loads(next(Path(root).glob("**/last-result.json")).read_text())
            return code, result, run.call_args_list

    def test_empty_selection_fails_without_running_tests(self):
        code, result, calls = self.run_filtered("0 tests, 0 benchmarks\n")
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(calls), 1)

    def test_selected_tests_run_with_configuration_and_no_dependency_lint(self):
        code, result, calls = self.run_filtered("wallet::ledger: test\n")
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        command = calls[1].args[0]
        self.assertIn("orchard,transparent-inputs,test-dependencies,unstable", command)
        self.assertIn("zakura-client-sqlite", command)
        self.assertEqual(result["status"], "pass")

    def test_changed_inputs_invalidate_success(self):
        old, new = {"sha": "a", "inputs": "b"}, {"sha": "a", "inputs": "c"}
        code, result, _ = self.run_filtered("ledger: test\n", [old, old, new])
        self.assertEqual(code, 3)
        self.assertEqual(result["status"], "invalidated")

    def test_documented_and_options_first_orders_parse_the_same_filter(self):
        for argv in (
            ["test", "--config", "transparent", "-p", "zakura-client-sqlite", "transparent_ledger"],
            ["--config", "transparent", "-p", "zakura-client-sqlite", "test", "transparent_ledger"],
        ):
            with patch.object(dev, "execute", return_value=0) as execute:
                self.assertEqual(dev.main(argv), 0)
            args = execute.call_args.args[0]
            self.assertEqual((args.command, args.filter, args.config, args.package), ("test", "transparent_ledger", "transparent", ["zakura-client-sqlite"]))

    def test_facade_requires_explicit_verification(self):
        with self.assertRaisesRegex(ValueError, "exclusive backends"):
            dev.cargo_args(argparse.Namespace(package=["zakura-wallet-lib"], config="default"))


if __name__ == "__main__":
    unittest.main()
