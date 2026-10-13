import importlib.util
from pathlib import Path
import subprocess
import json
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publish_crates", Path(__file__).parents[1] / "publish-crates.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def package(name, dependencies=None):
    return {"name": name, "version": "1.0.0", "path": Path(name) / "Cargo.toml",
            "manifest": {"dependencies": dependencies or {}}}


class PublishingTests(unittest.TestCase):
    def run_with(self, packages, statuses, **options):
        wait_error = options.pop("wait_error", None)
        with patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=(packages, options.pop("upstream", []))), \
             patch.object(release, "registry_version", side_effect=lambda name, version: statuses[name]), \
             patch.object(release, "wait_for_publication", side_effect=wait_error), \
             patch.object(release.subprocess, "run") as cargo:
            release.run_release(Path("."), **options)
            return cargo.call_args_list

    def test_uploads_follow_successful_dry_runs_in_dependency_order(self):
        calls = self.run_with([package("first"), package("second")],
                              {"first": "absent", "second": "absent"}, publish=True)
        self.assertEqual(len(calls), 4)
        for index, name in enumerate(("first", "second")):
            dry, upload = (calls[index * 2 + i].args[0] for i in (0, 1))
            self.assertIn(str(Path(name) / "Cargo.toml"), dry)
            self.assertEqual(dry, [*upload, "--dry-run"])
            self.assertIn("crates-io", upload)

    def test_failed_verification_never_uploads_or_continues(self):
        with patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=([package("first"), package("second")], [])), \
             patch.object(release, "registry_version", return_value="absent"), \
             patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")) as cargo:
            with self.assertRaises(subprocess.CalledProcessError):
                release.run_release(Path("."), publish=True)
            self.assertEqual(cargo.call_count, 1)
            self.assertIn("--dry-run", cargo.call_args.args[0])

    def test_missing_upstream_stops_before_any_cargo_command(self):
        with patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=([package("first")], [("upstream", "1.0.0")])), \
             patch.object(release, "registry_version", return_value="absent"), \
             patch.object(release.subprocess, "run") as cargo:
            with self.assertRaisesRegex(release.ReleaseError, "required wallet-pir"):
                release.run_release(Path("."), publish=True)
            cargo.assert_not_called()

    def test_default_verifies_all_crates_together_without_uploading(self):
        calls = self.run_with([package("first"), package("second")],
                              {"first": "available", "second": "absent"})
        self.assertEqual(len(calls), 1)
        command = calls[0].args[0]
        self.assertIn("--dry-run", command)
        self.assertIn("--keep-going", command)
        self.assertEqual(command[-4:], ["--package", "first", "--package", "second"])
        self.assertNotIn("--all-features", command)

    def test_publish_resume_skips_already_published_versions(self):
        calls = self.run_with([package("first"), package("second")],
                              {"first": "available", "second": "absent"}, publish=True)
        self.assertEqual(len(calls), 2)
        self.assertIn("second/Cargo.toml", calls[0].args[0])
        self.assertIn("--dry-run", calls[0].args[0])
        self.assertNotIn("--dry-run", calls[1].args[0])

    def test_plan_runs_no_cargo_commands(self):
        self.assertEqual(self.run_with([package("first")], {"first": "absent"}, plan=True), [])

    def test_unpublished_local_dependencies_are_included_in_whole_release_dry_run(self):
        packages = [package("first"), package("second", {"first": {"version": "1.0.0", "path": "../first"}})]
        calls = self.run_with(packages, {"first": "absent", "second": "absent"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[0][-4:], ["--package", "first", "--package", "second"])

    def test_dirty_or_changed_checkout_is_refused(self):
        for responses in (("new-commit",), ("commit", " M Cargo.toml")):
            with patch.object(release, "git", side_effect=responses):
                with self.assertRaises(release.ReleaseError):
                    release.check_checkout(Path("."), "commit")

    def test_registry_failure_is_not_treated_as_an_unpublished_version(self):
        with patch.object(release.urllib.request, "urlopen", side_effect=release.urllib.error.URLError("offline")):
            with self.assertRaises(release.ReleaseError):
                release.registry_version("first", "1.0.0")

    def test_explicit_dry_run_selects_no_uploads(self):
        with patch.object(release.sys, "argv", ["publish-crates.py", "--dry-run"]), \
             patch.object(release, "run_release") as run:
            self.assertEqual(release.main(), 0)
            run.assert_called_once_with(release.ROOT, False, False, False,
                                        output=None, publish_verified=None)

    def test_dry_run_cannot_be_combined_with_publish(self):
        with patch.object(release.sys, "argv", ["publish-crates.py", "--dry-run", "--publish"]), \
             patch.object(release, "run_release") as run:
            with self.assertRaises(SystemExit) as error:
                release.main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()

    def test_real_manifest_order_covers_all_workspace_crates(self):
        packages, upstream = release.release_packages(release.ROOT)
        workspace = release.tomllib.loads((release.ROOT / "Cargo.toml").read_text())["workspace"]
        manifests = [release.tomllib.loads((release.ROOT / directory / "Cargo.toml").read_text())["package"]
                     for directory in workspace["members"]]
        members = {package["name"] for package in manifests if package.get("publish") is not False}
        self.assertEqual({p["name"] for p in packages}, members)
        # wallet-pir's crates come from crates.io, so no git prerequisite remains.
        self.assertEqual(upstream, [])
        selected, upstream = release.release_packages(release.ROOT, without_transparent=True)
        self.assertEqual(len(selected), len(packages) - 1)
        self.assertEqual(upstream, [])

    def receipt(self, directory, selection, **changes):
        data = {"schema_version": 1, "commit": "commit", "without_transparent": False,
                "verification_passed": True,
                "packages": [{"name": p["name"], "version": p["version"],
                              "registry_status": "absent", "result": "remaining"}
                             for p in selection]}
        data.update(changes)
        path = Path(directory) / "verified.json"
        path.write_text(json.dumps(data))
        return path

    def test_verified_publication_never_compiles_and_preserves_dependency_order(self):
        packages = [package("first"), package("second")]
        with tempfile.TemporaryDirectory() as directory:
            receipt = self.receipt(directory, packages)
            output = Path(directory) / "progress.json"
            calls = self.run_with(packages, {"first": "absent", "second": "absent"},
                                  publish_verified=receipt, output=output)
            self.assertEqual(len(calls), 2)
            for call, name in zip(calls, ("first", "second")):
                command = call.args[0]
                self.assertIn(str(Path(name) / "Cargo.toml"), command)
                self.assertIn("--no-verify", command)
                self.assertIn("--locked", command)
                self.assertNotIn("--dry-run", command)
            self.assertEqual([p["result"] for p in json.loads(output.read_text())["packages"]],
                             ["published", "published"])

    def test_bad_receipts_stop_before_registry_queries_or_uploads(self):
        packages = [package("first"), package("second")]
        invalid = ({"commit": "other"}, {"verification_passed": False},
                   {"verification_passed": 1}, {"schema_version": 2},
                   {"without_transparent": True}, {"packages": []},
                   {"packages": [{"name": "second", "version": "1.0.0"},
                                 {"name": "first", "version": "1.0.0"}]},
                   {"packages": [{"name": "first", "version": "2.0.0"}]})
        with tempfile.TemporaryDirectory() as directory:
            for changes in invalid:
                with self.subTest(changes=changes), \
                     patch.object(release, "git", return_value="commit"), \
                     patch.object(release, "check_checkout"), \
                     patch.object(release, "release_packages", return_value=(packages, [])), \
                     patch.object(release, "registry_version") as registry, \
                     patch.object(release.subprocess, "run") as cargo:
                    with self.assertRaises(release.ReleaseError):
                        release.run_release(Path("."), publish_verified=self.receipt(directory, packages, **changes))
                    registry.assert_not_called()
                    cargo.assert_not_called()

    def test_missing_empty_or_malformed_receipt_never_uploads(self):
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "malformed.json"
            malformed.write_text("not json")
            for receipt in ("", Path(directory) / "missing.json", malformed):
                with self.subTest(receipt=receipt), \
                     patch.object(release, "git", return_value="commit"), \
                     patch.object(release, "check_checkout"), \
                     patch.object(release, "release_packages", return_value=([package("first")], [])), \
                     patch.object(release.subprocess, "run") as cargo:
                    with self.assertRaises(release.ReleaseError):
                        release.run_release(Path("."), publish_verified=receipt)
                    cargo.assert_not_called()

    def test_verified_mode_cannot_be_combined_with_local_publication(self):
        with patch.object(release.sys, "argv", ["publish-crates.py", "--publish-verified", "receipt.json", "--publish"]), \
             patch.object(release, "run_release") as run:
            with self.assertRaises(SystemExit):
                release.main()
            run.assert_not_called()

    def test_failed_whole_release_verification_leaves_unsuccessful_receipt(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=([package("first")], [])), \
             patch.object(release, "registry_version", return_value="absent"), \
             patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")):
            output = Path(directory) / "progress.json"
            with self.assertRaises(subprocess.CalledProcessError):
                release.run_release(Path("."), output=output)
            self.assertIs(json.loads(output.read_text())["verification_passed"], False)

    def test_successful_whole_release_verification_writes_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "progress.json"
            self.run_with([package("first")], {"first": "absent"}, output=output)
            release.validate_receipt(output, "commit", [package("first")], False)

    def test_receipts_cannot_be_written_inside_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(release.ReleaseError):
                release.output_path(Path(directory), Path(directory) / "receipt.json")

    def test_failed_upload_retains_prior_success_and_remaining_packages(self):
        packages = [package("first"), package("second"), package("third")]
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=(packages, [])), \
             patch.object(release, "registry_version", return_value="absent"), \
             patch.object(release, "wait_for_publication"), \
             patch.object(release.subprocess, "run", side_effect=[None, subprocess.CalledProcessError(1, "cargo")]) as cargo:
            output = Path(directory) / "progress.json"
            with self.assertRaises(subprocess.CalledProcessError):
                release.run_release(Path("."), publish_verified=self.receipt(directory, packages), output=output)
            self.assertEqual(cargo.call_count, 2)
            self.assertEqual([p["result"] for p in json.loads(output.read_text())["packages"]],
                             ["published", "failed", "remaining"])

    def test_upload_without_registry_confirmation_is_not_reported_as_published(self):
        packages = [package("first")]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "progress.json"
            with self.assertRaises(release.ReleaseError):
                self.run_with(packages, {"first": "absent"},
                              publish_verified=self.receipt(directory, packages), output=output,
                              wait_error=release.ReleaseError("not visible"))
            self.assertEqual(json.loads(output.read_text())["packages"][0]["result"], "uploaded_unconfirmed")

    def test_registry_is_rechecked_before_upload(self):
        with patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=([package("first")], [])), \
             patch.object(release, "registry_version", side_effect=["absent", "available"]), \
             patch.object(release.subprocess, "run") as cargo:
            release.run_release(Path("."), publish=True)
            cargo.assert_not_called()

    def test_yanked_or_unreachable_registry_stops_publication(self):
        for value in ("yanked", release.ReleaseError("registry unavailable")):
            with self.subTest(value=value), \
                 patch.object(release, "git", return_value="commit"), \
                 patch.object(release, "check_checkout"), \
                 patch.object(release, "release_packages", return_value=([package("first")], [])), \
                 patch.object(release, "registry_version", side_effect=["absent", value]), \
                 patch.object(release.subprocess, "run") as cargo:
                with self.assertRaises(release.ReleaseError):
                    release.run_release(Path("."), publish=True)
                cargo.assert_not_called()


if __name__ == "__main__":
    unittest.main()
