import importlib.util
from pathlib import Path
import subprocess
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
        with patch.object(release, "git", return_value="commit"), \
             patch.object(release, "check_checkout"), \
             patch.object(release, "release_packages", return_value=(packages, options.pop("upstream", []))), \
             patch.object(release, "registry_version", side_effect=lambda name, version: statuses[name]), \
             patch.object(release, "wait_for_publication"), \
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

    def test_default_does_not_upload_and_resume_skips_published_versions(self):
        calls = self.run_with([package("first"), package("second")],
                              {"first": "available", "second": "absent"})
        self.assertEqual(len(calls), 1)
        self.assertIn("--dry-run", calls[0].args[0])
        self.assertIn("second/Cargo.toml", calls[0].args[0])

    def test_plan_runs_no_cargo_commands(self):
        self.assertEqual(self.run_with([package("first")], {"first": "absent"}, plan=True), [])

    def test_unpublished_local_dependency_blocks_separate_dry_run(self):
        packages = [package("first"), package("second", {"first": {"version": "1.0.0", "path": "../first"}})]
        with self.assertRaisesRegex(release.ReleaseError, "needs first published first"):
            self.run_with(packages, {"first": "absent", "second": "absent"})

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
            run.assert_called_once_with(release.ROOT, False, False, False)

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
        members = {release.tomllib.loads((release.ROOT / directory / "Cargo.toml").read_text())["package"]["name"]
                   for directory in workspace["members"]}
        self.assertEqual({p["name"] for p in packages}, members)
        self.assertEqual(len(upstream), 8)
        selected, upstream = release.release_packages(release.ROOT, without_transparent=True)
        self.assertEqual(len(selected), len(packages) - 1)
        self.assertEqual(upstream, [])


if __name__ == "__main__":
    unittest.main()
