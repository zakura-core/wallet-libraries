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
            with self.assertRaisesRegex(release.ReleaseError, "required upstream"):
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
            run.assert_called_once_with(release.ROOT, False, False,
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
        # The facade pins the complete Common family. Publication must wait for
        # those exact registry versions when development uses a git revision.
        facade = release.tomllib.loads((release.ROOT / "wallet-lib/Cargo.toml").read_text())
        common_prerequisites = sorted({
            (dependency["package"], dependency["version"].removeprefix("="))
            for dependency in facade["dependencies"].values()
            if isinstance(dependency, dict)
            and dependency.get("git") == "https://github.com/zakura-core/common.git"
        })
        self.assertEqual(upstream, sorted(common_prerequisites + [
            ("ipir-native-client", "0.1.0-rc.1"),
            ("ipir-sp", "0.1.0-rc.7"),
            ("reinspiring", "0.1.3-rc.1"),
        ]))

    def test_wallet_pir_packages_are_refused_under_any_source(self):
        declarations = (
            'receiver-pir = "=0.1.0"',
            'receiver-pir = { version = "=0.1.0" }',
            'alias = { package = "transparent-shard", version = "=0.1.0" }',
            'renamed = { git = "https://github.com/valargroup/wallet-pir", version = "=0.1.0" }',
        )
        for declaration in declarations:
            for inherited in (False, True):
                self.check_forbidden_dependency(declaration, inherited)

    def test_node_dependencies_are_refused_before_publication(self):
        for declaration in (
            'zakura-chain = "=1.0.0"',
            'alias = { package = "zakura-state", version = "=1.0.0" }',
            'future-node = { git = "https://github.com/zakura-core/zakura.git", version = "=1.0.0" }',
            'alias = { package = "zakura-server-chain", version = "=0.0.1-rc0" }',
        ):
            for inherited in (False, True):
                self.check_forbidden_dependency(declaration, inherited)

    def test_wallet_pir_repository_spellings_are_refused(self):
        # An unlisted package name leaves only the repository identity to refuse it.
        for owner in ("valargroup", "zakura-core"):
            for url in (
                f"https://github.com/{owner}/wallet%2Dpir",
                f"https://%67ithub.com/{owner}/wallet-pir.git",
                f"https://github.com/{owner}/ignored/../wallet-pir.git",
                f"https://github.com/{owner}%2Fwallet-pir",
                f"https://github.com/{owner}/wallet-pir%2Egit",
                f"https://GITHUB.COM:443/{owner.upper()}/WALLET-PIR.git/",
                f"https://www.github.com/{owner}/wallet-pir",
                f"https://github.com./{owner}/wallet-pir",
                f"https://github.com//{owner}/wallet-pir",
                f"git+https://github.com/{owner}/wallet-pir?branch=main#0123abc",
                f"ssh://git@github.com/{owner}/wallet-pir.git",
                f"ssh://git@ssh.github.com:443/{owner}/wallet-pir",
                f"git@github.com:{owner}/wallet-pir.git",
                f" https://github.com/{owner}/wallet-pir ",
            ):
                for inherited in (False, True):
                    self.check_forbidden_dependency(f'future-wire = {{ git = "{url}", version = "=0.1.0" }}', inherited)

    def test_backslash_separated_repository_urls_are_refused(self):
        # Cargo parses special-scheme URLs as WHATWG URLs, where a backslash is a slash.
        urls = []
        for owner in ("valargroup", "zakura-core"):
            urls += [f"https:\\\\github.com\\{owner}\\wallet-pir", f"https://github.com\\{owner}\\wallet-pir.git",
                     f"https://github.com\\{owner}/wallet-pir", f"git+https://github.com/{owner}\\wallet-pir"]
        for url in urls:
            escaped = url.replace("\\", "\\\\")
            for declaration in (f'future-wire = {{ git = "{escaped}", version = "=1.0.0" }}',
                                f'future-wire = {{ git = "{escaped}", version = "=1.0.0", optional = true }}',
                                f'renamed = {{ package = "future-wire", git = "{escaped}", version = "=1.0.0" }}'):
                for inherited in (False, True):
                    self.check_forbidden_dependency(declaration, inherited)

    def test_cargo_normalized_backslash_sources_match_the_raw_predicate(self):
        # Independent oracle: Cargo's own source normalization, offline and without building.
        url = "https://github.com\\valargroup\\wallet-pir"
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text('[package]\nname = "probe"\nversion = "0.0.0"\n[lib]\npath = "lib.rs"\n'
                                f"[dependencies]\nfuture-wire = {{ git = '{url}', version = '=1.0.0' }}\n")
            output = subprocess.check_output(["cargo", "metadata", "--no-deps", "--offline", "--format-version", "1",
                                              "--manifest-path", str(manifest)], text=True)
        source = json.loads(output)["packages"][0]["dependencies"][0]["source"]
        self.assertEqual(source, "git+https://github.com/valargroup/wallet-pir")
        self.assertTrue(release.dependency_boundary.wallet_pir_owned(source))
        self.assertTrue(release.dependency_boundary.wallet_pir_owned(url))

    def test_neighbouring_git_repositories_remain_release_prerequisites(self):
        for url in (
            "https://evil.example\\github.com\\valargroup\\wallet-pir",
            "https://github.com\\valargroup\\wallet-pir-extra",
            "https://github.com\\other\\wallet-pir",
            "https://github.com/valargroup/wallet-pir-extra",
            "https://github.com/valargroup/wallet-pirate",
            "https://github.com/other/wallet-pir",
            "https://github.com/valargroup/wallet%252Dpir",
            "https://github.com.evil.example/valargroup/wallet-pir",
            "https://%67ithub.com.evil.example/valargroup/wallet-pir",
            "https://github.com/valargroup/wallet-pir/../ordinary",
            "https://evil.example/github.com/valargroup/wallet-pir",
            "https://github.com@evil.example/valargroup/wallet-pir",
            "https://github.com/zcash/librustzcash",
        ):
            for inherited in (False, True):
                escaped = url.replace("\\", "\\\\")
                declaration = f'external = {{ git = "{escaped}", version = "=0.1.0" }}'
                for table, root in self.release_roots(declaration, inherited):
                    with self.subTest(url=url, inherited=inherited, table=table), \
                            patch.object(release, "ORDER", ("first",)):
                        self.assertEqual(release.release_packages(root)[1], [("external", "0.1.0")])

    def release_roots(self, declaration, inherited):
        alias = declaration.split(" =", 1)[0]
        for table in ("dependencies", "dev-dependencies", "build-dependencies", 'target."cfg(unix)".dependencies',
                      'target."cfg(unix)".dev-dependencies', 'target."cfg(unix)".build-dependencies'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "manifests").mkdir()
                (root / "manifests/sources.toml").write_text(
                    '[dependency_boundary]\nnode_packages = ["zakura-chain", "zakura-state"]\nwallet_pir_packages = ["receiver-pir", "transparent-shard", "zakura-server-chain"]\n')
                (root / "first").mkdir()
                (root / "first/Cargo.toml").write_text(
                    f'[package]\nname = "first"\nversion = "1.0.0"\n[{table}]\n'
                    + (f'{alias} = {{ workspace = true }}\n' if inherited else declaration + "\n"))
                (root / "Cargo.toml").write_text('[workspace]\nmembers = ["first"]\n[workspace.dependencies]\n'
                                                     + (declaration + '\n' if inherited else ''))
                yield table, root

    def check_forbidden_dependency(self, declaration, inherited):
        for table, root in self.release_roots(declaration, inherited):
            with self.subTest(declaration=declaration, inherited=inherited, table=table), \
                    patch.object(release, "ORDER", ("first",)), \
                    self.assertRaisesRegex(release.ReleaseError, "depends on the (wallet-pir|node) package"):
                release.release_packages(root)

    def test_string_dependencies_keep_release_version_and_order_checks(self):
        for inherited in (False, True):
            for requirement, ordered, expected in (
                ("=1.0.0", True, None),
                ("=2.0.0", True, "mismatched dependency"),
                ("=1.0.0", False, "must be published before"),
            ):
                with self.subTest(inherited=inherited, requirement=requirement, ordered=ordered), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "manifests").mkdir()
                    (root / "manifests/sources.toml").write_text('[dependency_boundary]\nnode_packages = []\nwallet_pir_packages = []\n')
                    (root / "first").mkdir()
                    (root / "first/Cargo.toml").write_text('[package]\nname = "first"\nversion = "1.0.0"\n')
                    (root / "second").mkdir()
                    declaration = 'first = { workspace = true }' if inherited else f'first = "{requirement}"'
                    (root / "second/Cargo.toml").write_text(
                        '[package]\nname = "second"\nversion = "1.0.0"\n[dependencies]\n'
                        + declaration + '\nexternal = "0.5"\n')
                    (root / "Cargo.toml").write_text(
                        '[workspace]\nmembers = ["first", "second"]\n[workspace.dependencies]\n'
                        + f'first = "{requirement}"\n')
                    order = ("first", "second") if ordered else ("second", "first")
                    with patch.object(release, "ORDER", order):
                        if expected:
                            with self.assertRaisesRegex(release.ReleaseError, expected):
                                release.release_packages(root)
                        else:
                            packages, upstream = release.release_packages(root)
                            self.assertEqual([p["name"] for p in packages], ["first", "second"])
                            self.assertEqual(upstream, [])

    def receipt(self, directory, selection, **changes):
        data = {"schema_version": 2, "commit": "commit",
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
                   {"verification_passed": 1}, {"schema_version": 1},
                   {"packages": []},
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
            release.validate_receipt(output, "commit", [package("first")])

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
