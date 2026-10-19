import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "published_wallet_upgrades", Path(__file__).parents[1] / "check-published-wallet-upgrades.py"
)
upgrades = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrades)


class ConsumerDependenciesTests(unittest.TestCase):
    def consumer_dependencies(self, root, version, common_source):
        workspace = root / "workspace"
        probe = workspace / "scripts/probes/published_wallet_upgrades.rs"
        probe.parent.mkdir(parents=True)
        probe.write_text("fn main() {}\n")
        (workspace / "Cargo.lock").write_text("version = 4\n")
        packages = {
            "zcash_primitives": "zakura-primitives",
            "zcash_protocol": "zakura-protocol",
            "transparent": "zakura-transparent",
        }
        (workspace / "Cargo.toml").write_text(
            "[workspace.dependencies]\n" + "\n".join(
                f'{alias} = {{ package = "{package}", {common_source} }}'
                for alias, package in packages.items()
            )
        )
        with patch.object(upgrades, "ROOT", workspace):
            consumer = upgrades.consumer(root / "consumers", version)
        return tomllib.loads((consumer / "Cargo.toml").read_text())["dependencies"]

    def test_current_consumer_keeps_the_wallets_git_revision(self):
        revision = "7c6982448b5d52bf16d1c769bbd61551564f55bb"
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self.consumer_dependencies(
                Path(directory), "current",
                f'version = "=4.0.0-rc1", git = "https://github.com/zakura-core/common.git", rev = "{revision}"',
            )
        for alias in ("zcash_primitives", "zcash_protocol", "transparent"):
            self.assertEqual(dependencies[alias]["version"], "=4.0.0-rc1")
            self.assertEqual(dependencies[alias]["git"], "https://github.com/zakura-core/common.git")
            self.assertEqual(dependencies[alias]["rev"], revision)

    def test_current_registry_consumer_does_not_double_the_exact_version_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self.consumer_dependencies(
                Path(directory), "current", 'version = "=4.0.0-rc1"'
            )
        for alias in ("zcash_primitives", "zcash_protocol", "transparent"):
            self.assertEqual(dependencies[alias]["version"], "=4.0.0-rc1")
            self.assertNotIn("git", dependencies[alias])

    def test_current_probe_preserves_exact_workspace_versions(self):
        for requirement in ("4.0.0-rc0", "=4.0.0-rc0"):
            with self.subTest(requirement=requirement), tempfile.TemporaryDirectory() as directory:
                dependencies = self.consumer_dependencies(
                    Path(directory), "current", f'version = "{requirement}"'
                )
            for alias in ("zcash_primitives", "zcash_protocol", "transparent"):
                self.assertEqual(dependencies[alias]["version"], "=4.0.0-rc0")

    def test_published_writer_keeps_its_original_registry_family(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self.consumer_dependencies(
                Path(directory), "rc9", 'version = "=4.0.0-rc1", git = "https://github.com/zakura-core/common.git"'
            )
        for alias in ("zcash_primitives", "zcash_protocol", "transparent"):
            self.assertEqual(dependencies[alias]["version"], "=3.0.0")
            self.assertNotIn("git", dependencies[alias])


if __name__ == "__main__":
    unittest.main()
