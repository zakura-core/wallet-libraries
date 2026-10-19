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


class PublishedWalletUpgradeTests(unittest.TestCase):
    def test_current_probe_preserves_exact_workspace_versions(self):
        for requirement in ("4.0.0-rc0", "=4.0.0-rc0"):
            with self.subTest(requirement=requirement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
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
                (workspace / "Cargo.toml").write_text("\n".join(
                    f'{alias} = {{ package = "{package}", version = "{requirement}" }}'
                    for alias, package in packages.items()
                ))
                with patch.object(upgrades, "ROOT", workspace):
                    consumer = upgrades.consumer(root, "current")
                manifest = tomllib.loads((consumer / "Cargo.toml").read_text())
                for alias in packages:
                    self.assertEqual(manifest["dependencies"][alias]["version"], "=4.0.0-rc0")
