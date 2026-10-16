"""The receiver library must be consumable without a PIR service release."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNED_PACKAGES = {
    "receiver-wire", "receiver-directory", "receiver-pir", "receiver-pir-server",
    "pir-native", "pir-control", "pir-observability", "enhance-pir",
    "transparent-events", "transparent-filter", "transparent-native",
    "transparent-shard", "transparent-shard-server", "transparent-wallet",
    "transparent-wallet-store", "transparent-txid-client", "transparent-blocks",
}


def service_dependencies(manifest, workspace):
    found = []
    tables = [manifest, *manifest.get("target", {}).values()]
    for table in tables:
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, value in table.get(kind, {}).items():
                if isinstance(value, dict) and value.get("workspace"):
                    value = workspace.get(name, value)
                value = value if isinstance(value, dict) else {}
                package = value.get("package", name)
                source = value.get("git", "").lower().rstrip("/").removesuffix(".git")
                if package in OWNED_PACKAGES or source in {
                    "https://github.com/valargroup/wallet-pir",
                    "git@github.com:valargroup/wallet-pir",
                    "ssh://git@github.com/valargroup/wallet-pir",
                }:
                    found.append((kind, name))
    return found


class ReceiverBoundaryTests(unittest.TestCase):
    def test_receiver_library_has_no_service_owned_dependency(self):
        manifest = tomllib.loads((ROOT / "zakura/receiver-crypto/Cargo.toml").read_text())
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["dependencies"]
        self.assertEqual(service_dependencies(manifest, workspace), [])

    def test_receiver_consumers_have_no_service_owned_dependency(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["dependencies"]
        for crate in (
            "receiver-directory", "receiver-pir", "pir-receiver", "one-time-ivk-scenarios",
        ):
            manifest = tomllib.loads((ROOT / "zakura" / crate / "Cargo.toml").read_text())
            with self.subTest(crate=crate):
                self.assertEqual(service_dependencies(manifest, workspace), [])

    def test_optional_development_build_target_and_registry_edges_are_checked(self):
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            for value in (
                {"package": "receiver-wire", "version": "1", "optional": True},
                {"git": "https://github.com/valargroup/wallet-pir.git"},
                {"workspace": True},
            ):
                table = {kind: {"alias": value}}
                for manifest in (table, {"target": {"cfg(windows)": table}}):
                    with self.subTest(kind=kind, manifest=manifest):
                        self.assertEqual(
                            service_dependencies(manifest, {"alias": {"package": "receiver-wire", "version": "1"}}),
                            [(kind, "alias")],
                        )
