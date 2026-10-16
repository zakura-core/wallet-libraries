"""Ownership checks must cover registry, renamed and inactive dependencies."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("server_graph", Path(__file__).parents[1] / "server_graph.py")
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)


class ServerBoundaryTests(unittest.TestCase):
    def package(self, name="library-owned", **fields):
        return {"name": name, "source": None, "repository": "https://github.com/zakura-core/wallet-libraries", "dependencies": [], **fields}

    def check(self, package, wallet=False):
        return graph.problems({"packages": [package]}, {"receiver-wire"}, {"zakura-chain"}, wallet)

    def test_library_owned_records_are_allowed(self):
        self.assertEqual(self.check(self.package()), [])

    def test_registry_releases_cannot_hide_package_ownership(self):
        self.assertTrue(self.check(self.package("receiver-wire", source="registry+https://github.com/rust-lang/crates.io-index")))

    def test_renamed_git_and_registry_packages_keep_repository_ownership(self):
        for owner in ("valargroup", "zakura-core"):
            url = f"https://github.com/{owner}/wallet-pir"
            self.assertTrue(self.check(self.package(source=f"git+{url}?rev=abc#abc")))
            self.assertTrue(self.check(self.package(repository=url, source="registry+https://github.com/rust-lang/crates.io-index")))

    def test_inactive_dependency_declarations_are_checked(self):
        for kind, optional, target in ((None, False, None), (None, True, None), ("build", False, None), ("dev", False, None), (None, False, 'cfg(target_os = "windows")')):
            for name, source in (("receiver-wire", None), ("renamed-wire", "git+https://github.com/valargroup/wallet-pir?rev=abc")):
                dependency = {"name": name, "source": source, "kind": kind, "optional": optional, "target": target}
                with self.subTest(dependency=dependency):
                    self.assertTrue(self.check(self.package(dependencies=[dependency])))

    def test_only_server_consumers_may_resolve_node_packages(self):
        for name in ("zakura-chain", "zakura-server-chain"):
            self.assertEqual(self.check(self.package(name)), [])
            self.assertTrue(self.check(self.package(name), wallet=True))

    def test_inactive_node_declarations_are_rejected_for_wallet_facades(self):
        for name in ("zakura-chain", "zakura-server-chain"):
            for kind, optional, target in ((None, False, None), (None, True, None), ("build", False, None), ("dev", False, None), (None, False, 'cfg(target_os = "windows")')):
                package = self.package(dependencies=[{"name": name, "kind": kind, "optional": optional, "target": target}])
                with self.subTest(name=name, kind=kind, optional=optional, target=target):
                    self.assertTrue(graph.problems({"packages": [package]}, set(), {"zakura-chain"}, wallet=True, ownership=False))

    def run_probes(self, contaminated=None):
        consumers = {}
        def metadata(manifest, **kwargs):
            if manifest == graph.ROOT / "Cargo.toml":
                return {"workspace_members": ["wallet"]}
            if manifest == graph.ROOT / "zakura/pir-chain/Cargo.toml":
                return {"workspace_root": str(graph.ROOT / "zakura/pir-chain"), "workspace_members": ["server"], "packages": []}
            consumers[manifest.parent.name] = manifest.read_text()
            packages = [self.package("zakura-chain")] if manifest.parent.name == contaminated else []
            return {"packages": packages}
        with patch.object(graph, "metadata", side_effect=metadata), patch.object(graph.subprocess, "run"):
            graph.main()
        return consumers

    def test_facade_consumers_reject_node_packages_in_every_backend_mode(self):
        for mode in ("facade-default", "facade-zakura", "facade-lrz"):
            with self.subTest(mode=mode), self.assertRaisesRegex(SystemExit, "server/node package"):
                self.run_probes(contaminated=mode)

    def test_production_and_testing_server_consumers_are_both_exercised(self):
        consumers = self.run_probes()
        self.assertIn("server-production", consumers)
        self.assertNotIn('features = ["testing"]', consumers["server-production"])
        self.assertIn('features = ["testing"]', consumers["server"])


if __name__ == "__main__":
    unittest.main()
