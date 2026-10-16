"""Ownership checks must cover registry, renamed and inactive dependencies."""
import importlib.util
from pathlib import Path
import tempfile
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

    def test_repository_urls_with_ssh_ports_cannot_hide_new_packages(self):
        for owner in ("valargroup", "zakura-core"):
            for url in (
                f"git+ssh://git@github.com:22/{owner}/wallet-pir?rev=abc#def",
                f"ssh://git@github.com:443/{owner}/wallet-pir.git",
                f"git+ssh://git@ssh.github.com:443/{owner}/wallet-pir.git?rev=abc#def",
                f"git@ssh.github.com:{owner}/wallet-pir.git",
                f"git@github.com:{owner}/wallet-pir.git",
                f"git@GITHUB.COM:{owner}/wallet-pir.git",
                f"https://GITHUB.COM:443/{owner.upper()}/WALLET-PIR.git/",
                f"git+https://github.com/{owner}/wallet%2Dpir?rev=abc#def",
                f"https://github.com/{owner}%2Fwallet-pir",
                f"https://www.github.com/{owner}/wallet-pir",
                f"https://github.com./{owner}/wallet-pir",
                f"https://github.com//{owner}/wallet-pir",
                f"git@github.com:/{owner}/wallet-pir.git",
                f" https://github.com/{owner}/wallet-pir ",
            ):
                with self.subTest(url=url):
                    self.assertTrue(self.check(self.package("future-wire", source=url)))
                    self.assertTrue(self.check(self.package("future-wire", repository=url)))
                    self.assertTrue(self.check(self.package(dependencies=[{"name": "future-wire", "source": url}])))
                    with tempfile.TemporaryDirectory(dir=graph.ROOT) as directory:
                        lockfile = Path(directory) / "Cargo.lock"
                        lockfile.write_text(f'version = 4\n[[package]]\nname = "future-wire"\nversion = "0.1.0"\nsource = "{url}"\n')
                        self.assertTrue(graph.lock_problems(lockfile, set()))

    def test_neighbor_repositories_and_hosts_remain_allowed(self):
        for url in (
            None, "https://github.com/zakura-core/wallet-libraries",
            "git+ssh://git@github.com:22/valargroup/wallet-pir-tools?rev=abc",
            "https://example.com/valargroup/wallet-pir",
            "https://github.com.example.com/valargroup/wallet-pir",
            "ssh://git@ssh.github.com.example.com:443/valargroup/wallet-pir.git",
            "https://github.com/unrelated/wallet-pir",
            "https://example.com/github.com/valargroup/wallet-pir",
            "https://github.com/valargroup/wallet-pirate",
            "https://github.com/valargroup/wallet%252Dpir",
            "https://github.com@example.com/valargroup/wallet-pir",
        ):
            with self.subTest(url=url):
                self.assertFalse(graph.wallet_pir_owned(url))

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

    def run_probes(self, contaminated=None, root=None, locked=(), ownership=False):
        consumers = {}
        def metadata(manifest, **kwargs):
            if manifest == graph.ROOT / "Cargo.toml":
                return {"workspace_members": ["wallet"], "packages": [root] if root else []}
            if manifest == graph.ROOT / "zakura/pir-chain/Cargo.toml":
                return {"workspace_root": str(graph.ROOT / "zakura/pir-chain"), "workspace_members": ["server"], "packages": []}
            consumers[manifest.parent.name] = manifest.read_text()
            packages = [self.package("future-wire", repository="ssh://git@ssh.github.com:443/valargroup/wallet-pir") if ownership
                        else self.package("zakura-chain")] if manifest.parent.name == contaminated else []
            return {"packages": packages}
        def lock_problems(lockfile, owned):
            return [f"{lockfile.name}: resolves wallet-pir package receiver-pir"] if lockfile.relative_to(graph.ROOT).as_posix() in locked else []
        with patch.object(graph, "metadata", side_effect=metadata), patch.object(graph, "lock_problems", side_effect=lock_problems), \
                patch.object(graph.subprocess, "run"):
            graph.main()
        return consumers

    def test_facade_consumers_reject_node_packages_in_every_backend_mode(self):
        for mode in ("facade-default", "facade-zakura", "facade-lrz"):
            with self.subTest(mode=mode), self.assertRaisesRegex(SystemExit, "server/node package"):
                self.run_probes(contaminated=mode)

    def test_facade_consumers_reject_transitive_wallet_pir_ownership(self):
        for mode in ("facade-default", "facade-zakura", "facade-lrz"):
            with self.subTest(mode=mode), self.assertRaisesRegex(SystemExit, "package owned by wallet-pir"):
                self.run_probes(contaminated=mode, ownership=True)

    def test_production_and_testing_server_consumers_are_both_exercised(self):
        consumers = self.run_probes()
        self.assertIn("server-production", consumers)
        self.assertNotIn('features = ["testing"]', consumers["server-production"])
        self.assertIn('features = ["testing"]', consumers["server"])
        # The opt-in RocksDB reader is resolved and type-checked on its own.
        self.assertIn('features = ["rocksdb"]', consumers["server-rocksdb"])
        self.assertNotIn("rocksdb", consumers["server-production"] + consumers["server"])


    def test_ordinary_workspace_declarations_are_checked(self):
        member = self.package(dependencies=[{"name": "receiver-pir", "source": "git+https://github.com/valargroup/wallet-pir?tag=t", "kind": "dev"}])
        with self.assertRaisesRegex(SystemExit, "dependency on wallet-pir package receiver-pir"):
            self.run_probes(root=member)

    def test_both_lockfiles_are_checked(self):
        for lockfile in ("Cargo.lock", "zakura/pir-chain/Cargo.lock"):
            with self.subTest(lockfile=lockfile), self.assertRaisesRegex(SystemExit, "resolves wallet-pir package"):
                self.run_probes(locked=(lockfile,))

    def test_lockfile_entries_are_matched_by_name_and_source(self):
        with tempfile.TemporaryDirectory(dir=graph.ROOT) as directory:
            lockfile = Path(directory) / "Cargo.lock"
            lockfile.write_text(
                'version = 4\n[[package]]\nname = "library-owned"\nversion = "1.0.0"\n'
                '[[package]]\nname = "receiver-wire"\nversion = "0.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '[[package]]\nname = "renamed"\nversion = "0.1.0"\nsource = "git+https://github.com/valargroup/wallet-pir?tag=t#abc"\n'
            )
            errors = graph.lock_problems(lockfile, {"receiver-wire"})
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("receiver-wire" in e for e in errors) and any("renamed" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
