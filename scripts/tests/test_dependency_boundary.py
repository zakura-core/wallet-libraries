"""Wallet packages must reject node and wallet-pir dependencies under every source."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("dependency_boundary", Path(__file__).parents[1] / "dependency_boundary.py")
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)


class DependencyBoundaryTests(unittest.TestCase):
    def package(self, name="library-owned", **fields):
        return {"name": name, "source": None, "repository": "https://github.com/zakura-core/wallet-libraries", "dependencies": [], **fields}

    def check(self, package):
        return graph.problems({"packages": [package]}, {"receiver-wire", "zakura-server-chain"}, {"zakura-chain"})

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
                f"https://%67ithub.com/{owner}/wallet-pir.git",
                f"https://github.com/{owner}/ignored/../wallet-pir.git",
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
                        self.assertTrue(graph.lock_problems(lockfile, set(), set()))

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
            "https://%67ithub.com.evil.example/valargroup/wallet-pir",
            "https://github.com/valargroup/wallet-pir/../ordinary",
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

    def test_node_packages_and_repositories_are_forbidden_everywhere(self):
        for name, source in (("zakura-chain", None), ("new-node-package", "git+https://github.com/zakura-core/zakura.git?rev=abc#abc")):
            with self.subTest(name=name):
                self.assertTrue(self.check(self.package(name, source=source)))
                self.assertTrue(self.check(self.package(name, repository="https://github.com/zakura-core/zakura")))
                for kind, optional, target in ((None, False, None), (None, True, None), ("build", False, None), ("dev", False, None), (None, False, 'cfg(target_os = "windows")')):
                    dependency = {"name": name, "source": source, "kind": kind,
                                  "optional": optional, "target": target, "rename": "alias"}
                    self.assertTrue(self.check(self.package(dependencies=[dependency])))

    def test_node_repository_spellings_and_neighboring_sources(self):
        for url in ("https://github.com/zakura-core/zakura.git", "git@github.com:zakura-core/zakura.git",
                    "git+ssh://git@ssh.github.com:443/zakura-core/zakura.git?rev=abc#abc",
                    "https://github.com/zakura-core/ignored/../zakura.git",
                    "https://github.com/zakura%2Dcore/zakura",
                    "https://github.com\\zakura-core\\zakura.git"):
            with self.subTest(url=url):
                self.assertTrue(graph.node_owned(url))
                self.assertTrue(self.check(self.package("future-node", source=url)))
        for url in ("https://github.com/zakura-core/common", "https://github.com/zakura-core/zakura-tools",
                    "https://github.com.evil.example/zakura-core/zakura", "https://github.com/unrelated/zakura"):
            self.assertFalse(graph.node_owned(url))

    def run_probes(self, contaminated=None, root=None, locked=(), ownership=False):
        consumers = {}
        root_manifest = graph.ROOT / "Cargo.toml"
        tool_manifest = graph.ROOT / "tools/proto/Cargo.toml"
        def metadata(manifest, **kwargs):
            if manifest in (root_manifest, tool_manifest):
                return {"packages": [root] if root else [], "workspace_root": str(manifest.parent)}
            consumers[manifest.parent.name] = manifest.read_text()
            packages = []
            if manifest.parent.name == contaminated:
                packages.append(self.package("future-wire", repository="ssh://git@ssh.github.com:443/valargroup/wallet-pir")
                                if ownership else self.package("zakura-chain"))
            return {"packages": packages}
        def lock_problems(lockfile, owned, nodes):
            return [f"{lockfile.name}: resolves wallet-pir package receiver-pir"] if lockfile.relative_to(graph.ROOT).as_posix() in locked else []
        def repository_files(name):
            return ([root_manifest, tool_manifest] if name == "Cargo.toml"
                    else [graph.ROOT / "Cargo.lock", graph.ROOT / "tools/proto/Cargo.lock"])
        with patch.object(graph, "metadata", side_effect=metadata), \
                patch.object(graph, "repository_files", side_effect=repository_files), \
                patch.object(graph, "lock_problems", side_effect=lock_problems), \
                patch.object(graph.subprocess, "run"):
            graph.main()
        return consumers

    def test_fresh_component_and_facade_consumers_are_checked(self):
        consumers = self.run_probes()
        self.assertEqual(set(consumers), {"wallet", "facade-default", "facade-zakura"})
        self.assertNotIn("default-features", consumers["facade-default"])
        self.assertIn('features = ["zakura"]', consumers["facade-zakura"])
        self.assertIn("default-features = false", consumers["facade-zakura"])
        for name in consumers:
            for ownership in (False, True):
                with self.subTest(consumer=name, ownership=ownership), self.assertRaises(SystemExit):
                    self.run_probes(contaminated=name, ownership=ownership)

    def test_ordinary_workspace_declarations_are_checked(self):
        member = self.package(dependencies=[{"name": "receiver-pir", "source": "git+https://github.com/valargroup/wallet-pir?tag=t", "kind": "dev"}])
        with self.assertRaisesRegex(SystemExit, "dependency on wallet-pir package receiver-pir"):
            self.run_probes(root=member)

    def test_root_and_standalone_lockfiles_are_checked(self):
        for lockfile in ("Cargo.lock", "tools/proto/Cargo.lock"):
            with self.subTest(lockfile=lockfile), self.assertRaisesRegex(SystemExit, "resolves wallet-pir package"):
                self.run_probes(locked=(lockfile,))

    def test_lockfile_entries_are_matched_by_name_and_source(self):
        with tempfile.TemporaryDirectory(dir=graph.ROOT) as directory:
            lockfile = Path(directory) / "Cargo.lock"
            lockfile.write_text(
                'version = 4\n[[package]]\nname = "library-owned"\nversion = "1.0.0"\n'
                '[[package]]\nname = "receiver-wire"\nversion = "0.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '[[package]]\nname = "renamed"\nversion = "0.1.0"\nsource = "git+https://github.com/valargroup/wallet-pir?tag=t#abc"\n'
                '[[package]]\nname = "zakura-chain"\nversion = "1.0.0"\n'
                '[[package]]\nname = "new-node"\nversion = "1.0.0"\nsource = "git+https://github.com/zakura-core/zakura.git?rev=abc#abc"\n'
            )
            errors = graph.lock_problems(lockfile, {"receiver-wire"}, {"zakura-chain"})
        self.assertEqual(len(errors), 4)
        for name in ("receiver-wire", "renamed", "zakura-chain", "new-node"):
            self.assertTrue(any(name in error for error in errors))


if __name__ == "__main__":
    unittest.main()
