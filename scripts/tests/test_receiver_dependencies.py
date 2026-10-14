import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("receiver_dependencies", Path(__file__).parents[1] / "check-receiver-dependencies.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ReceiverDependencies(unittest.TestCase):
    def test_a_transitive_test_helper_cannot_restore_the_service_dependency(self):
        metadata = {"packages": [
            {"name": "wallet", "dependencies": [{"name": "test-helper", "kind": "dev", "source": None}]},
            {"name": "test-helper", "dependencies": [{"name": "receiver-server", "kind": "dev", "target": "cfg(unix)", "source": "git+https://github.com/valargroup/wallet-pir.git?rev=abc"}]},
        ]}
        self.assertEqual(check.violations(metadata), ["test-helper: dev dependency on wallet-pir (receiver-server)"])

    def test_registry_packaging_does_not_hide_service_owned_helpers(self):
        metadata = {"packages": [{"name": "receiver-pir-server", "source": "registry+https://github.com/rust-lang/crates.io-index", "repository": "https://github.com/valargroup/wallet-pir/"}]}
        self.assertTrue(check.violations(metadata))

    def test_node_code_is_rejected_even_when_the_source_is_not_git(self):
        metadata = {"packages": [{"name": "zakura-state", "source": None}]}
        self.assertTrue(check.violations(metadata))

    def test_independent_receiver_and_crypto_releases_are_allowed(self):
        metadata = {"packages": [{"name": "zakura-receiver-directory", "repository": "https://github.com/zakura-core/wallet-libraries", "dependencies": [{"name": "zakura-orchard", "source": "registry+https://github.com/rust-lang/crates.io-index"}]}]}
        self.assertEqual(check.violations(metadata), [])
