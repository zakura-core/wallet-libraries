import importlib.util
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "generate_workspace", ROOT / "scripts/generate-workspace.py"
)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class GenerationTests(unittest.TestCase):
    def test_current_sources_remove_encoding_and_preserve_fork_features(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifests").mkdir()
            shutil.copyfile(ROOT / "manifests/sources.toml", root / "manifests/sources.toml")
            sources = tomllib.loads((root / "manifests/sources.toml").read_text())
            upstream = root / sources["layout"]["upstream_manifest"]
            upstream.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / sources["layout"]["upstream_manifest"], upstream)
            self.assertEqual(generator.main(["generate-workspace.py", str(root)]), 0)
            first = (root / "Cargo.toml").read_text()
            dependencies = tomllib.loads(first)["workspace"]["dependencies"]
            self.assertNotIn("zcash_encoding", dependencies)
            self.assertNotIn("# zcash_encoding 0.5.0 is a breaking release", first)
            note = dependencies["zcash_note_encryption"]
            self.assertEqual(note["package"], "zakura-note-encryption")
            self.assertFalse(note["default-features"])
            self.assertNotIn("path", note)
            self.assertEqual(generator.main(["generate-workspace.py", str(root)]), 0)
            self.assertEqual(first, (root / "Cargo.toml").read_text())
