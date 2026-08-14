import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("podman_release", ROOT / "release.py")
RELEASE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RELEASE)
VALUES = json.loads((ROOT / "values.example.json").read_text(encoding="utf-8"))
RECORD = json.loads((ROOT / "release-record.example.json").read_text(encoding="utf-8"))


class ReleaseTests(unittest.TestCase):
    def test_release_record_signature_is_verified_as_a_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = root / "record.json"
            signature = root / "record.json.sig"
            key = root / "release.pub"
            record.write_text("{}", encoding="utf-8")
            signature.write_text("signature", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            with mock.patch.object(RELEASE, "run") as run:
                RELEASE.verify_release_record(record, signature, key)
            run.assert_called_once_with(
                [
                    "cosign",
                    "verify-blob",
                    "--insecure-ignore-tlog",
                    "--key",
                    str(key),
                    "--signature",
                    str(signature),
                    str(record),
                ]
            )

    def write_json(self, root: Path, name: str, value: dict) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_record_images_must_match_rendered_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = copy.deepcopy(RECORD)
            record["images"]["control"] = record["images"]["web"]
            path = self.write_json(root, "record.json", record)
            with self.assertRaisesRegex(ValueError, "images differ"):
                RELEASE.load_release(path, VALUES)

    def test_production_requires_staging_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = copy.deepcopy(VALUES)
            values["environment"] = "production"
            record = copy.deepcopy(RECORD)
            record["staging_qualification_ref"] = ""
            path = self.write_json(root, "record.json", record)
            with self.assertRaisesRegex(ValueError, "staging qualification"):
                RELEASE.load_release(path, values)

    @mock.patch.object(RELEASE, "run")
    def test_activation_uses_one_atomic_quadlet_symlink(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            (rendered / "makersbrain.network").write_text("[Network]\n")
            RELEASE.activate(
                rendered,
                RECORD["release_id"],
                root / "state",
                root / "quadlets",
            )
            current = root / "quadlets/makersbrain"
            self.assertTrue(current.is_symlink())
            self.assertEqual(
                current.resolve(), root / "state/releases" / RECORD["release_id"]
            )
            run.assert_any_call(
                ["systemctl", "--user", "enable", "--now", *RELEASE.PERSISTENT_UNITS]
            )


if __name__ == "__main__":
    unittest.main()
