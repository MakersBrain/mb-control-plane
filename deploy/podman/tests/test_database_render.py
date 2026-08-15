import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "database"
SPEC = importlib.util.spec_from_file_location("database_render", ROOT / "render.py")
RENDER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RENDER)
EXAMPLE = json.loads((ROOT / "values.example.json").read_text(encoding="utf-8"))


class DatabaseRendererTests(unittest.TestCase):
    def write_values(self, root: Path, values: dict) -> Path:
        path = root / "values.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        return path

    def test_rendered_database_is_private_tls_only_and_has_no_runtime_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            RENDER.render(self.write_values(root, EXAMPLE), output)
            unit = (output / "postgres.container").read_text()
            hba = (output / "pg_hba.conf").read_text()
            self.assertIn("PublishPort=10.50.2.70:5432:5432", unit)
            self.assertIn("ssl=on", unit)
            self.assertNotIn("podman.sock", unit)
            self.assertNotIn("docker.sock", unit)
            self.assertIn("hostssl all all 10.50.2.0/26 scram-sha-256", hba)
            self.assertIn("archive-push", unit)
            self.assertTrue((output / "postgres-recovery-init.service").is_file())
            self.assertTrue((output / "postgres-backup.timer").is_file())
            self.assertTrue((output / "postgres-full-backup.timer").is_file())
            self.assertTrue((output / "restore.py").is_file())

    def test_mutable_image_is_rejected(self):
        values = copy.deepcopy(EXAMPLE)
        values["postgres_image"] = "registry.example.test/postgres:latest"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "not pinned by digest"):
                RENDER.load_values(self.write_values(Path(temporary), values))

    def test_public_bind_address_is_rejected(self):
        values = copy.deepcopy(EXAMPLE)
        values["private_bind_ip"] = "203.0.113.10"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "private non-loopback"):
                RENDER.load_values(self.write_values(Path(temporary), values))

    def test_data_path_cannot_escape_protected_volume(self):
        values = copy.deepcopy(EXAMPLE)
        values["data_directory"] = "/tmp/postgres"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "protected database volume"):
                RENDER.load_values(self.write_values(Path(temporary), values))


if __name__ == "__main__":
    unittest.main()
