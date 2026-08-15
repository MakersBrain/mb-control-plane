import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("podman_render", ROOT / "render.py")
RENDER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RENDER)
EXAMPLE = json.loads((ROOT / "values.example.json").read_text(encoding="utf-8"))


class PodmanRendererTests(unittest.TestCase):
    def write_values(self, root: Path, values: dict) -> Path:
        path = root / "values.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        return path

    def test_staging_bundle_is_synthetic_and_socket_is_driver_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            RENDER.render(self.write_values(root, EXAMPLE), output)
            driver = (output / "control-container-driver.container").read_text()
            self.assertIn("DRIVER_CONTAINER_RUNTIME=podman", driver)
            self.assertIn("%t/podman/podman.sock", driver)
            self.assertIn(
                "DRIVER_POSTGRES_CA_SOURCE=/var/lib/makersbrain/tenant-runtime-secrets/postgres-ca.crt",
                driver,
            )
            for name in (
                "control-api.container",
                "control-backup-scheduler.container",
                "control-database-identities.container",
                "control-migrate.container",
                "control-workers@.container",
                "odoo.container",
            ):
                content = (output / name).read_text()
                self.assertIn("PGSSLMODE=verify-full", content)
                self.assertIn("PGSSLROOTCERT=/run/secrets/postgres-ca.crt", content)
            rauthy = (output / "rauthy.container").read_text()
            self.assertIn("PG_TLS=require", rauthy)
            self.assertIn("PG_TLS_NO_VERIFY=false", rauthy)
            cloudflared = (output / "cloudflared.container").read_text()
            self.assertIn("--no-autoupdate", cloudflared)
            self.assertIn("--token-file /run/secrets/tunnel-token", cloudflared)
            self.assertNotIn("EnvironmentFile=", cloudflared)
            self.assertNotIn("podman.sock", cloudflared)
            for path in output.glob("*.container"):
                if path.name != "control-container-driver.container":
                    self.assertNotIn("podman.sock", path.read_text())
            self.assertNotIn(
                "@@",
                "".join(path.read_text() for path in output.rglob("*") if path.is_file()),
            )

    def test_mutable_image_is_rejected(self):
        values = copy.deepcopy(EXAMPLE)
        values["images"]["control"] = "registry.example.test/makersbrain/control:latest"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "not pinned by digest"):
                RENDER.load_values(self.write_values(Path(temporary), values))

    def test_staging_personal_data_is_rejected(self):
        values = copy.deepcopy(EXAMPLE)
        values["data_mode"] = "personal"
        values["production_personal_data_allowed"] = True
        values["privacy_activation_record"] = "approved-record"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "staging is synthetic-only"):
                RENDER.load_values(self.write_values(Path(temporary), values))

    def test_production_personal_data_requires_external_activation_record(self):
        values = copy.deepcopy(EXAMPLE)
        values["environment"] = "production"
        values["data_mode"] = "personal"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_values(Path(temporary), values)
            with self.assertRaisesRegex(ValueError, "not approved"):
                RENDER.load_values(path)
            values["production_personal_data_allowed"] = True
            values["privacy_activation_record"] = ""
            path.write_text(json.dumps(values), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "activation record"):
                RENDER.load_values(path)


if __name__ == "__main__":
    unittest.main()
