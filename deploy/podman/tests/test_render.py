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
            self.assertIn(
                "DRIVER_RECOVERY_SECRET_SOURCE=/var/lib/makersbrain/tenant-recovery-secrets",
                driver,
            )
            self.assertIn(
                "/var/lib/makersbrain/tenant-runtime-secrets:/var/lib/makersbrain/tenant-runtime-secrets",
                driver,
            )
            self.assertIn(
                "/var/lib/makersbrain/tenant-recovery-secrets:/run/makersbrain-recovery-secrets:ro",
                driver,
            )
            self.assertNotIn("/run/makersbrain-backup-secrets", driver)
            for name in (
                "control-api.container",
                "control-backup-scheduler.container",
                "control-database-identities.container",
                "control-migrate.container",
                "control-workers@email-delivery.container",
                "odoo.container",
            ):
                content = (output / name).read_text()
                self.assertIn("PGSSLMODE=verify-full", content)
                self.assertIn("PGSSLROOTCERT=/run/secrets/postgres-ca.crt", content)
            rauthy = (output / "rauthy.container").read_text()
            self.assertIn("PG_TLS=require", rauthy)
            self.assertIn("PG_TLS_NO_VERIFY=false", rauthy)
            self.assertIn("/secrets/rauthy/config.toml:/app/config.toml:ro", rauthy)
            rauthy_ready = (output / "rauthy-ready.container").read_text()
            self.assertIn("http://rauthy:8092/auth/v1/health", rauthy_ready)
            self.assertIn(
                "rauthy-ready.container", (output / "control-web.container").read_text()
            )
            odoo = (output / "odoo.container").read_text()
            self.assertIn("resolve-secret-env.sh /entrypoint.sh odoo", odoo)
            self.assertIn("odoo-client-secrets.volume:/run/makersbrain-odoo-client-secrets:ro", odoo)
            self.assertIn(
                "paperless-client-secrets.volume",
                (output / "control-workers@invoice-capture.container").read_text(),
            )
            self.assertIn(
                "control-mail-gateway.container",
                (output / "control-workers@email-delivery.container").read_text(),
            )
            cloudflared = (output / "cloudflared.container").read_text()
            self.assertIn("--no-autoupdate", cloudflared)
            self.assertIn("--token-file /run/secrets/tunnel-token", cloudflared)
            self.assertNotIn("EnvironmentFile=", cloudflared)
            self.assertNotIn("podman.sock", cloudflared)
            vmagent = (output / "vmagent.container").read_text()
            self.assertIn("UserNS=keep-id:uid=65534,gid=65534", vmagent)
            self.assertIn(
                "/secrets/control-api/control_metrics_token:/run/secrets/control-metrics-token:ro",
                vmagent,
            )
            self.assertIn("/secrets/vmagent:/run/access:ro", vmagent)
            self.assertIn("-remoteWrite.forcePromProto=true", vmagent)
            self.assertIn("-remoteWrite.maxDiskUsagePerURL=256MB", vmagent)
            vmagent_config = (output / "vmagent.yml").read_text()
            self.assertIn("metrics_path: /internal/metrics/live", vmagent_config)
            self.assertIn("metrics_path: /internal/metrics", vmagent_config)
            self.assertIn("environment: 'staging'", vmagent_config)
            self.assertIn("targets: [catalogue-control:8687]", vmagent_config)
            self.assertIn("targets: [catalogue-service:8686]", vmagent_config)
            self.assertEqual(vmagent.count("Network="), 1)
            self.assertEqual(cloudflared.count("Network="), 1)
            self.assertEqual((output / "vmagent-entrypoint.sh").stat().st_mode & 0o777, 0o555)
            self.assertIn(
                "UserNS=keep-id:uid=999,gid=1000",
                (output / "redis.container").read_text(),
            )
            self.assertIn(
                "UserNS=keep-id:uid=100,gid=101",
                (output / "odoo.container").read_text(),
            )
            self.assertIn(
                "UserNS=keep-id:uid=101,gid=101",
                (output / "tenant-gateway.container").read_text(),
            )
            self.assertIn(
                "/postgres-ca.crt:/run/secrets/postgres-ca.crt:ro",
                (output / "control-container-driver.container").read_text(),
            )
            for path in output.glob("*.container"):
                if path.name != "control-container-driver.container":
                    self.assertNotIn("podman.sock", path.read_text())
            self.assertNotIn(
                "@@",
                "".join(path.read_text() for path in output.rglob("*") if path.is_file()),
            )

    def test_production_edge_and_metrics_join_the_catalogue_network(self):
        values = copy.deepcopy(EXAMPLE)
        values["environment"] = "production"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            RENDER.render(self.write_values(root, values), output)
            for name in ("cloudflared.container", "vmagent.container"):
                self.assertIn(
                    "Network=catalogue.network", (output / name).read_text()
                )

    def test_mutable_image_is_rejected(self):
        values = copy.deepcopy(EXAMPLE)
        values["images"]["control"] = "registry.example.test/makersbrain/control:latest"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "not pinned by digest"):
                RENDER.load_values(self.write_values(Path(temporary), values))

    def test_runtime_and_recovery_secret_roots_must_be_distinct(self):
        values = copy.deepcopy(EXAMPLE)
        values["recovery_secret_source"] = values["runtime_secret_source"]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "must be distinct"):
                RENDER.load_values(self.write_values(Path(temporary), values))

    def test_remote_write_must_be_an_exact_https_endpoint(self):
        values = copy.deepcopy(EXAMPLE)
        values["metrics_remote_write_url"] = "http://metrics.example.test/api/v1/write"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "exact HTTPS"):
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
