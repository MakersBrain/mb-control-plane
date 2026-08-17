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
    def write_recovery_identity(self, values: dict, root: Path) -> None:
        recovery = root / "recovery-secrets"
        recovery.mkdir()
        recovery.chmod(0o700)
        (recovery / "age-identity.txt").write_text("AGE-SECRET-KEY-fixture")
        (recovery / "age-identity.txt").chmod(0o600)
        values["recovery_secret_source"] = str(recovery)

    def write_observability_secrets(self, config_root: Path) -> None:
        control = config_root / "secrets/control-api"
        control.mkdir(parents=True, exist_ok=True)
        control.chmod(0o700)
        (control / "control_metrics_token").write_text("m" * 48, encoding="utf-8")
        (control / "control_metrics_token").chmod(0o600)
        alertmanager = config_root / "secrets/alertmanager"
        alertmanager.mkdir(parents=True, exist_ok=True)
        alertmanager.chmod(0o700)
        (alertmanager / "webhook-url").write_text(
            "https://alerts.example.test/makersbrain", encoding="utf-8"
        )
        (alertmanager / "webhook-token").write_text("a" * 48, encoding="utf-8")
        (alertmanager / "webhook-url").chmod(0o600)
        (alertmanager / "webhook-token").chmod(0o600)

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
            record["staging_qualification_ref"] = "manually-approved"
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "immutable staging qualification"):
                RELEASE.load_release(path, values)

    def test_activation_requires_regular_postgres_ca(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = copy.deepcopy(VALUES)
            values["runtime_secret_source"] = str(root / "runtime-secrets")
            self.write_recovery_identity(values, root)
            config_root = root / "config"
            config_root.mkdir()
            rauthy_secret = config_root / "secrets/rauthy"
            rauthy_secret.mkdir(parents=True)
            (rauthy_secret / "config.toml").write_text(
                '[database]\npg_password = "fixture"\n'
                'pg_tls_root_ca = """-----BEGIN CERTIFICATE-----fixture'
                '-----END CERTIFICATE-----"""\n', encoding="utf-8"
            )
            (rauthy_secret / "config.toml").chmod(0o600)
            tunnel_secret = config_root / "secrets/cloudflared"
            tunnel_secret.mkdir(parents=True)
            (tunnel_secret / "tunnel-token").write_text("token", encoding="utf-8")
            (tunnel_secret / "tunnel-token").chmod(0o600)
            self.write_observability_secrets(config_root)
            with self.assertRaisesRegex(ValueError, "PostgreSQL CA"):
                RELEASE.verify_runtime_secrets(values, config_root)
            secret_root = Path(values["runtime_secret_source"])
            secret_root.mkdir()
            target = root / "ca-target.crt"
            target.write_text(
                "-----BEGIN CERTIFICATE-----fixture-----END CERTIFICATE-----",
                encoding="utf-8",
            )
            (secret_root / "postgres-ca.crt").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                RELEASE.verify_runtime_secrets(values, config_root)
            (secret_root / "postgres-ca.crt").unlink()
            (secret_root / "postgres-ca.crt").write_text(
                "-----BEGIN CERTIFICATE-----fixture-----END CERTIFICATE-----",
                encoding="utf-8",
            )
            RELEASE.verify_runtime_secrets(values, config_root)

    def test_activation_requires_rauthy_ca_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = copy.deepcopy(VALUES)
            secret_root = root / "runtime-secrets"
            secret_root.mkdir()
            (secret_root / "postgres-ca.crt").write_text(
                "-----BEGIN CERTIFICATE-----fixture-----END CERTIFICATE-----",
                encoding="utf-8",
            )
            values["runtime_secret_source"] = str(secret_root)
            self.write_recovery_identity(values, root)
            config_root = root / "config"
            config_root.mkdir()
            tunnel_secret = config_root / "secrets/cloudflared"
            tunnel_secret.mkdir(parents=True)
            (tunnel_secret / "tunnel-token").write_text("token", encoding="utf-8")
            (tunnel_secret / "tunnel-token").chmod(0o600)
            self.write_observability_secrets(config_root)
            rauthy_secret = config_root / "secrets/rauthy"
            rauthy_secret.mkdir(parents=True)
            (rauthy_secret / "config.toml").write_text(
                '[database]\npg_password = "fixture"\n', encoding="utf-8"
            )
            (rauthy_secret / "config.toml").chmod(0o600)
            with self.assertRaisesRegex(ValueError, "pg_tls_root_ca"):
                RELEASE.verify_runtime_secrets(values, config_root)

    def test_host_preflight_resolves_scoped_secret_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            config = root / "config"
            secret_dir = config / "secrets/example"
            secret_dir.mkdir(parents=True)
            secret_dir.chmod(0o700)
            secret = secret_dir / "database_url"
            secret.write_text("postgresql://fixture", encoding="utf-8")
            secret.chmod(0o600)
            keys = secret_dir / "keys.json"
            keys.write_text("{}", encoding="utf-8")
            keys.chmod(0o600)
            environment = config / "example.env"
            environment.write_text(
                "CONTROL_DATABASE_URL=@/run/secrets/database_url\n"
                "CONTROL_INVITATION_SIGNING_KEYS_FILE=/run/secrets/keys.json\n",
                encoding="utf-8",
            )
            environment.chmod(0o600)
            (rendered / "example.container").write_text(
                "[Container]\nEnvironmentFile=/etc/makersbrain/example.env\n"
                "Volume=/etc/makersbrain/secrets/example:/run/secrets:ro\n",
                encoding="utf-8",
            )
            RELEASE.verify_host_configuration(rendered, config)
            secret.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group or others"):
                RELEASE.verify_host_configuration(rendered, config)

    def test_host_preflight_rejects_unmounted_secret_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            config = root / "config"
            config.mkdir()
            environment = config / "example.env"
            environment.write_text(
                "CONTROL_DATABASE_URL=@/run/secrets/database_url\n",
                encoding="utf-8",
            )
            environment.chmod(0o600)
            (rendered / "example.container").write_text(
                "[Container]\nEnvironmentFile=/etc/makersbrain/example.env\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "no scoped secret mount"):
                RELEASE.verify_host_configuration(rendered, config)

    def test_host_preflight_accepts_extensionless_file_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            config = root / "config"
            secret_dir = config / "secrets/example"
            secret_dir.mkdir(parents=True)
            secret_dir.chmod(0o700)
            secret = secret_dir / "credential"
            secret.write_text("fixture", encoding="utf-8")
            secret.chmod(0o600)
            (rendered / "example.container").write_text(
                "[Container]\n"
                "Volume=/etc/makersbrain/secrets/example/credential:"
                "/run/secrets/credential:ro\n",
                encoding="utf-8",
            )
            RELEASE.verify_host_configuration(rendered, config)

    def test_host_preflight_rejects_missing_vendor_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            config = root / "config"
            config.mkdir()
            environment = config / "odoo.env"
            environment.write_text(
                "MB_CONTROL_API_URL=http://control-api:8080\n", encoding="utf-8"
            )
            environment.chmod(0o600)
            (rendered / "odoo.container").write_text(
                "[Container]\nEnvironmentFile=/etc/makersbrain/odoo.env\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "MB_CONTROL_BRIDGE_TOKEN"):
                RELEASE.verify_host_configuration(rendered, config)

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

    @mock.patch.object(RELEASE, "run")
    def test_stage_only_copies_release_without_touching_live_quadlets(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            (rendered / "makersbrain.network").write_text("[Network]\n")
            RELEASE.stage(
                rendered,
                RECORD["release_id"],
                root / "state",
            )
            self.assertTrue((root / "state/releases" / RECORD["release_id"]).is_dir())
            self.assertFalse((root / "quadlets/makersbrain").exists())
            run.assert_not_called()

    @mock.patch.object(RELEASE, "run")
    def test_start_staged_requires_exact_current_release(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "state/releases" / RECORD["release_id"]
            release.mkdir(parents=True)
            quadlets = root / "quadlets"
            quadlets.mkdir()
            RELEASE.start_staged(RECORD["release_id"], root / "state", quadlets)
            self.assertEqual((quadlets / "makersbrain").resolve(), release)
            run.assert_any_call(
                ["systemctl", "--user", "enable", "--now", *RELEASE.PERSISTENT_UNITS]
            )
            with self.assertRaisesRegex(ValueError, "has not been staged"):
                RELEASE.start_staged("control-2026.08.15-ffffffffffffffff", root / "state", quadlets)

    @mock.patch.object(RELEASE, "run")
    def test_start_staged_rejects_a_bundle_that_no_longer_matches(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            (rendered / "makersbrain.network").write_text("[Network]\n")
            RELEASE.stage(rendered, RECORD["release_id"], root / "state")
            quadlets = root / "quadlets"
            quadlets.mkdir()
            RELEASE.start_staged(RECORD["release_id"], root / "state", quadlets, rendered)

            # The values moved but the release id did not, so what was verified
            # and what would be activated are two different bundles.
            (rendered / "makersbrain.network").write_text("[Network]\nLabel=changed\n")
            with self.assertRaisesRegex(ValueError, "does not match"):
                RELEASE.start_staged(RECORD["release_id"], root / "state", quadlets, rendered)

    def test_secret_files_may_end_with_a_newline(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_root = Path(temporary) / "config"
            config_root.mkdir()
            self.write_observability_secrets(config_root)
            alertmanager = config_root / "secrets/alertmanager"
            control = config_root / "secrets/control-api"
            (control / "control_metrics_token").write_text("m" * 48 + "\n", encoding="utf-8")
            (alertmanager / "webhook-url").write_text(
                "https://alerts.example.test/makersbrain\n", encoding="utf-8"
            )
            (alertmanager / "webhook-token").write_text("a" * 48 + "\n", encoding="utf-8")

            RELEASE.verify_observability_secrets(config_root)

    @mock.patch.object(RELEASE, "run")
    def test_failed_staged_start_restores_previous_release(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = root / "state/releases/previous"
            candidate = root / "state/releases" / RECORD["release_id"]
            previous.mkdir(parents=True)
            candidate.mkdir()
            quadlets = root / "quadlets"
            quadlets.mkdir()
            current = quadlets / "makersbrain"
            current.symlink_to(previous, target_is_directory=True)
            run.side_effect = [None, RuntimeError("unit failed"), None, None, None]
            with self.assertRaisesRegex(RuntimeError, "unit failed"):
                RELEASE.start_staged(RECORD["release_id"], root / "state", quadlets)
            self.assertEqual(current.resolve(), previous)


if __name__ == "__main__":
    unittest.main()
