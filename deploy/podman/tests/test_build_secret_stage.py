import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PODMAN = Path(__file__).parents[1]
# The scripts under test import each other by bare name, which only resolves
# when their own directory is importable. Test discovery runs from the repo
# root, so put it there before loading any of them.
if str(PODMAN) not in sys.path:
    sys.path.insert(0, str(PODMAN))


def _load(name):
    """Load a sibling deploy script by path, as the other tests in this directory do."""
    spec = importlib.util.spec_from_file_location(f"podman_{name}", PODMAN / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


RUNTIME = _load("build_runtime_stage")
SECRETS = _load("build_secret_stage")
RELEASE = _load("release")
RENDER = _load("render")


SCRIPT = PODMAN / "build_secret_stage.py"
RUNTIME_SCRIPT = PODMAN / "build_runtime_stage.py"
MANIFEST_SCRIPT = PODMAN / "build_materialization_manifest.py"
MATERIALIZE_SCRIPT = PODMAN / "materialize.py"
SPECIFICATION = PODMAN.parent / "configuration-spec.json"
VALUES = PODMAN / "values.example.json"


class BuildSecretStageTests(unittest.TestCase):
    def test_single_line_accepts_one_terminal_newline_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "value"
            path.write_text("value\r\n")
            self.assertEqual(SECRETS.single_line(path, "fixture"), "value")
            path.write_text("embedded\nnewline\n")
            with self.assertRaisesRegex(ValueError, "single line"):
                SECRETS.single_line(path, "fixture")

    def canonical(self, root: Path) -> tuple[Path, Path, Path]:
        source = root / "canonical"
        source.mkdir(mode=0o700)
        invitation_id = "staging-2026-08-17-test"
        for relative in sorted(SECRETS.required_sources()):
            path = source / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.parent.chmod(0o700)
            value = "s" * 64
            if relative.endswith("INVITATION_SIGNING_KEY_ID"):
                value = invitation_id
            elif relative.endswith("CONTROL_PRIVACY_LOOKUP_KEY_ID"):
                value = "lookup-2026-08-17-test"
            elif relative.endswith("CONTROL_PRIVACY_EXPORT_KEY_ID"):
                value = "export-2026-08-17-test"
            elif relative.endswith("INVITATION_SIGNING_PRIVATE_KEYS_JSON"):
                value = json.dumps({"keys": {invitation_id: "private-key"}})
            elif relative.endswith("INVITATION_VERIFICATION_PUBLIC_KEYS_JSON"):
                value = json.dumps({"keys": {invitation_id: "public-key"}})
            elif relative.endswith("RAUTHY_ENC_KEYS"):
                value = "2026-08-17/" + "k" * 44
            elif relative.endswith("BACKUP_AGE_RECIPIENT"):
                value = "age1" + "q" * 58
            elif relative.endswith("ALLOWED_RECIPIENTS"):
                value = "synthetic@example.test\n"
            elif relative.endswith("VMAGENT_ACCESS_CLIENT_ID"):
                value = "a" * 32 + ".access"
            elif relative.endswith("CONTROL_RAUTHY_ADMIN_KEY"):
                value = "makersbrain-runtime$" + "r" * 64
            elif relative.endswith("CONTROL_RAUTHY_DEPLOYMENT_KEY"):
                value = "makersbrain-deployment$" + "d" * 64
            path.write_text(value)
            path.chmod(0o600)
        ca = root / "postgres-ca.crt"
        ca.write_text(
            "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
        )
        ca.chmod(0o600)
        cosign = root / "release-cosign.pub"
        cosign.write_text("-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n")
        cosign.chmod(0o600)
        return source, ca, cosign

    def run_secret_builder(
        self,
        root: Path,
        source: Path,
        ca: Path,
        environment: str = "staging",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--source",
                str(source),
                "--environment",
                environment,
                "--staging-root",
                str(root / "stage"),
                "--references-output",
                str(root / "secret-references.json"),
                "--postgres-host",
                "10.20.0.3",
                "--postgres-ca",
                str(ca),
                "--driver-ca-path",
                "/run/secrets/postgres-ca.crt",
                "--member-origin",
                "https://app.staging.example.test",
            ],
            text=True,
            capture_output=True,
        )

    def test_builds_complete_value_safe_pipeline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, ca, cosign = self.canonical(root)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            result = self.run_secret_builder(root, source, ca)
            self.assertEqual(result.returncode, 0, result.stderr)
            references = json.loads((root / "secret-references.json").read_text())
            serialized_references = json.dumps(references)
            self.assertNotIn("s" * 64, serialized_references)
            self.assertNotEqual(
                references["processes"]["control-api"]["CONTROL_DATABASE_URL"],
                references["processes"]["worker-email"]["CONTROL_DATABASE_URL"],
            )
            clients = json.loads((stage / "rauthy/clients.json").read_text())
            self.assertEqual(
                clients[0]["redirect_uris"],
                ["https://app.staging.example.test/oauth/callback"],
            )
            api_keys = json.loads((stage / "rauthy/api_keys.json").read_text())
            self.assertEqual([item["name"] for item in api_keys], [
                "makersbrain-runtime", "makersbrain-deployment"
            ])
            for path in stage.rglob("*"):
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            rendered = root / "rendered"
            RENDER.render(VALUES, rendered)
            specification = json.loads(SPECIFICATION.read_text())
            definitions = RUNTIME.definitions(specification)
            contract = RUNTIME.rendered_environment_contract(rendered)
            supplied = references["processes"]
            processes: dict[str, dict[str, str]] = {}
            for key, definition in definitions.items():
                values: dict[str, str] = {}
                hardcoded = contract[RUNTIME.TARGETS[key]]
                required = RUNTIME.required_for(definition, specification, key)
                for name in required - hardcoded.keys() - supplied.get(key, {}).keys():
                    if name.endswith("_FILE"):
                        values[name] = "/run/secrets/test-value"
                    elif name in specification["secrets"] or RELEASE.file_secret_value(name):
                        self.fail(f"secret builder omitted required credential {key}:{name}")
                    else:
                        values[name] = "test-value"
                processes[key] = values
            runtime_input = root / "runtime.json"
            runtime_input.write_text(
                json.dumps({"schema_version": 1, "shared": {}, "processes": processes})
            )
            runtime_result = subprocess.run(
                [
                    "python3",
                    str(RUNTIME_SCRIPT),
                    "--input",
                    str(runtime_input),
                    "--secret-input",
                    str(root / "secret-references.json"),
                    "--rendered",
                    str(rendered),
                    "--staging-root",
                    str(stage),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(runtime_result.returncode, 0, runtime_result.stderr)
            manifest = root / "manifest.json"
            manifest_result = subprocess.run(
                [
                    "python3",
                    str(MANIFEST_SCRIPT),
                    "--source",
                    str(stage),
                    "--rendered",
                    str(rendered),
                    "--generation",
                    "control-2026.08.17-test",
                    "--output",
                    str(manifest),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(manifest_result.returncode, 0, manifest_result.stderr)
            check = subprocess.run(
                [
                    "python3",
                    str(MATERIALIZE_SCRIPT),
                    "--source",
                    str(stage),
                    "--manifest",
                    str(manifest),
                    "--rendered",
                    str(rendered),
                    "--generation-root",
                    str(root / "generations"),
                    "--current-link",
                    str(root / "current"),
                    "--check",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(check.returncode, 0, check.stderr)

    def test_production_accepts_logically_empty_recipient_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, ca, cosign = self.canonical(root)
            (source / "mail/ALLOWED_RECIPIENTS").write_bytes(b"")
            (root / "stage").mkdir(mode=0o700)

            result = self.run_secret_builder(
                root, source, ca, environment="production"
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (root / "stage/secrets/control-mail-gateway/mail_allowed_recipients").read_bytes(),
                b"\n",
            )

    def test_staging_rejects_empty_recipient_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, ca, cosign = self.canonical(root)
            (source / "mail/ALLOWED_RECIPIENTS").write_bytes(b"")
            (root / "stage").mkdir(mode=0o700)

            result = self.run_secret_builder(root, source, ca)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical source is empty", result.stderr)

    def test_rejects_broad_export_and_symlink(self):
        for case in ("extra", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, ca, cosign = self.canonical(root)
                stage = root / "stage"
                stage.mkdir(mode=0o700)
                if case == "extra":
                    (source / "application/UNSCOPED_ADMIN_TOKEN").write_text("bad")
                    (source / "application/UNSCOPED_ADMIN_TOKEN").chmod(0o600)
                    expected = "export drift"
                else:
                    target = source / "application/CONTROL_INTERNAL_TOKEN"
                    target.unlink()
                    target.symlink_to(source / "application/DEPLOYMENT_DRIVER_TOKEN")
                    expected = "symlink"
                result = self.run_secret_builder(root, source, ca)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
