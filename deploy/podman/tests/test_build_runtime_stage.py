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


BUILD = _load("build_runtime_stage")
RELEASE = _load("release")
RENDER = _load("render")


SPECIFICATION = PODMAN.parent / "configuration-spec.json"
VALUES = PODMAN / "values.example.json"
SCRIPT = PODMAN / "build_runtime_stage.py"


class BuildRuntimeStageTests(unittest.TestCase):
    def prepare(self, root: Path) -> tuple[Path, Path, Path]:
        rendered = root / "rendered"
        RENDER.render(VALUES, rendered)
        specification = json.loads(SPECIFICATION.read_text())
        definitions = BUILD.definitions(specification)
        contract = BUILD.rendered_environment_contract(rendered)
        process_values: dict[str, dict[str, str]] = {}
        for key, definition in definitions.items():
            hardcoded = contract[BUILD.TARGETS[key]]
            values: dict[str, str] = {}
            for name in BUILD.required_for(definition, specification, key) - hardcoded.keys():
                if name in specification["secrets"] or RELEASE.file_secret_value(name):
                    values[name] = "@/run/secrets/test-value"
                elif name.endswith("_FILE"):
                    values[name] = "/run/secrets/test-value"
                elif name == "CONTROL_OIDC_ISSUER":
                    values[name] = "https://auth.example.test/auth/v1/"
                elif name == "LISTEN_SCHEME":
                    values[name] = "http_https"
                else:
                    values[name] = "test-value"
            process_values[key] = values
        runtime_input = root / "runtime.json"
        runtime_input.write_text(
            json.dumps(
                {"schema_version": 1, "shared": {}, "processes": process_values}
            )
        )
        staging = root / "staging"
        staging.mkdir()
        return rendered, runtime_input, staging

    def run_tool(self, rendered: Path, runtime_input: Path, staging: Path):
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--input",
                str(runtime_input),
                "--rendered",
                str(rendered),
                "--staging-root",
                str(staging),
            ],
            text=True,
            capture_output=True,
        )

    def test_stages_every_rendered_process_file_without_plaintext_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered, runtime_input, staging = self.prepare(root)
            result = self.run_tool(rendered, runtime_input, staging)
            self.assertEqual(result.returncode, 0, result.stderr)
            files = {path.name for path in staging.glob("*.env")}
            self.assertEqual(files, set(BUILD.TARGETS.values()))
            for path in staging.glob("*.env"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            combined = "".join(path.read_text() for path in staging.glob("*.env"))
            self.assertNotIn("CONTROL_DATA_MODE=", combined)
            for line in combined.splitlines():
                name, value = line.split("=", 1)
                if RELEASE.file_secret_value(name):
                    self.assertTrue(value.startswith("@/run/"), name)

    def test_rejects_plaintext_secret_unused_setting_and_hardcoded_conflict(self):
        cases = ("secret", "unused", "conflict")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                rendered, runtime_input, staging = self.prepare(root)
                document = json.loads(runtime_input.read_text())
                if case == "secret":
                    document["processes"]["control-api"]["CONTROL_INTERNAL_TOKEN"] = "plaintext"
                    expected = "scoped @/run/"
                elif case == "unused":
                    document["shared"]["UNDECLARED_SETTING"] = "value"
                    expected = "unused settings"
                else:
                    document["shared"]["CONTROL_DATA_MODE"] = "personal"
                    expected = "conflicts with rendered value"
                runtime_input.write_text(json.dumps(document))
                result = self.run_tool(rendered, runtime_input, staging)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_refuses_to_overwrite_staged_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered, runtime_input, staging = self.prepare(root)
            first = self.run_tool(rendered, runtime_input, staging)
            second = self.run_tool(rendered, runtime_input, staging)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("refusing to overwrite", second.stderr)

    def test_rejects_http_rauthy_issuer_for_https_control_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered, runtime_input, staging = self.prepare(root)
            document = json.loads(runtime_input.read_text())
            document["processes"]["rauthy"]["LISTEN_SCHEME"] = "http"
            runtime_input.write_text(json.dumps(document))
            result = self.run_tool(rendered, runtime_input, staging)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("LISTEN_SCHEME must be http_https", result.stderr)


if __name__ == "__main__":
    unittest.main()
