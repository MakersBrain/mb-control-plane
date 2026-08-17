import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "build_materialization_manifest.py"


class BuildMaterializationManifestTests(unittest.TestCase):
    def prepare(self, root: Path) -> tuple[Path, Path]:
        source = root / "source"
        rendered = root / "rendered"
        (source / "secrets/api").mkdir(parents=True)
        rendered.mkdir()
        (source / "control-api.env").write_text("CONTROL_LISTEN=0.0.0.0:8080\n")
        (source / "secrets/api/token").write_text("x" * 64)
        (rendered / "control-api.container").write_text(
            "[Container]\n"
            "EnvironmentFile=/etc/makersbrain/control-api.env\n"
            "Volume=/etc/makersbrain/secrets/api:/run/secrets:ro\n"
        )
        return source, rendered

    def run_tool(self, root: Path, source: Path, rendered: Path):
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--source",
                str(source),
                "--rendered",
                str(rendered),
                "--generation",
                "control-2026.08.17-test",
                "--output",
                str(root / "manifest.json"),
            ],
            text=True,
            capture_output=True,
        )

    def test_builds_exact_locked_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, rendered = self.prepare(root)
            result = self.run_tool(root, source, rendered)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = root / "manifest.json"
            self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
            document = json.loads(manifest.read_text())
            self.assertEqual(
                document["entries"],
                [
                    {
                        "source": "control-api.env",
                        "target": "control-api.env",
                        "type": "environment",
                    },
                    {
                        "source": "secrets/api/token",
                        "target": "secrets/api/token",
                        "type": "secret",
                    },
                ],
            )

    def test_rejects_stray_and_symlinked_files(self):
        cases = ("stray", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, rendered = self.prepare(root)
                if case == "stray":
                    (source / "unmounted-secret").write_text("no")
                    expected = "outside rendered runtime mounts"
                else:
                    os.symlink(source / "secrets/api/token", source / "secrets/api/alias")
                    expected = "contains a symlink"
                result = self.run_tool(root, source, rendered)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_rejects_missing_environment_and_empty_mount(self):
        cases = ("environment", "mount")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, rendered = self.prepare(root)
                if case == "environment":
                    (source / "control-api.env").unlink()
                    expected = "regular, non-symlink"
                else:
                    (source / "secrets/api/token").unlink()
                    expected = "secret mount is empty"
                result = self.run_tool(root, source, rendered)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
