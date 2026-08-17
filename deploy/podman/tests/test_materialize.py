import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "materialize.py"


class MaterializeTests(unittest.TestCase):
    def write_manifest(self, root: Path, generation: str = "release-1", entries=None) -> Path:
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generation": generation,
                    "entries": entries
                    or [
                        {"source": "api.env", "target": "control-api.env", "type": "environment"},
                        {"source": "token", "target": "secrets/api/token", "type": "secret"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def run_tool(self, root: Path, manifest: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--source",
                str(root / "source"),
                "--manifest",
                str(manifest),
                "--rendered",
                str(root / "rendered"),
                "--generation-root",
                str(root / "generations"),
                "--current-link",
                str(root / "current"),
                *extra,
            ],
            text=True,
            capture_output=True,
        )

    def prepare(self, root: Path) -> None:
        source = root / "source"
        source.mkdir()
        (source / "api.env").write_text("CONTROL_LISTEN=0.0.0.0:8080\n", encoding="utf-8")
        (source / "token").write_text("a" * 64, encoding="utf-8")
        rendered = root / "rendered"
        rendered.mkdir()
        (rendered / "control-api.container").write_text(
            "[Container]\n"
            "EnvironmentFile=/etc/makersbrain/control-api.env\n"
            "Volume=/etc/makersbrain/secrets/api:/run/secrets:ro\n",
            encoding="utf-8",
        )

    def test_installs_locked_generation_and_atomically_switches_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            result = self.run_tool(root, self.write_manifest(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            current = root / "current"
            self.assertTrue(current.is_symlink())
            self.assertEqual(current.resolve().name, "release-1")
            self.assertEqual(
                stat.S_IMODE((current / "control-api.env").stat().st_mode), 0o400
            )
            self.assertEqual(
                stat.S_IMODE((current / "secrets/api/token").stat().st_mode), 0o600
            )
            self.assertEqual(stat.S_IMODE(current.resolve().stat().st_mode), 0o700)

    def test_check_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            result = self.run_tool(root, self.write_manifest(root), "--check")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "generations").exists())
            self.assertFalse((root / "current").exists())

    def test_rejects_negative_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            result = self.run_tool(root, self.write_manifest(root), "--uid", "-1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-negative", result.stderr)

    def test_rejects_symlink_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            (root / "source/token").unlink()
            os.symlink(root / "source/api.env", root / "source/token")
            result = self.run_tool(root, self.write_manifest(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains a symlink", result.stderr)

    def test_rejects_symlink_source_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            real = root / "real"
            real.mkdir()
            (real / "token").write_text("a" * 64, encoding="utf-8")
            os.symlink(real, root / "source/linked")
            entries = [
                {
                    "source": "linked/token",
                    "target": "secrets/api/token",
                    "type": "secret",
                }
            ]
            result = self.run_tool(root, self.write_manifest(root, entries=entries))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains a symlink", result.stderr)

    def test_rejects_traversal_duplicate_target_and_invalid_environment(self):
        cases = [
            ([{"source": "../token", "target": "token", "type": "secret"}], "normalized relative"),
            (
                [
                    {"source": "token", "target": "same", "type": "secret"},
                    {"source": "api.env", "target": "same", "type": "environment"},
                ],
                "duplicate target",
            ),
        ]
        for entries, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare(root)
                result = self.run_tool(root, self.write_manifest(root, entries=entries))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            (root / "source/api.env").write_text("export SECRET=no\n", encoding="utf-8")
            result = self.run_tool(root, self.write_manifest(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid environment assignment", result.stderr)

    def test_existing_generation_is_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            manifest = self.write_manifest(root)
            first = self.run_tool(root, manifest)
            second = self.run_tool(root, manifest)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("generation already exists", second.stderr)

    def test_rejects_missing_environment_and_empty_secret_mount(self):
        cases = [
            (
                [{"source": "token", "target": "secrets/api/token", "type": "secret"}],
                "omits rendered environment files",
            ),
            (
                [{"source": "api.env", "target": "control-api.env", "type": "environment"}],
                "leaves rendered secret mounts empty",
            ),
        ]
        for entries, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare(root)
                result = self.run_tool(root, self.write_manifest(root, entries=entries))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_rejects_unmounted_extra_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            (root / "source/extra").write_text("not mounted", encoding="utf-8")
            entries = [
                {"source": "api.env", "target": "control-api.env", "type": "environment"},
                {"source": "token", "target": "secrets/api/token", "type": "secret"},
                {"source": "extra", "target": "secrets/other/token", "type": "secret"},
            ]
            result = self.run_tool(root, self.write_manifest(root, entries=entries))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside rendered runtime mounts", result.stderr)


if __name__ == "__main__":
    unittest.main()
