import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1] / "database"
SPEC = importlib.util.spec_from_file_location("database_restore", ROOT / "restore.py")
RESTORE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RESTORE)
EXAMPLE = json.loads((ROOT / "values.example.json").read_text(encoding="utf-8"))


class DatabaseRestoreTests(unittest.TestCase):
    def write_values(self, root: Path) -> Path:
        path = root / "values.json"
        path.write_text(json.dumps(EXAMPLE), encoding="utf-8")
        return path

    def test_restore_is_isolated_digest_pinned_and_timezone_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            drills = root / "drills"
            drills.mkdir()
            target = drills / "quarterly-2026q3"

            def execute(command):
                if command[:2] == ["podman", "run"]:
                    (target / "PG_VERSION").write_text("17\n", encoding="utf-8")

            with mock.patch.object(RESTORE, "run", side_effect=execute) as run:
                summary = RESTORE.restore(
                    self.write_values(root),
                    drills,
                    target,
                    "2026-08-15 10:30:00+02:00",
                )

            command = run.call_args_list[1].args[0]
            self.assertIn("--pull=never", command)
            self.assertIn("--user=70:70", command)
            self.assertIn(f"--volume={target}:/restore:Z,U", command)
            self.assertIn("--pg1-path=/restore", command)
            self.assertIn("--target=2026-08-15 10:30:00+02:00", command)
            self.assertTrue(summary["isolated_restore"])
            self.assertEqual(summary["result"], "passed")

    def test_target_outside_drill_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            drills = root / "drills"
            drills.mkdir()
            with self.assertRaisesRegex(ValueError, "immediate child"):
                RESTORE.validated_target(drills, root / "outside")

    def test_naive_target_time_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "UTC offset"):
            RESTORE.validated_target_time("2026-08-15 10:30:00")

    def test_nonempty_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            drills = Path(temporary)
            target = drills / "existing"
            target.mkdir()
            (target / "keep").write_text("do not replace", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent or empty"):
                RESTORE.validated_target(drills, target)


if __name__ == "__main__":
    unittest.main()
