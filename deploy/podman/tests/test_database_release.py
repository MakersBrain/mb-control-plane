import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1] / "database"
sys.path.insert(0, str(ROOT))
PREVIOUS_RENDER = sys.modules.pop("render", None)
PREVIOUS_VALIDATE = sys.modules.pop("validate", None)
SPEC = importlib.util.spec_from_file_location("database_release", ROOT / "release.py")
RELEASE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RELEASE)
sys.path.remove(str(ROOT))
sys.modules.pop("render", None)
sys.modules.pop("validate", None)
if PREVIOUS_RENDER is not None:
    sys.modules["render"] = PREVIOUS_RENDER
if PREVIOUS_VALIDATE is not None:
    sys.modules["validate"] = PREVIOUS_VALIDATE
VALUES = json.loads((ROOT / "values.example.json").read_text(encoding="utf-8"))
RECORD = json.loads(
    (ROOT.parent / "release-record.example.json").read_text(encoding="utf-8")
)


class DatabaseReleaseTests(unittest.TestCase):
    def write_record(self, root: Path, record: dict) -> Path:
        path = root / "record.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    def test_production_requires_immutable_qualification(self):
        values = copy.deepcopy(VALUES)
        values["environment"] = "production"
        record = copy.deepcopy(RECORD)
        record["staging_qualification_ref"] = "manual-approval"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "immutable staging qualification"):
                RELEASE.load_release(self.write_record(Path(temporary), record), values)

    def test_all_database_secrets_are_inspected(self):
        with mock.patch.object(RELEASE, "run") as run:
            RELEASE.verify_database_secrets()
        self.assertEqual(run.call_count, len(RELEASE.DATABASE_SECRETS))
        self.assertIn(
            mock.call(["podman", "secret", "inspect", "pgbackrest_config"]),
            run.call_args_list,
        )

    @mock.patch.object(RELEASE, "run")
    def test_activation_initializes_recovery_and_enables_backup_timers(self, run):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            (rendered / "postgres.container").write_text("[Container]\n", encoding="utf-8")
            RELEASE.activate(
                rendered,
                RECORD["release_id"],
                root / "state",
                root / "quadlets",
                root / "systemd",
            )
            for name in RELEASE.RECOVERY_UNITS:
                self.assertTrue((root / "systemd" / name).is_symlink())
        run.assert_any_call(
            ["systemctl", "--user", "start", "postgres-recovery-init.service"]
        )
        run.assert_any_call(
            [
                "systemctl", "--user", "enable", "--now",
                "postgres-backup.timer", "postgres-full-backup.timer",
            ]
        )

    def test_failed_activation_restores_previous_quadlet_and_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rendered = root / "rendered"
            rendered.mkdir()
            for name in ("postgres.container", *RELEASE.RECOVERY_UNITS):
                (rendered / name).write_text("fixture\n", encoding="utf-8")
            previous = root / "previous"
            previous.mkdir()
            quadlets = root / "quadlets"
            quadlets.mkdir()
            (quadlets / "makersbrain-database").symlink_to(previous, target_is_directory=True)
            systemd = root / "systemd"
            systemd.mkdir()
            for name in RELEASE.RECOVERY_UNITS:
                (systemd / name).symlink_to(previous / name)
            with (
                mock.patch.object(RELEASE, "run", side_effect=RuntimeError("failed")),
                mock.patch.object(RELEASE, "run_best_effort"),
                self.assertRaisesRegex(RuntimeError, "failed"),
            ):
                RELEASE.activate(
                    rendered,
                    RECORD["release_id"],
                    root / "state",
                    quadlets,
                    systemd,
                )
            self.assertEqual((quadlets / "makersbrain-database").resolve(), previous)
            for name in RELEASE.RECOVERY_UNITS:
                self.assertEqual(os.readlink(systemd / name), str(previous / name))


if __name__ == "__main__":
    unittest.main()
