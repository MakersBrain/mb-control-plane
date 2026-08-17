import importlib.util
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1] / "database"
SPEC = importlib.util.spec_from_file_location("database_write_fence", ROOT / "write-fence.py")
FENCE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(FENCE)


class DatabaseWriteFenceTests(unittest.TestCase):
    def test_enable_fences_every_runtime_role_and_terminates_existing_sessions(self):
        statement = FENCE.sql("enable")
        for role in FENCE.RUNTIME_ROLES:
            self.assertIn(f'alter role "{role}" set default_transaction_read_only = on;', statement)
        self.assertIn("pg_terminate_backend", statement)
        self.assertNotIn('alter role "control"', statement)

    def test_disable_resets_roles_without_terminating_sessions(self):
        statement = FENCE.sql("disable")
        self.assertIn("reset default_transaction_read_only", statement)
        self.assertNotIn("pg_terminate_backend", statement)

    def test_verify_fails_closed_on_missing_or_unfenced_roles(self):
        statement = FENCE.sql("verify")
        self.assertIn("raise exception", statement)
        self.assertIn("default_transaction_read_only=on", statement)
        self.assertIn(str(len(FENCE.RUNTIME_ROLES)), statement)

    @mock.patch.object(FENCE.subprocess, "run")
    def test_secret_is_resolved_inside_the_database_container(self, run):
        FENCE.run("verify")
        command = run.call_args.args[0]
        rendered = " ".join(command)
        self.assertNotIn("--password=", rendered.lower())
        self.assertIn("/run/secrets/postgres_superuser_password", rendered)
        self.assertEqual(run.call_args.kwargs["input"], FENCE.sql("verify"))
