import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("publish_evidence", ROOT / "publish_evidence.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PUBLISH)
RELEASE = json.loads((ROOT / "release-record.example.json").read_text(encoding="utf-8"))


class PublishEvidenceTests(unittest.TestCase):
    def test_publish_uses_validated_files_and_returns_digest_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "release.json"
            release.write_text(json.dumps(RELEASE), encoding="utf-8")
            evidence = root / "evidence"
            evidence.mkdir()
            for check in PUBLISH.qualification.CHECKS:
                (evidence / f"{check}.json").write_text(
                    json.dumps(
                        {
                            "check": check,
                            "status": "passed",
                            "started_at": "2026-08-15T10:00:00Z",
                            "completed_at": "2026-08-15T10:01:00Z",
                            "summary": f"Synthetic check passed for {check.replace('_', ' ')}.",
                        }
                    ),
                    encoding="utf-8",
                )
            digest = "sha256:" + "a" * 64
            with mock.patch.object(
                PUBLISH,
                "run",
                side_effect=[
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, digest + "\n", ""),
                ],
            ) as run:
                reference = PUBLISH.publish(
                    release, evidence, "registry.example/makersbrain/staging-evidence"
                )
            self.assertEqual(
                reference,
                f"registry.example/makersbrain/staging-evidence@{digest}",
            )
            self.assertEqual(run.call_count, 2)
            self.assertNotIn("token", " ".join(run.call_args_list[0].args[0]))


if __name__ == "__main__":
    unittest.main()
