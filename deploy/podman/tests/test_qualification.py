import copy
import importlib.util
import json
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qualification", ROOT / "qualification.py")
QUALIFICATION = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(QUALIFICATION)
RELEASE = json.loads((ROOT / "release-record.example.json").read_text(encoding="utf-8"))


class QualificationTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        release = root / "release.json"
        release.write_text(json.dumps(RELEASE), encoding="utf-8")
        evidence = root / "evidence"
        evidence.mkdir()
        for check in QUALIFICATION.CHECKS:
            (evidence / f"{check}.json").write_text(
                json.dumps(
                    {
                        "check": check,
                        "status": "passed",
                        "started_at": "2026-08-15T10:00:00Z",
                        "completed_at": "2026-08-15T10:01:00Z",
                        "summary": f"Synthetic staging check passed for {check.replace('_', ' ')}.",
                    }
                ),
                encoding="utf-8",
            )
        return release, evidence, root / "qualification.json"

    def test_create_and_validate_exact_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            release, evidence, output = self.fixture(Path(temporary))
            QUALIFICATION.create(release, evidence, output)
            record = QUALIFICATION.validate(output, release, evidence)
            self.assertTrue(record["synthetic_data_only"])
            self.assertEqual(set(record["checks"]), set(QUALIFICATION.CHECKS))

    def test_paid_webshop_provider_checks_are_independently_mandatory(self):
        self.assertTrue(
            {
                "webshop_cloudflare_dns_tls",
                "webshop_scaleway_mail",
                "webshop_sumup_payment",
                "webshop_boxtal_shipping",
                "webshop_sendcloud_shipping",
                "webshop_browser_accessibility",
            }.issubset(QUALIFICATION.CHECKS)
        )

    def test_observability_delivery_is_independently_mandatory(self):
        self.assertIn("observability_delivery", QUALIFICATION.CHECKS)

    def test_failed_check_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            release, evidence, output = self.fixture(Path(temporary))
            path = evidence / "backup_restore.json"
            failed = json.loads(path.read_text())
            failed["status"] = "failed"
            path.write_text(json.dumps(failed))
            with self.assertRaisesRegex(ValueError, "did not pass"):
                QUALIFICATION.create(release, evidence, output)

    def test_release_image_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release, evidence, output = self.fixture(root)
            QUALIFICATION.create(release, evidence, output)
            changed = copy.deepcopy(RELEASE)
            changed["images"]["control"] = changed["images"]["web"]
            other = root / "other-release.json"
            other.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "images differs"):
                QUALIFICATION.validate(output, other, evidence)

    def test_evidence_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            release, evidence, output = self.fixture(Path(temporary))
            QUALIFICATION.create(release, evidence, output)
            path = evidence / "load_test.json"
            changed = json.loads(path.read_text())
            changed["summary"] = "Synthetic staging load targets passed after tampering."
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "digest differs"):
                QUALIFICATION.validate(output, release, evidence)

    def test_summary_rejects_identifiers_and_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            release, evidence, output = self.fixture(Path(temporary))
            path = evidence / "mail_delivery.json"
            changed = json.loads(path.read_text())
            changed["summary"] = "Passed for person@example.test"
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "unsafe"):
                QUALIFICATION.create(release, evidence, output)

    def test_evidence_archive_is_extracted_without_tar_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, evidence, _ = self.fixture(root)
            archive = root / "evidence.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                package.add(evidence, arcname="evidence")
            extracted = QUALIFICATION.extract_evidence(archive, root / "extracted")
            self.assertEqual(
                {path.name for path in extracted.iterdir()},
                {f"{check}.json" for check in QUALIFICATION.CHECKS},
            )

    def test_evidence_archive_rejects_unsafe_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                member = tarfile.TarInfo("../../outside.json")
                payload = b"{}"
                member.size = len(payload)
                package.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(ValueError, "exact mandatory files"):
                QUALIFICATION.extract_evidence(archive, root / "extracted")
            self.assertFalse((root.parent / "outside.json").exists())


if __name__ == "__main__":
    unittest.main()
