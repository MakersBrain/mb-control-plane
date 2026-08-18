#!/usr/bin/env python3
"""Build and validate a privacy-safe staging qualification record."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tarfile
from datetime import datetime, timezone
from pathlib import Path


RELEASE_ID = re.compile(r"^control-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{16,64}$")
IMAGE = re.compile(r"^\S+@sha256:[a-f0-9]{64}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
CHECKS = (
    "release_verification",
    "topology_reboot",
    "two_tenant_isolation",
    "queue_workers",
    "release_adoption",
    "failed_upgrade_fencing",
    "rollback",
    "provider_failure_recovery",
    "webshop_cloudflare_dns_tls",
    "webshop_scaleway_mail",
    "webshop_sumup_payment",
    "webshop_boxtal_shipping",
    "webshop_sendcloud_shipping",
    "webshop_browser_accessibility",
    "identity_mfa",
    "mail_delivery",
    "backup_restore",
    "erasure_restore_replay",
    "migration_rehearsal",
    "alerts_runbooks",
    "observability_delivery",
    "load_test",
    "log_privacy_review",
)
FORBIDDEN_SUMMARY = re.compile(
    r"@|bearer|password|secret|token|document body|email address", re.IGNORECASE
)


def timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{name} must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{name} must be a UTC RFC3339 timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"{name} must be UTC")
    return parsed


def load_object(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise ValueError(f"{path} must be a small regular, non-symlink JSON file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def validate_release(record: dict) -> None:
    if not RELEASE_ID.fullmatch(record.get("release_id", "")):
        raise ValueError("release record has an invalid release_id")
    images = record.get("images")
    if not isinstance(images, dict) or not images or not all(
        isinstance(name, str) and isinstance(image, str) and IMAGE.fullmatch(image)
        for name, image in images.items()
    ):
        raise ValueError("release record images are not immutable OCI references")


def evidence_file(root: Path, check: str) -> Path:
    return root / f"{check}.json"


def extract_evidence(archive: Path, output: Path) -> Path:
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("evidence archive must be a small regular, non-symlink file")
    if output.exists() and (not output.is_dir() or output.is_symlink() or any(output.iterdir())):
        raise ValueError("evidence extraction directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    evidence_root = output / "evidence"
    evidence_root.mkdir(mode=0o700)
    expected = {f"evidence/{check}.json" for check in CHECKS}
    with tarfile.open(archive, mode="r:gz") as package:
        members = package.getmembers()
        file_members = [member for member in members if member.isfile()]
        names = [member.name.removeprefix("./") for member in file_members]
        if len(names) != len(expected) or set(names) != expected:
            raise ValueError("evidence archive does not contain the exact mandatory files")
        if any(
            (member.isdir() and member.name.removeprefix("./").rstrip("/") != "evidence")
            or (not member.isdir() and not member.isfile())
            or (member.isfile() and member.size > 64 * 1024)
            for member in members
        ):
            raise ValueError("evidence archive contains an unsafe member")
        for member, name in zip(file_members, names, strict=True):
            source = package.extractfile(member)
            if source is None:
                raise ValueError("evidence archive member cannot be read")
            payload = source.read(64 * 1024 + 1)
            if len(payload) > 64 * 1024:
                raise ValueError("evidence archive member is too large")
            target = evidence_root / Path(name).name
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(payload)
    return evidence_root


def validate_evidence(path: Path, expected_check: str) -> tuple[dict, datetime, datetime]:
    evidence = load_object(path)
    if set(evidence) != {"check", "status", "started_at", "completed_at", "summary"}:
        raise ValueError(f"{path.name} has unexpected or missing fields")
    if evidence["check"] != expected_check or evidence["status"] != "passed":
        raise ValueError(f"{expected_check} did not pass")
    summary = evidence["summary"]
    if (
        not isinstance(summary, str)
        or not 8 <= len(summary) <= 200
        or any(ord(character) < 32 for character in summary)
        or FORBIDDEN_SUMMARY.search(summary)
    ):
        raise ValueError(f"{expected_check} summary is unsafe or invalid")
    started = timestamp(evidence["started_at"], f"{expected_check}.started_at")
    completed = timestamp(evidence["completed_at"], f"{expected_check}.completed_at")
    if completed < started:
        raise ValueError(f"{expected_check} completed before it started")
    return evidence, started, completed


def create(release_path: Path, evidence_root: Path, output: Path) -> dict:
    release = load_object(release_path)
    validate_release(release)
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        raise ValueError("evidence directory must be a regular directory")
    expected_files = {f"{check}.json" for check in CHECKS}
    actual_files = {path.name for path in evidence_root.iterdir() if path.is_file()}
    if actual_files != expected_files:
        raise ValueError(
            f"evidence set mismatch: missing={sorted(expected_files - actual_files)} "
            f"extra={sorted(actual_files - expected_files)}"
        )
    checks: dict[str, dict[str, str]] = {}
    starts: list[datetime] = []
    completions: list[datetime] = []
    for check in CHECKS:
        path = evidence_file(evidence_root, check)
        evidence, started, completed = validate_evidence(path, check)
        starts.append(started)
        completions.append(completed)
        checks[check] = {
            "status": "passed",
            "summary": evidence["summary"],
            "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    record = {
        "schema_version": 1,
        "qualification_id": f"staging-{release['release_id']}",
        "environment": "staging",
        "synthetic_data_only": True,
        "release_id": release["release_id"],
        "source_commit": release["source_commit"],
        "images": release["images"],
        "started_at": min(starts).isoformat().replace("+00:00", "Z"),
        "completed_at": max(completions).isoformat().replace("+00:00", "Z"),
        "checks": checks,
    }
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def validate(record_path: Path, release_path: Path, evidence_root: Path | None = None) -> dict:
    record = load_object(record_path)
    release = load_object(release_path)
    validate_release(release)
    required = {
        "schema_version",
        "qualification_id",
        "environment",
        "synthetic_data_only",
        "release_id",
        "source_commit",
        "images",
        "started_at",
        "completed_at",
        "checks",
    }
    if set(record) != required:
        raise ValueError("qualification record has unexpected or missing fields")
    if record["schema_version"] != 1 or record["environment"] != "staging":
        raise ValueError("qualification record is not staging schema v1")
    if record["synthetic_data_only"] is not True:
        raise ValueError("staging qualification must attest synthetic-only data")
    for field in ("release_id", "source_commit", "images"):
        if record[field] != release[field]:
            raise ValueError(f"qualification {field} differs from the release")
    if record["qualification_id"] != f"staging-{release['release_id']}":
        raise ValueError("qualification_id does not bind the release")
    started = timestamp(record["started_at"], "started_at")
    completed = timestamp(record["completed_at"], "completed_at")
    if completed < started:
        raise ValueError("qualification completed before it started")
    checks = record["checks"]
    if not isinstance(checks, dict) or set(checks) != set(CHECKS):
        raise ValueError("qualification does not contain the exact mandatory checks")
    for check in CHECKS:
        result = checks[check]
        if (
            not isinstance(result, dict)
            or set(result) != {"status", "summary", "evidence_sha256"}
            or result.get("status") != "passed"
            or not isinstance(result.get("summary"), str)
            or FORBIDDEN_SUMMARY.search(result["summary"])
            or not SHA256.fullmatch(result.get("evidence_sha256", ""))
        ):
            raise ValueError(f"qualification check {check} is invalid")
        if evidence_root is not None:
            path = evidence_file(evidence_root, check)
            validate_evidence(path, check)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != result["evidence_sha256"]:
                raise ValueError(f"qualification evidence digest differs for {check}")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--release-record", type=Path, required=True)
    create_parser.add_argument("--evidence-dir", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--record", type=Path, required=True)
    validate_parser.add_argument("--release-record", type=Path, required=True)
    validate_parser.add_argument("--evidence-dir", type=Path)
    extract_parser = subparsers.add_parser("extract")
    extract_parser.add_argument("--archive", type=Path, required=True)
    extract_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        create(args.release_record, args.evidence_dir, args.output)
        print("staging qualification record created")
    elif args.command == "validate":
        validate(args.record, args.release_record, args.evidence_dir)
        print("staging qualification record is valid")
    else:
        extract_evidence(args.archive, args.output)
        print("staging evidence archive extracted safely")


if __name__ == "__main__":
    main()
