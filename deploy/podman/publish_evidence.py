#!/usr/bin/env python3
"""Validate and publish staging evidence without exposing credentials in arguments."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

import qualification


REPOSITORY = re.compile(r"^\S+/staging-evidence$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def publish(release_record: Path, evidence_dir: Path, repository: str) -> str:
    if not REPOSITORY.fullmatch(repository) or "@" in repository or "://" in repository:
        raise ValueError("repository must be an untagged OCI staging-evidence repository")
    if evidence_dir.name != "evidence":
        raise ValueError("evidence directory must be named evidence")
    release = qualification.load_object(release_record)
    qualification.validate_release(release)
    with tempfile.TemporaryDirectory(prefix="makersbrain-qualification-") as temporary:
        qualification.create(
            release_record, evidence_dir, Path(temporary) / "qualification.json"
        )
    tag = f"{repository}:{release['release_id']}"
    layers = [
        f"evidence/{check}.json:application/vnd.makersbrain.staging-check.v1+json"
        for check in qualification.CHECKS
    ]
    run(
        [
            "oras",
            "push",
            tag,
            "--artifact-type",
            "application/vnd.makersbrain.staging-evidence.v1",
            *layers,
        ],
        cwd=evidence_dir.parent,
    )
    digest = run(["oras", "resolve", tag], capture_output=True).stdout.strip()
    if not DIGEST.fullmatch(digest):
        raise ValueError("registry returned an invalid evidence digest")
    return f"{repository}@{digest}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-record", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    print(publish(args.release_record, args.evidence_dir, args.repository))


if __name__ == "__main__":
    main()
