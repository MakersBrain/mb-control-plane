#!/usr/bin/env python3
"""Verify and activate one signed PostgreSQL host release."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import render
import validate


RELEASE_ID = re.compile(r"^control-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{16,64}$")
COMMIT = re.compile(r"^[a-f0-9]{40,64}$")


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def load_release(path: Path, values: dict) -> dict:
    record = json.loads(path.read_text(encoding="utf-8"))
    if not RELEASE_ID.fullmatch(record.get("release_id", "")):
        raise ValueError("release_id is invalid")
    if not COMMIT.fullmatch(record.get("source_commit", "")):
        raise ValueError("source_commit is invalid")
    if not record.get("ci_run_url", "").startswith("https://"):
        raise ValueError("ci_run_url must be HTTPS")
    if record.get("images", {}).get("postgres") != values["postgres_image"]:
        raise ValueError("release record PostgreSQL image differs from database values")
    if values["environment"] == "production":
        if len(record.get("staging_qualification_ref", "").strip()) < 8:
            raise ValueError("production requires a staging qualification reference")
    return record


def activate(rendered: Path, release_id: str, state_root: Path, quadlet_root: Path) -> None:
    release_root = state_root / "database-releases" / release_id
    if release_root.exists():
        raise ValueError("database release has already been staged")
    release_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    quadlet_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.copytree(rendered, release_root)
    current = quadlet_root / "makersbrain-database"
    previous = os.readlink(current) if current.is_symlink() else None
    temporary = quadlet_root / f".makersbrain-database-{release_id}"
    os.symlink(release_root, temporary, target_is_directory=True)
    os.replace(temporary, current)
    try:
        run(["systemctl", "--user", "daemon-reload"])
        run(["systemctl", "--user", "enable", "--now", "postgres.service"])
    except Exception:
        current.unlink(missing_ok=True)
        if previous is not None:
            os.symlink(previous, current, target_is_directory=True)
        run(["systemctl", "--user", "daemon-reload"])
        if previous is not None:
            run(["systemctl", "--user", "start", "postgres.service"])
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--release-record", type=Path, required=True)
    parser.add_argument("--release-signature", type=Path, required=True)
    parser.add_argument("--cosign-key", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, default=Path.home() / ".local/state/makersbrain")
    parser.add_argument(
        "--quadlet-root", type=Path, default=Path.home() / ".config/containers/systemd"
    )
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()

    if not args.cosign_key.is_file() or not args.release_signature.is_file():
        raise ValueError("Cosign public key or release signature is missing")
    run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            str(args.cosign_key),
            "--signature",
            str(args.release_signature),
            str(args.release_record),
        ]
    )
    values = render.load_values(args.values)
    record = load_release(args.release_record, values)
    image = values["postgres_image"]
    run(["cosign", "verify", "--key", str(args.cosign_key), image])
    run(["podman", "pull", image])
    with tempfile.TemporaryDirectory(prefix="makersbrain-database-release-") as temporary:
        rendered = Path(temporary)
        render.render(args.values, rendered)
        validate.validate(rendered)
        if args.activate:
            activate(rendered, record["release_id"], args.state_root, args.quadlet_root)
        else:
            print("database release signature, image and Quadlet are valid")


if __name__ == "__main__":
    main()
