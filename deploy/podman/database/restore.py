#!/usr/bin/env python3
"""Restore pgBackRest data into an isolated recovery-drill directory."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

DRILL_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
IMAGE = re.compile(r"^[^\s]+@sha256:[a-f0-9]{64}$")
DEFAULT_ROOT = Path("/var/lib/makersbrain/postgresql/recovery-drills")


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def validated_target(root: Path, target: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    if root.is_symlink() or not resolved_root.is_dir():
        raise ValueError("recovery-drill root must be a real directory")
    if not DRILL_NAME.fullmatch(target.name):
        raise ValueError("target directory name is invalid")
    if target.parent.resolve(strict=True) != resolved_root:
        raise ValueError("target must be an immediate child of the recovery-drill root")
    if target.is_symlink():
        raise ValueError("target directory cannot be a symbolic link")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ValueError("target directory must be absent or empty")
    return target


def validated_target_time(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("target time must include an explicit UTC offset")
    return value


def postgres_image(values_path: Path) -> str:
    values = json.loads(values_path.read_text(encoding="utf-8"))
    image = values.get("postgres_image", "")
    if not IMAGE.fullmatch(image):
        raise ValueError("postgres_image is not pinned by digest")
    if values.get("data_directory") != "/var/lib/makersbrain/postgresql/data":
        raise ValueError("values do not describe the protected database volume")
    return image


def restore(values_path: Path, root: Path, target: Path, target_time: str | None) -> dict:
    image = postgres_image(values_path)
    target = validated_target(root, target)
    target_time = validated_target_time(target_time)
    target.mkdir(mode=0o700, exist_ok=True)

    run(["podman", "secret", "inspect", "pgbackrest_config"])
    command = [
        "podman", "run", "--rm", "--pull=never",
        "--name=makersbrain-postgres-restore",
        "--user=70:70",
        "--secret=pgbackrest_config,target=/etc/pgbackrest/pgbackrest.conf,uid=70,gid=70,mode=0400",
        f"--volume={target}:/restore:Z,U",
        image,
        "pgbackrest", "--stanza=makersbrain", "--pg1-path=/restore",
    ]
    if target_time is not None:
        command.extend(["--type=time", f"--target={target_time}", "--target-action=promote"])
    command.append("restore")

    started = time.monotonic()
    run(command)
    if not (target / "PG_VERSION").is_file():
        raise RuntimeError("restore completed without a PostgreSQL PG_VERSION file")
    return {
        "check": "backup_restore",
        "result": "passed",
        "mode": "point-in-time" if target_time is not None else "latest",
        "target_time": target_time,
        "duration_seconds": round(time.monotonic() - started, 3),
        "isolated_restore": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--recovery-root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--target-directory", type=Path, required=True)
    parser.add_argument("--target-time")
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    summary = restore(
        args.values,
        args.recovery_root,
        args.target_directory,
        args.target_time,
    )
    encoded = json.dumps(summary, sort_keys=True) + "\n"
    if args.summary is not None:
        descriptor = os.open(args.summary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
