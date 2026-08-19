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

COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_IDENTITY = (
    "https://github.com/MakersBrain/odoo/"
    ".github/workflows/release.yml@refs/heads/main"
)


RELEASE_ID = re.compile(r"^control-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{16,64}$")
COMMIT = re.compile(r"^[a-f0-9]{40,64}$")
QUALIFICATION_REF = re.compile(r"^\S+/qualifications@sha256:[a-f0-9]{64}$")
DATABASE_SECRETS = (
    "postgres_superuser_password", "control_postgres_password",
    "control_api_postgres_password", "control_membership_postgres_password",
    "control_provisioning_postgres_password", "control_invoice_postgres_password",
    "control_inventory_postgres_password", "control_email_postgres_password",
    "control_reconciliation_postgres_password", "control_lifecycle_postgres_password",
    "control_backup_postgres_password", "control_driver_postgres_password",
    "control_release_postgres_password", "control_privacy_postgres_password",
    "rauthy_postgres_password", "odoo_postgres_password", "postgres_tls_certificate",
    "postgres_tls_private_key", "pgbackrest_config",
)
RECOVERY_UNITS = (
    "postgres-recovery-init.service",
    "postgres-backup.service",
    "postgres-backup.timer",
    "postgres-full-backup.service",
    "postgres-full-backup.timer",
)


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def run_best_effort(command: list[str]) -> None:
    subprocess.run(command, check=False)


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
        if not QUALIFICATION_REF.fullmatch(record.get("staging_qualification_ref", "").strip()):
            raise ValueError("production requires an immutable staging qualification artifact")
    return record


def verify_database_secrets() -> None:
    for name in DATABASE_SECRETS:
        run(["podman", "secret", "inspect", name])


def ensure_data_directory(path: Path) -> None:
    """Create the validated database data child without accepting a symlink."""
    if path.is_symlink():
        raise ValueError("database data directory must not be a symlink")
    if path.exists() and not path.is_dir():
        raise ValueError("database data path must be a directory")
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    path.chmod(0o700)


def activate(
    rendered: Path,
    release_id: str,
    state_root: Path,
    quadlet_root: Path,
    systemd_root: Path,
) -> None:
    release_root = state_root / "database-releases" / release_id
    if release_root.exists():
        raise ValueError("database release has already been staged")
    release_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    quadlet_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    systemd_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.copytree(rendered, release_root)
    current = quadlet_root / "makersbrain-database"
    previous = os.readlink(current) if current.is_symlink() else None
    if current.exists() and not current.is_symlink():
        raise ValueError("database Quadlet activation path is not a managed symlink")
    previous_units: dict[str, str | None] = {}
    for name in RECOVERY_UNITS:
        target = systemd_root / name
        if target.exists() and not target.is_symlink():
            raise ValueError(f"database recovery unit is not a managed symlink: {target}")
        previous_units[name] = os.readlink(target) if target.is_symlink() else None
    try:
        for name in RECOVERY_UNITS:
            target = systemd_root / name
            temporary_unit = systemd_root / f".{name}-{release_id}"
            os.symlink(release_root / name, temporary_unit)
            os.replace(temporary_unit, target)
        temporary = quadlet_root / f".makersbrain-database-{release_id}"
        os.symlink(release_root, temporary, target_is_directory=True)
        os.replace(temporary, current)
        run(["systemctl", "--user", "daemon-reload"])
        # Quadlet generates postgres.service at daemon-reload time. Generated
        # units cannot be enabled directly; the Quadlet [Install] section owns
        # its default.target linkage, so activation only needs to start it.
        run(["systemctl", "--user", "start", "postgres.service"])
        run(["systemctl", "--user", "start", "postgres-recovery-init.service"])
        run(
            [
                "systemctl", "--user", "enable", "--now",
                "postgres-backup.timer", "postgres-full-backup.timer",
            ]
        )
    except Exception:
        run_best_effort(
            [
                "systemctl", "--user", "disable", "--now",
                "postgres-backup.timer", "postgres-full-backup.timer",
            ]
        )
        current.unlink(missing_ok=True)
        if previous is not None:
            os.symlink(previous, current, target_is_directory=True)
        for name, old_target in previous_units.items():
            (systemd_root / f".{name}-{release_id}").unlink(missing_ok=True)
            unit = systemd_root / name
            unit.unlink(missing_ok=True)
            if old_target is not None:
                os.symlink(old_target, unit)
        (quadlet_root / f".makersbrain-database-{release_id}").unlink(missing_ok=True)
        run_best_effort(["systemctl", "--user", "daemon-reload"])
        if previous is not None:
            run_best_effort(["systemctl", "--user", "start", "postgres.service"])
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--release-record", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, default=Path.home() / ".local/state/makersbrain")
    parser.add_argument(
        "--quadlet-root", type=Path, default=Path.home() / ".config/containers/systemd"
    )
    parser.add_argument(
        "--systemd-root", type=Path, default=Path.home() / ".config/systemd/user"
    )
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="makersbrain-database-release-") as temporary:
        rendered = Path(temporary)
        render.render(args.values, rendered)
        validate.validate(rendered)
        values = render.load_values(args.values)
        record = load_release(args.release_record, values)
        if args.activate:
            verify_database_secrets()
        image = values["postgres_image"]
        run(
            [
                "cosign",
                "verify",
                "--certificate-oidc-issuer",
                COSIGN_OIDC_ISSUER,
                "--certificate-identity",
                COSIGN_IDENTITY,
                "--certificate-github-workflow-repository",
                "MakersBrain/odoo",
                image,
            ]
        )
        run(["podman", "pull", image])
        if args.activate:
            ensure_data_directory(Path(values["data_directory"]))
            activate(
                rendered,
                record["release_id"],
                args.state_root,
                args.quadlet_root,
                args.systemd_root,
            )
        else:
            print("database release image, record and Quadlet are valid")


if __name__ == "__main__":
    main()
