#!/usr/bin/env python3
"""Verify and atomically activate one rootless Podman release."""

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
PERSISTENT_UNITS = [
    "cloudflared.service",
    "redis.service",
    "odoo.service",
    "rauthy.service",
    "tenant-gateway.service",
    "control-api.service",
    "control-web.service",
    "document-extraction.service",
    "control-container-driver.service",
    "control-backup-scheduler.service",
    "control-workers@tenant-provisioning.service",
    "control-workers@membership-provisioning.service",
    "control-workers@invoice-capture.service",
    "control-workers@inventory-capture.service",
    "control-workers@email-delivery.service",
    "control-workers@tenant-reconciliation.service",
    "control-workers@tenant-lifecycle.service",
    "control-workers@release-adoption.service",
    "control-workers@privacy-operations.service",
]


def load_release(path: Path, values: dict) -> dict:
    record = json.loads(path.read_text(encoding="utf-8"))
    if not RELEASE_ID.fullmatch(record.get("release_id", "")):
        raise ValueError("release_id is invalid")
    if not COMMIT.fullmatch(record.get("source_commit", "")):
        raise ValueError("source_commit is invalid")
    if not record.get("ci_run_url", "").startswith("https://"):
        raise ValueError("ci_run_url must be HTTPS")
    if record.get("images") != values["images"]:
        raise ValueError("release record images differ from rendered values")
    if values["environment"] == "production":
        qualification = record.get("staging_qualification_ref", "").strip()
        if len(qualification) < 8:
            raise ValueError("production requires a staging qualification reference")
    return record


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def verify_release_record(record: Path, signature: Path, key: Path) -> None:
    if not signature.is_file():
        raise ValueError("release-record signature is missing")
    run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            str(key),
            "--signature",
            str(signature),
            str(record),
        ]
    )


def verify_and_pull(images: dict[str, str], key: Path) -> None:
    if not key.is_file():
        raise ValueError("Cosign public key is missing")
    for name in sorted(images):
        image = images[name]
        run(["cosign", "verify", "--key", str(key), image])
        run(["podman", "pull", image])


def verify_runtime_secrets(values: dict, config_root: Path) -> None:
    secret_root = Path(values["runtime_secret_source"])
    postgres_ca = secret_root / "postgres-ca.crt"
    if not postgres_ca.is_file() or postgres_ca.is_symlink():
        raise ValueError(
            f"PostgreSQL CA must be a regular, non-symlink file: {postgres_ca}"
        )
    rauthy_environment = config_root / "rauthy.env"
    if not rauthy_environment.is_file() or rauthy_environment.is_symlink():
        raise ValueError(
            f"Rauthy environment must be a regular, non-symlink file: {rauthy_environment}"
        )
    root_ca = next(
        (
            line.partition("=")[2].strip().strip('"').strip("'")
            for line in rauthy_environment.read_text(encoding="utf-8").splitlines()
            if line.startswith("PG_TLS_ROOT_CA=")
        ),
        "",
    )
    if len(root_ca) < 30 or "BEGIN CERTIFICATE" not in root_ca:
        raise ValueError("Rauthy PG_TLS_ROOT_CA must contain the PostgreSQL CA PEM")
    tunnel_token = config_root / "secrets/cloudflared/tunnel-token"
    if not tunnel_token.is_file() or tunnel_token.is_symlink():
        raise ValueError(
            f"Cloudflare Tunnel token must be a regular, non-symlink file: {tunnel_token}"
        )
    if tunnel_token.stat().st_mode & 0o077:
        raise ValueError("Cloudflare Tunnel token must not be accessible by group or others")


def activate(
    rendered: Path,
    release_id: str,
    state_root: Path,
    quadlet_root: Path | None = None,
) -> None:
    releases = state_root / "releases"
    quadlet_root = quadlet_root or Path.home() / ".config/containers/systemd"
    release_root = releases / release_id
    if release_root.exists():
        raise ValueError("release has already been staged")
    releases.mkdir(parents=True, exist_ok=True, mode=0o700)
    quadlet_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    shutil.copytree(rendered, release_root)
    for path in release_root.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)

    current = quadlet_root / "makersbrain"
    previous = os.readlink(current) if current.is_symlink() else None
    temporary = quadlet_root / f".makersbrain-{release_id}"
    os.symlink(release_root, temporary, target_is_directory=True)
    os.replace(temporary, current)
    try:
        run(["systemctl", "--user", "daemon-reload"])
        run(["systemctl", "--user", "enable", "--now", *PERSISTENT_UNITS])
    except Exception:
        current.unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
        if previous is not None:
            os.symlink(previous, current, target_is_directory=True)
            run(["systemctl", "--user", "daemon-reload"])
            run(["systemctl", "--user", "start", *PERSISTENT_UNITS])
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--release-record", type=Path, required=True)
    parser.add_argument("--release-signature", type=Path, required=True)
    parser.add_argument("--cosign-key", type=Path, required=True)
    parser.add_argument(
        "--state-root", type=Path, default=Path.home() / ".local/state/makersbrain"
    )
    parser.add_argument(
        "--quadlet-root",
        type=Path,
        default=Path.home() / ".config/containers/systemd",
    )
    parser.add_argument("--config-root", type=Path, default=Path("/etc/makersbrain"))
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()

    if not args.cosign_key.is_file():
        raise ValueError("Cosign public key is missing")
    verify_release_record(args.release_record, args.release_signature, args.cosign_key)
    values = render.load_values(args.values)
    record = load_release(args.release_record, values)
    if args.activate:
        verify_runtime_secrets(values, args.config_root)
    verify_and_pull(values["images"], args.cosign_key)
    with tempfile.TemporaryDirectory(prefix="makersbrain-release-") as temporary:
        rendered = Path(temporary)
        render.render(args.values, rendered)
        validate.validate(rendered)
        if args.activate:
            activate(rendered, record["release_id"], args.state_root, args.quadlet_root)
        else:
            print("release signatures, images, record and Quadlets are valid")


if __name__ == "__main__":
    main()
