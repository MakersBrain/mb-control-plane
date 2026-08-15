#!/usr/bin/env python3
"""Validate a rendered MakersBrain Quadlet bundle without contacting a host."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


IMAGE = re.compile(r"^Image=\S+@sha256:[a-f0-9]{64}$", re.MULTILINE)
FORBIDDEN = ("docker.sock", "tcp://")


def validate(root: Path) -> None:
    expected = {
        "makersbrain.network",
        "cloudflared.container",
        "control-database-identities.container",
        "control-migrate.container",
        "privacy-export-init.container",
        "rauthy-bootstrap.container",
        "rauthy-ready.container",
        "control-api.container",
        "control-container-driver.container",
        "control-workers@.container",
        "control-backup-scheduler.container",
        "document-extraction.container",
        "odoo.container",
        "rauthy.container",
        "redis.container",
        "tenant-gateway.container",
        "control-web.container",
        "resolve-secret-env.sh",
    }
    missing = sorted(expected - {path.name for path in root.iterdir()})
    if missing:
        raise ValueError(f"bundle is incomplete: {', '.join(missing)}")
    values = json.loads((root / "rendered-values.json").read_text(encoding="utf-8"))
    for path in root.iterdir():
        if path.suffix not in {".container", ".network", ".target"}:
            continue
        content = path.read_text(encoding="utf-8")
        if "@@" in content:
            raise ValueError(f"unresolved value in {path.name}")
        if path.suffix == ".container" and not IMAGE.search(content):
            raise ValueError(f"container image is not digest-pinned in {path.name}")
        for marker in FORBIDDEN:
            if marker in content:
                raise ValueError(f"forbidden marker {marker!r} in {path.name}")
    driver = (root / "control-container-driver.container").read_text(encoding="utf-8")
    if "%t/podman/podman.sock:/run/podman/podman.sock" not in driver:
        raise ValueError("driver does not use the private rootless Podman socket")
    if "DRIVER_POSTGRES_CA_SOURCE=" not in driver:
        raise ValueError("driver does not declare the PostgreSQL CA source")
    tls_clients = {
        "control-api.container",
        "control-backup-scheduler.container",
        "control-database-identities.container",
        "control-migrate.container",
        "control-workers@.container",
        "odoo.container",
    }
    for name in tls_clients:
        content = (root / name).read_text(encoding="utf-8")
        if "PGSSLMODE=verify-full" not in content:
            raise ValueError(f"PostgreSQL certificate verification is missing from {name}")
        if "PGSSLROOTCERT=/run/secrets/postgres-ca.crt" not in content:
            raise ValueError(f"PostgreSQL CA path is missing from {name}")
    rauthy = (root / "rauthy.container").read_text(encoding="utf-8")
    if "PG_TLS=require" not in rauthy or "PG_TLS_NO_VERIFY=false" not in rauthy:
        raise ValueError("Rauthy PostgreSQL TLS verification is not mandatory")
    if "/secrets/rauthy/config.toml:/app/config.toml:ro" not in rauthy:
        raise ValueError("Rauthy scoped config mount is missing")
    rauthy_ready = (root / "rauthy-ready.container").read_text(encoding="utf-8")
    if "http://rauthy:8092/auth/v1/health" not in rauthy_ready:
        raise ValueError("Rauthy readiness gate is missing")
    if "rauthy-ready.container" not in (root / "control-web.container").read_text():
        raise ValueError("web does not wait for Rauthy readiness")
    odoo = (root / "odoo.container").read_text(encoding="utf-8")
    if "resolve-secret-env.sh /entrypoint.sh odoo" not in odoo:
        raise ValueError("Odoo does not resolve its scoped file secrets at runtime")
    for path in root.glob("*.container"):
        if path.name != "control-container-driver.container" and "podman.sock" in path.read_text():
            raise ValueError(f"Podman socket leaked to {path.name}")
    cloudflared = (root / "cloudflared.container").read_text(encoding="utf-8")
    if "--no-autoupdate" not in cloudflared or "--token-file /run/secrets/tunnel-token" not in cloudflared:
        raise ValueError("Cloudflare Tunnel is not pinned to a file-scoped connector token")
    if "EnvironmentFile=" in cloudflared or "postgres" in cloudflared.lower():
        raise ValueError("Cloudflare Tunnel received unrelated application configuration")
    if values["environment"] == "production" and values["data_mode"] == "personal":
        if not values.get("production_personal_data_allowed"):
            raise ValueError("personal-data activation is not approved")
        if len(values.get("privacy_activation_record", "").strip()) < 8:
            raise ValueError("personal-data activation record is missing")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate.py RENDERED_BUNDLE")
    validate(Path(sys.argv[1]))
    print("rendered rootless Podman bundle is valid")
