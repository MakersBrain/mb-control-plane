#!/usr/bin/env python3
"""Validate a rendered MakersBrain PostgreSQL host bundle."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


IMAGE = re.compile(r"^Image=\S+@sha256:[a-f0-9]{64}$", re.MULTILINE)


def validate(root: Path) -> None:
    expected = {"postgres.container", "pg_hba.conf", "init-databases.sh", "rendered-values.json"}
    missing = expected - {path.name for path in root.iterdir()}
    if missing:
        raise ValueError(f"database bundle is incomplete: {', '.join(sorted(missing))}")
    unit = (root / "postgres.container").read_text(encoding="utf-8")
    hba = (root / "pg_hba.conf").read_text(encoding="utf-8")
    values = json.loads((root / "rendered-values.json").read_text(encoding="utf-8"))
    if not IMAGE.search(unit):
        raise ValueError("PostgreSQL image is not digest-pinned")
    if "docker.sock" in unit or "podman.sock" in unit or "tcp://" in unit:
        raise ValueError("database unit contains a forbidden runtime socket")
    if "ssl=on" not in unit or "postgres_tls_private_key" not in unit:
        raise ValueError("database TLS is not fail-closed")
    if f"hostssl all all {values['app_subnet_cidr']} scram-sha-256" not in hba:
        raise ValueError("pg_hba does not restrict clients to the application subnet")
    if "hostnossl all all 0.0.0.0/0 reject" not in hba:
        raise ValueError("unencrypted PostgreSQL clients are not rejected")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate.py RENDERED_DATABASE_BUNDLE")
    validate(Path(sys.argv[1]))
    print("rendered rootless PostgreSQL bundle is valid")
