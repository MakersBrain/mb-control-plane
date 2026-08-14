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
        "control-database-identities.container",
        "control-migrate.container",
        "privacy-export-init.container",
        "rauthy-bootstrap.container",
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
    for path in root.glob("*.container"):
        if path.name != "control-container-driver.container" and "podman.sock" in path.read_text():
            raise ValueError(f"Podman socket leaked to {path.name}")
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
