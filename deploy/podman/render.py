#!/usr/bin/env python3
"""Render the immutable rootless Podman Quadlet bundle."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGE = re.compile(r"^[^\s]+@sha256:[a-f0-9]{64}$")
NETWORK = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def load_values(path: Path) -> dict:
    values = json.loads(path.read_text(encoding="utf-8"))
    if values.get("environment") not in {"staging", "production"}:
        raise ValueError("environment must be staging or production")
    if values.get("data_mode") not in {"synthetic", "personal"}:
        raise ValueError("data_mode must be synthetic or personal")
    if values["environment"] == "staging" and values["data_mode"] != "synthetic":
        raise ValueError("staging is synthetic-only")
    personal = values["data_mode"] == "personal"
    if personal and values["environment"] != "production":
        raise ValueError("personal data is production-only")
    if personal and not values.get("production_personal_data_allowed", False):
        raise ValueError("production personal-data activation is not approved")
    if personal and len(values.get("privacy_activation_record", "").strip()) < 8:
        raise ValueError("an external privacy activation record is required")
    if not NETWORK.fullmatch(values.get("runtime_network", "")):
        raise ValueError("runtime_network is invalid")
    secret_source = Path(values.get("runtime_secret_source", ""))
    if not secret_source.is_absolute() or secret_source == Path("/"):
        raise ValueError("runtime_secret_source must be a narrow absolute path")
    required_images = {
        "control", "web", "odoo", "rauthy", "redis", "nginx", "alpine", "postgres",
        "paperless", "backup", "cloudflared"
    }
    images = values.get("images", {})
    if set(images) != required_images:
        raise ValueError(f"images must contain exactly: {', '.join(sorted(required_images))}")
    for name, reference in images.items():
        if not IMAGE.fullmatch(reference):
            raise ValueError(f"image {name} is not pinned by digest")
    bind_ip = values.get("public_bind_ip", "")
    if bind_ip not in {"127.0.0.1", "::1"}:
        raise ValueError("public services must bind to a loopback edge origin")
    if not HOST.fullmatch(values.get("postgres_host", "")):
        raise ValueError("postgres_host is invalid")
    return values


def replacements(values: dict) -> dict[str, str]:
    result = {
        "ENVIRONMENT": values["environment"],
        "DATA_MODE": values["data_mode"],
        "RUNTIME_NETWORK": values["runtime_network"],
        "RUNTIME_SECRET_SOURCE": values["runtime_secret_source"],
        "PUBLIC_BIND_IP": values["public_bind_ip"],
        "POSTGRES_HOST": values["postgres_host"],
    }
    result.update({f"{name.upper()}_IMAGE": value for name, value in values["images"].items()})
    return result


def render(values_path: Path, output: Path) -> None:
    values = load_values(values_path)
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    tokens = replacements(values)
    for source_root in (HERE / "quadlets", HERE / "systemd", HERE / "assets"):
        for source in sorted(path for path in source_root.rglob("*") if path.is_file()):
            target = output / source.relative_to(source_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = source.read_text(encoding="utf-8")
            for key, value in tokens.items():
                content = content.replace(f"@@{key}@@", value)
            if "@@" in content:
                raise ValueError(f"unresolved template value in {source.name}")
            target.write_text(content, encoding="utf-8")
            target.chmod(0o644)
    shutil.copy2(values_path, output / "rendered-values.json")
    (output / "rendered-values.json").chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render(args.values, args.output)


if __name__ == "__main__":
    main()
