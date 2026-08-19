#!/usr/bin/env python3
"""Render the immutable rootless Podman Quadlet bundle."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
IMAGE = re.compile(r"^[^\s]+@sha256:[a-f0-9]{64}$")
NETWORK = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
WORKERS = (
    "tenant-provisioning",
    "membership-provisioning",
    "invoice-capture",
    "inventory-capture",
    "email-delivery",
    "tenant-reconciliation",
    "tenant-lifecycle",
    "release-adoption",
    "privacy-operations",
)


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
    recovery_source = Path(values.get("recovery_secret_source", ""))
    if not recovery_source.is_absolute() or recovery_source == Path("/"):
        raise ValueError("recovery_secret_source must be a narrow absolute path")
    if recovery_source == secret_source:
        raise ValueError("runtime and recovery secret sources must be distinct")
    required_images = {
        "control", "web", "odoo", "rauthy", "redis", "nginx", "alpine", "postgres",
        "paperless", "backup", "cloudflared", "vmagent"
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
    remote_write = urlsplit(values.get("metrics_remote_write_url", ""))
    if (
        remote_write.scheme != "https"
        or not remote_write.hostname
        or remote_write.username
        or remote_write.password
        or remote_write.port not in (None, 443)
        or remote_write.path != "/api/v1/write"
        or remote_write.query
        or remote_write.fragment
    ):
        raise ValueError(
            "metrics_remote_write_url must be an exact HTTPS /api/v1/write endpoint"
        )
    return values


def replacements(values: dict) -> dict[str, str]:
    result = {
        "ENVIRONMENT": values["environment"],
        "DATA_MODE": values["data_mode"],
        "RUNTIME_NETWORK": values["runtime_network"],
        "RUNTIME_SECRET_SOURCE": values["runtime_secret_source"],
        "RECOVERY_SECRET_SOURCE": values["recovery_secret_source"],
        "PUBLIC_BIND_IP": values["public_bind_ip"],
        "POSTGRES_HOST": values["postgres_host"],
        "METRICS_REMOTE_WRITE_URL": values["metrics_remote_write_url"],
        "CATALOGUE_NETWORK": (
            "Network=catalogue.network"
            if values["environment"] == "production"
            else ""
        ),
    }
    result.update({f"{name.upper()}_IMAGE": value for name, value in values["images"].items()})
    return result


def render(values_path: Path, output: Path) -> None:
    values = load_values(values_path)
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    tokens = replacements(values)

    def rendered(content: str, name: str) -> str:
        for key, value in tokens.items():
            content = content.replace(f"@@{key}@@", value)
        if "@@" in content:
            raise ValueError(f"unresolved template value in {name}")
        return content

    for source_root in (HERE / "quadlets", HERE / "systemd", HERE / "assets"):
        for source in sorted(path for path in source_root.rglob("*") if path.is_file()):
            relative = source.relative_to(source_root)
            if any(part.endswith(".container.d") for part in relative.parts):
                continue
            if source.name == "control-workers@.container":
                base = source.read_text(encoding="utf-8")
                for worker in WORKERS:
                    content = base
                    dropin = source_root / f"control-workers@{worker}.container.d"
                    for fragment in sorted(dropin.glob("*.conf")):
                        content += "\n" + fragment.read_text(encoding="utf-8")
                    target = output / f"control-workers@{worker}.container"
                    target.write_text(rendered(content, target.name), encoding="utf-8")
                    target.chmod(0o644)
                continue
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            content = rendered(source.read_text(encoding="utf-8"), source.name)
            target.write_text(content, encoding="utf-8")
            target.chmod(0o555 if target.name == "vmagent-entrypoint.sh" else 0o644)
    shutil.copy2(values_path, output / "rendered-values.json")
    (output / "rendered-values.json").chmod(0o600)
    shutil.copy2(HERE.parent / "resolve-secret-env.sh", output / "resolve-secret-env.sh")
    (output / "resolve-secret-env.sh").chmod(0o555)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render(args.values, args.output)


if __name__ == "__main__":
    main()
