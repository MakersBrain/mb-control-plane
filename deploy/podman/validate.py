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
    workers = {
        f"control-workers@{worker}.container"
        for worker in (
            "tenant-provisioning", "membership-provisioning", "invoice-capture",
            "inventory-capture", "email-delivery", "tenant-reconciliation",
            "tenant-lifecycle", "release-adoption", "privacy-operations",
        )
    }
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
        "control-backup-scheduler.container",
        "document-extraction.container",
        "control-mail-gateway.container",
        "odoo.container",
        "rauthy.container",
        "redis.container",
        "tenant-gateway.container",
        "control-web.container",
        "vmagent.container",
        "vmagent.yml",
        "vmagent-entrypoint.sh",
        "web-nginx.conf",
        "reconcile-database-identities.sh",
        "resolve-secret-env.sh",
    } | workers
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
        for line in content.splitlines():
            if line.startswith(("Requires=", "Wants=", "After=", "Before=")):
                if any(unit.endswith(".container") for unit in line.split("=", 1)[1].split()):
                    raise ValueError(
                        f"Quadlet dependency in {path.name} must name the generated .service unit"
                    )
    driver = (root / "control-container-driver.container").read_text(encoding="utf-8")
    if "%t/podman/podman.sock:/run/podman/podman.sock" not in driver:
        raise ValueError("driver does not use the private rootless Podman socket")
    if "DRIVER_POSTGRES_CA_SOURCE=" not in driver:
        raise ValueError("driver does not declare the PostgreSQL CA source")
    identities = (root / "control-database-identities.container").read_text(
        encoding="utf-8"
    )
    if (
        "./reconcile-database-identities.sh:"
        "/run/makersbrain/reconcile-database-identities.sh:ro"
        not in identities
    ):
        raise ValueError("database identity initializer asset is not mounted")
    tls_clients = {
        "control-api.container",
        "control-backup-scheduler.container",
        "control-database-identities.container",
        "control-migrate.container",
        "odoo.container",
    }
    for name in tls_clients | workers:
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
    if "rauthy-ready.service" not in (root / "control-web.container").read_text():
        raise ValueError("web does not wait for Rauthy readiness")
    control_api = (root / "control-api.container").read_text(encoding="utf-8")
    if "rauthy-ready.service" not in control_api:
        raise ValueError("control API does not wait for Rauthy readiness")
    odoo = (root / "odoo.container").read_text(encoding="utf-8")
    if "resolve-secret-env.sh /entrypoint.sh odoo" not in odoo:
        raise ValueError("Odoo does not resolve its scoped file secrets at runtime")
    if "UserNS=keep-id:uid=100,gid=101" not in odoo:
        raise ValueError("Odoo does not map its rootless runtime identity")
    if "odoo-client-secrets.volume:/run/makersbrain-odoo-client-secrets:ro" not in odoo:
        raise ValueError("Odoo cannot authenticate tenant-scoped outbound bridge calls")
    mail = (root / "control-mail-gateway.container").read_text(encoding="utf-8")
    if (
        "MAIL_GATEWAY_ENVIRONMENT=" not in mail
        or "/secrets/control-mail-gateway:/run/secrets:ro" not in mail
        or (
            "scaleway-sns-fr-par-trust-chain.pem:"
            "/etc/makersbrain/scaleway-sns-fr-par-trust-chain.pem:ro"
        )
        not in mail
        or "podman.sock" in mail
    ):
        raise ValueError("mail gateway is not isolated and environment-scoped")
    mail_worker = root / "control-workers@email-delivery.container"
    if "Requires=control-mail-gateway.service" not in mail_worker.read_text():
        raise ValueError("email worker does not wait for the mail gateway")
    scoped_worker_markers = {
        "control-workers@membership-provisioning.container": "paperless-client-secrets.volume",
        "control-workers@invoice-capture.container": "paperless-client-secrets.volume",
        "control-workers@inventory-capture.container": "tenant-secrets.volume",
        "control-workers@tenant-reconciliation.container": "tenant-secrets.volume",
        "control-workers@privacy-operations.container": "privacy-exports.volume",
    }
    for name, marker in scoped_worker_markers.items():
        if marker not in (root / name).read_text():
            raise ValueError(f"scoped worker capability is missing from {name}")
    for path in root.glob("*.container"):
        if path.name != "control-container-driver.container" and "podman.sock" in path.read_text():
            raise ValueError(f"Podman socket leaked to {path.name}")
    for name in ("control-web.container", "tenant-gateway.container"):
        if "UserNS=keep-id:uid=101,gid=101" not in (root / name).read_text():
            raise ValueError(f"nginx runtime identity is not mapped in {name}")
    cloudflared = (root / "cloudflared.container").read_text(encoding="utf-8")
    if "--no-autoupdate" not in cloudflared or "--token-file /run/secrets/tunnel-token" not in cloudflared:
        raise ValueError("Cloudflare Tunnel is not pinned to a file-scoped connector token")
    if "UserNS=keep-id:uid=65532,gid=65532" not in cloudflared:
        raise ValueError("Cloudflare Tunnel cannot read its rootless scoped token")
    if "EnvironmentFile=" in cloudflared or "postgres" in cloudflared.lower():
        raise ValueError("Cloudflare Tunnel received unrelated application configuration")
    vmagent = (root / "vmagent.container").read_text(encoding="utf-8")
    vmagent_config = (root / "vmagent.yml").read_text(encoding="utf-8")
    expected_networks = 2 if values["environment"] == "production" else 1
    if (
        "/secrets/control-api/control_metrics_token:/run/secrets/control-metrics-token:ro"
        not in vmagent
        or "/secrets/vmagent:/run/access:ro" not in vmagent
        or "UserNS=keep-id:uid=65534,gid=65534" not in vmagent
        or "credentials_file: /run/secrets/control-metrics-token"
        not in vmagent_config
        or "/internal/metrics/live" not in vmagent_config
        or "/internal/metrics" not in vmagent_config
        or vmagent.count("Network=") != expected_networks
        or "environment: '@@" in vmagent_config
        or "-remoteWrite.forcePromProto=true" not in vmagent
        or "-remoteWrite.maxDiskUsagePerURL=512MiB" not in vmagent
    ):
        raise ValueError("vmagent does not use the isolated scrape and remote-write credentials")

    catalogue_targets = (
        "targets: [catalogue-control:8687]",
        "targets: [catalogue-service:8686]",
    )
    if values["environment"] == "production":
        if any(target not in vmagent_config for target in catalogue_targets):
            raise ValueError("production vmagent is missing catalogue scrape targets")
    elif any(target in vmagent_config for target in catalogue_targets):
        raise ValueError("staging vmagent contains unreachable catalogue scrape targets")

    cloudflared = (root / "cloudflared.container").read_text(encoding="utf-8")
    if cloudflared.count("Network=") != expected_networks or (
        values["environment"] == "production"
        and "Network=catalogue.network" not in cloudflared
    ):
        raise ValueError("cloudflared does not join the required runtime networks")
    if "UserNS=keep-id:uid=999,gid=1000" not in (
        root / "redis.container"
    ).read_text(encoding="utf-8"):
        raise ValueError("Redis does not run as its rootless image identity")
    driver = (root / "control-container-driver.container").read_text(encoding="utf-8")
    if "/postgres-ca.crt:/run/secrets/postgres-ca.crt:ro" not in driver:
        raise ValueError("deployment driver has no mounted PostgreSQL CA")
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
