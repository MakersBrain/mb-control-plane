#!/usr/bin/env python3
"""Static workspace Compose and Docker namespace boundary checks."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
OVERLAY = (ROOT / "deploy/compose.workspace.yml").read_text(encoding="utf-8")
CLOUDFLARE = (ROOT / "deploy/compose.cloudflare.yml").read_text(encoding="utf-8")
CONFIGURE = (ROOT / "deploy/configure-workspace.sh").read_text(encoding="utf-8")
GATEWAY = (ROOT / "deploy/gateway.conf").read_text(encoding="utf-8")
ACCEPTANCE = (ROOT / "tools/workspace_recovery_acceptance.py").read_text(encoding="utf-8")
DRIVER = "\n".join(
    path.read_text(encoding="utf-8")
    for path in [ROOT / "src/docker_driver.rs", *sorted((ROOT / "src/docker_driver").glob("*.rs"))]
)


def main() -> int:
    for marker in (
        "WORKSPACE_DOCKER_NAMESPACE",
        "WORKSPACE_SECRET_ROOT",
        "WORKSPACE_RECOVERY_SECRET_SOURCE",
        "DRIVER_WORKSPACE_NAMESPACE",
    ):
        if marker not in COMPOSE:
            raise SystemExit(f"base Compose omits workspace parameter: {marker}")
    for marker in (
        "minio:",
        "minio-init:",
        "mb-workspace-writer",
        "mb-workspace-reader",
        "WORKSPACE_EXPORT_ROOT",
    ):
        if marker not in OVERLAY and marker not in (ROOT / "deploy/minio-init.sh").read_text():
            raise SystemExit(f"workspace profile omits local S3 marker: {marker}")
    for marker in (
        "docker_resource(",
        '"mb.workspace"',
        "DRIVER_WORKSPACE_NAMESPACE must be",
    ):
        if marker not in DRIVER:
            raise SystemExit(f"Docker driver omits workspace boundary: {marker}")
    for marker in (
        'install -m 0444 "$source"',
        'install -m 0444 "$resolved_root/recovery/BACKUP_AGE_IDENTITY"',
        'chmod 0555 "$recovery_secrets" "$public_files"',
        "WORKSPACE_SECRET_ROOT=$compose_secrets",
        "WORKSPACE_RECOVERY_SECRET_SOURCE=$recovery_secrets",
    ):
        if marker not in CONFIGURE:
            raise SystemExit(f"workspace configuration omits safe container secret view: {marker}")
    if "LISTEN_SCHEME: http_https" not in CLOUDFLARE:
        raise SystemExit("Cloudflare profile disables Rauthy's internal HTTP discovery listener")
    if "server_names_hash_bucket_size 128" not in GATEWAY:
        raise SystemExit("tenant gateway cannot represent workspace-qualified tenant hostnames")
    for marker in (
        '"HostConfig": {"NetworkMode":state.config.docker_network',
        '--role=odoo',
        '--role=\\"$PAPERLESS_DATABASE\\"',
    ):
        if marker not in DRIVER:
            raise SystemExit(f"recovery jobs omit runtime requirement: {marker}")
    for command in ("seed", "backup", "rehearse", "mutate", "restore", "verify"):
        if f'"{command}"' not in ACCEPTANCE:
            raise SystemExit(f"recovery acceptance omits command: {command}")
    print("workspace Compose and dynamic Docker resources are namespace-scoped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
