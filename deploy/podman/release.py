#!/usr/bin/env python3
"""Verify and atomically activate one rootless Podman release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import render
import validate


RELEASE_ID = re.compile(r"^control-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{16,64}$")
COMMIT = re.compile(r"^[a-f0-9]{40,64}$")
SOURCE_REF = re.compile(r"^refs/(heads|tags)/[^\s]+$")
QUALIFICATION_REF = re.compile(r"^\S+/qualifications@sha256:[a-f0-9]{64}$")
COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_IDENTITY = (
    "https://github.com/MakersBrain/odoo/"
    ".github/workflows/release.yml@refs/heads/main"
)
PERSISTENT_UNITS = [
    "cloudflared.service",
    "redis.service",
    "odoo.service",
    "rauthy.service",
    "tenant-gateway.service",
    "control-api.service",
    "control-web.service",
    "document-extraction.service",
    "control-mail-gateway.service",
    "control-container-driver.service",
    "control-backup-scheduler.service",
    "vmagent.service",
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
UNIT_PROCESS = {
    "control-migrate.container": "migration",
    "control-api.container": "api",
    "control-container-driver.container": "docker_driver",
    "document-extraction.container": "document_extraction_broker",
    "control-mail-gateway.container": "mail_gateway",
    "control-backup-scheduler.container": "backup_scheduler",
}
WORKER_PROCESS = {
    "tenant-provisioning": "provisioning_worker",
    "membership-provisioning": "membership_worker",
    "invoice-capture": "invoice_worker",
    "inventory-capture": "inventory_worker",
    "email-delivery": "email_worker",
    "tenant-reconciliation": "reconciliation_worker",
    "tenant-lifecycle": "lifecycle_worker",
    "release-adoption": "release_worker",
    "privacy-operations": "privacy_worker",
}
VENDOR_REQUIRED_ENVIRONMENT = {
    "odoo.container": {"PASSWORD", "MB_CONTROL_BRIDGE_TOKEN", "MB_CONTROL_API_URL"},
    "rauthy.container": {
        "HIQLITE", "PG_HOST", "PG_PORT", "PG_USER", "PG_DB_NAME", "HQL_NODE_ID",
        "HQL_NODES", "LISTEN_ADDRESS", "LISTEN_PORT_HTTP", "LISTEN_SCHEME", "PUB_URL",
        "BOOTSTRAP_DIR", "ENC_KEY_ACTIVE", "RP_ID", "RP_ORIGIN", "RP_NAME",
    },
    "control-database-identities.container": {
        "POSTGRES_SUPERUSER_PASSWORD", "CONTROL_API_POSTGRES_PASSWORD",
        "CONTROL_MEMBERSHIP_POSTGRES_PASSWORD", "CONTROL_PROVISIONING_POSTGRES_PASSWORD",
        "CONTROL_INVOICE_POSTGRES_PASSWORD", "CONTROL_INVENTORY_POSTGRES_PASSWORD",
        "CONTROL_EMAIL_POSTGRES_PASSWORD", "CONTROL_RECONCILIATION_POSTGRES_PASSWORD",
        "CONTROL_LIFECYCLE_POSTGRES_PASSWORD", "CONTROL_BACKUP_POSTGRES_PASSWORD",
        "CONTROL_DRIVER_POSTGRES_PASSWORD", "CONTROL_RELEASE_POSTGRES_PASSWORD",
        "CONTROL_PRIVACY_POSTGRES_PASSWORD",
    },
}

WRITABLE_STATE_FILES = {
    "MAIL_GATEWAY_EVENT_JOURNAL_FILE": Path(
        "/var/lib/makersbrain/mail-events/events.jsonl"
    ),
}

PINNED_RELEASE_FILES = {
    "MAIL_GATEWAY_SNS_TRUST_CHAIN_FILE": Path(
        "/etc/makersbrain/scaleway-sns-fr-par-trust-chain.pem"
    ),
}


def file_secret_value(name: str) -> bool:
    return (
        name.endswith(("DATABASE_URL", "_TOKEN", "_PASSWORD"))
        or (name.endswith("_KEY") and not name.endswith("_KEY_ID"))
        or name in {"PASSWORD", "POSTGRES_SUPERUSER_PASSWORD"}
    )


def load_release(path: Path, values: dict) -> dict:
    record = json.loads(path.read_text(encoding="utf-8"))
    if not RELEASE_ID.fullmatch(record.get("release_id", "")):
        raise ValueError("release_id is invalid")
    if not COMMIT.fullmatch(record.get("source_commit", "")):
        raise ValueError("source_commit is invalid")
    if not SOURCE_REF.fullmatch(record.get("source_ref", "")):
        raise ValueError("source_ref is invalid")
    if not record.get("ci_run_url", "").startswith("https://"):
        raise ValueError("ci_run_url must be HTTPS")
    if record.get("images") != values["images"]:
        raise ValueError("release record images differ from rendered values")
    if values["environment"] == "production":
        qualification = record.get("staging_qualification_ref", "").strip()
        if not QUALIFICATION_REF.fullmatch(qualification):
            raise ValueError("production requires an immutable staging qualification artifact")
    return record


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def verify_and_pull(images: dict[str, str], verify_keyless: bool) -> None:
    for name in sorted(images):
        image = images[name]
        if verify_keyless:
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


def verify_runtime_secrets(values: dict, config_root: Path) -> None:
    secret_root = Path(values["runtime_secret_source"])
    recovery_root = Path(values["recovery_secret_source"])
    if recovery_root == secret_root:
        raise ValueError("runtime and recovery secret roots must be distinct")
    protected_path(recovery_root, directory=True)
    protected_path(recovery_root / "age-identity.txt", directory=False)
    postgres_ca = secret_root / "postgres-ca.crt"
    if not postgres_ca.is_file() or postgres_ca.is_symlink():
        raise ValueError(
            f"PostgreSQL CA must be a regular, non-symlink file: {postgres_ca}"
        )
    rauthy_config = config_root / "secrets/rauthy/config.toml"
    protected_path(rauthy_config, directory=False)
    config_text = rauthy_config.read_text(encoding="utf-8")
    configured_ca = re.search(
        r"pg_tls_root_ca\s*=\s*\"\"\"(.*?)\"\"\"", config_text, re.DOTALL
    )
    ca_text = postgres_ca.read_text(encoding="utf-8")
    certificates = re.compile(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
    )
    configured_certificates = certificates.findall(
        configured_ca.group(1) if configured_ca else ""
    )
    host_certificates = certificates.findall(ca_text)
    if not configured_certificates or configured_certificates != host_certificates:
        raise ValueError("Rauthy pg_tls_root_ca must contain the exact PostgreSQL CA PEM")
    if not re.search(r"^pg_password\s*=\s*.+$", config_text, re.MULTILINE):
        raise ValueError("Rauthy config is missing its scoped PostgreSQL credential")
    tunnel_token = config_root / "secrets/cloudflared/tunnel-token"
    if not tunnel_token.is_file() or tunnel_token.is_symlink():
        raise ValueError(
            f"Cloudflare Tunnel token must be a regular, non-symlink file: {tunnel_token}"
        )
    if tunnel_token.stat().st_mode & 0o077:
        raise ValueError("Cloudflare Tunnel token must not be accessible by group or others")
    verify_observability_secrets(config_root)


def verify_observability_secrets(config_root: Path) -> None:
    """Check the credentials vmagent reads off disk."""
    metrics_token = config_root / "secrets/control-api/control_metrics_token"
    protected_path(metrics_token, directory=False)
    metrics_value = read_secret_line(metrics_token)
    if not 32 <= len(metrics_value) <= 512 or any(
        character in metrics_value for character in "\r\n\0"
    ):
        raise ValueError("vmagent metrics token must be a bounded single-line secret")
    access_client_id = config_root / "secrets/vmagent/access-client-id"
    access_client_secret = config_root / "secrets/vmagent/access-client-secret"
    protected_path(access_client_id, directory=False)
    protected_path(access_client_secret, directory=False)
    access_id_value = read_secret_line(access_client_id)
    access_secret_value = read_secret_line(access_client_secret)
    if not re.fullmatch(r"[0-9a-f]{32}\.access", access_id_value):
        raise ValueError("vmagent Access client ID is invalid")
    if not 32 <= len(access_secret_value) <= 512 or any(
        character in access_secret_value for character in "\r\n\0"
    ):
        raise ValueError("vmagent Access client secret must be bounded")


def read_secret_line(path: Path) -> str:
    """Read a one-line secret, tolerating the trailing newline files normally carry.

    Prometheus and Alertmanager trim it when they read these files, so rejecting
    it here would block a deployment that works.
    """
    value = path.read_text(encoding="utf-8")
    if value.endswith("\n"):
        value = value[:-1]
    if value.endswith("\r"):
        value = value[:-1]
    return value


def protected_path(path: Path, *, directory: bool, public: bool = False) -> None:
    valid = path.is_dir() if directory else path.is_file()
    if not valid or path.is_symlink():
        kind = "directory" if directory else "file"
        raise ValueError(f"required host {kind} is missing or unsafe: {path}")
    if not public and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"protected host path is accessible by group or others: {path}")


def configured_host_path(raw: str, config_root: Path) -> Path:
    path = Path(raw)
    try:
        relative = path.relative_to("/etc/makersbrain")
    except ValueError:
        return path
    return config_root / relative


def unit_instances(name: str) -> tuple[str, ...]:
    match = re.fullmatch(r"control-workers@([a-z-]+)\.container", name)
    return (match.group(1),) if match else ("",)


def verify_mounted_file(
    secret: Path,
    setting: str,
    mounts: list[tuple[Path, Path, bool]],
) -> None:
    if not secret.is_absolute() or not str(secret).startswith("/run/"):
        raise ValueError(f"{setting} must name a scoped runtime file")
    matches = [
        mount
        for mount in mounts
        if secret == mount[0] or mount[0] in secret.parents
    ]
    if not matches:
        raise ValueError(f"{setting} has no scoped secret mount")
    target, host, source_is_file = max(
        matches, key=lambda mount: len(mount[0].parts)
    )
    if source_is_file:
        resolved = host
    else:
        relative = secret.relative_to(target)
        if ".." in relative.parts:
            raise ValueError(f"{setting} escapes its scoped secret mount")
        resolved = host / relative
    protected_path(resolved, directory=False)


def verify_host_configuration(rendered: Path, config_root: Path) -> None:
    specification = json.loads(
        (Path(__file__).resolve().parents[1] / "configuration-spec.json").read_text(
            encoding="utf-8"
        )
    )
    required_by_process = specification["required_environment"]
    for unit in sorted(rendered.glob("*.container")):
        lines = unit.read_text(encoding="utf-8").splitlines()
        for instance in unit_instances(unit.name):
            environment_names = {
                line.removeprefix("Environment=").split("=", 1)[0]
                for line in lines
                if line.startswith("Environment=") and "=" in line.removeprefix("Environment=")
            }
            mounts: list[tuple[Path, Path, bool]] = []
            for line in lines:
                if not line.startswith("Volume="):
                    continue
                value = line.removeprefix("Volume=").replace("%i", instance)
                source, separator, remainder = value.partition(":")
                if not separator:
                    raise ValueError(f"invalid Volume entry in {unit.name}")
                target = remainder.partition(":")[0]
                if not source.startswith("/") or source.startswith("%t/"):
                    continue
                host = configured_host_path(source, config_root)
                target_path = Path(target)
                source_is_file = host.is_file() and not host.is_symlink()
                public = host.name == "postgres-ca.crt"
                protected_path(host, directory=not source_is_file, public=public)
                mounts.append((target_path, host, source_is_file))

            for line in lines:
                if not line.startswith("EnvironmentFile="):
                    continue
                raw = line.removeprefix("EnvironmentFile=").replace("%i", instance)
                environment_file = configured_host_path(raw, config_root)
                protected_path(environment_file, directory=False)
                seen: set[str] = set()
                for environment_line in environment_file.read_text(encoding="utf-8").splitlines():
                    stripped = environment_line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    name, value = stripped.split("=", 1)
                    if name in seen:
                        raise ValueError(f"duplicate {name} in {environment_file}")
                    seen.add(name)
                    environment_names.add(name)
                    reference = value.strip().strip('"').strip("'")
                    if name in WRITABLE_STATE_FILES:
                        if Path(reference) != WRITABLE_STATE_FILES[name]:
                            raise ValueError(
                                f"{name} in {environment_file} must use its approved state path"
                            )
                        continue
                    if name in PINNED_RELEASE_FILES:
                        if Path(reference) != PINNED_RELEASE_FILES[name]:
                            raise ValueError(
                                f"{name} in {environment_file} must use its approved release path"
                            )
                        asset = rendered / Path(reference).name
                        if not asset.is_file() or asset.is_symlink():
                            raise ValueError(f"immutable release asset is missing: {asset.name}")
                        continue
                    if file_secret_value(name) and not reference.startswith("@/run/"):
                        raise ValueError(
                            f"{name} in {environment_file} must use a scoped file secret"
                        )
                    if reference.startswith("@/run/"):
                        verify_mounted_file(
                            Path(reference[1:]), f"{name} in {environment_file}", mounts
                        )
                    elif name.endswith("_FILE"):
                        verify_mounted_file(
                            Path(reference), f"{name} in {environment_file}", mounts
                        )
            process = UNIT_PROCESS.get(unit.name)
            if unit.name.startswith("control-workers@"):
                process = WORKER_PROCESS.get(instance)
                if process is None:
                    raise ValueError(f"unknown worker instance in release contract: {instance}")
            required = set(required_by_process.get(process, [])) if process else set()
            required.update(VENDOR_REQUIRED_ENVIRONMENT.get(unit.name, set()))
            missing = required - environment_names
            if missing:
                identity = f"{unit.name}:{instance}" if instance else unit.name
                raise ValueError(
                    f"host configuration for {identity} omits required settings: {sorted(missing)}"
                )


def stage(
    rendered: Path,
    release_id: str,
    state_root: Path,
) -> None:
    releases = state_root / "releases"
    release_root = releases / release_id
    if release_root.exists():
        raise ValueError("release has already been staged")
    releases.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(rendered, release_root)
    for path in release_root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        else:
            source_mode = stat.S_IMODE((rendered / path.relative_to(release_root)).stat().st_mode)
            path.chmod(0o555 if source_mode & 0o111 else 0o644)


def tree_digest(root: Path) -> str:
    """Content digest of a rendered or staged bundle, over relative paths and bytes."""
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def start_staged(
    release_id: str,
    state_root: Path,
    quadlet_root: Path | None = None,
    rendered: Path | None = None,
) -> None:
    quadlet_root = quadlet_root or Path.home() / ".config/containers/systemd"
    release_root = state_root / "releases" / release_id
    if not release_root.is_dir():
        raise ValueError("requested release has not been staged")
    # Everything verified above was rendered fresh from --values; what gets
    # activated is whatever was staged earlier. If the values moved while the
    # release id did not, those are two different bundles.
    if rendered is not None and tree_digest(rendered) != tree_digest(release_root):
        raise ValueError(
            "staged release does not match the bundle rendered from --values: "
            "re-stage under a new release id"
        )
    quadlet_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    current = quadlet_root / "makersbrain"
    previous = os.readlink(current) if current.is_symlink() else None
    temporary = quadlet_root / f".makersbrain-{release_id}"
    os.symlink(release_root, temporary, target_is_directory=True)
    os.replace(temporary, current)
    try:
        run(["systemctl", "--user", "daemon-reload"])
        # Quadlet services are generated units. Their WantedBy relationships
        # come from the source files' [Install] sections, and systemd refuses
        # `enable` for generated units. Reload the generator output, then start
        # the persistent set explicitly for this activation.
        # `start` is a no-op for an already-running generated unit, leaving its
        # old image and command alive after the symlink switch. Restart is the
        # actual release boundary and also pulls in the one-shot migration and
        # initialization dependencies of the new generation.
        run(["systemctl", "--user", "restart", *PERSISTENT_UNITS])
    except Exception:
        current.unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
        if previous is not None:
            os.symlink(previous, current, target_is_directory=True)
            run(["systemctl", "--user", "daemon-reload"])
            run(["systemctl", "--user", "restart", *PERSISTENT_UNITS])
        raise


def activate(
    rendered: Path,
    release_id: str,
    state_root: Path,
    quadlet_root: Path | None = None,
) -> None:
    stage(rendered, release_id, state_root)
    start_staged(release_id, state_root, quadlet_root, rendered)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--release-record", type=Path, required=True)
    parser.add_argument(
        "--state-root", type=Path, default=Path.home() / ".local/state/makersbrain"
    )
    parser.add_argument(
        "--quadlet-root",
        type=Path,
        default=Path.home() / ".config/containers/systemd",
    )
    parser.add_argument("--config-root", type=Path, default=Path("/etc/makersbrain"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--activate", action="store_true")
    mode.add_argument("--stage-only", action="store_true")
    mode.add_argument("--start-staged", action="store_true")
    args = parser.parse_args()

    values = render.load_values(args.values)
    record = load_release(args.release_record, values)
    with tempfile.TemporaryDirectory(prefix="makersbrain-release-") as temporary:
        rendered = Path(temporary)
        render.render(args.values, rendered)
        validate.validate(rendered)
        changes_host = args.activate or args.stage_only or args.start_staged
        if changes_host:
            verify_runtime_secrets(values, args.config_root)
            verify_host_configuration(rendered, args.config_root)
        verify_and_pull(
            values["images"], verify_keyless=values["environment"] == "production"
        )
        if args.activate:
            activate(rendered, record["release_id"], args.state_root, args.quadlet_root)
        elif args.stage_only:
            stage(rendered, record["release_id"], args.state_root)
        elif args.start_staged:
            start_staged(record["release_id"], args.state_root, args.quadlet_root, rendered)
        else:
            print("release image digests, record and Quadlets are valid")


if __name__ == "__main__":
    main()
