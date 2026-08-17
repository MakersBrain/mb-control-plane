#!/usr/bin/env python3
"""Build the exact process-owned secret tree from a canonical manager export."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import quote

import materialize


PROCESS_DIR = {
    "control-migrate": "control-migrate",
    "control-api": "control-api",
    "document-extraction": "document-extraction",
    "docker-driver": "control-container-driver",
    "worker-membership": "control-worker-membership-provisioning",
    "worker-provisioning": "control-worker-tenant-provisioning",
    "worker-invoice": "control-worker-invoice-capture",
    "worker-inventory": "control-worker-inventory-capture",
    "worker-email": "control-worker-email-delivery",
    "worker-reconciliation": "control-worker-tenant-reconciliation",
    "worker-lifecycle": "control-worker-tenant-lifecycle",
    "worker-release": "control-worker-release-adoption",
    "worker-privacy": "control-worker-privacy-operations",
    "backup-scheduler": "control-backup-scheduler",
    "control-mail-gateway": "control-mail-gateway",
    "odoo": "odoo",
    "control-database-identities": "database-identities",
}

DATABASE_ROLES = {
    "control-migrate": ("CONTROL_POSTGRES_PASSWORD", "control", "control_database_url"),
    "control-api": ("CONTROL_API_POSTGRES_PASSWORD", "control_api", "control_api_database_url"),
    "worker-membership": ("CONTROL_MEMBERSHIP_POSTGRES_PASSWORD", "control_membership_worker", "control_membership_database_url"),
    "worker-provisioning": ("CONTROL_PROVISIONING_POSTGRES_PASSWORD", "control_provisioning_worker", "control_provisioning_database_url"),
    "worker-invoice": ("CONTROL_INVOICE_POSTGRES_PASSWORD", "control_invoice_worker", "control_invoice_database_url"),
    "worker-inventory": ("CONTROL_INVENTORY_POSTGRES_PASSWORD", "control_inventory_worker", "control_inventory_database_url"),
    "worker-email": ("CONTROL_EMAIL_POSTGRES_PASSWORD", "control_email_worker", "control_email_database_url"),
    "worker-reconciliation": ("CONTROL_RECONCILIATION_POSTGRES_PASSWORD", "control_reconciliation_worker", "control_reconciliation_database_url"),
    "worker-lifecycle": ("CONTROL_LIFECYCLE_POSTGRES_PASSWORD", "control_lifecycle_worker", "control_lifecycle_database_url"),
    "backup-scheduler": ("CONTROL_BACKUP_POSTGRES_PASSWORD", "control_backup_scheduler", "control_backup_database_url"),
    "docker-driver": ("CONTROL_DRIVER_POSTGRES_PASSWORD", "control_driver_ledger", "control_driver_database_url"),
    "worker-release": ("CONTROL_RELEASE_POSTGRES_PASSWORD", "control_release_worker", "control_release_database_url"),
    "worker-privacy": ("CONTROL_PRIVACY_POSTGRES_PASSWORD", "control_privacy_worker", "control_privacy_database_url"),
}

DATABASE_IDENTITY_NAMES = (
    "POSTGRES_SUPERUSER_PASSWORD",
    "CONTROL_API_POSTGRES_PASSWORD",
    "CONTROL_MEMBERSHIP_POSTGRES_PASSWORD",
    "CONTROL_PROVISIONING_POSTGRES_PASSWORD",
    "CONTROL_INVOICE_POSTGRES_PASSWORD",
    "CONTROL_INVENTORY_POSTGRES_PASSWORD",
    "CONTROL_EMAIL_POSTGRES_PASSWORD",
    "CONTROL_RECONCILIATION_POSTGRES_PASSWORD",
    "CONTROL_LIFECYCLE_POSTGRES_PASSWORD",
    "CONTROL_BACKUP_POSTGRES_PASSWORD",
    "CONTROL_DRIVER_POSTGRES_PASSWORD",
    "CONTROL_RELEASE_POSTGRES_PASSWORD",
    "CONTROL_PRIVACY_POSTGRES_PASSWORD",
)

DIRECT = (
    ("application/CONTROL_INTERNAL_TOKEN", "control-api", "CONTROL_INTERNAL_TOKEN", "control_internal_token"),
    ("observability/CONTROL_METRICS_TOKEN", "control-api", "CONTROL_METRICS_TOKEN", "control_metrics_token"),
    ("application/CONTROL_MAIL_EVENT_TOKEN", "control-api", "CONTROL_MAIL_EVENT_TOKEN", "control_mail_event_token"),
    ("application/CONTROL_RELEASE_PUBLISH_TOKEN", "control-api", "CONTROL_RELEASE_PUBLISH_TOKEN", "control_release_publish_token"),
    ("application/DOCUMENT_EXTRACTION_TOKEN", "control-api", "CONTROL_EXTRACTION_BROKER_TOKEN", "document_extraction_token"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "control-api", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "deployment_driver_token"),
    ("application/CONTROL_PRIVACY_EXPORT_KEY", "control-api", "CONTROL_PRIVACY_EXPORT_KEY", "control_privacy_export_key"),
    ("application/DOCUMENT_EXTRACTION_TOKEN", "document-extraction", "BROKER_TOKEN", "document_extraction_token"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "docker-driver", "DRIVER_TOKEN", "deployment_driver_token"),
    ("application/PRIVACY_DRIVER_TOKEN", "docker-driver", "DRIVER_PRIVACY_TOKEN", "privacy_driver_token"),
    ("database/ODOO_POSTGRES_PASSWORD", "docker-driver", "DRIVER_ODOO_POSTGRES_PASSWORD", "odoo_postgres_password"),
    ("application/ODOO_BRIDGE_TOKEN", "docker-driver", "DRIVER_ODOO_BRIDGE_TOKEN", "odoo_bridge_token"),
    ("application/CONTROL_RAUTHY_DEPLOYMENT_KEY", "docker-driver", "DRIVER_RAUTHY_ADMIN_KEY", "control_rauthy_deployment_key"),
    ("application/CONTROL_RAUTHY_ADMIN_KEY", "worker-membership", "CONTROL_RAUTHY_ADMIN_KEY", "control_rauthy_admin_key"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "worker-provisioning", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "deployment_driver_token"),
    ("application/DOCUMENT_EXTRACTION_TOKEN", "worker-invoice", "CONTROL_EXTRACTION_BROKER_TOKEN", "document_extraction_token"),
    ("application/DOCUMENT_EXTRACTION_TOKEN", "worker-inventory", "CONTROL_EXTRACTION_BROKER_TOKEN", "document_extraction_token"),
    ("application/MAIL_WEBHOOK_TOKEN", "worker-email", "CONTROL_MAIL_WEBHOOK_TOKEN", "mail_webhook_token"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "worker-reconciliation", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "deployment_driver_token"),
    ("reconciliation/CONTROL_CLOUDFLARE_API_TOKEN", "worker-reconciliation", "CONTROL_CLOUDFLARE_API_TOKEN", "control_cloudflare_api_token"),
    ("reconciliation/CONTROL_MAIL_SCW_SECRET_KEY", "worker-reconciliation", "CONTROL_MAIL_SCW_SECRET_KEY", "control_mail_scw_secret_key"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "worker-lifecycle", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "deployment_driver_token"),
    ("application/CONTROL_PRIVACY_LOOKUP_KEY", "worker-lifecycle", "CONTROL_PRIVACY_LOOKUP_KEY", "control_privacy_lookup_key"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "worker-release", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "deployment_driver_token"),
    ("application/CONTROL_PRIVACY_LOOKUP_KEY", "worker-privacy", "CONTROL_PRIVACY_LOOKUP_KEY", "control_privacy_lookup_key"),
    ("application/CONTROL_PRIVACY_EXPORT_KEY", "worker-privacy", "CONTROL_PRIVACY_EXPORT_KEY", "control_privacy_export_key"),
    ("application/PRIVACY_DRIVER_TOKEN", "worker-privacy", "CONTROL_PRIVACY_DRIVER_TOKEN", "privacy_driver_token"),
    ("application/DEPLOYMENT_DRIVER_TOKEN", "backup-scheduler", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "deployment_driver_token"),
    ("database/ODOO_POSTGRES_PASSWORD", "odoo", "PASSWORD", "odoo_postgres_password"),
    ("application/ODOO_BRIDGE_TOKEN", "odoo", "MB_CONTROL_BRIDGE_TOKEN", "odoo_bridge_token"),
    ("application/MAIL_WEBHOOK_TOKEN", "control-mail-gateway", "MAIL_GATEWAY_INTERNAL_TOKEN", "mail_webhook_token"),
    ("mail/SCW_TEM_SECRET_KEY", "control-mail-gateway", "MAIL_GATEWAY_SCW_SECRET_KEY", "scaleway_tem_secret_key"),
    ("application/CONTROL_MAIL_EVENT_TOKEN", "control-mail-gateway", "MAIL_GATEWAY_CONTROL_EVENT_TOKEN", "control_mail_event_token"),
)

OPTIONAL_PROVIDERS = (
    ("document-extraction/AZURE_DOCUMENT_KEY", "document-extraction", "BROKER_AZURE_KEY", "azure_document_key"),
    ("document-extraction/INVENTORY_OPENAI_KEY", "document-extraction", "BROKER_OPENAI_KEY", "inventory_openai_key"),
    ("document-extraction/INVENTORY_AZURE_MULTIMODAL_KEY", "document-extraction", "BROKER_AZURE_MULTIMODAL_KEY", "inventory_azure_multimodal_key"),
    ("document-extraction/INVENTORY_GEMINI_KEY", "document-extraction", "BROKER_GEMINI_KEY", "inventory_gemini_key"),
    ("document-extraction/INVENTORY_CLAUDE_KEY", "document-extraction", "BROKER_CLAUDE_KEY", "inventory_claude_key"),
    ("document-extraction/INVENTORY_VISION_KEY", "document-extraction", "BROKER_VISION_KEY", "inventory_vision_key"),
    ("document-extraction/INVENTORY_UPCITEMDB_KEY", "document-extraction", "BROKER_UPCITEMDB_KEY", "inventory_upcitemdb_key"),
)

BACKUP = (
    ("backup/BACKUP_S3_ACCESS_KEY_ID", "BACKUP_S3_ACCESS_KEY_ID", "backup_s3_access_key_id"),
    ("backup/BACKUP_S3_SECRET_ACCESS_KEY", "BACKUP_S3_SECRET_ACCESS_KEY", "backup_s3_secret_access_key"),
    ("backup/RESTORE_S3_ACCESS_KEY_ID", "RESTORE_S3_ACCESS_KEY_ID", "restore_s3_access_key_id"),
    ("backup/RESTORE_S3_SECRET_ACCESS_KEY", "RESTORE_S3_SECRET_ACCESS_KEY", "restore_s3_secret_access_key"),
    ("backup/BACKUP_AGE_RECIPIENT", "BACKUP_AGE_RECIPIENT", "backup_age_recipient"),
)

SPECIAL_SOURCES = {
    "application/INVITATION_SIGNING_KEY_ID",
    "application/INVITATION_SIGNING_PRIVATE_KEYS_JSON",
    "application/INVITATION_VERIFICATION_PUBLIC_KEYS_JSON",
    "application/CONTROL_PRIVACY_LOOKUP_KEY_ID",
    "application/CONTROL_PRIVACY_EXPORT_KEY_ID",
    "database/RAUTHY_POSTGRES_PASSWORD",
    "database/RAUTHY_ENC_KEYS",
    "database/RAUTHY_BOOTSTRAP_ADMIN_PASSWORD",
    "database/RAUTHY_HQL_SECRET_RAFT",
    "database/RAUTHY_HQL_SECRET_API",
    "tunnel/CLOUDFLARE_TUNNEL_TOKEN",
    "mail/ALLOWED_RECIPIENTS",
    "observability/ALERTMANAGER_WEBHOOK_URL",
    "observability/ALERTMANAGER_WEBHOOK_TOKEN",
}


def required_sources() -> set[str]:
    sources = {source for source, *_rest in DIRECT}
    sources.update(f"database/{name}" for name in DATABASE_IDENTITY_NAMES)
    sources.update(f"database/{password}" for password, _role, _file in DATABASE_ROLES.values())
    sources.update(source for source, _variable, _file in BACKUP)
    sources.update(SPECIAL_SOURCES)
    return sources


def source_file(
    root: Path,
    relative: str,
    *,
    optional: bool = False,
    allow_empty: bool = False,
) -> Path | None:
    path = root / relative
    if optional and not path.exists() and not path.is_symlink():
        return None
    materialize.regular_source(root, Path(relative))
    if path.stat().st_mode & 0o077:
        materialize.fail(f"canonical source is accessible by group or others: {relative}")
    if not allow_empty and not path.read_bytes():
        materialize.fail(f"canonical source is empty: {relative}")
    return path


def single_line(path: Path, label: str) -> str:
    data = path.read_text(encoding="utf-8")
    if any(character in data for character in "\r\n\0"):
        materialize.fail(f"canonical source must be a single line: {label}")
    return data


class Stage:
    def __init__(self, root: Path):
        self.root = root
        self.references: dict[str, dict[str, str]] = {}

    def write(self, relative: Path, data: bytes) -> None:
        target = self.root / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (target.parent, *target.parent.parents):
            if parent == self.root.parent or parent == self.root:
                break
            parent.chmod(0o700)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def secret(self, source: Path, process: str, variable: str, filename: str) -> None:
        target = Path("secrets") / PROCESS_DIR[process] / filename
        self.write(target, source.read_bytes())
        self.references.setdefault(process, {})[variable] = f"@/run/secrets/{filename}"

    def file_reference(self, process: str, variable: str, filename: str) -> None:
        self.references.setdefault(process, {})[variable] = f"/run/secrets/{filename}"

    def direct(self, process: str, variable: str, value: str) -> None:
        self.references.setdefault(process, {})[variable] = value


def database_url(user: str, password: str, host: str, port: int, database: str, ca: str) -> bytes:
    return (
        f"postgresql://{user}:{quote(password, safe='')}@{host}:{port}/{database}"
        f"?sslmode=verify-full&sslrootcert={quote(ca, safe='/')}"
    ).encode()


def build(
    source: Path,
    stage: Stage,
    environment: str,
    postgres_host: str,
    postgres_port: int,
    postgres_ca: Path,
    driver_ca_path: str,
    release_cosign_key: Path,
) -> dict[str, object]:
    expected = required_sources()
    optional_sources = {item[0] for item in OPTIONAL_PROVIDERS}
    actual = {
        str(path.relative_to(source))
        for path in source.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    missing = expected - actual
    extras = actual - expected - optional_sources
    if missing or extras:
        materialize.fail(
            f"canonical secret export drift: missing={sorted(missing)} extra={sorted(extras)}"
        )
    for relative in sorted(actual):
        source_file(
            source,
            relative,
            allow_empty=(
                environment == "production" and relative == "mail/ALLOWED_RECIPIENTS"
            ),
        )

    for source_name, process, variable, filename in DIRECT:
        stage.secret(source_file(source, source_name), process, variable, filename)  # type: ignore[arg-type]
    for source_name, process, variable, filename in OPTIONAL_PROVIDERS:
        path = source_file(source, source_name, optional=True)
        if path is not None:
            stage.secret(path, process, variable, filename)

    for process, (password_name, role, filename) in DATABASE_ROLES.items():
        password_path = source_file(source, f"database/{password_name}")
        ca = driver_ca_path if process == "docker-driver" else "/run/secrets/postgres-ca.crt"
        data = database_url(
            role,
            single_line(password_path, password_name),  # type: ignore[arg-type]
            postgres_host,
            postgres_port,
            "makersbrain_control",
            ca,
        )
        target = Path("secrets") / PROCESS_DIR[process] / filename
        stage.write(target, data)
        stage.references.setdefault(process, {})["DRIVER_DATABASE_URL" if process == "docker-driver" else "CONTROL_DATABASE_URL"] = f"@/run/secrets/{filename}"

    superuser = source_file(source, "database/POSTGRES_SUPERUSER_PASSWORD")
    admin_url = database_url(
        "postgres",
        single_line(superuser, "POSTGRES_SUPERUSER_PASSWORD"),  # type: ignore[arg-type]
        postgres_host,
        postgres_port,
        "postgres",
        driver_ca_path,
    )
    stage.write(Path("secrets/control-container-driver/postgres_admin_database_url"), admin_url)
    stage.references.setdefault("docker-driver", {})["DRIVER_POSTGRES_ADMIN_URL"] = "@/run/secrets/postgres_admin_database_url"

    for name in DATABASE_IDENTITY_NAMES:
        path = source_file(source, f"database/{name}")
        filename = name.lower()
        stage.secret(path, "control-database-identities", name, filename)  # type: ignore[arg-type]

    for source_name, variable, filename in BACKUP:
        path = source_file(source, source_name)
        stage.secret(path, "docker-driver", variable, filename)  # type: ignore[arg-type]
    age_recipient = single_line(source_file(source, "backup/BACKUP_AGE_RECIPIENT"), "BACKUP_AGE_RECIPIENT")  # type: ignore[arg-type]
    if not re.fullmatch(r"age1[0-9a-z]{50,100}", age_recipient):
        materialize.fail("BACKUP_AGE_RECIPIENT is not a bounded age X25519 recipient")
    stage.direct("docker-driver", "BACKUP_AGE_IDENTITY_FILE", "/run/makersbrain-recovery-secrets/age-identity.txt")

    private_keys = source_file(source, "application/INVITATION_SIGNING_PRIVATE_KEYS_JSON")
    public_keys = source_file(source, "application/INVITATION_VERIFICATION_PUBLIC_KEYS_JSON")
    key_id = single_line(source_file(source, "application/INVITATION_SIGNING_KEY_ID"), "INVITATION_SIGNING_KEY_ID")  # type: ignore[arg-type]
    for path, label in ((private_keys, "private"), (public_keys, "public")):
        document = json.loads(path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
        if not isinstance(document, dict) or key_id not in document.get("keys", {}):
            materialize.fail(f"invitation {label} key set omits active key ID")
    stage.write(Path("secrets/control-worker-email-delivery/invitation-signing-keys.json"), private_keys.read_bytes())  # type: ignore[union-attr]
    stage.file_reference("worker-email", "CONTROL_INVITATION_SIGNING_KEYS_FILE", "invitation-signing-keys.json")
    stage.direct("worker-email", "CONTROL_INVITATION_SIGNING_KEY_ID", key_id)
    stage.write(Path("secrets/control-api/invitation-verification-keys.json"), public_keys.read_bytes())  # type: ignore[union-attr]
    stage.file_reference("control-api", "CONTROL_INVITATION_VERIFICATION_KEYS_FILE", "invitation-verification-keys.json")
    stage.direct("control-api", "CONTROL_INVITATION_SIGNING_KEY_ID", key_id)

    for key_name, processes in (
        ("CONTROL_PRIVACY_LOOKUP_KEY_ID", ("worker-lifecycle", "worker-privacy")),
        ("CONTROL_PRIVACY_EXPORT_KEY_ID", ("control-api", "worker-privacy")),
    ):
        value = single_line(source_file(source, f"application/{key_name}"), key_name)  # type: ignore[arg-type]
        for process in processes:
            stage.direct(process, key_name, value)

    ca_text = postgres_ca.read_text(encoding="utf-8")
    if not re.search(r"-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----", ca_text, re.S):
        materialize.fail("PostgreSQL CA source contains no PEM certificate")
    rauthy_values = {
        name: single_line(source_file(source, f"database/{name}"), name)  # type: ignore[arg-type]
        for name in (
            "RAUTHY_POSTGRES_PASSWORD",
            "RAUTHY_ENC_KEYS",
            "RAUTHY_BOOTSTRAP_ADMIN_PASSWORD",
            "RAUTHY_HQL_SECRET_RAFT",
            "RAUTHY_HQL_SECRET_API",
        )
    }
    active, separator, _key = rauthy_values["RAUTHY_ENC_KEYS"].partition("/")
    if not separator or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", active):
        materialize.fail("RAUTHY_ENC_KEYS has no valid active date prefix")
    toml = (
        "[cluster]\n"
        f"secret_raft = {json.dumps(rauthy_values['RAUTHY_HQL_SECRET_RAFT'])}\n"
        f"secret_api = {json.dumps(rauthy_values['RAUTHY_HQL_SECRET_API'])}\n"
        "[database]\n"
        f"pg_password = {json.dumps(rauthy_values['RAUTHY_POSTGRES_PASSWORD'])}\n"
        f"pg_tls_root_ca = \"\"\"{ca_text.rstrip()}\n\"\"\"\n"
        "[bootstrap]\n"
        f"password_plain = {json.dumps(rauthy_values['RAUTHY_BOOTSTRAP_ADMIN_PASSWORD'])}\n"
        "[encryption]\n"
        f"keys = [{json.dumps(rauthy_values['RAUTHY_ENC_KEYS'])}]\n"
        f"key_active = {json.dumps(active)}\n"
    )
    stage.write(Path("secrets/rauthy/config.toml"), toml.encode())
    stage.direct("rauthy", "ENC_KEY_ACTIVE", active)

    materialize.regular_source(release_cosign_key.parent, Path(release_cosign_key.name))
    stage.write(
        Path("secrets/control-worker-release-adoption/release-cosign.pub"),
        release_cosign_key.read_bytes(),
    )
    stage.file_reference(
        "worker-release", "CONTROL_RELEASE_COSIGN_KEY_FILE", "release-cosign.pub"
    )

    tunnel = source_file(source, "tunnel/CLOUDFLARE_TUNNEL_TOKEN")
    stage.write(Path("secrets/cloudflared/tunnel-token"), tunnel.read_bytes())  # type: ignore[union-attr]
    allowed = source_file(
        source,
        "mail/ALLOWED_RECIPIENTS",
        allow_empty=environment == "production",
    )
    allowed_text = allowed.read_text(encoding="utf-8")  # type: ignore[union-attr]
    recipients = [line.strip() for line in allowed_text.splitlines() if line.strip()]
    if (environment == "staging" and not recipients) or len(recipients) > 100 or any(
        "*" in recipient
        or not re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}",
            recipient,
        )
        for recipient in recipients
    ):
        materialize.fail("mail allowlist must contain only bounded exact recipients")
    # A single LF represents the empty production set while keeping the mounted
    # file materialized and distinct from a missing secret.
    allowed_bytes = allowed.read_bytes() or b"\n"  # type: ignore[union-attr]
    stage.write(
        Path("secrets/control-mail-gateway/mail_allowed_recipients"), allowed_bytes
    )
    stage.file_reference("control-mail-gateway", "MAIL_GATEWAY_ALLOWED_RECIPIENTS_FILE", "mail_allowed_recipients")
    for source_name, target in (
        ("observability/ALERTMANAGER_WEBHOOK_URL", "webhook-url"),
        ("observability/ALERTMANAGER_WEBHOOK_TOKEN", "webhook-token"),
    ):
        path = source_file(source, source_name)
        value = single_line(path, source_name)  # type: ignore[arg-type]
        if target == "webhook-url" and (
            not value.startswith("https://") or any(character.isspace() for character in value)
        ):
            materialize.fail("Alertmanager webhook URL must be an HTTPS capability")
        if target == "webhook-token" and not 32 <= len(value) <= 512:
            materialize.fail("Alertmanager webhook token must be bounded")
        stage.write(Path("secrets/alertmanager") / target, path.read_bytes())  # type: ignore[union-attr]

    return {"schema_version": 1, "shared": {}, "processes": stage.references}


def write_json(path: Path, document: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        materialize.fail("refusing to overwrite secret reference output")
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a scoped secret stage from an exact Infisical export")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument(
        "--environment", required=True, choices=("staging", "production")
    )
    parser.add_argument("--staging-root", required=True, type=Path)
    parser.add_argument("--references-output", required=True, type=Path)
    parser.add_argument("--postgres-host", required=True)
    parser.add_argument("--postgres-port", type=int, default=5432)
    parser.add_argument("--postgres-ca", required=True, type=Path)
    parser.add_argument("--driver-ca-path", required=True)
    parser.add_argument("--release-cosign-key", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    if source.is_symlink() or not source.is_dir():
        materialize.fail("canonical source must be a real directory")
    if source.stat().st_mode & 0o077:
        materialize.fail("canonical source directory is accessible by group or others")
    for directory in (path for path in source.rglob("*") if path.is_dir()):
        if directory.is_symlink() or directory.stat().st_mode & 0o077:
            materialize.fail(
                f"canonical source directory is unsafe: {directory.relative_to(source)}"
            )
    if args.staging_root.is_symlink() or not args.staging_root.is_dir():
        materialize.fail("staging root must be a real existing directory")
    if args.staging_root.stat().st_mode & 0o077:
        materialize.fail("staging root is accessible by group or others")
    if any(args.staging_root.iterdir()):
        materialize.fail("secret staging root must be empty")
    if not 1 <= args.postgres_port <= 65535:
        materialize.fail("PostgreSQL port is invalid")
    materialize.regular_source(args.postgres_ca.parent, Path(args.postgres_ca.name))
    materialize.regular_source(
        args.release_cosign_key.parent, Path(args.release_cosign_key.name)
    )
    document = build(
        source,
        Stage(args.staging_root),
        args.environment,
        args.postgres_host,
        args.postgres_port,
        args.postgres_ca,
        args.driver_ca_path,
        args.release_cosign_key,
    )
    write_json(args.references_output, document)
    print(f"staged scoped secrets for {len(document['processes'])} processes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
