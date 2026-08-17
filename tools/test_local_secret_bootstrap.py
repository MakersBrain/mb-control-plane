#!/usr/bin/env python3
"""Exercise local secret generation without touching a developer environment."""

from __future__ import annotations

import json
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
DEPLOY = CONTROL / "deploy"


def main() -> int:
    specification = json.loads((DEPLOY / "configuration-spec.json").read_text())
    secret_names = set(specification["secrets"])
    compose = (DEPLOY / "compose.yml").read_text()
    expected_files = set(
        re.findall(r"\{file: \./secrets/runtime/([a-z0-9_.-]+)\}", compose)
    )
    with tempfile.TemporaryDirectory(prefix="makersbrain-secret-bootstrap-") as directory:
        target = Path(directory) / ".env"
        subprocess.run(
            [str(DEPLOY / "bootstrap-local-env.sh"), str(target)],
            cwd=CONTROL.parent,
            check=True,
            capture_output=True,
            text=True,
        )
        runtime = Path(directory) / "secrets/runtime"
        actual_files = {path.name for path in runtime.iterdir() if path.is_file()}
        if actual_files != expected_files:
            raise SystemExit(
                "bootstrap/Compose secret-file drift: "
                f"missing={sorted(expected_files - actual_files)} "
                f"extra={sorted(actual_files - expected_files)}"
            )
        environment = target.read_text()
        values = dict(
            re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=(.*)$", environment)
        )
        for name in secret_names & set(values):
            if not values[name].startswith("@/run/secrets/"):
                raise SystemExit(f"bootstrap wrote plaintext secret setting {name}")
        for path in runtime.iterdir():
            if stat.S_IMODE(path.stat().st_mode) != 0o444:
                raise SystemExit(f"bootstrap secret has unsafe mode: {path.name}")
        if stat.S_IMODE(runtime.stat().st_mode) != 0o700:
            raise SystemExit("bootstrap secret directory is not mode 0700")
            value = path.read_text()
            if value and value in environment:
                raise SystemExit(f"bootstrap secret value leaked into .env: {path.name}")
        if stat.S_IMODE(target.stat().st_mode) != 0o600:
            raise SystemExit("bootstrap environment file is not mode 0600")
        rauthy_config = runtime / "rauthy_config.toml"
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", "HIQLITE=false",
                "-e", "PG_HOST=postgres",
                "-e", "PG_PORT=5432",
                "-e", "PG_USER=rauthy",
                "-e", "PG_DB_NAME=rauthy",
                "-e", "PG_TLS=disable",
                "-e", "HQL_NODE_ID=1",
                "-e", "HQL_NODES=1 localhost:8100 localhost:8200",
                "-e", "LISTEN_ADDRESS=0.0.0.0",
                "-e", "LISTEN_PORT_HTTP=8092",
                "-e", "LISTEN_SCHEME=http",
                "-e", "PUB_URL=rauthy.localhost:8093",
                "-e", "PROXY_MODE=false",
                "-e", "BOOTSTRAP_DIR=/bootstrap",
                "-e", "BOOTSTRAP_ADMIN_EMAIL=owner@example.test",
                "-e", "RP_ID=rauthy.localhost",
                "-e", "RP_ORIGIN=http://rauthy.localhost:8093",
                "-e", "RP_NAME=MakersBrain",
                "-v", f"{rauthy_config}:/app/config.toml:ro",
                "ghcr.io/sebadob/rauthy:0.36.1",
                "validate-config", "--path", "/app/config.toml",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        generated_during_legacy_upgrade = {
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
            "CONTROL_RELEASE_PUBLISH_TOKEN",
            "CONTROL_METRICS_TOKEN",
            "DOCUMENT_EXTRACTION_TOKEN",
            "PRIVACY_DRIVER_TOKEN",
            "CONTROL_PRIVACY_LOOKUP_KEY",
            "CONTROL_PRIVACY_EXPORT_KEY",
            "CONTROL_PRIVACY_LOOKUP_KEY_ID",
            "CONTROL_PRIVACY_EXPORT_KEY_ID",
            "CONTROL_DATA_MODE",
            "CONTROL_RELEASE_ID",
            "INVITATION_SIGNING_KEY_ID",
            "RELEASE_SLSA_BUILDER_ID",
        }
        legacy_lines: list[str] = []
        preserved_internal_token = ""
        for line in environment.splitlines():
            match = re.match(r"^([A-Z][A-Z0-9_]*)=@/run/secrets/([a-z0-9_.-]+)$", line)
            if match:
                value = (runtime / match.group(2)).read_text()
                if match.group(1) == "CONTROL_INTERNAL_TOKEN":
                    preserved_internal_token = value
                line = f"{match.group(1)}='{value}'"
            name = line.split("=", 1)[0]
            if name in generated_during_legacy_upgrade:
                continue
            legacy_lines.append(line)
        target.write_text("\n".join(legacy_lines) + "\n")
        target.chmod(0o600)
        shutil.rmtree(runtime)
        shutil.rmtree(Path(directory) / "secrets/invitation")
        subprocess.run(
            [
                str(DEPLOY / "migrate-local-env-secrets.sh"),
                "--apply",
                str(target),
            ],
            cwd=CONTROL.parent,
            check=True,
            capture_output=True,
            text=True,
        )
        migrated_values = dict(
            re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=(.*)$", target.read_text())
        )
        for name in secret_names & set(migrated_values):
            if not migrated_values[name].startswith("@/run/secrets/"):
                raise SystemExit(f"migration retained plaintext secret setting {name}")
        migrated_files = {path.name for path in runtime.iterdir() if path.is_file()}
        if migrated_files != expected_files:
            raise SystemExit("legacy migration did not reconstruct the Compose secret set")
        if (runtime / "control_internal_token").read_text() != preserved_internal_token:
            raise SystemExit("legacy migration rotated an existing credential")
        if not (Path(directory) / "secrets/invitation/public-keys.json").is_file():
            raise SystemExit("legacy migration did not generate invitation signing keys")
        repeated = subprocess.run(
            [str(DEPLOY / "bootstrap-local-env.sh"), str(target)],
            cwd=CONTROL.parent,
            capture_output=True,
            text=True,
        )
        if repeated.returncode == 0:
            raise SystemExit("bootstrap overwrote existing credentials")
    print("local secret bootstrap and legacy migration are private and Compose-complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
