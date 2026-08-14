#!/usr/bin/env python3
"""Fail if the long-lived Paperless container regresses to metadata secrets."""

from pathlib import Path
import json
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SERVICES = (ROOT / "src/docker_driver/services.rs").read_text(encoding="utf-8")
HOOK = (ROOT / "deploy/paperless-post-consume.py").read_text(encoding="utf-8")
DRIVER_TREE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in [
        ROOT / "src/docker_driver.rs",
        *sorted((ROOT / "src/docker_driver").glob("*.rs")),
    ]
)

for forbidden in (
    "PAPERLESS_DBPASS=",
    "PAPERLESS_SECRET_KEY=",
    "PAPERLESS_ADMIN_PASSWORD=",
    "PAPERLESS_SOCIALACCOUNT_PROVIDERS=",
    "PAPERLESS_WEBHOOK_SECRET=",
):
    if forbidden in SERVICES:
        raise SystemExit(f"Paperless secret returned to Docker Env metadata: {forbidden}")

required = (
    "PAPERLESS_DBPASS_FILE=",
    "PAPERLESS_SECRET_KEY_FILE=",
    "PAPERLESS_ADMIN_PASSWORD_FILE=",
    "PAPERLESS_SOCIALACCOUNT_PROVIDERS_FILE=",
    "PAPERLESS_WEBHOOK_SECRET_FILE=",
    "runtime_secret_mount(",
    'PathBuf::from("paperless").join(workshop.to_string())',
)
for marker in required:
    if marker not in SERVICES:
        raise SystemExit(f"Paperless file-secret boundary is missing: {marker}")

if 'secret("PAPERLESS_WEBHOOK_SECRET")' not in HOOK:
    raise SystemExit("Paperless post-consume hook does not resolve its file secret")

for forbidden in (
    'format!("PGPASSWORD=',
    'format!("PASSWORD=',
    'format!("AWS_ACCESS_KEY_ID=',
    'format!("AWS_SECRET_ACCESS_KEY=',
    'format!("AGE_RECIPIENT=',
    'format!("MB_CONTROL_BRIDGE_TOKEN=',
    'format!("--db_password={',
    'MANIFEST_B64=',
):
    if forbidden in DRIVER_TREE:
        raise SystemExit(f"dynamic Docker metadata contains a secret value: {forbidden}")

for marker in (
    "run_docker_job_with_secrets(",
    '"PGPASSFILE=/run/makersbrain-job-secrets/pgpass"',
    "aws_secret_prelude()",
    'ContainerRuntimeKind::Podman => json!({',
    '"Type":"bind"',
):
    if marker not in DRIVER_TREE:
        raise SystemExit(f"dynamic job secret boundary is missing: {marker}")

model = json.loads(
    subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ROOT / "deploy/.env.example"),
            "-f",
            str(ROOT / "deploy/compose.yml"),
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    ).stdout
)


def named_volumes(service):
    return {
        mount["source"]: (mount["target"], mount.get("read_only", False))
        for mount in model["services"][service].get("volumes", [])
        if mount["type"] == "volume"
    }


expected_worker_volumes = {
    "control-api": {"tenant-secrets"},
    "worker-membership": {"tenant-secrets", "paperless-client-secrets"},
    "worker-invoice": {"tenant-secrets", "paperless-client-secrets"},
    "worker-inventory": {"tenant-secrets"},
    "worker-provisioning": set(),
    "worker-reconciliation": {"tenant-secrets"},
}
for service, expected in expected_worker_volumes.items():
    actual = named_volumes(service)
    sensitive = set(actual) & {
        "tenant-secrets",
        "paperless-client-secrets",
        "backup-secrets",
    }
    if sensitive != expected:
        raise SystemExit(
            f"{service} dynamic-secret volume drift: expected {sorted(expected)}, got {sorted(sensitive)}"
        )
    if any(not actual[source][1] for source in expected):
        raise SystemExit(f"{service} has a writable dynamic-secret mount")

print("dynamic container metadata contains only scoped secret-file references")
