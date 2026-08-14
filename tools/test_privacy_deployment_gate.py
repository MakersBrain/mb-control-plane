#!/usr/bin/env python3
"""Prove active personal-data processors are fenced by the governance gate."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
DEPLOY = CONTROL / "deploy"
GOVERNANCE_ENVIRONMENT = {
    "CONTROL_DATA_MODE",
    "CONTROL_PRIVACY_CONTROLLER_REF",
    "CONTROL_PRIVACY_PROCESSING_RECORD_REF",
    "CONTROL_PRIVACY_RETENTION_APPROVAL_REF",
    "CONTROL_PRIVACY_PROCESSOR_REGISTER_REF",
    "CONTROL_PRIVACY_DPIA_APPROVAL_REF",
    "CONTROL_PRIVACY_PROCESSING_REGION",
}
PROCESSORS = {
    "control-api",
    "document-extraction",
    "docker-driver",
    "worker-membership",
    "worker-provisioning",
    "worker-invoice",
    "worker-inventory",
    "worker-email",
    "worker-reconciliation",
    "worker-lifecycle",
    "worker-release",
    "worker-privacy",
    "backup-scheduler",
    "rauthy-bootstrap",
    "rauthy",
    "odoo",
    "tenant-gateway",
}


def rendered_compose() -> dict:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(DEPLOY / ".env.example"),
            "-f",
            str(DEPLOY / "compose.yml"),
            "config",
            "--format",
            "json",
        ],
        cwd=CONTROL,
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError("rendered Compose model is not an object")
    return value


def main() -> int:
    services = rendered_compose().get("services", {})
    if not isinstance(services, dict):
        raise AssertionError("rendered Compose model has no services")
    missing = PROCESSORS - set(services)
    if missing:
        raise AssertionError(f"privacy-gated processors are missing: {sorted(missing)}")

    migration = services.get("control-migrate", {})
    migration_dependencies = migration.get("depends_on", {})
    if "control-migrate" in migration_dependencies:
        raise AssertionError("the governance/migration gate depends on itself")
    for service_name in sorted(PROCESSORS):
        dependency = services[service_name].get("depends_on", {}).get("control-migrate")
        if not isinstance(dependency, dict) or dependency.get("condition") != "service_completed_successfully":
            raise AssertionError(
                f"{service_name} can start before the privacy governance gate completes"
            )

    for service_name in ("control-migrate", "control-api"):
        environment = services[service_name].get("environment", {})
        absent = GOVERNANCE_ENVIRONMENT - set(environment)
        if absent:
            raise AssertionError(
                f"{service_name} omits governance settings: {sorted(absent)}"
            )
    print("every active personal-data processor is fenced by the governance gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
